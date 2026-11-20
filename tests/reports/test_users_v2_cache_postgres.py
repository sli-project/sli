"""Real PostgreSQL cold snapshot/cache contract for multiple synthetic domains."""
import os

import pytest

from server.sli.plugins.ad.reports.definitions import users
from tests.postgres_integration_guard import assert_disposable_database
from tests.reports.test_users_v2_performance import SyntheticDirectory, _two_population_snapshot


def _expected_current_context(scope):
    expected = _two_population_snapshot(scope)
    # The loader decorates the otherwise unchanged current snapshot.
    expected["metadata"]["comparison_role"] = "current_context"
    return expected


def test_expected_snapshot_includes_loader_decoration():
    with SyntheticDirectory(3).installed():
        assert users._snapshots([1])["current"] == _expected_current_context([1])


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_cold_snapshot_scopes_and_warm_reuse_on_postgres(monkeypatch):
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    from server.sli.core import postgres_runtime_pipeline

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("isolated PostgreSQL DSN is required")
    # conftest gives this test its own empty sli_test_* database. Keep the real
    # bounded query adapter, SQL, source projection and snapshot loader intact.
    with psycopg.connect(dsn, autocommit=True) as conn:
        assert_disposable_database(conn)
        conn.execute("""
            create table domains(id int primary key, fqdn text);
            insert into domains values (11,'current.invalid'),(22,'archive.invalid');
            create table storage_v2_entity_type(id int primary key,value text);
            insert into storage_v2_entity_type values (1,'ad_user'),(2,'ad_group');
            create table entities_v2(id bigint primary key,domain_id int,
                entity_type_id int,display_name text,natural_key text);
            create view entities_v2_active as select * from entities_v2;
            create table ad_context_entity_versions(entity_id bigint,source_section text,
                valid_to_utc timestamptz,last_observed_at_utc timestamptz,
                attributes_json jsonb,source_run_id text);
            create table ad_context_entity_aliases(entity_id bigint,alias_type text,alias_value text);
            create table ad_context_runs(run_id text primary key,domain_id int,status text,
                observed_at_utc timestamptz,created_at timestamptz,completed_at timestamptz,
                source_pack_version text);
            create table ad_context_sections(run_id text,section_name text,status text,
                record_count int,error_code text);
            create table ad_context_relation_versions(id bigint,domain_id int,
                source_entity_id bigint,target_entity_id bigint,relation_kind text,
                source_section text,valid_to_utc timestamptz,last_observed_at_utc timestamptz,
                attributes_json jsonb);
            insert into ad_context_runs select 'run-' || id,id,'completed',
                '2026-10-21T12:00:00Z','2026-10-21T12:00:00Z','2026-10-21T12:00:00Z','2.0.0'
                from domains;
            insert into ad_context_sections select run_id,'directory_accounts','complete',1275,null
                from ad_context_runs;
            insert into entities_v2 select id,case when id<=1275 then 11 else 22 end,1,
                'Synthetic account ' || id,'fixture-' || id from generate_series(1,2550) id;
            insert into ad_context_entity_versions select id,'directory_accounts',null,
                '2026-10-21T12:00:00Z',jsonb_build_object('attributes',jsonb_build_object(
                    'sam_account_name',natural_key,'enabled',true)), 'run-' || domain_id
                from entities_v2;
            update ad_context_entity_versions set attributes_json=jsonb_set(attributes_json,
                '{attributes,sam_account_name}', '"nested$"') where entity_id=1;
            update ad_context_entity_versions set attributes_json=jsonb_set(attributes_json,
                '{attributes,enabled}', 'null') where entity_id=2;
            update ad_context_entity_versions set attributes_json=
                '{"sam_account_name":"flat$","enabled":true}' where entity_id=3;
        """)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", lambda: psycopg.connect(dsn, row_factory=dict_row))
    users._cache.clear()
    try:
        for scope, expected in (([11], {11}), ([22], {22}), (None, {11, 22}), ([], set())):
            expected_snapshot = _expected_current_context(scope)
            snapshot = users._snapshots(scope)
            assert snapshot["current"] == expected_snapshot
            accounts = snapshot["current"]["users"]
            assert {account["domainId"] for account in accounts} == expected
            assert len(accounts) == 1275 * len(expected)
            assert snapshot["previous_state"] == "not_requested"
            assert users._snapshots(scope) is snapshot
        # Warm hits must not open any database connection, including empty scope.
        def unavailable():
            pytest.fail("warm snapshot opened PostgreSQL")

        monkeypatch.setattr(postgres_runtime_pipeline, "connect", unavailable)
        for scope in ([11], [22], None, []):
            assert users._snapshots(scope)["current"] is not None
    finally:
        users._cache.clear()
