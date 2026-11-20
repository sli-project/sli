"""Real migrated API-role query and denied metadata; no fixture GRANTs."""
import json
import os
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

import pytest

from server.sli.sigma import rule_list
from server.sli.sigma.registry import RegistryScope, register_revision
from server.sli.storage.evidence_ref import EvidenceScope
from tests.migrations.historical_postgres import historical_connection
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_sigma_attack_coverage import END, START, observation
from tests.unit.test_sigma_rule_list import policy

pytestmark = pytest.mark.postgres_integration
HISTORICAL_TIP = (325, "t109_workstation_path")


@pytest.fixture
def sigma_label_history(tmp_path, monkeypatch):
    # The complete predecessor of NPS 326 supports these historical unwinds.
    with historical_connection(tmp_path, monkeypatch, HISTORICAL_TIP) as conn:
        yield conn


def test_api_role_reads_exact_scopes_revisions_and_policy_without_title_grant(monkeypatch):
    psycopg = pytest.importorskip("psycopg")
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Disposable migrated PostgreSQL required")
    scope = EvidenceScope(str(uuid4()), "sli.windows.ad-dc", "fixture-t019-source", "fixture-generation")
    monkeypatch.setattr(rule_list, "get_runtime_connection",
                        lambda: psycopg.connect(make_conninfo(dsn, user="adlog_user"), row_factory=dict_row))
    with psycopg.connect(make_conninfo(dsn, user="adlog_user"), row_factory=dict_row) as runtime:
        assert_disposable_database(runtime)
        assert runtime.execute("select session_user,current_user").fetchone() == {
            "session_user": "adlog_user", "current_user": "adlog_user"}
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as admin:
        assert_disposable_database(admin)
        privileges = admin.execute("""select
            has_column_privilege('adlog_user','sli_sigma.sigma_rule_revisions','raw_sha256','SELECT') as digest,
            has_column_privilege('adlog_user','sli_sigma.sigma_rule_revisions','canonical_rule','SELECT') as metadata,
            has_function_privilege('adlog_user','public.read_admitted_sigma_revision(text,integer)','EXECUTE') as worker_reader
        """).fetchone()
        assert privileges == {"digest": True, "metadata": False, "worker_reader": False}
        with admin.cursor() as cur:
            canonical = {"id": "00000000-0000-0000-0000-000000000001", "title": "Synthetic retained rule title",
                         "description": "Synthetic retained purpose", "private_unused_field": "must not be returned"}
            registered = register_revision(cur, RegistryScope(scope.installation_id, scope.plugin_id, scope.source_instance_id),
                raw_yaml=b"title: Synthetic retained rule title\n", canonical_rule=canonical,
                upstream_commit="b" * 40, status="test", level="low", tags=[], author="Synthetic fixture",
                license_id="DRL-1.1", source_uri="https://example.invalid/rule.yml", requirements={})
            cur.execute("""insert into sli_sigma.attack_source_scopes
                (installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,resources)
                values(%s,%s,%s,%s,%s,%s::jsonb)""",
                (*asdict(scope).values(), json.dumps([{"server_id": 1, "channel": "Security"}])))
            history = observation(counts={"scanned": 10, "evaluable": 10, "matched": 3})
            history["document_json"]["mode"] = "test"
            cur.execute("""insert into sli_sigma.attack_history_coverage
                (installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,
                 rule_id,raw_sha256,time_from,time_to,document_json)
                values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)""",
                (*asdict(scope).values(), canonical["id"], registered["raw_sha256"], START, END,
                 json.dumps(history["document_json"])))
            item = policy(policy_id=f"fixture-t019-{uuid4()}")
            item["selector"]["execution"].update(scope=asdict(scope), rule_sha256=registered["raw_sha256"])
            cur.execute("""insert into semantic_risk_policies
                (policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
                values(%s,2,'detection_match','shadow',%s::jsonb,%s)""",
                (item["policy_id"], json.dumps({"title": item["policy_title"], "source_selector": item["selector"]}), bytes(32)))
        # Even a product owner cannot bypass the DB session user's scope ACL.
        assert rule_list.get_sigma_rules({"platform_owner": True}, scope=scope)["state"] == "unavailable"
        with psycopg.connect(make_conninfo(dsn, user="adlog_user"), row_factory=dict_row) as runtime:
            assert runtime.execute("select * from sli_sigma.read_rule_labels(%s,%s,%s,%s,%s)",
                (scope.installation_id, scope.plugin_id, scope.source_instance_id, canonical["id"], registered["raw_sha256"])).fetchall() == []
        admin.execute("""insert into sli_sigma.scope_access
            (principal_oid,principal_name,installation_id,plugin_id,source_instance_id)
            select oid,rolname,%s,%s,%s from pg_roles where rolname='adlog_user'""",
            (scope.installation_id, scope.plugin_id, scope.source_instance_id))
        discovery = rule_list.get_sigma_rules({"platform_owner": True})
        assert asdict(scope) in discovery["sources"]
        data = rule_list.get_sigma_rules({"platform_owner": True}, scope=scope)
        assert data["state"] == "available", data["reason"]
        row = data["rules"][0]
        assert row["raw_sha256"] == registered["raw_sha256"] and row["title"] == canonical["title"]
        assert row["description"] == canonical["description"] and row["metadata_state"] == "available"
        assert row["executions"][0]["counts"]["matched"] == 3
        assert row["runtime"]["enabled"] == 0
        assert row["admission"]["policies"][0]["policy_id"] == item["policy_id"]
        assert row["admission"]["policies"][0]["policy_version"] == 2
        assert row["admission"]["policies"][0]["admitted"] is False
        denied = rule_list.get_sigma_rules({"platform_owner": True}, scope=EvidenceScope(
            scope.installation_id, scope.plugin_id, scope.source_instance_id, "different-generation"))
        assert denied["state"] == "unavailable" and denied["rules"] == []
        with psycopg.connect(make_conninfo(dsn, user="adlog_user"), autocommit=True, row_factory=dict_row) as runtime:
            params = (scope.installation_id, scope.plugin_id, scope.source_instance_id, canonical["id"], registered["raw_sha256"])
            sql = "select * from sli_sigma.read_rule_labels(%s,%s,%s,%s,%s)"
            labels = runtime.execute(sql, params).fetchone()
            assert set(labels) == {"rule_id", "raw_sha256", "title", "description"}
            assert labels["title"] == canonical["title"] and labels["description"] == canonical["description"]
            for index, wrong in [(0, str(uuid4())), (1, "sli.file-audit"), (2, "other-source"), (3, str(uuid4())), (4, "f" * 64)]:
                changed = list(params); changed[index] = wrong
                assert runtime.execute(sql, changed).fetchall() == []
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                runtime.execute("select canonical_rule,raw_yaml from sli_sigma.sigma_rule_revisions")
            for title, description, expected in [("x" * 512, "y" * 4000, True), ("x" * 513, "y" * 4001, False), ({"bad": True}, 12, False)]:
                with admin.cursor() as cur:
                    extra = register_revision(cur, RegistryScope(scope.installation_id, scope.plugin_id, scope.source_instance_id),
                        raw_yaml=json.dumps([title, description]).encode(), canonical_rule={"id": canonical["id"], "title": title, "description": description},
                        upstream_commit="b" * 40, status="test", level="low", tags=[], author="Synthetic", license_id="DRL-1.1",
                        source_uri="https://example.invalid/rule.yml", requirements={})
                result = runtime.execute(sql, (*params[:4], extra["raw_sha256"])).fetchone()
                assert (result["title"] == title if expected else result["title"] is None)
                assert (result["description"] == description if expected else result["description"] is None)


@pytest.mark.postgres_owned_cluster
def test_label_migration_reapply_rollback_and_prerequisite_guards(sigma_label_history):
    from tests.migrations.test_report_producer_migration285 import (
        restore_successors,
        rollback_successors,
    )
    psycopg = pytest.importorskip("psycopg")
    root = Path(__file__).resolve().parents[2]
    forward = (root / "config/postgres_migrations/286_sigma_rule_labels.sql").read_text("utf-8")
    backward = (root / "config/postgres_migrations/286_sigma_rule_labels.rollback.sql").read_text("utf-8")
    forward287 = (root / "config/postgres_migrations/287_workstation_inventory_job.sql").read_text("utf-8")
    backward287 = (root / "config/postgres_migrations/287_workstation_inventory_job.rollback.sql").read_text("utf-8")
    conn = sigma_label_history
    assert_disposable_database(conn)
    with pytest.raises(psycopg.errors.RaiseException, match="migration 286 prerequisites failed"):
        conn.execute(forward)
    conn.execute("rollback")
    # Later migrations must still fence a direct 287 rollback.
    with pytest.raises(psycopg.errors.RaiseException, match="migration 287 rollback prerequisites failed"):
        conn.execute(backward287)
    conn.execute("rollback")
    successors = rollback_successors(conn, after=287)
    # A real 287 successor must block direct 286 rollback. Remove it
    # through its own guarded rollback before exercising the 286 body.
    with pytest.raises(psycopg.errors.RaiseException, match="migration 286 rollback prerequisites failed"):
        conn.execute(backward)
    conn.execute("rollback")
    conn.execute(backward287)
    conn.execute(backward)
    assert conn.execute("select to_regprocedure('sli_sigma.read_rule_labels(uuid,text,text,uuid,text)')").fetchone()[0] is None
    # 287 may not be applied to 285 without the genuine 286.
    with pytest.raises(psycopg.errors.RaiseException, match="migration 287 prerequisites failed"):
        conn.execute(forward287)
    conn.execute("rollback")
    conn.execute("update schema_migrations set name='wrong' where version=285")
    with pytest.raises(psycopg.errors.RaiseException, match="migration 286 prerequisites failed"):
        conn.execute(forward)
    conn.execute("rollback")
    conn.execute("update schema_migrations set name='report_producer' where version=285")
    conn.execute(forward)
    assert conn.execute("select has_function_privilege('adlog_user','sli_sigma.read_rule_labels(uuid,text,text,uuid,text)','EXECUTE')").fetchone()[0]
    assert not conn.execute("select has_function_privilege('adlog_semantic_worker','sli_sigma.read_rule_labels(uuid,text,text,uuid,text)','EXECUTE')").fetchone()[0]
    catalog = conn.execute("""select r.rolname,p.prosecdef,p.proconfig,
        not exists(select 1 from aclexplode(p.proacl) a where a.grantee=0 and a.privilege_type='EXECUTE')
        from pg_proc p join pg_roles r on r.oid=p.proowner
        where p.oid='sli_sigma.read_rule_labels(uuid,text,text,uuid,text)'::regprocedure""").fetchone()
    assert catalog[0:2] == ('adlog_sigma_owner', True) and catalog[3] is True
    assert [value.replace(' ', '') for value in catalog[2]] == ['search_path=pg_catalog,pg_temp']
    conn.execute(forward287)
    restore_successors(conn, successors)
    assert conn.execute("select version,name from schema_migrations where version>=285 order by version").fetchall() == [
        (285, "report_producer"), (286, "sigma_rule_labels"), (287, "workstation_inventory_job"),
        *successors]


@pytest.mark.postgres_owned_cluster
def test_report_fixture_restores_exact_label_successor(sigma_label_history):
    from psycopg.rows import dict_row

    from tests.migrations import test_report_producer_migration285 as producer

    conn = sigma_label_history
    conn.row_factory = dict_row
    assert_disposable_database(conn)
    upstream = conn.execute('select * from schema_migrations where version<=284 order by version').fetchall()
    query = 'select version,name from schema_migrations where version>=285 order by version'
    expected = conn.execute(query).fetchall()
    assert {'version': 288, 'name': 'file_audit_service_filter'} in expected
    assert {'version': 297, 'name': 'agent_stream_import_health'} in expected
    assert {'version': 296, 'name': 'agent_runtime_switch'} in expected
    producer.reapply(conn)
    assert conn.execute(query).fetchall() == expected
    assert conn.execute('select * from schema_migrations where version<=284 order by version').fetchall() == upstream
    assert conn.execute("select to_regprocedure('sli_sigma.read_rule_labels(uuid,text,text,uuid,text)') as f").fetchone()['f']
    assert conn.execute("select to_regprocedure('public.read_workstation_inventory_input_v1(uuid,uuid,bigint)') as f").fetchone()['f']
    assert conn.execute("select to_regclass('public.sli_agent_stream_import_health') as t").fetchone()['t']
    assert conn.execute("select to_regprocedure('public.replace_agent_runtime_v296(uuid,uuid,text,text)') as f").fetchone()['f']


@pytest.mark.parametrize('missing_rollback', [False, True])
@pytest.mark.postgres_owned_cluster
def test_successor_files_define_future_order_and_missing_rollback_refuses_before_reset(
    tmp_path, monkeypatch, sigma_label_history, missing_rollback,
):
    from tests.migrations import test_report_producer_migration285 as producer

    directory = tmp_path / 'config/postgres_migrations'
    directory.mkdir(parents=True)
    for path in (producer.ROOT / 'config/postgres_migrations').glob('*.sql'):
        if path.name[:3].isdigit() and 287 < int(path.name[:3]) <= HISTORICAL_TIP[0]:
            (directory / path.name).write_bytes(path.read_bytes())
    conn = sigma_label_history
    assert_disposable_database(conn)
    # Two synthetic successors require ascending apply / descending rollback.
    # Their SQL guards fail if the helper gets either order wrong.
    previous = conn.execute('select max(version) from schema_migrations').fetchone()[0]
    for version in (997, 998):
        forward = f"""begin;
            do $$ begin
                if (select max(version) from schema_migrations)<>{previous} then
                    raise exception 'synthetic_successor_order';
                end if;
            end $$;
            create table public.synthetic_successor_{version}(id integer);
            insert into schema_migrations(version,name) values({version},'synthetic_successor');
            commit;"""
        backward = f"""begin;
            do $$ begin
                if (select max(version) from schema_migrations)<>{version} then
                    raise exception 'synthetic_successor_order';
                end if;
            end $$;
            drop table public.synthetic_successor_{version};
            delete from schema_migrations where version={version};
            commit;"""
        (directory / f'{version}_synthetic_successor.sql').write_text(forward, encoding='utf-8')
        if not (missing_rollback and version == 997):
            (directory / f'{version}_synthetic_successor.rollback.sql').write_text(backward, encoding='utf-8')
        conn.execute(forward)
        previous = version
    monkeypatch.setattr(producer, 'ROOT', tmp_path)
    query = 'select version,name from schema_migrations order by version'
    before = conn.execute(query).fetchall()
    if missing_rollback:
        with pytest.raises(ValueError, match='producer_fixture_reviewed_successor_missing'):
            producer.rollback_successors(conn, after=287)
        assert conn.execute(query).fetchall() == before
    else:
        successors = producer.rollback_successors(conn, after=287)
        assert conn.execute('select max(version) from schema_migrations').fetchone() == (287,)
        assert conn.execute("select to_regclass('public.synthetic_successor_998')").fetchone() == (None,)
        producer.restore_successors(conn, successors)
        assert conn.execute(query).fetchall() == before
    assert conn.execute("select to_regclass('public.synthetic_successor_997'),"
                        "to_regclass('public.synthetic_successor_998')").fetchone() == (
                            'synthetic_successor_997', 'synthetic_successor_998')


@pytest.mark.parametrize('successor_state', ['foreign', 'foreign_filter', 'foreign_health', 'foreign_runtime', 'future'])
def test_report_predecessor_rejects_foreign_or_future_successor_without_partial_reset(successor_state):
    from tests.migrations import test_report_producer_migration285 as producer

    psycopg = pytest.importorskip('psycopg')
    from psycopg.rows import dict_row
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('Disposable migrated PostgreSQL required')
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        upstream = conn.execute('select * from schema_migrations where version<=285 order by version').fetchall()
        if successor_state == 'foreign':
            conn.execute("update schema_migrations set name='synthetic_foreign' where version=286")
        elif successor_state == 'foreign_filter':
            conn.execute("update schema_migrations set name='synthetic_foreign' where version=288")
        elif successor_state == 'foreign_health':
            conn.execute("update schema_migrations set name='synthetic_foreign' where version=297")
        elif successor_state == 'foreign_runtime':
            conn.execute("update schema_migrations set name='synthetic_foreign' where version=296")
        else:
            conn.execute("insert into schema_migrations(version,name) values(999999,'synthetic_future')")
        ledger = conn.execute('select * from schema_migrations order by version').fetchall()
        # Whole-chain preflight rejects foreign/future ledger entries before
        # rolling back the otherwise valid 287 successor.
        with pytest.raises(ValueError, match='producer_fixture_successor_invalid'):
            producer.predecessor(conn)
        conn.execute('rollback')
        assert conn.execute('select * from schema_migrations order by version').fetchall() == ledger
        assert conn.execute('select * from schema_migrations where version<=285 order by version').fetchall() == upstream
        assert conn.execute("select to_regclass('public.report_producer_claims') as t").fetchone()['t']
        assert conn.execute("select to_regprocedure('sli_sigma.read_rule_labels(uuid,text,text,uuid,text)') as f").fetchone()['f']
        assert conn.execute("select to_regprocedure('public.read_workstation_inventory_input_v1(uuid,uuid,bigint)') as f").fetchone()['f']
        assert conn.execute("select to_regclass('public.sli_agent_stream_import_health') as t").fetchone()['t']
        assert conn.execute("select name from schema_migrations where version=287").fetchone()['name'] == 'workstation_inventory_job'
        assert conn.execute("select to_regclass('public.sli_agent_runtime_switches') as t").fetchone()['t']
