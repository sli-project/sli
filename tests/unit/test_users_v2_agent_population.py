import json
import os
from uuid import uuid4

import pytest

from server.sli.plugins.ad.reports import users_v2_reporting as users
from tests.postgres_integration_guard import assert_disposable_database


def test_v2_directory_coverage_uses_the_same_authorized_domains(monkeypatch):
    from server.sli.plugins.ad.reports import users_reporting as legacy

    calls = []
    monkeypatch.setattr(legacy, 'query_rows_bounded', lambda sql, params=(), **kw: calls.append((sql, params)) or [])
    monkeypatch.setattr(users, 'query_rows_bounded', lambda sql, params=(), **kw: calls.append((sql, params)) or [])
    monkeypatch.setattr(legacy, 'report_domain_fqdn', lambda: pytest.fail('V2 must not require a legacy deployment FQDN'))
    legacy.get_users_report(domain_ids=[1275], _directory_only=True)
    coverage = next(sql for sql, _ in calls if 'users_report_coverage' in sql)
    assert "lower(fqdn)='legacy.invalid'" not in coverage
    assert 'where id=any(?)' in coverage
    calls.clear()
    legacy.get_users_report(domain_ids=[], _directory_only=True)
    assert calls == []


def test_empty_authorized_domain_scope_never_queries_population(monkeypatch):
    monkeypatch.setattr(users, 'query_rows_bounded', lambda *a, **k: pytest.fail('empty scope queried'))
    assert users._directory_user_population(domain_ids=[]) == []


def test_domain_directory_date_is_not_refreshed_by_membership_or_another_domain(monkeypatch):
    from server.sli.plugins.ad.reports import users_reporting as legacy

    old, recent = "2026-09-15T00:00:00Z", "2026-10-16T00:00:00Z"

    def query(sql, params=(), **kwargs):
        assert "users_report_coverage" in sql
        assert params == ([11, 22],)
        return [{"domain_id": domain_id, "domain_name": f"domain-{domain_id}.invalid",
                 "section_name": section, "run_status": "completed", "section_status": "complete",
                 "record_count": 1, "observed_at_utc": old if domain_id == 11 and section == "directory_accounts" else recent}
                for domain_id in (11, 22) for section in ("directory_accounts", "privileged_membership")]

    monkeypatch.setattr(legacy, "query_rows_bounded", query)
    monkeypatch.setattr(users, "_directory_user_rows", lambda **kwargs: [])
    payload = legacy.get_users_report(domain_ids=[11, 22], _directory_only=True)
    by_domain = {row["domain_id"]: row for row in payload["coverage"]["domains"]}
    assert by_domain[11]["observed_at_utc"] == "2026-09-15T00:00:00+00:00"
    assert by_domain[11]["latest_observed_at_utc"] == "2026-10-16T00:00:00+00:00"
    assert by_domain[22]["observed_at_utc"] == "2026-10-16T00:00:00+00:00"


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_agent_directory_population_honors_domain_type_and_current_source(monkeypatch):
    psycopg = pytest.importorskip('psycopg')
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.rows import dict_row

    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('isolated PostgreSQL DSN is required')
    database = 'sli_test_users_agent_population_' + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert_disposable_database(admin)
        admin.execute(sql.SQL('create database {}').format(sql.Identifier(database)))
        try:
            parts = conninfo_to_dict(dsn)
            parts['dbname'] = database
            with psycopg.connect(**parts, autocommit=True, row_factory=dict_row) as conn:
                conn.execute("""create table domains(id int primary key,fqdn text);
                    insert into domains values(1,'legacy.invalid'),(1275,'agent.invalid'),(3,'other.invalid');
                    create table storage_v2_entity_type(id int primary key,value text);
                    insert into storage_v2_entity_type values(1,'ad_user'),(2,'ad_computer');
                    create table entities_v2_active(id bigint primary key,domain_id int,
                        entity_type_id int,display_name text,natural_key text);
                    create table ad_context_entity_versions(entity_id bigint,source_section text,
                        valid_to_utc timestamptz,last_observed_at_utc timestamptz,attributes_json jsonb);""")
                for identity, domain, kind, section, current, attrs in (
                    (1, 1, 1, 'directory_accounts', True, {'object_class': 'user'}),
                    (2, 1275, 1, 'directory_accounts', True, {}),
                    (3, 3, 1, 'directory_accounts', True, {}),
                    (4, 1275, 2, 'directory_accounts', True, {}),
                    (5, 1275, 1, 'security_event', True, {}),
                    (6, 1275, 1, 'directory_accounts', False, {}),
                    (7, 1275, 1, 'directory_accounts', True, {'object_class': 'computer'}),
                    (8, 1275, 1, 'directory_accounts', True, {'sam_account_name': 'fixture$'}),
                ):
                    conn.execute('insert into entities_v2_active values(%s,%s,%s,%s,%s)',
                                 (identity, domain, kind, 'Synthetic', str(identity)))
                    conn.execute("""insert into ad_context_entity_versions values(%s,%s,
                        case when %s then null else now() end,now(),%s::jsonb)""",
                                 (identity, section, current, json.dumps({'attributes': attrs})))

                def query(statement, params=(), **_):
                    from server.sli.core.database import _pg_sql

                    return conn.execute(_pg_sql(statement), params).fetchall()

                monkeypatch.setattr(users, 'query_rows_bounded', query)
                for domains, expected in (([1275], {2, 8}), ([1], {1}), ([3], {3}),
                                          ([1, 1275], {1, 2, 8}), (None, {1, 2, 3, 8}), ([], set()), ([999], set())):
                    population = users._directory_user_population(domain_ids=domains)
                    assert {item['entity_id'] for item in population} == expected
                assembly = users._directory_user_rows(domain_ids=[1275], legacy_assembly=True)
                assert {item['entity_id'] for item in assembly} == {2}
        finally:
            admin.execute(sql.SQL('drop database {} with (force)').format(sql.Identifier(database)))
