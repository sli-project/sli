"""Synthetic context diagnostics, not a measurement of stand or ClickHouse speed."""
import json
import os
from time import monotonic

import pytest

from tests.postgres_integration_guard import assert_disposable_database


@pytest.mark.postgres_integration
def test_inventory_timeout_from_real_context_query_is_not_erased(monkeypatch):
    dsn = os.environ.get('ADLOG_TEST_PG_DSN', '').strip()
    if not dsn:
        pytest.skip('Disposable PostgreSQL DSN required')
    psycopg = pytest.importorskip('psycopg')
    from server.sli.core.database import QueryTimeoutError
    from server.sli.plugins.ad.reports import computers_v6_reporting as computers
    from server.sli.plugins.ad.reports import what_where_when_reporting as population
    from server.sli.plugins.ad.reports.definitions import new_logon_pairs as report

    monkeypatch.setenv('ADLOG_PG_DSN', dsn)
    read = computers.query_rows_bounded
    def short_test_budget(sql, params=(), **kwargs):
        # Only this disposable test lowers the timeout, not runtime defaults.
        return read(sql, params, **{**kwargs, 'statement_timeout_ms': 20})
    monkeypatch.setattr(computers, 'query_rows_bounded', short_test_budget)
    with psycopg.connect(dsn) as blocker:
        assert_disposable_database(blocker)
        blocker.execute('lock table ad_context_runs in access exclusive mode')
        with pytest.raises(QueryTimeoutError) as raised:
            population._load_workstation_population([1], raise_on_error=True)
        body = report._failure(raised.value, 'context_read_failed')
        assert body['state'] == 'error' and not body['items']
        assert body['limitations'][0]['code'] == 'context_read_timeout'
        assert 'ad_context_runs' not in str(body)
        assert dsn not in str(body)


@pytest.mark.postgres_integration
def test_latest_user_classification_with_retained_snapshot_volume():
    dsn = os.environ.get('ADLOG_TEST_PG_DSN', '').strip()
    if not dsn:
        pytest.skip('Disposable PostgreSQL DSN required')
    psycopg = pytest.importorskip('psycopg')
    from psycopg.rows import dict_row
    from server.sli.entities.what_where_when_projection import _canonical_hash, _load_service_accounts

    # Explicit synthetic envelope: 2,000 accounts, 168 hourly snapshots (7 days).
    # It is not inferred from any user's inventory and does not prove stand scale.
    payload = {'users': [{'samAccountName': f'synthetic-user-{i}'} for i in range(2000)]}
    plans = []
    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        assert_disposable_database(connection)
        forest = connection.execute("insert into forests(name) values ('t051.example.test') returning id").fetchone()['id']
        domain = connection.execute("insert into domains(forest_id,fqdn) values (%s,'t051.example.test') returning id", (forest,)).fetchone()['id']
        connection.execute("""insert into users_report_v2_snapshots
            (domain_id,contract_id,schema_version,scope_json,scope_sha256,bucket_start_utc,
             captured_at_utc,source_observed_at_utc,source_state,user_count,payload_json,payload_sha256)
            select %s,'sli.users-report.v2',1,'{}'::jsonb,%s,
                   '2026-10-01'::timestamptz + n * interval '1 hour',
                   '2026-10-01'::timestamptz + n * interval '1 hour',
                   '2026-10-01'::timestamptz + n * interval '1 hour',
                   'complete',2000,%s::jsonb,%s from generate_series(0,167) n""",
            (domain, bytes(32), json.dumps(payload), _canonical_hash(payload)))
        connection.execute('analyze users_report_v2_snapshots')
        expected = connection.execute('select max(snapshot_id) as id from users_report_v2_snapshots where domain_id=%s', (domain,)).fetchone()['id']

        class Cursor:
            def __enter__(self):
                self.cursor = connection.cursor()
                return self
            def __exit__(self, *args):
                self.cursor.close()
            def execute(self, sql, params):
                self.cursor.execute('explain (analyze, buffers, format json) ' + sql, params)
                plans.append(self.cursor.fetchone()['QUERY PLAN'][0])
                self.cursor.execute(sql, params)
            def fetchone(self):
                return self.cursor.fetchone()

        class Connection:
            def cursor(self):
                return Cursor()

        started = monotonic()
        snapshot, accounts = _load_service_accounts(Connection(), domain)
        elapsed = monotonic() - started
        assert snapshot == expected
        assert len(accounts) == 2000
        assert accounts['synthetic-user-0'] is False
        assert len(plans) == 1
        plan = plans[0]
        # Only structural measurements leave the test: never query text/values/DSN.
        def nodes(node):
            return [{'node': node['Node Type'], 'rows': node['Actual Rows'],
                     'loops': node['Actual Loops'], 'shared_hit_blocks': node.get('Shared Hit Blocks', 0)}] + [
                child for item in node.get('Plans', []) for child in nodes(item)]
        print('T051 synthetic PostgreSQL context:', json.dumps({
            'users': 2000, 'snapshots': 168, 'loader_with_explain_seconds': elapsed,
            'sql_execution_ms': plan['Execution Time'], 'nodes': nodes(plan['Plan']),
            'scope': 'user-classification only; no ClickHouse or end-to-end report claim',
        }, sort_keys=True))
