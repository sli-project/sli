"""Production receipt SQL against synthetic PostgreSQL tables, never stand data."""
from datetime import datetime, timezone
import os

import pytest

from server.sli.sources import plugin_receipts
from server.sli.core.database import _pg_sql
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


@pytest.fixture
def database():
    psycopg = pytest.importorskip('psycopg')
    from psycopg.rows import dict_row
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('Disposable PostgreSQL required')
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        conn.execute("set statement_timeout='5s'")
        conn.execute("set time zone 'UTC'")
        conn.execute('''create temporary table sli_agent_receipts(
            packet_id text primary key,module_id text not null,received_at timestamptz not null);
            create temporary table sli_agent_packet_inbox(packet_id text primary key,imported_at timestamptz);
            create temporary table sli_agent_snapshot_cycles(module_id text not null,
                transport_state text,completed_at timestamptz,publication_state text,published_at timestamptz)''')
        yield conn


def test_runtime_receipt_query_keeps_transport_import_and_snapshot_publication_separate(database, monkeypatch):
    database.execute('''insert into sli_agent_receipts values
        ('ad-old','sli.windows.ad-dc','2026-01-01'),
        ('ad-pending','sli.windows.ad-dc','2026-01-03'),
        ('ad-history','sli.windows.ad-dc-history','2026-01-04'),
        ('snapshot-chunk','sli.ad-snapshot','2026-01-05'),
        ('gpo-chunk','sli.gpo-snapshot','2026-01-06'),
        ('nps','sli.vpn-nps','2026-01-07'),
        ('other','unknown','2026-12-01');
        insert into sli_agent_packet_inbox values
        ('ad-old','2026-01-02'),('ad-pending',null),('ad-history',null),
        ('snapshot-chunk','2026-01-30');
        insert into sli_agent_snapshot_cycles values
        ('sli.ad-snapshot','complete','2026-01-05','pending',null),
        ('sli.gpo-snapshot','complete','2026-01-06','published','2026-01-08'),
        ('sli.gpo-snapshot','pending',null,'pending',null)''')
    queries = []
    def query(sql, params, **kwargs):
        queries.append(sql)
        return database.execute(_pg_sql(sql), params).fetchall()
    monkeypatch.setattr(plugin_receipts, 'query_rows_bounded', query)
    facts = plugin_receipts.read_plugin_receipts(['sli.ad', 'sli.gpo', 'sli.remote-access', 'sli.sigma', 'sli.file-audit'])
    def iso(day):
        return datetime(2026, 1, day, tzinfo=timezone.utc).isoformat()
    assert facts['sli.ad'] == dict(state='observed', last_received_at=iso(5), last_imported_at=iso(2), last_snapshot_completed_at=iso(5))
    assert facts['sli.gpo'] == dict(state='observed', last_received_at=iso(6), last_imported_at=iso(8), last_snapshot_completed_at=iso(6))
    assert facts['sli.remote-access']['last_received_at'] == iso(7)
    assert facts['sli.remote-access']['last_imported_at'] is None
    assert facts['sli.sigma']['state'] == 'not_supported'
    assert facts['sli.file-audit']['state'] == 'no_receipts'
    assert queries == [plugin_receipts._RECEIPTS_SQL]


def test_empty_runtime_receipts_are_not_unavailable(database, monkeypatch):
    monkeypatch.setattr(plugin_receipts, 'query_rows_bounded', lambda sql, params, **kwargs: database.execute(_pg_sql(sql), params).fetchall())
    assert plugin_receipts.read_plugin_receipts(['sli.ad'])['sli.ad'] == dict(
        state='no_receipts', last_received_at=None, last_imported_at=None, last_snapshot_completed_at=None)


def test_receipt_reader_through_real_bounded_helper(database, monkeypatch):
    from contextlib import nullcontext

    from server.sli.core import postgres_runtime_pipeline

    database.execute("insert into sli_agent_receipts values ('runtime','sli.windows.ad-dc','2026-10-25')")
    # Exercise query_rows_bounded -> _pg_sql -> psycopg, including binding.
    # Keep the fixture's temporary tables alive after the helper closes its scope.
    monkeypatch.setattr(postgres_runtime_pipeline, 'connect', lambda: nullcontext(database))
    fact = plugin_receipts.read_plugin_receipts(['sli.ad'])['sli.ad']
    assert fact['state'] == 'observed'
    assert fact['last_received_at'] == datetime(2026, 10, 25, tzinfo=timezone.utc).isoformat()
