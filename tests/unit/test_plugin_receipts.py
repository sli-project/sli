"""Synthetic timestamp facts, not a claim about live collection or completeness."""
from datetime import datetime, timezone

import pytest
from psycopg import OperationalError

from server.sli.sources import plugin_state


def test_receipts_use_the_runtime_database_placeholder_adapter(monkeypatch):
    from contextlib import nullcontext

    from server.sli.core import postgres_runtime_pipeline
    from server.sli.sources import plugin_receipts as receipts

    now = datetime(2026, 10, 25, tzinfo=timezone.utc)
    calls = []

    class Cursor:
        def execute(self, sql, params=()):
            if not params:
                return  # bounded helper's SET LOCAL statements
            calls.append((sql, params))
            assert sql.count('%s') == 2 and '%%s' not in sql and '?' not in sql

        def fetchall(self):
            return [{'module_id': 'sli.windows.ad-dc', 'last_received_at': now,
                     'last_imported_at': now, 'last_snapshot_completed_at': None}]

    class Connection:
        def cursor(self):
            return nullcontext(Cursor())

    monkeypatch.setattr(postgres_runtime_pipeline, 'connect', lambda: nullcontext(Connection()))
    result = receipts.read_plugin_receipts(['sli.ad'])['sli.ad']
    assert result['state'] == 'observed' and result['last_received_at'] == now.isoformat()
    assert len(calls) == 1


def test_listing_attaches_actual_receipts_without_changing_lifecycle(monkeypatch):
    from tests.access.test_plugin_state import Connection, ITEM
    connection = Connection({**ITEM, 'plugin_id': 'sli.ad'})
    monkeypatch.setattr(plugin_state, 'connect', lambda: connection)
    monkeypatch.setattr(plugin_state, 'read_plugin_receipts', lambda ids: {'sli.ad': {'state': 'observed', 'last_received_at': '2026-01-01T00:00:00+00:00', 'last_imported_at': None, 'last_snapshot_completed_at': None}}, raising=False)
    result = plugin_state.list_plugin_states()[0]
    assert result['data_receipts']['last_received_at'] == '2026-01-01T00:00:00+00:00'
    assert result['enabled'] is False and result['receiving_data'] is False
    assert result['last_data_at_utc'] is None and connection.commits == 0


def test_module_mapping_receipt_and_import_are_independent(monkeypatch):
    from server.sli.sources import plugin_receipts as receipts
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    calls = []
    def query(sql, params, **kwargs):
        calls.append((sql, params, kwargs))
        return [dict(module_id='sli.windows.ad-dc', last_received_at=now, last_imported_at=None, last_snapshot_completed_at=None),
                dict(module_id='sli.ad-snapshot', last_received_at=None, last_imported_at=None, last_snapshot_completed_at=now)]
    monkeypatch.setattr(receipts, 'query_rows_bounded', query)
    data = receipts.read_plugin_receipts(['sli.ad', 'sli.gpo', 'sli.sigma', 'unknown'])
    assert data['sli.ad'] == dict(state='observed', last_received_at=now.isoformat(), last_imported_at=None, last_snapshot_completed_at=now.isoformat())
    assert data['sli.gpo']['state'] == 'no_receipts'
    assert data['sli.sigma']['state'] == data['unknown']['state'] == 'not_supported'
    assert set(calls[0][1][0]) == {'sli.windows.ad-dc', 'sli.windows.ad-dc-history', 'sli.ad-snapshot', 'sli.gpo-snapshot'}
    assert calls[0][2]['statement_timeout_ms'] == 3000
    assert calls[0][2]['wall_timeout_ms'] == 4000
    assert len(calls) == 1


def test_receipt_read_failure_is_unknown_not_empty(monkeypatch):
    from server.sli.sources import plugin_receipts as receipts
    def fail(*args, **kwargs):
        raise OperationalError('private diagnostic')
    monkeypatch.setattr(receipts, 'query_rows_bounded', fail)
    data = receipts.read_plugin_receipts(['sli.workstations', 'sli.sigma'])
    assert data['sli.workstations']['state'] == 'unavailable'
    assert data['sli.sigma']['state'] == 'not_supported'
    assert 'private' not in str(data)


def test_no_mapped_plugin_does_not_query(monkeypatch):
    from server.sli.sources import plugin_receipts as receipts
    monkeypatch.setattr(receipts, 'query_rows_bounded', lambda *a, **k: pytest.fail('No receipt source'))
    assert receipts.read_plugin_receipts(['sli.sigma'])['sli.sigma']['state'] == 'not_supported'


def test_timeout_is_unavailable_and_authorization_failure_propagates(monkeypatch):
    from server.sli.core.database import QueryTimeoutError
    from server.sli.sources import plugin_receipts as receipts
    def timeout(*args, **kwargs):
        raise QueryTimeoutError('private timeout', timeout_ms=3000, cancelled=True)
    monkeypatch.setattr(receipts, 'query_rows_bounded', timeout)
    assert receipts.read_plugin_receipts(['sli.ad'])['sli.ad']['state'] == 'unavailable'
    def denied(*args, **kwargs):
        raise PermissionError('denied')
    monkeypatch.setattr(receipts, 'query_rows_bounded', denied)
    with pytest.raises(PermissionError):
        receipts.read_plugin_receipts(['sli.ad'])
