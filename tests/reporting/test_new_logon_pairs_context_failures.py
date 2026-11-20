"""Keep the original failure across the real inventory-to-report boundary."""
from asyncio import CancelledError
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from server.sli.core.database import QueryTimeoutError
from server.sli.plugins.ad.reports import new_logon_pairs_reporting as engine
from server.sli.plugins.ad.reports import what_where_when_reporting as population
from tests.reporting.test_new_logon_pairs_v2 import context, report


class Cancelled(Exception):
    sqlstate = '57014'


@pytest.mark.parametrize('error,code', [
    (QueryTimeoutError('private SQL', timeout_ms=3000), 'context_read_timeout'),
    (Cancelled('private SQL'), 'context_read_cancelled'),
    (PermissionError('private SQL'), None),
    (CancelledError('private SQL'), None),
])
def test_inventory_failure_keeps_typed_reason_through_report(monkeypatch, error, code):
    monkeypatch.setattr(report, 'logon_domain_scope', lambda *args: [7])
    connection = SimpleNamespace(cursor=lambda: nullcontext(object()))
    monkeypatch.setattr(engine, 'connect', lambda: nullcontext(connection))
    monkeypatch.setattr(engine, '_load_domain_controller_membership',
                        lambda *args, **kwargs: SimpleNamespace(server_ids={10}))
    monkeypatch.setattr(engine, '_load_service_accounts', lambda *args: (1, {}))
    monkeypatch.setattr(engine, 'load_latest_computers_v6_source_snapshot',
                        lambda *args, **kwargs: {'collection_status': 'complete'})
    def unavailable(**kwargs):
        raise error
    monkeypatch.setattr(population, 'get_computers_v6_report', unavailable)
    def forbidden(*args):
        pytest.fail('failed context must not start history or retry')
    monkeypatch.setattr(engine, 'load_history', forbidden)
    if code is None:
        with pytest.raises(type(error)):
            report.REPORT.query(context())
        return
    body = report.REPORT.query(context())
    assert body['state'] == 'error' and body['items'] == []
    assert body['limitations'][0]['code'] == code
    assert 'private SQL' not in str(body)


def test_inventory_fail_closed_default_is_unchanged(monkeypatch):
    def unavailable(**kwargs):
        raise RuntimeError('private SQL')
    monkeypatch.setattr(population, 'get_computers_v6_report', unavailable)
    assert population._load_workstation_population([7]) == {
        'state': 'unavailable', 'partial': True, 'items': [],
    }


def test_inventory_explicit_failure_has_specific_reason():
    body = report._failure(RuntimeError('logon_inventory_unavailable'), 'context_read_failed')
    assert body['limitations'][0]['code'] == 'computer_inventory_unavailable'


@pytest.mark.parametrize('reason', ['stored_snapshot_hash_mismatch',
    'stored_snapshot_object_count_mismatch', 'stored_snapshot_identity_mismatch',
    'stored_snapshot_status_mismatch', 'stored_base_inventory_status_mismatch'])
def test_computer_snapshot_integrity_failures_are_allowlisted(reason):
    body = report._failure(RuntimeError(reason), 'context_read_failed')
    assert body['limitations'][0]['code'] == 'context_verification_failed'
