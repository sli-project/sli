"""HTTP dispatcher -> real authorization/compiler/capture/snapshot contracts.

Only identity/registry/SQL transport boundaries are synthetic; no live DB.
"""
from copy import deepcopy
from datetime import datetime, timezone
from email.message import Message
from io import BytesIO
import json
from types import SimpleNamespace

import pytest

from server.api import http_server
from server.api.errors import RequestInputError
from server.sli.events import evsearch_history, evsearch_postgres
from tests.unit.test_evsearch_grouping import AggregateFake
from tests.unit.test_evsearch_history import History, stored

NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)
FIELDS = ('id', 'time_created_utc', 'event_id', 'channel')


def test_read_routes_are_registered_in_real_dispatcher():
    for name in ('query', 'page', 'members'):
        assert http_server.ROUTE_REGISTRY.candidates('POST', '/api/v1/event-search/' + name)


@pytest.fixture
def rig(monkeypatch):
    from server.sli.events import evsearch_runtime as runtime
    access = {'decision_id': 'synthetic-decision', 'capabilities': ['events.view'],
              'reports': [{'report_key': 'events.explorer', 'version': 1, 'allowed': True,
                           'allowed_actions': ['view'], 'grants': [{'scope': {'kind': 'all'},
                           'field_categories': ['security', 'technical', 'raw_evidence'], 'allowed_actions': ['view']}]}]}
    publication = {'dataset_key': 'events.v2', 'version': 1,
                   'fields_json': [{'key': k, 'category': 'raw_evidence' if k == 'id' else 'technical'} for k in FIELDS],
                   'definition_json': {'columns': list(FIELDS), 'actions': ['view']}}
    hot = [{'id': i, 'time_created_utc': NOW.isoformat(), 'event_id': 4740,
            'channel': 'Security', '_evsearch_id': i, '_evsearch_time': NOW,
            '_evsearch_fingerprint': 'AA' * 32} for i in (1, 2)]
    # Use the previous day so every event is inside the frozen [from,to).
    for row in hot:
        row['time_created_utc'] = '2026-10-18T12:00:00+00:00'
        row['_evsearch_time'] = datetime.fromisoformat(row['time_created_utc'])
    cold = History([stored(3)])
    aggregate = AggregateFake()
    def pg(sql, params=(), **budgets):
        if 'report_registry_v4' in sql:
            return [deepcopy(publication)]
        if 'jsonb_to_recordset' in sql:
            from server.sli.events.evsearch_grouping import PartialQuery
            return aggregate(PartialQuery('postgres', sql, params), budgets['wall_timeout_ms'])
        assert 'events_v2_core e' in sql and 'e.time_created_utc>=?' in sql
        return deepcopy(hot)
    def ch(sql, timeout_ms):
        if 'format(JSONEachRow' in sql:
            from server.sli.events.evsearch_grouping import PartialQuery
            return aggregate(PartialQuery('clickhouse', sql), timeout_ms)
        return cold.query(sql, timeout_ms)
    monkeypatch.setattr(runtime, 'effective_access', lambda principal: deepcopy(access))
    monkeypatch.setattr(runtime, 'query_rows_bounded', pg)
    monkeypatch.setattr(evsearch_postgres, 'query_rows_bounded', pg)
    monkeypatch.setattr('server.sli.core.database.query_rows_bounded', pg)
    monkeypatch.setattr(evsearch_history, '_query_rows', ch)
    monkeypatch.setattr(evsearch_history.history, 'primary_read_enabled', lambda: True)
    monkeypatch.setattr(runtime, 'load_storage_policy', lambda: SimpleNamespace(db_retention_days=7))
    service = runtime.EventSearchRuntime()
    service.store.utcnow = lambda: NOW
    monkeypatch.setattr(runtime, 'RUNTIME', service)
    monkeypatch.setattr(http_server, 'auth_required', lambda: True)
    identity = {'type': 'session', 'id': 1, 'role': 'viewer'}
    monkeypatch.setattr(http_server, 'principal_from_headers', lambda headers: deepcopy(identity) if identity else None)
    def call(name, body=None, raw_body=None, duplicate_origin=False, **headers):
        handler = object.__new__(http_server.RequestHandler)
        handler.server = SimpleNamespace()
        handler.client_address = ('127.0.0.1', 1)
        handler.path = '/api/v1/event-search/' + name
        handler.command = 'POST'
        handler.headers = Message()
        data = raw_body if raw_body is not None else json.dumps(body if body is not None else {'contract_version': 'evsearch.v1', 'page_size': 1}).encode()
        for k, v in {'Host': 'example.test', 'Origin': 'http://example.test', 'Content-Type': 'application/json', 'Content-Length': str(len(data)), **headers}.items():
            handler.headers[k] = v
        if duplicate_origin:
            handler.headers['Origin'] = 'http://example.test'
        handler.rfile = BytesIO(data)
        handler.connection = SimpleNamespace(gettimeout=lambda: None, settimeout=lambda value: None)
        handler._access_decision = lambda: deepcopy(access)
        handler._send_json = lambda payload, status=200, **kw: setattr(handler, 'result', (status, payload))
        try:
            handler._do_POST()
        except RequestInputError as exc:
            handler._send_json({'error': exc.code}, exc.status)
        return handler.result
    return SimpleNamespace(call=call, access=access, publication=publication, hot=hot, cold=cold,
                           identity=identity, service=service)


def test_dispatcher_query_page_members_freeze_and_foreign_execution(rig):
    status, first = rig.call('query')
    assert status == 200, first
    assert first['coverage'] == 'unknown'
    assert all(g['count'] == 1 for g in first['items'])
    assert first['next_cursor']
    group = first['items'][0]['group_key']
    member_request = {'execution_id': first['execution_id'], 'group_key': group}
    status, members = rig.call('members', member_request)
    assert status == 200, members
    assert len(members['items']) == 1
    rig.hot.clear()
    assert rig.call('members', member_request) == (200, members)
    rig.identity['id'] = 2
    assert rig.call('members', member_request)[0] == 410
    assert rig.call('page', {'execution_id': first['execution_id'], 'cursor': first['next_cursor']})[0] == 410


@pytest.mark.parametrize('change', ['revoke', 'publication', 'history'])
def test_recheck_before_every_read(rig, monkeypatch, change):
    _, first = rig.call('query')
    if change == 'revoke':
        rig.access['reports'][0]['allowed'] = False
    elif change == 'publication':
        rig.publication['definition_json']['revision'] = 2
    else:
        monkeypatch.setattr(evsearch_history.history, 'primary_read_enabled', lambda: False)
    status, payload = rig.call('members', {'execution_id': first['execution_id'], 'group_key': first['items'][0]['group_key']})
    assert status in (403, 409, 503), payload
    assert 'items' not in payload


@pytest.mark.parametrize('headers,status', [({'Origin': 'https://foreign.test'},403), ({'Content-Type':'text/plain'},415), ({'Content-Length':'20000'},413), ({'Content-Length':'no'},400)])
def test_origin_and_body_are_enforced(rig, headers, status):
    assert rig.call('query', **headers)[0] == status


def test_api_keys_anonymous_and_missing_capability_do_not_get_execution(rig):
    rig.identity['type'] = 'api_key'
    assert rig.call('query')[0] == 403
    rig.identity.clear()
    assert rig.call('query')[0] == 401


def test_expired_overbudget_and_cross_execution_cursor(rig):
    _, first = rig.call('query')
    _, second = rig.call('query')
    assert rig.call('page', {'execution_id': second['execution_id'], 'cursor': first['next_cursor']})[0] == 422
    rig.service.store.clock = lambda: float('inf')
    assert rig.call('page', {'execution_id': first['execution_id']})[0] == 410


def test_missing_capability_and_denied_field_do_not_capture(rig):
    rig.access['capabilities'].clear()
    assert rig.call('query')[0] == 403
    rig.access['capabilities'].append('events.view')
    rig.publication['fields_json'] = [f for f in rig.publication['fields_json'] if f['key'] != 'id']
    assert rig.call('query')[0] == 403
    assert rig.service.store.execution_count == 0


@pytest.mark.parametrize('kind', ['rows', 'bytes', 'busy', 'deadline'])
def test_resource_failures_never_publish_partial_execution(rig, kind):
    if kind == 'rows':
        rig.service.store.max_events = 1
    elif kind == 'bytes':
        rig.service.store.max_snapshot_bytes = 10
    elif kind == 'busy':
        rig.service._operation.acquire()
    else:
        calls = iter(range(0, 100, 9))
        rig.service.store.clock = lambda: next(calls)
    try:
        status, body = rig.call('query')
        assert status in (422, 503), body
        assert 'execution_id' not in body
        assert rig.service.store.execution_count == 0
    finally:
        if kind == 'busy':
            rig.service._operation.release()


def test_disabled_history_and_unsupported_scope_never_fall_back(rig, monkeypatch):
    monkeypatch.setattr(evsearch_history.history, 'primary_read_enabled', lambda: False)
    assert rig.call('query')[0] == 503
    monkeypatch.setattr(evsearch_history.history, 'primary_read_enabled', lambda: True)
    rig.access['reports'][0]['grants'][0]['scope'] = {'kind': 'domain', 'ids': [7]}
    assert rig.call('query')[0] == 200  # existing domain scope is supported
    rig.publication['fields_json'].append({'key': 'outcome', 'category': 'security'})
    rig.publication['definition_json']['columns'].append('outcome')
    status, body = rig.call('query', {'contract_version': 'evsearch.v1', 'conditions': [
        {'field': 'outcome', 'operator': 'eq', 'value': 'failure'}]})
    assert status == 503 and body['error'] == 'evsearch.history_predicate_unavailable'
    assert rig.service.store.execution_count == 1  # only the earlier supported search


def test_body_shape_and_explicit_query_limits(rig):
    assert rig.call('query', [1, 2])[0] == 400
    assert rig.call('query', {'contract_version': 'evsearch.v1', 'page_size': 101})[0] == 422
    assert rig.call('query', {'contract_version': 'evsearch.v1', 'access': {'all': True}})[0] == 422
    assert rig.call('query', {'contract_version': 'evsearch.v1', 'period': {
        'preset': 'custom', 'from': '2020-01-01T00:00:00Z', 'to': '2026-01-01T00:00:00Z', 'timezone': 'UTC'}})[0] == 422


def test_retention_is_pinned_and_raw_payload_is_not_inferred(rig, monkeypatch):
    from server.sli.events import evsearch_runtime as runtime
    _, result = rig.call('query')
    monkeypatch.setattr(runtime, 'load_storage_policy', lambda: SimpleNamespace(db_retention_days=90))
    status, members = rig.call('members', {'execution_id': result['execution_id'], 'group_key': result['items'][0]['group_key']})
    assert status == 200
    assert members['retention_boundary'] == result['retention_boundary']
    assert members['items'][0]['source_payload_state'] == 'unknown'
    assert set(members['items'][0]['fields']) == set(FIELDS)


def test_malformed_json_and_duplicate_origin_fail_before_runtime(rig):
    assert rig.call('query', raw_body=b'{bad')[0] == 400
    assert rig.call('query', duplicate_origin=True)[0] == 403
    assert rig.service.store.execution_count == 0


def test_storage_admission_failure_invalidates_existing_execution(rig, monkeypatch):
    from server.sli.events import evsearch_runtime as runtime
    _, result = rig.call('query')
    request = {'execution_id': result['execution_id']}
    def denied(**kwargs):
        raise runtime.StorageRouteAuthorizationError('storage_transition_authorization_invalid')
    with monkeypatch.context() as patch:
        patch.setattr(runtime, 'resolve_storage_route', denied)
        assert rig.call('page', request)[0] == 503
    assert rig.call('page', request)[0] == 410


def test_dispatcher_deduplicates_identical_hot_cold_id_and_rejects_conflict(rig):
    duplicate = deepcopy(rig.hot[0])
    duplicate.update(id=3, _evsearch_id=3)
    rig.hot.append(duplicate)
    status, result = rig.call('query', {'contract_version': 'evsearch.v1', 'page_size': 100})
    assert status == 200, result
    assert sum(g['count'] for g in result['items']) == 3
    duplicate['_evsearch_fingerprint'] = 'BB' * 32
    status, failure = rig.call('query')
    assert status == 503 and failure['error'] == 'evsearch.storage_integrity_error'
    assert 'execution_id' not in failure


def test_unchanged_execution_does_not_read_either_event_store_again(rig, monkeypatch):
    _, result = rig.call('query')
    from server.sli.events import evsearch_runtime as runtime
    def no_capture(*args, **kwargs):
        pytest.fail('page/members must not recapture changing source events')
    monkeypatch.setattr(runtime, 'read_hot_capture', no_capture)
    monkeypatch.setattr(evsearch_history.ClickHouseHistoryReader, 'read', no_capture)
    assert rig.call('page', {'execution_id': result['execution_id']})[0] == 200
    assert rig.call('members', {'execution_id': result['execution_id'], 'group_key': result['items'][0]['group_key']})[0] == 200


def test_one_capped_budget_starts_before_authentication(rig, monkeypatch):
    from server.sli.reporting.read_timeout import remaining_read_ms
    monkeypatch.setenv('ADLOG_REPORT_READ_TIMEOUT_MS', '20000')
    original = http_server.RequestHandler._authorize_mutation
    def authorized(handler, **kwargs):
        remaining = remaining_read_ms()
        assert remaining is not None and 0 < remaining <= 8000
        return original(handler, **kwargs)
    monkeypatch.setattr(http_server.RequestHandler, '_authorize_mutation', authorized)
    assert rig.call('query')[0] == 200
    assert remaining_read_ms() is None
