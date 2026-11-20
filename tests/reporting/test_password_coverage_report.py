"""Sanitized coverage presentation; SQL authority/runtime acceptance is separate."""
from dataclasses import replace
from copy import deepcopy

import pytest

from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import security_problems as report
from server.sli.semantic import findings
from server.sli.core.messages import response_messages


STAMP = '2026-10-20T00:00:00.000000Z'


def context(domains=(7,)):
    access = {'reports': [{'report_key': 'security.queue', 'allowed': True,
        'allowed_actions': ['view'], 'grants': [{'scope': {'kind': 'all'},
        'allowed_actions': ['view'], 'field_categories': ['security']}]}]}
    return QueryContext(access=access, params={}, domain_ids=list(domains),
                        runtime={'storage_route_authorization': 'sealed'})


def row(**changes):
    return {'domain_id': '7', 'rule_id': 'qw.password-brute-force', 'scope_ref': 'a' * 64,
        'policy_state': 'enabled', 'status': 'partial', 'reason': 'recent_loss',
        'last_attempt_at': STAMP, 'last_completed_at': STAMP, 'last_successful_cutoff': STAMP,
        'loss': {}, 'frozen_episode_count': '0', 'evidence_snapshot_as_of': None, **changes}


def raw(rows, **changes):
    return {'state': 'empty', 'items': [], 'semantic_runtime': {'findings_state': 'active'},
        'password_detection_coverage': {'availability': 'observed', 'as_of': STAMP,
            'rows': rows, 'has_more': False}, **changes}


@pytest.mark.parametrize('rows', [[], [row()]])
def test_zero_findings_unknown_or_loss_is_partial(monkeypatch, rows):
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: raw(rows))
    result = report._query(context())
    assert result['state'] == 'partial'
    assert result['coverage']['password_detection']['rows'] == rows
    assert any(item['code'] == 'password_coverage_incomplete' for item in result['limitations'])


def test_denied_core_projection_never_reads_coverage(monkeypatch):
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: pytest.fail('unauthorized read'))
    denied = replace(context(), access={})
    with pytest.raises(PermissionError):
        report._query(denied)


@pytest.mark.parametrize('status', ['partial', 'error', 'stale', 'unknown', 'frozen'])
def test_enabled_bad_states_do_not_become_empty(monkeypatch, status):
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: raw([row(status=status)]))
    assert report._query(context())['state'] == 'partial'


@pytest.mark.parametrize('state', ['error', 'stale', 'denied'])
def test_coverage_never_downgrades_existing_state(monkeypatch, state):
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: raw([], state=state))
    result = report._query(context())
    assert result['state'] == state
    if state == 'denied':
        assert 'password_detection' not in result['coverage']


@pytest.mark.parametrize('policy,expected', [('disabled', 'empty'), ('disabled_last_known', 'partial'), ('unknown', 'partial')])
def test_current_disable_is_separate_from_unconfirmed_last_known(monkeypatch, policy, expected):
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: raw([row(policy_state=policy)]))
    result = report._query(context())
    assert result['state'] == expected
    assert result['coverage']['password_detection']['rows'][0]['policy_state'] == policy


def test_empty_scope_suppresses_coverage_and_unrestricted_uses_explicit_catalog(monkeypatch):
    calls = []
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: calls.append(kwargs) or raw([row()]))
    monkeypatch.setattr(report, 'password_coverage_catalog_domains', lambda: [7, 8])
    result = report._query(context(()))
    assert calls[-1]['password_coverage_domain_ids'] == []
    assert 'password_detection' not in result['coverage']
    report._query(replace(context(), domain_ids=None))
    assert calls[-1]['password_coverage_domain_ids'] == [7, 8]


def test_restricted_projection_intersects_selected_domains_before_call(monkeypatch):
    selected = context((7, 999))
    selected.access['reports'][0]['grants'][0]['scope'] = {'kind': 'domain', 'ids': [7]}
    calls = []
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: calls.append(kwargs) or raw([]))
    monkeypatch.setattr(report, 'password_coverage_catalog_domains', lambda: pytest.fail('restricted catalog read'))
    report._query(selected)
    assert calls[-1]['password_coverage_domain_ids'] == [7]


def test_has_more_is_partial_even_with_healthy_visible_rows(monkeypatch):
    payload = raw([row(status='healthy', reason=None)])
    payload['password_detection_coverage']['has_more'] = True
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: payload)
    assert report._query(context())['state'] == 'partial'


def test_core_field_denial_never_reads_catalog_or_findings(monkeypatch):
    selected = context()
    selected.access['reports'][0]['grants'][0]['field_categories'] = ['technical']
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: pytest.fail('forbidden read'))
    monkeypatch.setattr(report, 'password_coverage_catalog_domains', lambda: pytest.fail('forbidden catalog'))
    with pytest.raises(PermissionError):
        report._query(selected)


def sql_page(**changes):
    item = row(domain_id=7, frozen_episode_count=0, status='healthy', reason=None)
    item.update(changes)
    return {'as_of': STAMP, 'rows': [item], 'has_more': False}


def read_page(monkeypatch, page):
    calls = []
    monkeypatch.setattr(findings, 'query_rows', lambda sql, params=(): calls.append((sql, params)) or [{'coverage': page}])
    result = findings._read_password_detection_coverage([7])
    assert calls == [('select public.read_password_detection_coverage(?::bigint[]) as coverage', ([7],))]
    return result


def test_exact_bigint_lower_bound_enclosure_frozen_snapshot_are_preserved(monkeypatch):
    summary = {'count_lower_bound': 9007199254740993, 'count_exact': False,
        'from': '2026-10-18T00:00:00Z', 'to': '2026-10-19T20:00:00Z',
        'observation_window_from': '2026-10-19T01:00:00Z', 'as_of': STAMP}
    value = sql_page(loss={'too_late': summary}, frozen_episode_count=2,
                     evidence_snapshot_as_of='2026-10-19T00:00:00Z')
    before = deepcopy(value)
    result = read_page(monkeypatch, value)
    item = result['rows'][0]
    assert item['domain_id'] == '7' and item['status'] == 'frozen'
    assert item['loss']['too_late'] == {**summary, 'count_lower_bound': '9007199254740993'}
    assert item['frozen_episode_count'] == '2'
    assert item['evidence_snapshot_as_of'] == '2026-10-19T00:00:00Z'
    assert value == before  # Consumer never mutates the stored observation.


def test_completed_attempt_ttl_boundary_and_empty_attempt_do_not_refresh_health(monkeypatch):
    value = sql_page(last_completed_at='2026-10-19T23:55:00Z', last_attempt_at=STAMP)
    result = read_page(monkeypatch, value)
    assert result['rows'][0]['status'] == 'stale'
    assert result['rows'][0]['reason'] == 'attempt_stale'
    value['rows'][0]['last_completed_at'] = '2026-10-19T23:55:00.000001Z'
    assert read_page(monkeypatch, value)['rows'][0]['status'] == 'healthy'


@pytest.mark.parametrize('bad', ['foreign_domain', 'private_key', 'over256', 'unknown_reason', 'bad_count', 'future_time', 'duplicate', 'bad_loss'])
def test_malformed_or_unauthorized_projection_fails_closed_without_private_echo(monkeypatch, bad):
    value = sql_page()
    if bad == 'foreign_domain':
        value['rows'][0]['domain_id'] = 999
    elif bad == 'private_key':
        value['rows'][0]['source_xml'] = '<private-secret/>'
    elif bad == 'over256':
        value['rows'] *= 257
    elif bad == 'unknown_reason':
        value['rows'][0]['reason'] = 'private-secret'
    elif bad == 'bad_count':
        value['rows'][0]['frozen_episode_count'] = 0.5
    elif bad == 'future_time':
        value['rows'][0]['last_completed_at'] = '2027-01-01T00:00:00Z'
    elif bad == 'duplicate':
        value['rows'] *= 2
    else:
        value['rows'][0]['loss'] = {'private-secret': {}}
    assert read_page(monkeypatch, value) == {
        'availability': 'unavailable', 'as_of': None, 'rows': [], 'has_more': False}


def test_null_and_empty_domains_never_query(monkeypatch):
    monkeypatch.setattr(findings, 'query_rows', lambda *args: pytest.fail('unexpected coverage read'))
    with pytest.raises(ValueError):
        findings._read_password_detection_coverage(None)
    with pytest.raises(ValueError):
        findings._read_password_detection_coverage([None])
    assert findings._read_password_detection_coverage([]) is None


def test_bounded_api_is_read_even_when_findings_are_empty(monkeypatch):
    calls = []
    monkeypatch.setattr(findings, 'is_postgres_runtime_db', lambda: True)
    monkeypatch.setattr(findings, 'resolve_storage_route', lambda **kwargs: {'route': 'v2'})
    monkeypatch.setattr(findings, '_attach_postgres_finding_details', lambda *args, **kwargs: None)
    monkeypatch.setattr(findings, 'get_findings_refresh_status', lambda **kwargs: {'limitations': []})
    def read(sql, params=()):
        calls.append((sql, params))
        return [{'coverage': sql_page()}] if 'read_password_detection_coverage' in sql else []
    monkeypatch.setattr(findings, 'query_rows', read)
    result = findings.get_security_problems_data(domain_ids=[7], password_coverage_domain_ids=[7])
    assert result['items'] == []
    assert result['password_detection_coverage']['rows'][0]['domain_id'] == '7'
    assert sum('read_password_detection_coverage' in sql for sql, _ in calls) == 1


def test_sql_failure_owned_context_exits_before_partial_and_follow_up_query(monkeypatch):
    from server.sli.core import database, postgres_runtime_pipeline
    from server.sli.reporting import read_timeout

    events = []
    class Cursor:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            events.append('cursor_closed')
        def execute(self, sql, params):
            if 'read_password_detection_coverage' in sql:
                events.append('sql_failure')
                raise RuntimeError('private SQL error')
            events.append('follow_up')
        def fetchall(self):
            return [{'ok': 1}]
    class Connection:
        def __enter__(self):
            return self
        def __exit__(self, kind, *args):
            events.append('rollback_and_close' if kind else 'read_complete_and_close')
        def cursor(self):
            return Cursor()
    monkeypatch.setattr(read_timeout, 'remaining_read_ms', lambda: None)
    monkeypatch.setattr(database, 'is_postgres_runtime_db', lambda: True)
    monkeypatch.setattr(postgres_runtime_pipeline, 'connect', Connection)
    monkeypatch.setattr(findings, 'query_rows', database.query_rows)
    assert findings._read_password_detection_coverage([7])['availability'] == 'unavailable'
    assert events[-1] == 'rollback_and_close'
    assert database.query_rows('select 1 as ok') == [{'ok': 1}]
    assert events.index('rollback_and_close') < events.index('follow_up')
    # This proves context ordering under a fake connection, not real PG recovery.


@pytest.mark.parametrize('locale', ['ru', 'en'])
def test_partial_message_is_localized_and_never_claims_absence_proof(monkeypatch, locale):
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: raw([]))
    result = response_messages(report._query(context()), locale)
    text = next(item['text'] for item in result['limitations'] if item['code'] == 'password_coverage_incomplete')
    assert ('не доказывает' if locale == 'ru' else 'does not prove') in text


@pytest.mark.parametrize('initial_state,frozen_count,expected_state', [
    ('empty', 0, 'empty'), ('ok', 0, 'ok'),
    ('empty', 2, 'partial'), ('ok', 2, 'partial'),
])
@pytest.mark.parametrize('locale', ['ru', 'en'])
def test_current_disable_preserves_outstanding_frozen_coverage(monkeypatch, initial_state, frozen_count, expected_state, locale):
    snapshot = '2026-10-18T00:00:00Z' if frozen_count else None
    wire = sql_page(policy_state='disabled', status='healthy', frozen_episode_count=frozen_count,
                    evidence_snapshot_as_of=snapshot)
    coverage = findings._password_coverage_page(wire, {7})
    before = deepcopy(coverage)
    payload = raw(coverage['rows'], state=initial_state,
                  items=[{'id': 7, 'status': 'new'}] if initial_state == 'ok' else [])
    payload['password_detection_coverage'] = coverage
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: payload)
    result = response_messages(report._query(context()), locale)
    assert result['state'] == expected_state
    assert len(result['items']) == (1 if initial_state == 'ok' else 0)
    assert result['coverage']['password_detection'] == before
    item = result['coverage']['password_detection']['rows'][0]
    assert item['policy_state'] == 'disabled'
    assert item['frozen_episode_count'] == str(frozen_count)
    assert item['evidence_snapshot_as_of'] == snapshot
    warnings = [item['text'] for item in result['limitations'] if item['code'] == 'password_coverage_incomplete']
    if frozen_count:
        assert len(warnings) == 1
        assert ('не доказывает' if locale == 'ru' else 'does not prove') in warnings[0]
    else:
        assert not warnings
    assert coverage == before


_SEMANTIC_LOSS_CODES = (
    'missing_target', 'unclassified_failure', 'ambiguous_failure',
    'conflicting_client', 'missing_client',
)


@pytest.mark.parametrize('code', _SEMANTIC_LOSS_CODES)
@pytest.mark.parametrize('placement', ['loss', 'reason', 'both'])
def test_semantic_loss_valid_page_preserves_codes_counts_and_partial_report(monkeypatch, code, placement):
    summary = {'count_lower_bound': 9007199254740993, 'count_exact': False,
        'from': '2026-10-18T00:00:00Z', 'to': '2026-10-19T20:00:00Z',
        'observation_window_from': '2026-10-19T01:00:00Z', 'as_of': STAMP}
    has_loss = placement != 'reason'
    has_reason = placement != 'loss'
    wire = sql_page(status='partial' if has_reason else 'healthy',
                    reason=code if has_reason else None,
                    loss={code: summary} if has_loss else {})
    before = deepcopy(wire)
    coverage = read_page(monkeypatch, wire)
    assert coverage['availability'] == 'observed'
    item = coverage['rows'][0]
    assert item['status'] == 'partial'
    assert item['reason'] == (code if has_reason else 'recent_loss')
    assert item['loss'] == ({code: {**summary, 'count_lower_bound': '9007199254740993'}} if has_loss else {})
    assert 'xml_invalid' not in item['loss']
    assert wire == before
    payload = raw(coverage['rows'])
    payload['password_detection_coverage'] = coverage
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: payload)
    result = report._query(context())
    assert result['state'] == 'partial'
    assert result['items'] == []
    assert result['coverage']['password_detection'] == coverage


@pytest.mark.parametrize('code', ['future_event', 'outside_horizon', 'private-unapproved-code'])
@pytest.mark.parametrize('placement', ['loss', 'reason'])
def test_semantic_loss_unknown_codes_still_fail_closed(monkeypatch, code, placement):
    summary = {'count_lower_bound': 1, 'count_exact': True, 'from': STAMP, 'to': STAMP,
        'observation_window_from': STAMP, 'as_of': STAMP}
    wire = sql_page(reason=code) if placement == 'reason' else sql_page(loss={code: summary})
    assert read_page(monkeypatch, wire) == {
        'availability': 'unavailable', 'as_of': None, 'rows': [], 'has_more': False}


@pytest.mark.parametrize('code', _SEMANTIC_LOSS_CODES)
@pytest.mark.parametrize('bad', ['string_count', 'extra_private_field'])
def test_semantic_loss_approved_codes_do_not_relax_exact_summary_shape(monkeypatch, code, bad):
    summary = {'count_lower_bound': 1, 'count_exact': True, 'from': STAMP, 'to': STAMP,
        'observation_window_from': STAMP, 'as_of': STAMP}
    if bad == 'string_count':
        summary['count_lower_bound'] = '1'
    else:
        summary['source_xml'] = '<private-not-exportable/>'
    assert read_page(monkeypatch, sql_page(reason=code, loss={code: summary})) == {
        'availability': 'unavailable', 'as_of': None, 'rows': [], 'has_more': False}
