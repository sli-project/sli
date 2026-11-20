"""Snapshot-native evidence stays distinct from unavailable EventLog rows."""
from dataclasses import replace

import pytest

from server.sli.reporting.v2.reports import security_problems as report
from tests.reporting.test_security_problems_v2 import _context
from server.sli.semantic import file_acl_evidence
from tests.unit.test_file_acl_input import RESOURCE


def native():
    return dict(storage_kind='file_audit_snapshot', evidence_key='1' * 64,
                evidence_role='semantic_scenario', availability='available', historical=True,
                observed_at_utc='2026-01-01T00:00:00+00:00', resource=None,
                coverage=dict(state='complete', unread_objects=0, has_more=False),
                grants=[], grants_has_more=False, limitations=[])


def test_native_snapshot_is_not_a_missing_event_and_uses_registered_detail(monkeypatch):
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: {'items': [{'id': 7}]})
    monkeypatch.setattr(report, 'get_problem_evidence_page', lambda *args, **kwargs: {
        'items': [native()], 'has_more': False, 'total': 1,
        'watermark': '2026-01-02T00:00:00+00:00', 'next_position': None})
    body = report._detail(_context({}), '7')
    assert body['state'] == 'ok'
    assert body['coverage']['evidence_missing_sources'] == 0
    assert body['coverage']['evidence_native_snapshots'] == 1
    assert report.REPORT.detail.row_component == 'problems.acl-evidence'
    assert 'event_db_id' not in body['items'][0]


def test_snapshot_cursor_is_bound_to_selected_domains_and_action(monkeypatch):
    monkeypatch.setattr(report, 'get_security_problems_data', lambda **kwargs: {'items': [{'id': 7}]})
    monkeypatch.setattr(report, 'get_problem_evidence_page', lambda *args, **kwargs: {
        'items': [native()], 'has_more': True, 'total': 2,
        'watermark': '2026-01-02T00:00:00+00:00',
        'next_position': {'storage_kind': 'file_audit_snapshot', 'native_key': '1' * 64}})
    context = replace(_context({}), domain_ids=[7])
    body = report._detail(context, '7')
    with pytest.raises(ValueError, match='invalid_cursor'):
        report._detail(replace(context, cursor=body['next_cursor'], domain_ids=[8]), '7')


@pytest.mark.parametrize('action,capabilities,fields', [('view', [], True), ('export', ['file-audit.view'], True),
                                                     ('view', ['file-audit.view'], False)])
def test_independent_native_scope_or_fields_denial_hides_payload_and_counts(monkeypatch, action, capabilities, fields):
    calls = []
    def read(sql, params=()):
        calls.append(sql)
        if 'clock_timestamp' in sql:
            return [{'watermark': '2026-01-02T00:00:00+00:00'}]
        if 'read_file_acl_finding_resources' in sql:
            return [{'resources': [RESOURCE]}]
        if 'count(*)' in sql:
            return [{'total': 0}]
        if 'left join events_v2_core' in sql:
            return []
        pytest.fail('unauthorized native payload/count lookup')
    monkeypatch.setattr(file_acl_evidence, 'query_rows', read)
    page = file_acl_evidence.page(7, access={'capabilities': capabilities}, action=action, fields_allowed=fields)
    assert page['items'] == [] and page['total'] == 0 and page['has_more'] is False
    assert not any('read_file_acl_finding_evidence(' in sql for sql in calls)
    if not fields:
        assert not any('read_file_acl_finding_resources' in sql for sql in calls)


def test_mixed_typed_keyset_keeps_all_events_and_native_rows_without_fake_ids(monkeypatch):
    import json

    snapshots = [native() | {'evidence_key': str(i) * 64, '_native_key': str(i) * 64} for i in (1, 2, 3)]
    def read(sql, params=()):
        if 'clock_timestamp' in sql:
            return [{'watermark': '2026-01-02T00:00:00+00:00'}]
        if 'read_file_acl_finding_resources' in sql:
            return [{'resources': [RESOURCE]}]
        if 'count(*)' in sql:
            return [{'total': 2}]
        if 'left join events_v2_core' in sql:
            return [{'evidence_id': i, 'event_db_id': i, 'evidence_role': 'semantic_scenario'} for i in (1, 2) if i > params[1]][:params[3]]
        if 'read_file_acl_finding_evidence(' in sql:
            assert json.loads(params[1]) == [RESOURCE]
            rows = [r.copy() for r in snapshots if params[2] is None or r['_native_key'] > params[2]]
            return [{'evidence': {'items': rows[:params[3]], 'has_more': len(rows) > params[3], 'total': 3}}]
        pytest.fail('unexpected query')
    monkeypatch.setattr(file_acl_evidence, 'query_rows', read)
    combined, position, watermark = [], None, None
    for _ in range(3):
        page = file_acl_evidence.page(7, access={'capabilities': ['file-audit.view']}, fields_allowed=True,
                                     limit=2, position=position, watermark=watermark)
        assert page['total'] == 5
        combined.extend(page['items'])
        position, watermark = page['next_position'], page['watermark']
    assert [row.get('event_db_id') for row in combined if row['storage_kind'] == 'core_event'] == [1, 2]
    assert [row['evidence_key'] for row in combined if row['storage_kind'] == 'file_audit_snapshot'] == [str(i) * 64 for i in (1, 2, 3)]
    assert not page['has_more']
    assert all('event_db_id' not in row and '_native_key' not in row for row in combined if row['storage_kind'] == 'file_audit_snapshot')
