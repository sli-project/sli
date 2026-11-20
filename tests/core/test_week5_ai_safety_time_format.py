from __future__ import annotations

import json

import pytest

from tests.support.pg_fake import FakePgStore


def _seed_ai_story(store: FakePgStore) -> None:
    rows = [
        (1, 4624, '2026-07-07T02:34:28.9127653Z', 'svc-backup', 'svc-backup', '192.0.2.13', 'WS01', '0xabc', {'TargetUserName': 'svc-backup', 'IpAddress': '192.0.2.13', 'WorkstationName': 'WS01'}),
        (2, 4672, '2026-07-07T02:36:28.1000000Z', 'svc-backup', 'svc-backup', '192.0.2.13', 'WS01', '0xabc', {'SubjectUserName': 'svc-backup', 'LogonId': '0xabc'}),
    ]
    for record_id, event_id, ts, subject, target, ip, workstation, logon_id, event_data in rows:
        store.add_event(
            event_id=event_id, time=ts, time_local=ts.replace('T', ' ').replace('Z', ''), record_id=record_id,
            subject=subject, target=target, ip=ip, workstation=workstation, logon_id=logon_id,
            message=f'User EXAMPLE\\{target} logged on from {ip} workstation {workstation}',
            event_data=event_data,
        )


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> FakePgStore:
    store = FakePgStore().install_security_monitor(monkeypatch).install_event_search(monkeypatch)
    _seed_ai_story(store)
    return store


def test_event_time_is_formatted_for_people() -> None:
    from server.sli.core.time_format import format_event_time, iso_utc_seconds

    raw = '2026-07-07T02:34:28.9127653Z'
    assert format_event_time(raw) == '07.07.2026 02:34:28 UTC'
    assert iso_utc_seconds(raw) == '2026-07-07T02:34:28Z'


def test_reports_render_readable_event_time(monkeypatch) -> None:
    from server.sli.events import event_details
    from server.sli.events.event_details import get_event_detail_report_data, render_event_detail_report

    monkeypatch.setattr(event_details, 'is_postgres_runtime_db', lambda: True)
    monkeypatch.setattr(event_details, 'log_event', lambda *_a, **_k: None)
    monkeypatch.setattr(event_details, '_get_v2_event_detail_by_id', lambda filters, **_kwargs: {
        'id': filters['event_db_id'], 'server': 'DC1', 'channel': 'Security', 'event_id': 4625,
        'event_record_id': 1, 'time_created_utc': '2026-07-07T02:34:28.9127653Z',
        'subject_user_name': 'svc-backup', 'event_data_json': '{}',
    })
    data = get_event_detail_report_data(event_db_id=1)
    assert data['items'][0]['time_created_utc_display'] == '07.07.2026 02:34:28 UTC'
    html = render_event_detail_report(data)
    assert '<td class="mono">2026-07-07T02:34:28.9127653Z</td>' not in html


def test_ai_redaction_preview_masks_sensitive_values(store: FakePgStore) -> None:
    from server.sli.access.data_redaction import build_ai_redaction_preview, render_ai_redaction_preview_report

    data = build_ai_redaction_preview(q='svc-backup', redaction_level='strict', limit=10, time_from='2026-07-01T00:00:00Z')
    payload = data['payload']
    serialized = json.dumps(payload, ensure_ascii=False)
    assert data['safety']['ai_call_performed'] is False
    assert data['source']['preview_events'] == 2
    assert 'svc-backup' not in serialized
    assert '192.0.2.13' not in serialized
    assert 'WS01' not in serialized
    assert 'account_001' in serialized
    assert 'ip_001' in serialized
    assert 'host_001' in serialized
    html = render_ai_redaction_preview_report(data)
    assert 'Предпросмотр данных для AI-анализа' in html
    assert 'запрос к AI не выполняется' in html
