from __future__ import annotations

import pytest

from tests.support.pg_fake import FakePgStore


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> FakePgStore:
    store = FakePgStore().install_event_search(monkeypatch)
    from server.sli.semantic import investigation

    # Findings storage is PostgreSQL-only and out of scope for these tests.
    monkeypatch.setattr(investigation, 'get_findings_data', lambda **_kwargs: {'items': [], 'summary': [], 'backend': 'postgres'})
    rows = [
        (1, 4624, '2026-07-07T08:00:00Z', 'admin', 'alice', '192.0.2.2', 'WS01', '0x111', {'LogonType': '10', 'IpAddress': '192.0.2.2'}),
        (2, 4723, '2026-07-07T08:10:00Z', 'alice', 'alice', '', 'WS01', '0x111', {'TargetUserName': 'alice'}),
        (3, 4740, '2026-07-07T08:20:00Z', 'DC1$', 'alice', '192.0.2.2', 'WS01', '', {'TargetUserName': 'alice', 'CallerComputerName': 'WS01'}),
        (4, 4625, '2026-07-07T08:30:00Z', 'alice', 'alice', '192.0.2.11', 'WS02', '', {'Status': '0xC000006A', 'IpAddress': '192.0.2.11'}),
    ]
    for record_id, event_id, ts, subject, target, ip, workstation, logon_id, event_data in rows:
        store.add_event(
            event_id=event_id, time=ts, time_local=ts.replace('T', ' ').replace('Z', ''), record_id=record_id,
            subject=subject, target=target, ip=ip, workstation=workstation, logon_id=logon_id,
            message=f'event {event_id} for alice', event_data=event_data,
        )
    return store


def test_global_event_search_finds_account_across_event_fields(store: FakePgStore) -> None:
    from server.sli.events.event_search import get_event_search_data, render_event_search_report


    data = get_event_search_data(q='alice', order='asc', time_from='2026-07-01T00:00:00Z')
    assert data['total'] is None
    assert data['total_is_exact'] is False
    assert data['returned_count'] == 4
    assert [item['event_id'] for item in data['items']] == [4624, 4723, 4740, 4625]
    assert data['facets'] == {}
    assert data['facets_computed'] is False
    assert data['has_more'] is False

    html = render_event_search_report(data)
    assert 'Быстрый поиск по журналам и событиям' in html
    assert 'Показать цепочку по учётной записи' in html
    assert 'Учетная запись заблокирована' in html


def test_account_timeline_groups_logon_password_and_lockout(store: FakePgStore) -> None:
    from server.sli.events.event_search import get_account_timeline_data, render_account_timeline_report


    data = get_account_timeline_data(q='alice', time_from='2026-07-01T00:00:00Z')
    assert data['summary']['total'] == 4
    assert data['summary']['logons'] == 2
    assert data['summary']['password_or_lockout'] == 2
    assert [item['event_id'] for item in data['chain']] == [4625, 4740, 4723, 4624]

    html = render_account_timeline_report(data)
    assert 'Цепочка событий по учётной записи' in html
    assert 'Вход выполнен' in html
    assert 'Попытка смены пароля' in html
    assert 'Учетная запись заблокирована' in html


def test_investigation_preserves_calendar_window_in_form_tabs_and_links(store: FakePgStore) -> None:
    from server.sli.semantic.investigation import get_investigation_workspace_data, render_investigation_workspace_report

    data = get_investigation_workspace_data(
        q='alice',
        time_from='2026-07-07T08:00:00Z',
        time_to='2026-07-07T08:30:00Z',
    )

    html = render_investigation_workspace_report(data)
    assert 'type="datetime-local" name="time_from" value="2026-07-07T08:00"' in html
    assert 'time_from=2026-07-07T08%3A00%3A00Z' in html
    assert 'time_to=2026-07-07T08%3A30%3A00Z' in html
