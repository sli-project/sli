from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tests.support.pg_fake import FakePgStore


def _seed_security_story(store: FakePgStore) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    rows = [
        (1, 4625, 'alice', 'alice', '192.0.2.2', 'WS01', 'failed logon'),
        (2, 4624, 'alice', 'alice', '192.0.2.2', 'WS01', 'successful logon'),
        (3, 4634, 'alice', 'alice', '192.0.2.2', 'WS01', 'logoff noise'),
        (4, 4672, 'alice', 'alice', '192.0.2.2', 'WS01', 'special privileges'),
        (5, 4724, 'admin', 'alice', '192.0.2.11', 'WS02', 'password reset'),
        (6, 4728, 'admin', 'Domain Admins', '192.0.2.4', 'WS03', 'group membership changed'),
    ]
    for record_id, event_id, subject, target, ip, workstation, msg in rows:
        store.add_event(
            event_id=event_id, time=ts, record_id=record_id, subject=subject, target=target,
            ip=ip, workstation=workstation, message=msg,
            event_data={'TargetUserName': target, 'IpAddress': ip},
        )


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> FakePgStore:
    store = FakePgStore().install_security_monitor(monkeypatch).install_event_search(monkeypatch)
    from server.sli.semantic import investigation

    # Findings storage is PostgreSQL-only and out of scope for these tests.
    monkeypatch.setattr(investigation, 'get_findings_data', lambda **_kwargs: {'items': [], 'summary': [], 'backend': 'postgres'})
    _seed_security_story(store)
    return store


def test_p5_security_monitor_filters_export_and_dashboard_summary(store: FakePgStore) -> None:
    from server.sli.core.database import get_event_summary
    from server.sli.events.security_events_monitor import get_security_events_monitor_data, render_security_events_monitor_csv, render_security_events_monitor_report

    default = get_security_events_monitor_data()
    default_ids = {int(item['event_id']) for item in default['items']}
    assert 4625 in default_ids
    assert 4724 in default_ids
    assert 4728 in default_ids
    assert 4624 not in default_ids
    assert 4634 not in default_ids

    source_view = get_security_events_monitor_data(source='192.0.2.2', event_id=4672, risk='info')
    assert {int(item['event_id']) for item in source_view['items']} == {4672}

    mixed_case_account = get_security_events_monitor_data(account='AdMiN')
    assert {int(item['event_id']) for item in mixed_case_account['items']} == {4724, 4728}

    html = render_security_events_monitor_report(default)
    assert 'Вкладки ИБ' in html
    assert 'CSV' in html
    assert 'Все входы/выходы' in html

    csv_text = render_security_events_monitor_csv(default)
    assert 'event_label' in csv_text
    assert 'record_type' in csv_text
    assert 'metadata' in csv_text
    assert f',{default["matched_total"]},{default["returned_count"]},false,' in csv_text
    assert 'Пароли' in csv_text or 'Группы' in csv_text

    summary = get_event_summary()
    security_24h = summary['security_24h_summary']
    assert security_24h['important_total'] >= 4
    assert security_24h['failed_logons'] == 1
    assert security_24h['passwords'] == 1
    assert security_24h['groups'] == 1


def test_empty_monitor_tab_explains_the_result_and_keeps_rolling_period_links_fresh(store: FakePgStore) -> None:
    from server.sli.events.security_events_monitor import _clean_query_params, get_security_events_monitor_data, render_security_events_monitor_report

    data = get_security_events_monitor_data(
        group='accounts', period='24h',
        time_from='2020-01-01T00:00:00+00:00', limit=10,
    )

    assert data['matched_total'] == 0
    html = render_security_events_monitor_report(data)
    assert 'не найдено событий категории «Учетные записи»' in html
    assert 'Показать важные события' in html
    assert 'Показать входы и выходы' in html
    params = _clean_query_params(data['filters'])
    assert params['period'] == '24h'
    assert 'time_from' not in params


def test_p6_investigation_story_grouped_timeline_and_scope(store: FakePgStore) -> None:
    from server.sli.semantic.investigation import get_investigation_workspace_data, render_investigation_workspace_report


    story = get_investigation_workspace_data(q='alice')
    timeline_times = [item['time'] for item in story['timeline']['chain']]
    assert timeline_times == sorted(timeline_times, reverse=True)
    assert story['summary']['first_event_utc'] == min(timeline_times)
    assert story['summary']['last_event_utc'] == max(timeline_times)
    assert story['summary']['chain_events'] >= 4
    assert story['summary']['category_summary']['failed_logons'] == 1
    assert story['summary']['category_summary']['passwords'] == 1
    assert any(pivot['kind'] == 'тот же IP' for pivot in story['pivots'])
    assert any('evidence' in check.lower() or '4624' in check for check in story['next_checks'])

    html = render_investigation_workspace_report(story)
    assert 'Смысловая сводка' in html
    assert 'Хронология событий' in html
    assert 'Экспорт JSON' in html
    assert 'Что проверить дальше' in html

    all_events = get_investigation_workspace_data(q='alice', scope='all')
    all_ids = [int(item['event_id']) for item in all_events['timeline']['chain']]
    assert 4634 in all_ids
