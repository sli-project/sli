from __future__ import annotations

from pathlib import Path


def test_week8_role_views_group_shared_data_without_removing_layers(tmp_path: Path) -> None:
    from server.sli.access.role_views import get_role_views_data, render_role_overview_report

    data = get_role_views_data(preloaded={
        "events": {
            "total_events": 3,
            "by_channel": [{"channel": "Security", "count": 3}],
        },
        "entities": {"total_entities": 2, "total_event_entity_links": 3},
        "collector": {"items": [], "summary": {"security_high": 0}},
        "system": {"status": "ok", "retention": {"candidates": 0}},
        "findings": {"items": [{"status": "open"}]},
        "ai_runs": {"items": []},
        "sources": [{"hostname": "DC1"}],
    })
    ids = [view['id'] for view in data['views']]
    assert ids == ['security', 'it', 'technical']
    assert data['summary']['total_events'] == 3
    assert data['summary']['security_events'] == 3
    assert data['summary']['active_findings'] >= 1

    security = next(view for view in data['views'] if view['id'] == 'security')
    it = next(view for view in data['views'] if view['id'] == 'it')
    technical = next(view for view in data['views'] if view['id'] == 'technical')
    assert any('findings' in action['url'] for action in security['actions'])
    assert any('collector-health' in action['url'] for action in it['actions'])
    assert any('event-details' in action['url'] for action in technical['actions'])

    html = render_role_overview_report(data)
    assert 'ИБ / ИТ / Технический слой' in html
    assert 'Мы ничего не удаляем' in html
    assert '/reports/ai-reports.html' in html
    assert '/reports/collector-health.html' in html


def test_week8_release_check_returns_role_views(tmp_path: Path) -> None:
    from scripts.maintenance.release_check import run_release_check

    # release_check only prepares the parent directory of the DB path; it never opens it.
    result = run_release_check()
    assert result['role_views'] == ['security', 'it', 'technical']
    assert 'server/sli/access/role_views.py' not in result['missing_files']
    assert result['status'] in {'ok', 'warn'}
