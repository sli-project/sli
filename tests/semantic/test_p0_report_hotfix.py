from __future__ import annotations

from pathlib import Path

from server.sli.semantic.investigation import get_investigation_workspace_data, render_investigation_workspace_report
from server.sli.events.security_events_monitor import _event_ids_for_filter


def test_investigation_empty_query_is_start_screen(tmp_path: Path) -> None:
    data = get_investigation_workspace_data(q="")
    html = render_investigation_workspace_report(data)

    assert data["empty_query"] is True
    assert "Введите учетную запись" in html
    assert "Введите объект расследования" in html
    assert "320795" not in html


def test_security_monitor_default_excludes_success_logon_noise() -> None:
    ids = set(_event_ids_for_filter(group=None, event_id=None))

    assert 4625 in ids
    assert 4724 in ids
    assert 4740 in ids
    assert 4728 in ids
    assert 4624 not in ids
    assert 4634 not in ids
