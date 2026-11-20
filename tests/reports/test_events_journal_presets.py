"""Быстрые сценарии «Журнала событий» не теряются из-за сопоставления view -> Event ID."""

from __future__ import annotations

import pytest

from server.sli.reporting.reporting_v4_catalog import EVENT_VIEW_EVENT_IDS
from server.sli.reporting.v2.reports import events_journal


def test_every_preset_event_id_belongs_to_its_view():
    for label, params in events_journal.REPORT.presets:
        view, event_id = params["view"], int(params["q"])
        if view == "all":
            continue
        assert event_id in EVENT_VIEW_EVENT_IDS[view], f"пресет «{label}»: {event_id} не входит в view={view}"


def test_audit_log_cleared_preset_reaches_filters():
    preset = dict(events_journal.REPORT.presets)["Очистка журнала аудита"]
    assert preset == {"q": "1102", "view": "attention"}
    assert 1102 in EVENT_VIEW_EVENT_IDS["attention"]


@pytest.mark.parametrize("view", ["attention", "authentication", "accounts"])
def test_views_are_known_to_the_query_layer(view):
    assert view in EVENT_VIEW_EVENT_IDS
