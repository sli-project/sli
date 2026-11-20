from __future__ import annotations

import json

from server.sli.reporting.report_template import render_target_report


def _context(event_rows: list[dict[str, object]]) -> dict[str, object]:
    return {
        "title": "Security report",
        "subtitle": "Test report",
        "scope_name": "DC1",
        "period_text": "test window",
        "total_events": len(event_rows),
        "main_noise": "none",
        "coverage_status": "complete",
        "analysis_mode": "local_rules_ai_layer",
        "risk_score": 0,
        "risk_note": "No risk",
        "kpis": [],
        "main_conclusion": "No findings",
        "main_limitation": "Test fixture",
        "channel_rows": [],
        "actions": [],
        "findings": [],
        "coverage_rows": [],
        "correlation_rows": [],
        "event_rows": event_rows,
        "source_facts": [],
        "assumptions": [],
        "server_links": [],
    }


def _embedded_rows_json(report: str) -> str:
    prefix = "const rows = "
    start = report.index(prefix) + len(prefix)
    end = report.index(";\nfunction escapeHtml", start)
    return report[start:end]


def test_event_rows_json_is_safe_inside_html_script_and_round_trips() -> None:
    hostile = "</script><script>alert(1)</script><!--\u2028\u2029"
    rows = [
        {
            "risk": "High",
            "event_id": 1,
            "channel": "Security",
            "provider_name": "Provider",
            "count": 1,
            "description": hostile,
            "why": "reason",
            "detail_url": "/events/1",
            "action": "review",
            "missing": "none",
        },
        {
            "risk": "Info",
            "event_id": 2,
            "channel": "System",
            "provider_name": "Benign Provider",
            "count": 3,
            "description": "ordinary text & symbols < >",
            "why": "normal control",
            "detail_url": "/events/2",
            "action": "none",
            "missing": "none",
        },
    ]

    embedded = _embedded_rows_json(render_target_report(_context(rows)))

    assert "</script" not in embedded.casefold()
    assert "<!--" not in embedded
    assert "\u2028" not in embedded
    assert "\u2029" not in embedded
    assert json.loads(embedded) == rows
