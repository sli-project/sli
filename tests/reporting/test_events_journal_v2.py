"""«Журнал событий» on the v2 framework: filters reach the published report unchanged."""

from __future__ import annotations

from dataclasses import replace

import pytest

from server.sli.reporting.v2.definition import QueryContext, parse_params
from server.sli.reporting.v2.reports import events_journal as report


def _context(query: dict[str, list[str]], cursor: str | None = None) -> QueryContext:
    params, _ = parse_params(report.REPORT, query)
    return QueryContext(access={"reports": []}, params=params, domain_ids=None, action="view", cursor=cursor, limit=50, timezone="UTC")


def test_query_passes_window_view_search_and_cursor(monkeypatch: pytest.MonkeyPatch):
    calls = []
    monkeypatch.setattr(report, "query_rows_bounded", lambda *args, **kwargs: [])
    monkeypatch.setattr(report, "execute_report", lambda key, principal, **kwargs: calls.append((key, kwargs)) or {"state": "available", "items": [
        {"id": 5, "event_id": 4728, "subject_user_name": "admin", "target_user_name": "ivanov", "channel": "Security", "time_created_utc": "2026-09-29T10:00:00Z"},
    ], "has_more": True, "next_cursor": "c2"})
    body = report._query(_context({"period": ["custom"], "from": ["2026-09-29T09:00:00Z"], "to": ["2026-09-29T11:00:00Z"], "view": ["accounts"], "q": ["4728"], "server": ["DC1"]}, cursor="c1"))
    key, kwargs = calls[0]
    assert key == "events.explorer" and kwargs["access"] == {"reports": []}
    assert kwargs["query_filters"] == {"time_from": "2026-09-29T09:00:00Z", "time_to": "2026-09-29T11:00:00Z", "view": "accounts", "q": "4728", "server": "DC1", "cursor": "c1"}
    row = body["items"][0]
    assert row["title_text"] == "неизвестный тип события" and row["participant"] == "ivanov" and row["on_behalf"] == "admin"
    assert body["has_more"] is True and body["next_cursor"] == "c2"
    assert body["window"]["from_utc"] == "2026-09-29T09:00:00Z"


def test_all_view_is_not_sent_and_empty_slice_is_empty(monkeypatch: pytest.MonkeyPatch):
    calls = []
    monkeypatch.setattr(report, "execute_report", lambda key, principal, **kwargs: calls.append(kwargs) or {"state": "available", "items": []})
    body = report._query(_context({}))
    assert "view" not in calls[0]["query_filters"]
    assert body["state"] == "empty"


def test_default_journal_keeps_the_complete_server_access_scope(monkeypatch: pytest.MonkeyPatch):
    calls = []
    access = {"reports": [{"report_key": "events.explorer", "allowed": True,
                           "grants": [{"scope": {"kind": "domain", "ids": [7, 8]}}]}]}
    monkeypatch.setattr(report, "execute_report", lambda key, principal, **kwargs: calls.append(kwargs) or {"state": "available", "items": []})
    context = replace(_context({}), access=access)
    report._query(context)
    assert calls[0]["access"] is access
    assert set(calls[0]["query_filters"]) == {"time_from", "time_to"}
    assert not any(param.kind == "domain" for param in report.REPORT.params)


def test_export_uses_the_published_document_without_cursor(monkeypatch: pytest.MonkeyPatch):
    seen = {}
    monkeypatch.setattr(report, "export_report_csv_document", lambda key, principal, query_filters, access: seen.update(query_filters) or {"csv": "x", "row_count": 3, "truncated": False})
    assert report._export(_context({}, cursor="ignored")) == ("x", {"rows": 3, "truncated": False})
    assert "cursor" not in seen
