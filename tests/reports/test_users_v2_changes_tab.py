"""Вкладка «Изменения» отчёта ad.users.v2: пустота объясняется, а не прячется."""

from __future__ import annotations

import pytest

from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import users as report

CURRENT = {
    "metadata": {"observed_at": "2026-10-02T19:00:00Z", "collection_status": "completed"},
    "users": [
        {"id": "user:1", "entityId": 1, "displayName": "Иванов", "samAccountName": "ivanov", "enabled": True,
         "lockedOut": False, "memberships": {"status": "observed", "direct": [], "effective": [], "unresolved": []}},
    ],
    "groups": [],
}


def _context(tab: str) -> QueryContext:
    return QueryContext(
        access={}, params={"view": "all", "relation": "effective", "threshold": 60}, domain_ids=[1], action="view",
        cursor=None, limit=100, timezone="UTC", tab=tab,
    )


def test_changes_tab_with_single_snapshot_is_partial_and_says_why(monkeypatch):
    monkeypatch.setattr(report, "_snapshots", lambda _domain_ids, **_kw: {"state": "ok", "current": CURRENT, "previous": None})
    payload = report._query(_context("changes"))

    # Основные строки есть (API вернул пользователей), а вкладка сравнения пуста честно.
    assert payload["items"]
    assert payload["collections"]["changes"] == []
    assert payload["state"] == "partial"
    assert "single_snapshot" in {item["code"] for item in payload["limitations"]}


def test_changes_tab_lists_rows_when_previous_snapshot_exists(monkeypatch):
    previous = {**CURRENT, "users": [{**CURRENT["users"][0], "lockedOut": True}]}
    monkeypatch.setattr(report, "_snapshots", lambda _domain_ids, **_kw: {"state": "ok", "current": CURRENT, "previous": previous})
    payload = report._query(_context("changes"))

    assert [row["type"] for row in payload["collections"]["changes"]] == ["locked_changed"]
    assert "single_snapshot" not in {item["code"] for item in payload["limitations"]}


@pytest.fixture(autouse=True)
def _hygiene_settings(monkeypatch):
    from server.sli.core import platform_settings

    monkeypatch.setattr(platform_settings, "_stored_row", lambda _key: None)
