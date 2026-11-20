"""«VPN и привилегии» = 0 при 13 строках — не расхождение: метрика считает пересечения, а не строки."""

from __future__ import annotations

from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import vpn_audit


def _context() -> QueryContext:
    return QueryContext(access={}, params={}, domain_ids=None, action="view", cursor=None, limit=50, timezone="UTC")


def _raw(overlap_rows: int, coverage: str) -> dict:
    items = [{"display_name": f"U{i}", "natural_key": f"sid:{i}", "activity_state": "active", "privileged_overlap": i < overlap_rows}
             for i in range(13)]
    return {"state": "available", "items": items, "summary": {
        "total_users": 13, "enabled_users": 13, "inactive_users": 0, "disabled_users": 0, "privileged_overlap_users": overlap_rows,
        "collection": {"privileged_membership": {"state": coverage}, "vpn_membership": {"state": "complete"}},
    }}


def test_privilege_metric_counts_overlaps_not_rows(monkeypatch):
    monkeypatch.setattr(vpn_audit, "execute_report", lambda *_a, **_kw: _raw(0, "complete"))
    payload = vpn_audit._query(_context())
    metrics = {item["key"]: item["value"] for item in payload["metrics"]}

    assert len(payload["items"]) == 13 and metrics["total_users"] == 13
    assert metrics["privileged_overlap_users"] == 0
    assert {row["privilege_text"] for row in payload["items"]} == {"Не обнаружено"}


def test_privilege_metric_matches_rows_with_overlap(monkeypatch):
    monkeypatch.setattr(vpn_audit, "execute_report", lambda *_a, **_kw: _raw(3, "complete"))
    payload = vpn_audit._query(_context())

    assert {item["key"]: item["value"] for item in payload["metrics"]}["privileged_overlap_users"] == 3
    assert sum(row["privilege_text"] == "Есть пересечение" for row in payload["items"]) == 3
