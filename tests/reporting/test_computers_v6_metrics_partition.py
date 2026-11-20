"""D3: метрики компьютеров не пересекаются и в сумме дают «Всего в AD»."""
from __future__ import annotations

import pytest

from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import computers as report
from server.sli.reports import computers_v6_reporting as engine


def test_v2_metrics_partition_sums_to_total(monkeypatch) -> None:
    raw = {
        "state": "available",
        "items": [],
        "summary": {
            "total_computers": 20, "attention": 3,
            "workstation_enabled": 10, "server_enabled": 4, "unknown_type_enabled": 1,
            "disabled": 4, "unknown_enabled": 1, "unknown_type": 3,
        },
    }
    monkeypatch.setattr(report, "_engine", lambda context, **_: raw)
    metrics = {m["key"]: m for m in report._query(QueryContext(access={}, params={}))["metrics"]}
    parts = ("ws", "srv", "unknown", "disabled", "unknown_state")
    assert sum(metrics[key]["value"] for key in parts) == metrics["all"]["value"]
    assert metrics["unknown"]["filter"] == {"view": "all", "type": "unknown", "enabled": "enabled"}
    assert metrics["disabled"]["filter"]["enabled"] == "disabled"


@pytest.mark.parametrize("enabled_filter", ["", "enabled", "disabled", "unknown"])
def test_engine_partitions_types_and_account_states(monkeypatch, enabled_filter) -> None:
    items = [
        {"entity_id": index, "display_name": f"PC-{index}", "computer_type": kind,
         "enabled": enabled, "reasons": [], "quality_issues": [], "activity": {}, "network": {}}
        for index, (kind, enabled) in enumerate(
            (kind, enabled) for kind in ("workstation", "server", "unknown")
            for enabled in (True, False, None)
        )
    ]
    monkeypatch.setattr(engine, "_coverage", lambda _: {"state": "available"})
    monkeypatch.setattr(engine, "query_rows_bounded", lambda *_args, **_kwargs: items)
    monkeypatch.setattr(engine, "_item", lambda row, _: dict(row))
    monkeypatch.setattr(engine, "_load_computers_v6_source_overlay", lambda _: {})
    monkeypatch.setattr(engine, "_apply_computers_v6_source_overlay", lambda *_: None)
    monkeypatch.setattr(engine, "_requalify_computers_v6_item", lambda *_: None)
    monkeypatch.setattr(engine, "_semantic_rows", lambda _: [])
    monkeypatch.setattr(engine, "_load_snapshot_comparison", lambda _: {})
    result = engine.get_computers_v6_report(domain_ids=[1], view="all", enabled=enabled_filter)
    summary = result["summary"]
    assert summary["total_computers"] == 9
    assert summary["unknown_type"] == 3
    assert summary["unknown_type_enabled"] == 1
    assert sum(summary[key] for key in (
        "workstation_enabled", "server_enabled", "unknown_type_enabled", "disabled", "unknown_enabled",
    )) == 9
    assert result["filtered_count"] == (3 if enabled_filter else 9)
