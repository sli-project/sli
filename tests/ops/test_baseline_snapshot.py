from __future__ import annotations

import json

from scripts.maintenance.baseline_snapshot import build_baseline_snapshot
from scripts.maintenance.collect_diagnostics import _diagnostic_decision, _top_slow_stages
from server.sli.ops.version import BASELINE_ID, PROJECT_VERSION, get_release_metadata


def test_release_metadata_has_stage0_baseline() -> None:
    metadata = get_release_metadata()
    assert metadata["project_version"] == PROJECT_VERSION
    assert metadata["baseline_id"] == BASELINE_ID
    assert metadata["schema"]["schema_declared_max_version"] >= 4
    assert "schema_migration_version" not in metadata["schema"]


def test_baseline_snapshot_lists_guarantees() -> None:
    snapshot = build_baseline_snapshot(include_checks=False)
    assert snapshot["package_type"] == "BASELINE_SNAPSHOT"
    assert any("read-only" in item.lower() for item in snapshot["baseline_guarantees"])
    assert any(item["path"] == "docs/ADMIN_GUIDE.md" and item["exists"] for item in snapshot["critical_files"])


def test_top_slow_stages_parses_jsonl() -> None:
    text = "\n".join([
        json.dumps({"ts": "t1", "stage": "fast", "duration_ms": 5}),
        json.dumps({"ts": "t2", "stage": "slow", "duration_ms": 500, "server": "DC1"}),
    ])
    result = _top_slow_stages(text)
    assert result["top_events"][0]["stage"] == "slow"
    assert result["by_stage"][0]["stage"] == "slow"


def test_diagnostic_decision_propagates_release_warning() -> None:
    status, reasons = _diagnostic_decision(
        checks={"release_check": {"exit_code": 0, "stdout_tail": '{"status":"warn","warnings":["storage warn"]}'}},
        db_snapshot={"exists": True},
        health_warnings=[],
        internal_tail="",
        storage={"sizes": {"raw": {"bytes": 0}, "processed": {"bytes": 0}, "project": {"bytes": 0}}},
    )
    assert status == "warn"
    assert any("storage warn" in item for item in reasons)
