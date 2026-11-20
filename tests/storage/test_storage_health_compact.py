from __future__ import annotations

import os
import json
from datetime import datetime, timezone
from decimal import Decimal

from scripts.maintenance.bundle_common import AUDIT_ACTIONS_LOG, audit_action
from scripts.maintenance.release_check import run_release_check
from scripts.maintenance.storage_cleanup import compact_cleanup_result, compact_storage_health, render_json
from server.sli.storage.storage_policy import apply_storage_cleanup_plan, build_storage_cleanup_plan


def test_compact_cleanup_result_omits_full_action_list(tmp_path, monkeypatch):
    logs = tmp_path / "logs"
    logs.mkdir(parents=True)
    old = logs / "old.debug.log"
    old.write_text("x", encoding="utf-8")
    os.utime(old, (1000000000, 1000000000))
    monkeypatch.setattr("server.sli.storage.storage_policy.DATA_DIR", tmp_path / "data")
    monkeypatch.setattr("server.sli.storage.storage_policy.ROOT", tmp_path)
    monkeypatch.setattr("server.sli.storage.storage_policy.LOG_DIR", logs)
    monkeypatch.setenv("ADLOG_LOG_RETENTION_DAYS", "1")
    plan = build_storage_cleanup_plan(limit=5)
    result = apply_storage_cleanup_plan(plan, apply=False)
    compact = compact_cleanup_result(result)
    assert "actions" not in compact
    assert compact["total_candidates"] >= 1
    assert compact["actions_sample"]


def test_storage_health_json_serializes_postgres_datetime() -> None:
    checked_at = datetime(2026, 7, 27, 3, 0, tzinfo=timezone.utc)

    payload = json.loads(render_json({
        "postgres_operations": {
            "database": {"checked_at": checked_at},
        },
        "storage_lifecycle": {
            "latest_snapshot": {"disk_free_percent": Decimal("12.50")},
        },
    }))

    assert payload["postgres_operations"]["database"]["checked_at"] == checked_at.isoformat()
    assert payload["storage_lifecycle"]["latest_snapshot"]["disk_free_percent"] == 12.5


def test_compact_storage_health_keeps_decision_fields_without_table_dump() -> None:
    compact = compact_storage_health({
        "status": "warn",
        "warnings": ["полный обход проекта неполон: ошибок чтения 2"],
        "disk_pressure": {
            "collection_allowed": True,
            "disk": {"free_human": "100 GB", "free_percent": 25},
            "blocking_threshold": {"free_human": "10 GB"},
        },
        "postgres_operations": {
            "status": "ok",
            "connectivity_status": "ready",
            "metrics_status": "complete",
            "database": {"database_human": "10 GB"},
            "tables": [{"table_name": "events"}],
        },
        "project_overview": {
            "total_human": "12 GB",
            "scan": {
                "complete_project_tree": False,
                "errors": 2,
                "error_paths": ["one", "two"],
            },
        },
        "cleanup_preview": {"total_candidates": 0, "total_human": "0 B"},
    })

    assert compact["status"] == "warn"
    assert compact["project"]["scan_errors"] == 2
    assert compact["safety"]["read_only"] is True
    assert "tables" not in compact["postgres"]


def test_postgres_status_cli_serializes_database_timestamp(monkeypatch, capsys) -> None:
    from scripts.maintenance import postgres_status

    checked_at = datetime(2026, 7, 27, 3, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(
        postgres_status,
        "get_postgres_operations_status",
        lambda **_: {
            "status": "ok",
            "database": {"checked_at": checked_at},
            "safety": {"read_only": True},
        },
    )
    monkeypatch.setattr("sys.argv", ["postgres_status.py"])

    assert postgres_status.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["database"]["checked_at"] == str(checked_at)
    assert payload["safety"]["read_only"] is True


def test_audit_action_is_skipped_during_pytest(monkeypatch):
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "stage2_hotfix1")
    before = AUDIT_ACTIONS_LOG.read_text(encoding="utf-8", errors="replace") if AUDIT_ACTIONS_LOG.exists() else ""
    audit_action("unit_test_should_not_write", "ok")
    after = AUDIT_ACTIONS_LOG.read_text(encoding="utf-8", errors="replace") if AUDIT_ACTIONS_LOG.exists() else ""
    assert after == before


def test_release_check_uses_compact_storage_cleanup(monkeypatch):
    def fake_run_command(args, **kwargs):
        joined = " ".join(str(item) for item in args)
        if "storage_cleanup.py" in joined:
            return {"exit_code": 0, "stdout_tail": '{"actions_sample": [], "total_candidates": 0}', "timed_out": False}
        return {"exit_code": 0, "stdout_tail": "{}", "timed_out": False}

    monkeypatch.setattr("scripts.maintenance.release_check.run_command", fake_run_command)
    result = run_release_check()
    cleanup = result["storage_cleanup_dry_run"]
    tail = cleanup.get("stdout_tail") or ""
    assert cleanup.get("exit_code") == 0
    assert "actions_sample" in tail
    assert "\"actions\"" not in tail
