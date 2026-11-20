from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from scripts.maintenance.collect_diagnostics import build_diagnostics
from scripts.maintenance.release_check import run_release_check
from scripts.maintenance.runtime_watchdog import run_watchdog
from scripts.maintenance import runtime_watchdog as runtime_watchdog_module
from scripts.maintenance import self_test as self_test_module
from scripts.maintenance.self_test import run_self_test
from scripts.maintenance.ui_nav_check import run_ui_nav_check
from server.sli.ops.diagnostics import make_internal_error_id, make_structured_log_payload, validate_structured_log_payload
from server.sli.ops.diagnostics_report import get_diagnostics_overview, render_diagnostics_report
from server.sli.access.role_views import get_role_views_meta


def test_structured_log_payload_has_stage1_required_fields() -> None:
    payload = make_structured_log_payload(
        component="selftest",
        event="unit_probe",
        message="probe",
        status="completed",
        duration_ms=3,
        trace_id="trace-1",
    )
    validation = validate_structured_log_payload(payload)
    assert validation["status"] == "ok"
    assert payload["component"] == "selftest"
    assert payload["event"] == "unit_probe"
    assert payload["duration_ms"] == 3
    assert payload["trace_id"] == "trace-1"


def test_internal_error_id_has_visible_prefix() -> None:
    error_id = make_internal_error_id()
    assert error_id.startswith("INT-")
    assert len(error_id.split("-")) >= 3


def test_offline_self_test_is_safe_and_reports_checks(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ADLOG_SELFTEST_NO_LOG", "1")
    monkeypatch.setenv("ADLOG_DB_BACKEND", "postgres")
    monkeypatch.setenv("ADLOG_PG_DSN", "host=127.0.0.1 dbname=sli_selftest user=sli_selftest")
    monkeypatch.setenv("ADLOG_STORAGE_READ_MODE", "v2")
    monkeypatch.setenv("ADLOG_STORAGE_WRITE_MODE", "v2")
    result = run_self_test(live=False, json_log=False)
    assert result["mode"] == "offline"
    assert result["status"] in {"ok", "warn"}
    names = {item["name"] for item in result["checks"]}
    assert {
        "python", "imports", "directories", "postgres_runtime_contract",
        "structured_log_schema", "pytest_temp",
    }.issubset(names)


def test_pytest_temp_check_falls_back_when_configured_basetemp_is_blocked(tmp_path: Path, monkeypatch) -> None:
    blocked_parent = tmp_path / "blocked-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")
    fallback_tmp = tmp_path / "fallback-tmp"
    monkeypatch.setattr(self_test_module, "PYTEST_BASETEMP", blocked_parent / "pytest")
    monkeypatch.setattr(self_test_module, "TMP_DIR", fallback_tmp)

    result = self_test_module._check_pytest_temp()

    assert result["status"] == "warn"
    assert result["basetemp"] == str(fallback_tmp / "pytest-selftest")
    assert result["attempted"][0]["error_type"] in {"FileExistsError", "NotADirectoryError", "OSError"}


def test_ui_nav_check_is_fast_and_has_roles() -> None:
    result = run_ui_nav_check()
    assert result["status"] in {"ok", "warn"}
    assert {"security", "it", "technical"}.issubset(set(result["role_views"]))
    assert "diagnostics.html" in result["reports"]


def test_role_views_meta_does_not_require_heavy_data() -> None:
    meta = get_role_views_meta()
    assert [item["id"] for item in meta["views"]] == ["security", "it", "technical"]


def test_release_check_includes_stage1_checks(monkeypatch) -> None:
    def fake_run_command(args, **kwargs):
        return {"exit_code": 0, "stdout_tail": "{}", "timed_out": False}

    monkeypatch.setattr("scripts.maintenance.release_check.run_command", fake_run_command)
    result = run_release_check()
    assert result["status"] in {"ok", "warn"}
    assert "self_test_offline" in result
    assert "ui_nav_check" in result
    assert "role_views" in result["checks_duration_ms"]


def test_runtime_watchdog_returns_readonly_snapshot() -> None:
    result = run_watchdog()
    assert result["status"] in {"ok", "warn"}
    assert "storage" in result["items"]


def test_runtime_watchdog_json_cli_serializes_database_datetimes(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        runtime_watchdog_module,
        "run_watchdog",
        lambda: {"status": "ok", "duration_ms": 1, "warnings": [], "items": {"queued_at": datetime(2026, 7, 17, tzinfo=timezone.utc)}},
    )
    monkeypatch.setattr(sys, "argv", ["runtime_watchdog.py", "--json"])

    assert runtime_watchdog_module.main() == 0
    assert json.loads(capsys.readouterr().out)["items"]["queued_at"].startswith("2026-07-17")


def test_diagnostics_report_renders_without_running_checks() -> None:
    data = get_diagnostics_overview(run_checks=False)
    html = render_diagnostics_report(data)
    assert "Диагностика" in html
    assert "self_test.py" in html


def test_collect_diagnostics_contains_stage1_checks(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADLOG_SELFTEST_NO_LOG", "1")
    monkeypatch.setattr("scripts.maintenance.collect_diagnostics._health_snapshots", lambda **_: {})
    monkeypatch.setattr("scripts.maintenance.collect_diagnostics._db_snapshot", lambda **_: {"exists": False, "mode": "test"})
    monkeypatch.setattr("scripts.maintenance.collect_diagnostics._storage_snapshot", lambda **_: {"project": {"bytes": 0}})
    monkeypatch.setattr("scripts.maintenance.collect_diagnostics.run_command", lambda *_, **__: {"exit_code": 0, "stdout_tail": "{}", "timed_out": False, "duration_ms": 0})
    result = build_diagnostics(out_dir=tmp_path, last_lines=5, include_release_check=False)
    zip_path = Path(result["zip_path"])
    assert zip_path.exists()
    import zipfile

    with zipfile.ZipFile(zip_path, "r") as zf:
        checks = json.loads(zf.read("snapshots/checks.json").decode("utf-8"))
    assert "self_test_offline" in checks
    assert "ui_nav_check" in checks
    assert "runtime_watchdog" in checks


def test_diagnostics_in_process_checks_turn_exceptions_into_failed_entries(monkeypatch) -> None:
    import server.sli.ops.diagnostics_report as report

    monkeypatch.setattr(report, "run_command", lambda *_, **__: {"exit_code": 0, "stdout_tail": "{}", "timed_out": False, "duration_ms": 0})
    monkeypatch.setattr("server.sli.ops.ui_nav_check.run_ui_nav_check", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    result = report.get_diagnostics_overview(run_checks=True)

    assert result["parsed_checks"]["ui_nav_check"]["status"] == "failed"
    assert result["checks"]["ui_nav_check"]["exit_code"] == -1
    assert result["parsed_checks"]["runtime_watchdog"]["status"] in {"ok", "warn"}
    assert any(w.startswith("ui_nav_check: status=failed") for w in result["warnings"])
