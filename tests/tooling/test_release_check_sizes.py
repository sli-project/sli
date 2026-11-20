from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.maintenance.bundle_common import (
    PYTEST_BASETEMP_ROOT,
    dir_size_report,
    pytest_quick_command,
    safe_pytest_env,
    unique_pytest_basetemp,
)
from scripts.maintenance.collect_diagnostics import build_diagnostics
from scripts.maintenance.release_check import run_release_check


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_dir_size_report_is_bounded(tmp_path: Path) -> None:
    for idx in range(20):
        (tmp_path / f"file-{idx}.txt").write_text("x" * 10, encoding="utf-8")
    report = dir_size_report(tmp_path, max_entries=5)
    assert report["truncated"] is True
    assert report["reason"] == "max_entries"
    assert report["files_seen"] <= 5
    assert "duration_ms" in report


def test_release_check_reports_duration_and_fast_runtime_size(monkeypatch) -> None:
    def fake_run_command(args, **kwargs):
        return {"exit_code": 0, "stdout_tail": "{}", "timed_out": False}

    monkeypatch.setattr("scripts.maintenance.release_check.run_command", fake_run_command)
    result = run_release_check()
    assert result["status"] in {"ok", "warn"}
    assert isinstance(result.get("duration_ms"), int)
    assert result["runtime_size_checks"]["mode"] == "fast_bounded"
    assert "runtime_size_checks" in result["checks_duration_ms"]


def test_release_check_keeps_storage_size_messages_advisory(monkeypatch) -> None:
    def fake_run_command(args, **kwargs):
        return {"exit_code": 0, "stdout_tail": "{}", "timed_out": False}

    monkeypatch.setattr("scripts.maintenance.release_check.run_command", fake_run_command)
    monkeypatch.setattr("scripts.maintenance.release_check._runtime_source_warnings", lambda root: [])
    monkeypatch.setattr(
        "scripts.maintenance.release_check._quick_runtime_size_checks",
        lambda root: (["data/raw больше 1 ГБ — высокий приоритет обслуживания: 2.3 GB"], {"mode": "fast_bounded"}),
    )
    monkeypatch.setattr("scripts.maintenance.release_check.audit_pg_runtime_parity", lambda root: {"status": "ok", "failures": []})

    result = run_release_check()

    assert result["status"] == "ok"
    assert result["warnings"] == []
    assert result["storage_advisories"] == ["data/raw больше 1 ГБ — высокий приоритет обслуживания: 2.3 GB"]


def test_pytest_uses_project_controlled_temp() -> None:
    env = safe_pytest_env()
    command = pytest_quick_command()
    first = unique_pytest_basetemp("unit")
    second = unique_pytest_basetemp("unit")
    assert first != second
    assert first.is_relative_to(PYTEST_BASETEMP_ROOT)
    assert second.is_relative_to(PYTEST_BASETEMP_ROOT)
    assert first != PROJECT_ROOT / "data" / "tmp"
    assert first != PYTEST_BASETEMP_ROOT
    assert ".pytest_tmp" not in str(first)
    assert Path(env["TEMP"]).is_relative_to(PROJECT_ROOT)
    assert first.is_relative_to(PROJECT_ROOT)
    joined = " ".join(str(item) for item in command)
    assert str(PYTEST_BASETEMP_ROOT) in joined
    assert ".pytest_tmp" not in joined
    assert env["TEMP"].endswith(str(Path("data") / "tmp"))
    assert "PYTEST_ADDOPTS" in env
    assert "--basetemp=" in env["PYTEST_ADDOPTS"]
    runner = PROJECT_ROOT / "scripts" / "maintenance" / "run_pytest.py"
    result = subprocess.run(
        [
            sys.executable,
            str(runner),
            "--run-label",
            "stage0-hotfix",
            "--",
            # Bind mounts may not support truncating unlinked fd-capture files.
            "--capture=sys",
            "tests/tooling/test_release_check_sizes.py::test_dir_size_report_is_bounded",
        ],
        cwd=PROJECT_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert result.returncode == 0, result.stdout
    assert "PYTEST_BASETEMP=" in result.stdout
    assert "PYTEST_EXIT_CODE=0" in result.stdout
    assert str(PYTEST_BASETEMP_ROOT) in result.stdout


def test_collect_diagnostics_fast_creates_bundle(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("scripts.maintenance.collect_diagnostics._health_snapshots", lambda **_: {})
    monkeypatch.setattr("scripts.maintenance.collect_diagnostics._db_snapshot", lambda **_: {"exists": False, "mode": "test"})
    monkeypatch.setattr("scripts.maintenance.collect_diagnostics._storage_snapshot", lambda **_: {"project": {"bytes": 0}})
    monkeypatch.setattr("scripts.maintenance.collect_diagnostics.run_command", lambda *_, **__: {"exit_code": 0, "stdout_tail": "{}", "timed_out": False, "duration_ms": 0})
    result = build_diagnostics(out_dir=tmp_path, last_lines=10, include_release_check=False)
    assert result["status"] in {"ok", "warn", "failed"}
    zip_path = Path(result["zip_path"])
    assert zip_path.exists()
    assert result["duration_ms"] >= 0


def test_pytest_ini_sets_safe_basetemp() -> None:
    pytest_ini = PROJECT_ROOT / "pytest.ini"
    text = pytest_ini.read_text(encoding="utf-8")
    assert "--basetemp=.pytest_tmp" not in text
    assert "--basetemp=data/tmp/pytest" not in text
    assert "-p no:cacheprovider" in text
