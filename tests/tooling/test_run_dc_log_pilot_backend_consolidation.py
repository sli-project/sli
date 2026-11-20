"""Collection pipeline consolidation: production must not silently choose
between Python/PowerShell collectors or PostgreSQL/SQLite importers on every
run.
"""
from __future__ import annotations

import pytest

import scripts.run_dc_log_pilot as runner


def test_auto_backend_never_silently_falls_back_to_powershell(monkeypatch) -> None:
    """choose_collector_backend("auto") must resolve to Python whenever the
    host can run it (the only real production configuration), and must
    raise -- not silently switch backends -- when it cannot. PowerShell is
    only ever chosen when explicitly requested."""
    monkeypatch.setattr(runner, "python_collector_available", lambda: (True, "available"))
    assert runner.choose_collector_backend("auto") == ("python", "auto_python_available")

    monkeypatch.setattr(runner, "python_collector_available", lambda: (False, "pywin32_unavailable: boom"))
    with pytest.raises(runner.CollectorBackendUnavailableError):
        runner.choose_collector_backend("auto")

    # Explicit override always works regardless of host capability.
    assert runner.choose_collector_backend("powershell") == ("powershell", "forced_powershell")


def test_auto_retry_after_python_failure_fallback_was_removed() -> None:
    """The previous auto-retry-after-all-channels-failed fallback silently
    re-ran the whole collection through PowerShell -- untested, unbounded
    duplicate latency, and it could change which engine produced the
    imported data without any operator decision. It must be gone, not
    merely unreachable."""
    source = __import__("pathlib").Path(runner.__file__).read_text(encoding="utf-8")
    assert "auto_retry_after_python_all_failed" not in source
    assert "collector_backend_auto_retry" not in source


@pytest.mark.parametrize("opt_in", [None, "1"])
def test_main_rejects_non_postgres_backend_unconditionally(tmp_path, monkeypatch, opt_in) -> None:
    """A non-postgres backend must fail fast (exit 66) before any real work,
    even if the removed rollback opt-in variable is still set in the env."""
    monkeypatch.setattr(runner, "runtime_db_backend", lambda: "sqlite")
    if opt_in is None:
        monkeypatch.delenv("ADLOG_ALLOW_SQLITE_IMPORT_ROLLBACK", raising=False)
    else:
        monkeypatch.setenv("ADLOG_ALLOW_SQLITE_IMPORT_ROLLBACK", opt_in)

    def _explode(*_a, **_k):
        raise AssertionError("run_command must not be reached once the backend gate fails closed")

    monkeypatch.setattr(runner, "run_command", _explode)
    monkeypatch.setattr(runner, "choose_collector_backend", lambda _requested: ("python", "forced_python"))
    monkeypatch.setattr(runner, "validate_adapter_for_channels", lambda *_a, **_k: [])
    monkeypatch.setattr(
        runner.sys, "argv",
        ["run_dc_log_pilot.py", "--server", "DC1", "--connect-address", "DC1",
         "--hours", "1", "--collector-backend", "python", "--no-technical-report"],
    )

    assert runner.main() == 66


def test_pilot_has_no_sqlite_import_or_report_leftovers() -> None:
    source = __import__("pathlib").Path(runner.__file__).read_text(encoding="utf-8")
    for token in ("import sqlite3", "sqlite_writer", "import_event_jsonl_to_sqlite",
                  "sqlite_import_rollback_opt_in_enabled", "ad_logs.sqlite", "get_report_data"):
        assert token not in source


def test_import_for_backend_rejects_non_postgres(tmp_path) -> None:
    with pytest.raises(ValueError, match="non_postgres_backend_forbidden"):
        runner.run_import_for_backend(
            target_backend="sqlite", output_dir=tmp_path, server="DC1",
            trace_id="t", job_id=None, collector_backend="python",
        )
