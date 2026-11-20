from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

import pytest

from server.sli.ops.logging_config import (
    JsonLineFormatter,
    WindowsSafeRotatingFileHandler,
    append_jsonl_bounded,
)
from scripts.maintenance.server_control import _summarize_health_body


pytestmark = pytest.mark.windows


def test_windows_safe_rotating_handler_suppresses_locked_rollover(tmp_path: Path, monkeypatch) -> None:
    log_path = tmp_path / "adlog-monitor.log"
    internal_path = tmp_path / "internal-errors.log"
    log_path.write_text("x" * 100, encoding="utf-8")
    handler = WindowsSafeRotatingFileHandler(
        log_path,
        maxBytes=1,
        backupCount=1,
        encoding="utf-8",
        rollover_error_log_path=internal_path,
    )
    handler.setFormatter(JsonLineFormatter())

    def locked_rollover(self):  # type: ignore[no-untyped-def]
        raise PermissionError("locked for test")

    monkeypatch.setattr(RotatingFileHandler, "doRollover", locked_rollover)
    record = logging.LogRecord(
        name="adlog_monitor",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="probe",
        args=(),
        exc_info=None,
    )
    handler.emit(record)
    handler.emit(record)
    handler.close()

    assert log_path.exists()
    assert "probe" in log_path.read_text(encoding="utf-8")
    warning_text = internal_path.read_text(encoding="utf-8")
    assert "log_rotation_skipped" in warning_text
    assert "PermissionError" in warning_text


def test_server_control_health_summary_is_compact() -> None:
    body = '{"status":"ok","channels":[' + ','.join(['{"status":"warn"}'] * 20) + ']}'
    summary = _summarize_health_body(body)
    assert summary["status"] == "ok"
    assert summary["items_count"] == 20
    assert summary["warning_items"] == 20
    assert "body_tail" not in summary


def test_bounded_jsonl_append_rotates_closed_file(tmp_path: Path) -> None:
    log_path = tmp_path / "worker.log"
    log_path.write_text("x" * 120, encoding="utf-8")

    assert append_jsonl_bounded(
        log_path,
        {"event": "probe"},
        max_bytes=100,
        backup_count=2,
    )

    assert '"event": "probe"' in log_path.read_text(encoding="utf-8")
    assert (tmp_path / "worker.log.1").stat().st_size == 120
