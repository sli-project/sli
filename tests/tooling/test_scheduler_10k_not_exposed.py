from __future__ import annotations

from pathlib import Path


def test_toolkit_does_not_expose_10k_scheduler_action() -> None:
    text = Path("tools/adlog-tool.ps1").read_text(encoding="utf-8")
    assert "pg-controlled-scheduler-10k-start" not in text
    assert 'ADLOG_CANARY_MAX_EVENTS = "10000"' not in text
    assert 'ADLOG_CANARY_COMMAND_TIMEOUT_SECONDS = "1800"' not in text


def test_non_archive_scheduler_message_is_not_hardcoded_archive() -> None:
    text = Path("server/jobs/collector.py").read_text(encoding="utf-8")
    assert "def _scheduler_server_collection_message" in text
    function = text.split("def _scheduler_server_collection_message", 1)[1].split("def _collect_server_once", 1)[0]
    assert "без archive/watermark" in function
    assert "Выполняется архивный read-only" in function
    collect_once = text.split("def _collect_server_once", 1)[1].split("def _collection_mode_for_plan", 1)[0]
    assert "_scheduler_server_collection_message(server)" in collect_once
    assert "Выполняется архивный read-only сбор логов с {server}" not in collect_once
