from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_tool_does_not_expose_archive_watermark_canary_action():
    text = (ROOT / "tools" / "adlog-tool.ps1").read_text(encoding="utf-8")
    assert "pg-archive-canary-scheduler-start" not in text
    assert 'ADLOG_SCHEDULER_PROFILE = "archive-watermark-security-1000"' not in text


def test_runtime_status_exposes_archive_watermark_canary_flags():
    text = (ROOT / "server" / "jobs" / "collector.py").read_text(encoding="utf-8")
    assert '"watermark_enabled": archive_enabled' in text
    assert '"archive_watermark_canary": canary_enabled and archive_enabled' in text
    assert '"scheduler_archive_watermark_canary_enabled"' in text
