from __future__ import annotations

from pathlib import Path

import pytest

from server.jobs import collector

ROOT = Path(__file__).resolve().parents[2]


def test_tool_does_not_expose_archive_watermark_canary_action():
    text = (ROOT / "tools" / "adlog-tool.ps1").read_text(encoding="utf-8")
    assert "pg-archive-canary-scheduler-start" not in text
    assert 'ADLOG_SCHEDULER_PROFILE = "archive-watermark-security-1000"' not in text


@pytest.mark.parametrize(("canary", "archive"), [(True, True), (True, False), (False, True), (False, False)])
def test_runtime_status_exposes_archive_watermark_canary_flags(monkeypatch, canary, archive):
    monkeypatch.setenv("ADLOG_SCHEDULER_CANARY", str(int(canary)))
    monkeypatch.delenv("ADLOG_POSTGRES_SCHEDULER_CANARY", raising=False)
    monkeypatch.setenv("ADLOG_CANARY_ARCHIVE", str(int(archive)))
    monkeypatch.setattr(collector, "_runtime_db_backend", lambda: "postgres")

    status = collector.get_scheduler_runtime_status()

    assert status["scheduler_canary"]["watermark_enabled"] is archive
    assert status["scheduler_canary"]["archive_watermark_canary"] is (canary and archive)
    assert status["scheduler_archive_watermark_canary_enabled"] is (canary and archive)
