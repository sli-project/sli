from __future__ import annotations

from pathlib import Path


def test_db0101_caps_scheduler_max_events_to_5000_by_default() -> None:
    text = Path("server/jobs/collector.py").read_text(encoding="utf-8")
    assert "ADLOG_CANARY_MAX_EVENTS_CAP" in text
    assert "requested_max_events_per_channel" in text
    assert "max_events_capped" in text
    assert "min(requested_max_events, max_events_cap)" in text


def test_db0101_toolkit_does_not_offer_old_5k_scheduler() -> None:
    text = Path("tools/adlog-tool.ps1").read_text(encoding="utf-8")
    assert "pg-controlled-scheduler-start" not in text
    assert 'ADLOG_SCHEDULER_PROFILE = "controlled-security-5000"' not in text


def test_db0101_toolkit_keeps_only_guarded_http_restart() -> None:
    text = Path("tools/adlog-tool.ps1").read_text(encoding="utf-8")
    assert '"http-restart"' in text
    assert "http_copy_control.py" in text
    assert "pg-emergency-safe-restart" not in text
