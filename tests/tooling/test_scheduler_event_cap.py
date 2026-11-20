from __future__ import annotations

from pathlib import Path

from server.jobs import collector


def test_db0101_caps_scheduler_max_events_to_5000_by_default(monkeypatch) -> None:
    monkeypatch.setenv("ADLOG_SCHEDULER_CANARY", "1")
    monkeypatch.setenv("ADLOG_CANARY_MAX_EVENTS", "10000")
    monkeypatch.delenv("ADLOG_CANARY_MAX_EVENTS_CAP", raising=False)
    monkeypatch.setattr(collector, "_runtime_db_backend", lambda: "postgres")

    canary = collector.get_scheduler_runtime_status()["scheduler_canary"]

    assert canary["requested_max_events_per_channel"] == 10000
    assert canary["max_events_per_channel"] == 5000
    assert canary["max_events_capped"] is True


def test_db0101_toolkit_does_not_offer_old_5k_scheduler() -> None:
    text = Path("tools/adlog-tool.ps1").read_text(encoding="utf-8")
    assert "pg-controlled-scheduler-start" not in text
    assert 'ADLOG_SCHEDULER_PROFILE = "controlled-security-5000"' not in text


def test_db0101_toolkit_keeps_only_guarded_http_restart() -> None:
    text = Path("tools/adlog-tool.ps1").read_text(encoding="utf-8")
    assert '"http-restart"' in text
    assert "http_copy_control.py" in text
    assert "pg-emergency-safe-restart" not in text
