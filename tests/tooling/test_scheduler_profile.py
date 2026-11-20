from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from server.jobs import collector


def test_scheduler_tick_uses_effective_job_params(monkeypatch) -> None:
    calls = []
    events = {}

    @contextmanager
    def acquired(*args):
        yield True

    class EndOfTick(Exception):
        pass

    def stop_sleep(seconds):
        raise EndOfTick

    monkeypatch.setenv("ADLOG_SCHEDULER_CANARY", "1")
    monkeypatch.setenv("ADLOG_SCHEDULER_PROFILE", "synthetic-profile")
    monkeypatch.setenv("ADLOG_CANARY_MAX_EVENTS", "123")
    monkeypatch.setenv("ADLOG_CANARY_MAX_EVENTS_CAP", "5000")
    monkeypatch.setenv("ADLOG_CANARY_HOURS", "2")
    monkeypatch.setattr(collector, "session_advisory_lock", acquired)
    monkeypatch.setattr(collector, "create_collect_job", lambda **spec: calls.append(spec) or {"id": 1})
    monkeypatch.setattr(collector, "_wait_for_scheduled_job_terminal", lambda job_id: None)
    monkeypatch.setattr(collector, "log_event", lambda category, code, message, **fields: events.update({code: fields}))
    monkeypatch.setattr(collector, "time", SimpleNamespace(sleep=stop_sleep))

    with pytest.raises(EndOfTick):
        collector._scheduler_loop(interval_seconds=30, hours=24, max_events_per_channel=1000)

    assert calls == [{"hours": 2, "max_events_per_channel": 123, "reason": "scheduled"}]
    assert events["scheduler_tick"]["scheduler_profile"] == "synthetic-profile"


def test_runtime_status_exposes_scheduler_profile(monkeypatch) -> None:
    monkeypatch.setenv("ADLOG_SCHEDULER_PROFILE", "Synthetic-Profile")
    monkeypatch.setattr(collector, "_runtime_db_backend", lambda: "postgres")

    assert collector.get_scheduler_runtime_status()["scheduler_profile"] == "synthetic-profile"


def test_toolkit_does_not_offer_controlled_scheduler_actions() -> None:
    text = Path("tools/adlog-tool.ps1").read_text(encoding="utf-8")
    assert "pg-controlled-scheduler-start" not in text
    assert "pg-controlled-scheduler-stop" not in text
    assert "controlled-security-5000" not in text
