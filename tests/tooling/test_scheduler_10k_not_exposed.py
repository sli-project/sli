from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess

from server.jobs import collector


def test_toolkit_does_not_expose_10k_scheduler_action() -> None:
    text = Path("tools/adlog-tool.ps1").read_text(encoding="utf-8")
    assert "pg-controlled-scheduler-10k-start" not in text
    assert 'ADLOG_CANARY_MAX_EVENTS = "10000"' not in text
    assert 'ADLOG_CANARY_COMMAND_TIMEOUT_SECONDS = "1800"' not in text


def test_non_archive_scheduler_progress_identifies_the_active_profile(monkeypatch) -> None:
    updates = []
    monkeypatch.setenv("ADLOG_SCHEDULER_CANARY", "1")
    monkeypatch.setenv("ADLOG_SCHEDULER_PROFILE", "synthetic-profile")
    monkeypatch.setenv("ADLOG_CANARY_CHANNELS", "Security,System")
    monkeypatch.setenv("ADLOG_CANARY_ARCHIVE", "0")
    monkeypatch.setattr(collector, "_update_job", lambda job_id, **update: updates.append(update))
    monkeypatch.setattr(collector, "_set_job_current_server", lambda *args: None)
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(collector, "_run_single_server_collection", lambda *args, **kwargs: CompletedProcess([], 0, "", ""))

    collector._collect_server_once(1, "dc1.example.test", 1, 100)

    assert updates[0]["status"] == "running"
    message = updates[0]["message"]
    for name in ("synthetic-profile", "Security", "System", "dc1.example.test"):
        assert name in message
