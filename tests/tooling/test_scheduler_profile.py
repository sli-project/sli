from __future__ import annotations

from pathlib import Path


def test_scheduler_effective_job_params_controls_active_job_metadata() -> None:
    text = Path("server/jobs/collector.py").read_text(encoding="utf-8")
    assert "def _scheduler_effective_job_params" in text
    loop = text.split("def _scheduler_loop", 1)[1].split("def create_analysis_job", 1)[0]
    assert "_scheduler_effective_job_params" in loop
    assert "max_events_per_channel=int(effective" in loop
    assert "scheduler_profile=effective" in loop


def test_runtime_status_exposes_scheduler_profile() -> None:
    text = Path("server/jobs/collector.py").read_text(encoding="utf-8")
    assert "scheduler_profile" in text
    assert "ADLOG_SCHEDULER_PROFILE" in text


def test_toolkit_does_not_offer_controlled_scheduler_actions() -> None:
    text = Path("tools/adlog-tool.ps1").read_text(encoding="utf-8")
    assert "pg-controlled-scheduler-start" not in text
    assert "pg-controlled-scheduler-stop" not in text
    assert "controlled-security-5000" not in text
