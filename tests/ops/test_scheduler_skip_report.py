from __future__ import annotations

import importlib


def test_scheduler_skip_report_defaults_to_canary(monkeypatch):
    monkeypatch.setenv("ADLOG_SCHEDULER_CANARY", "1")
    monkeypatch.delenv("ADLOG_SCHEDULER_SKIP_REPORT", raising=False)
    import server.jobs.collector as collector

    collector = importlib.reload(collector)
    status = collector.get_scheduler_runtime_status()

    assert status["scheduler_skip_report"] is True
    assert status["scheduler_canary"]["skip_report"] is True


def test_scheduler_skip_report_can_be_disabled(monkeypatch):
    monkeypatch.setenv("ADLOG_SCHEDULER_CANARY", "1")
    monkeypatch.setenv("ADLOG_SCHEDULER_SKIP_REPORT", "0")
    import server.jobs.collector as collector

    collector = importlib.reload(collector)
    status = collector.get_scheduler_runtime_status()

    assert status["scheduler_skip_report"] is False
    assert status["scheduler_canary"]["skip_report"] is False
