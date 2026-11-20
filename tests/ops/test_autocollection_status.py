from __future__ import annotations

from server.jobs import collector


def test_autocollection_status_fast_does_not_call_deep_collectors(monkeypatch):
    collector._jobs.clear()

    def fail_collector_health():  # pragma: no cover - called only on regression
        raise AssertionError("collector health must not run in fast status")

    def fail_performance(*, timeout_seconds=0.5):  # pragma: no cover - called only on regression
        raise AssertionError("performance SQL must not run in fast status")

    monkeypatch.setattr(collector, "_safe_collector_health", fail_collector_health)
    monkeypatch.setattr(collector, "_recent_performance_breakdown", fail_performance)
    monkeypatch.setattr(collector, "_archive_channel_summary_fast", lambda: [{"server": "DC1", "channel": "Security"}])

    status = collector.get_autocollection_status()

    assert status["mode"] == "fast"
    assert status["status"] == "idle"
    assert status["collector_health"]["status"] == "skipped"
    assert status["performance"]["status"] == "skipped"
    assert status["channels"] == [{"server": "DC1", "channel": "Security"}]


def test_autocollection_status_deep_uses_bounded_helpers(monkeypatch):
    collector._jobs.clear()
    calls = []
    monkeypatch.setattr(collector, "_safe_collector_health", lambda: {"status": "ok", "items": []})
    monkeypatch.setattr(collector, "_recent_performance_breakdown", lambda *, timeout_seconds=0.5: calls.append(timeout_seconds) or {"stages": []})

    status = collector.get_autocollection_status(deep=True)

    assert status["mode"] == "deep"
    assert calls == [0.5]
