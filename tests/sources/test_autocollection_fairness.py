from __future__ import annotations

from server.sli.sources import collector_adaptive
from server.sli.core import postgres_runtime_pipeline
from server.sli.storage.archive_state import utc_now
from server.sli.sources.collector_adaptive import get_adaptive_plan_for_server
from server.jobs import collector


def _pg_plan(monkeypatch, *, fairness_channels: list[str]):
    """Plan from PostgreSQL state (Security 180 minutes behind) with the given stale channels."""
    monkeypatch.setattr(collector_adaptive, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(
        postgres_runtime_pipeline,
        "get_adaptive_plan_state_pg",
        lambda *args, **kwargs: {
            "backend": "postgres",
            "security_lag_minutes": 180,
            "adaptive_state": None,
            "fairness_channels": fairness_channels,
        },
    )
    return get_adaptive_plan_for_server("DC1")


def test_fairness_adds_stale_non_security_channels(monkeypatch):
    plan = _pg_plan(monkeypatch, fairness_channels=["System", "DNS Server"])
    assert plan.recovery_mode is True
    assert 'Security' in plan.channels
    assert any(ch != 'Security' for ch in plan.channels)
    assert plan.fairness_channels
    assert plan.channel_limits[plan.fairness_channels[0]] <= 100


def test_fairness_does_not_invent_channels_without_state(monkeypatch):
    plan = _pg_plan(monkeypatch, fairness_channels=[])
    assert plan.recovery_mode is True
    assert plan.channels == ['Security']
    assert plan.fairness_channels == []


def test_skipped_overlap_summary_is_aggregated():
    jobs = [
        {'id': 3, 'status': 'skipped', 'skipped_reason': 'overlap', 'created_at': '2026-07-09T01:02:00+00:00'},
        {'id': 2, 'status': 'skipped', 'skipped_reason': 'overlap', 'created_at': '2026-07-09T01:01:00+00:00'},
        {'id': 1, 'status': 'completed', 'created_at': '2026-07-09T01:00:00+00:00'},
    ]
    result = collector._skipped_overlap_summary(jobs)
    assert result['count'] == 2
    assert result['normal'] is True
    assert 'активный сбор' in result['message']


def test_progress_line_updates_active_job_state():
    collector._jobs.clear()
    job = collector.Job(id=1, kind='collect_all_dc_logs:test', status='running', servers=['DC1'], hours=1, max_events_per_channel=100, created_at=utc_now(), updated_at=utc_now())
    collector._jobs[1] = job
    collector._update_job_progress_from_line(1, 'DC1', 'Starting channel: DNS Server')
    collector._update_job_progress_from_line(1, 'DC1', 'Progress channel: DNS Server count=25 record_id=100')
    snapshot = collector.get_job(1)
    assert snapshot['current_server'] == 'DC1'
    assert snapshot['current_channel'] == 'DNS Server'
    assert snapshot['events_collected'] == 25
