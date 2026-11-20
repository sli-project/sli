"""Exercise real report writers with synthetic report data, without a database."""
from contextlib import contextmanager

import pytest

from server.jobs import collector
from server.sli.reports import analysis
from server.sli.sources.post_collection_pipeline import PostCollectionLeaseLost


@pytest.fixture
def reports(monkeypatch, tmp_path):
    monkeypatch.setattr(analysis, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(analysis, "log_event", lambda *a, **kw: None)
    for name in ("_collect_summary", "_build_recommendations", "_correlate_events",
                 "_logging_gap_rows", "_criticality_rows_for_servers", "_time_bounds_for_servers",
                 "_criticality_rows", "_server_time_bounds", "_build_report_context"):
        monkeypatch.setattr(analysis, name, lambda *a, **kw: {})
    monkeypatch.setattr(analysis, "get_collector_health", lambda: {})
    monkeypatch.setattr(analysis, "render_target_report", lambda _: "current-report")
    monkeypatch.setattr(analysis, "render_collector_health_report", lambda _: "current-health")
    monkeypatch.setattr(collector, "generate_recommendation_report", analysis.generate_recommendation_report)
    monkeypatch.setattr(collector, "heartbeat_post_collection_job", lambda *a, **kw: None)
    return tmp_path


def test_lease_loss_during_render_cannot_overwrite_newer_files(monkeypatch, reports):
    names = ["server-DC1-security-profile.html", "domain-security-overview.html", "collector-health.html"]
    for name in names:
        (reports / name).write_text("new-owner-report")
    live = True

    def render(_):
        nonlocal live
        live = False
        return "stale-owner-report"

    @contextmanager
    def guard(*args, **kwargs):
        if not live:
            raise PostCollectionLeaseLost("job-1")
        yield

    monkeypatch.setattr(analysis, "render_target_report", render)
    monkeypatch.setattr(collector, "post_collection_lease_guard", guard, raising=False)
    with pytest.raises(PostCollectionLeaseLost):
        collector._generate_report_with_heartbeat(
            job_id=1, servers=["DC1"], durable_job_id="job-1",
            worker_id="worker-a", claim_attempt=1,
        )
    assert {p.name: p.read_text() for p in reports.iterdir()} == dict.fromkeys(names, "new-owner-report")


def test_each_publication_is_atomic_and_inside_live_claim_guard(monkeypatch, reports):
    guards = []
    held = False

    @contextmanager
    def guard(durable_job_id, **kwargs):
        nonlocal held
        guards.append((durable_job_id, kwargs))
        held = True
        try:
            yield
        finally:
            held = False

    from pathlib import Path
    replace = Path.replace

    def guarded_replace(path, target):
        assert held, "file publication must hold the ownership row lock"
        assert path.read_text() in {"current-report", "current-health"}
        return replace(path, target)

    monkeypatch.setattr(collector, "post_collection_lease_guard", guard, raising=False)
    monkeypatch.setattr(Path, "replace", guarded_replace)
    collector._generate_report_with_heartbeat(
        job_id=1, servers=["DC1"], durable_job_id="job-1",
        worker_id="worker-a", claim_attempt=2,
    )
    assert len(guards) == 3
    assert guards == [("job-1", {"worker_id": "worker-a", "claim_attempt": 2})] * 3
    assert len(list(reports.iterdir())) == 3


def test_failed_promotion_leaves_published_bytes_and_no_temporary_file(monkeypatch, reports):
    from pathlib import Path

    target = reports / "server-DC1-security-profile.html"
    target.write_text("published-report")

    @contextmanager
    def guard(*args, **kwargs):
        yield

    def fail_replace(*args, **kwargs):
        raise OSError("synthetic promotion failure")

    monkeypatch.setattr(collector, "post_collection_lease_guard", guard)
    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(OSError, match="synthetic promotion failure"):
        collector._generate_report_with_heartbeat(
            job_id=1, servers=["DC1"], durable_job_id="job-1",
            worker_id="worker-a", claim_attempt=1,
        )
    assert {p.name: p.read_text() for p in reports.iterdir()} == {target.name: "published-report"}
