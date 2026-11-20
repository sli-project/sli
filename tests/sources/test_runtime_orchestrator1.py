from __future__ import annotations

import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace


def test_external_post_collection_mode_queues_without_using_web_executor(monkeypatch) -> None:
    from server.jobs import collector

    now = collector.utc_now()
    job = collector.Job(4101, "collect", "completed", ["DC1"], 1, 100, now, now)
    with collector._lock:
        collector._jobs[job.id] = job
    queued: list[dict] = []
    monkeypatch.setenv("ADLOG_EXTERNAL_POST_COLLECTION_WORKER", "1")
    monkeypatch.setattr(collector, "queue_post_collection_job", lambda **kwargs: queued.append(kwargs) or {})
    monkeypatch.setattr(collector._post_collection_executor, "submit", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("web executor must not run")))
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: None)
    try:
        collector._enqueue_post_collection(job.id, ["DC1"], "test-trace")
        assert queued and queued[0]["durable_job_id"] == job.durable_id
        assert job.durable_id not in collector._post_collection_active
    finally:
        with collector._lock:
            collector._jobs.pop(job.id, None)


def test_independent_worker_claims_and_executes_durable_rows(monkeypatch) -> None:
    from server.jobs import collector

    row = {"durable_job_id": "durable-1", "servers_json": '["DC1"]', "phase": "findings_queued", "attempt_count": 1}
    calls: list[tuple] = []
    monkeypatch.setattr(collector, "claim_queued_post_collection_jobs", lambda **kwargs: [row])
    monkeypatch.setattr(collector, "_run_post_collection_job", lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setattr(collector, "get_job", lambda _job_id: {"analysis_status": "completed"})

    result = collector.run_persisted_post_collection_worker_once(worker_id="worker-a", limit=1)

    assert result == {"claimed": 1, "completed": 1, "failed": 0}
    assert calls[0][0][1] == ["DC1"]
    assert calls[0][1]["worker_id"] == "worker-a"
    assert calls[0][1]["claim_attempt"] == 1


def test_worker_cli_is_separate_from_web_server() -> None:
    script = Path("scripts/runtime/post_collection_worker.py")
    source = script.read_text(encoding="utf-8")
    assert "run_persisted_post_collection_worker_once" in source
    assert "run_server(" not in source
    result = subprocess.run([sys.executable, str(script), "--help"], text=True, capture_output=True, timeout=20, check=False)
    assert result.returncode == 0
    assert "durable post-collection worker" in result.stdout


def test_collection_worker_uses_one_cycle_and_never_starts_the_web_server(monkeypatch) -> None:
    from scripts.runtime import collection_worker

    @contextmanager
    def locked():
        yield True

    monkeypatch.setattr(collection_worker, "load_config", lambda: SimpleNamespace(db_backend="postgres"))
    monkeypatch.setattr(collection_worker, "get_active_collection_block", lambda: None)
    monkeypatch.setattr(collection_worker, "collection_worker_lock", locked)
    monkeypatch.setattr(collection_worker, "create_collect_job", lambda **kwargs: {"id": 55})
    monkeypatch.setattr(collection_worker, "get_job", lambda job_id: {"id": job_id, "status": "completed", "phase": "done", "duration_ms": 7, "errors": []})
    history: list[tuple] = []
    monkeypatch.setattr(collection_worker, "start_runtime_collection_run", lambda **kwargs: history.append(("start", kwargs)))
    monkeypatch.setattr(collection_worker, "update_runtime_collection_run", lambda *args, **kwargs: history.append(("update", args, kwargs)))

    result = collection_worker.run_cycle(hours=1, max_events=100, wait_seconds=1)

    assert result["status"] == "completed"
    assert result["job_id"] == 55
    assert result["run_id"]
    assert history[0][0] == "start"
    assert history[-1][2]["status"] == "completed"
    source = Path(collection_worker.__file__).read_text(encoding="utf-8")
    assert "session_advisory_lock" in source
    assert 'os.environ["ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER"] = "1"' in source
    assert 'os.environ["ADLOG_EXTERNAL_POST_COLLECTION_WORKER"] = "1"' in source
    assert "run_server(" not in source


def test_collection_worker_cli_is_safe_to_inspect_without_starting_collection() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/runtime/collection_worker.py", "--help"],
        text=True, capture_output=True, timeout=20, check=False,
    )
    assert result.returncode == 0
    assert "outside the web server" in result.stdout


def test_runtime_history_deduplicates_repeated_cycle_diagnostics() -> None:
    from server.sli.sources.runtime_collection_history import _unique_texts

    assert _unique_texts(["DC1: DNS denied", "DC2: DNS denied", "DC1: DNS denied"]) == [
        "DC1: DNS denied",
        "DC2: DNS denied",
    ]


def test_report_generation_refreshes_durable_and_worker_heartbeats(monkeypatch, tmp_path) -> None:
    from server.jobs import collector

    durable_heartbeats: list[dict] = []
    worker_heartbeats: list[dict] = []
    renewed = threading.Event()
    report = tmp_path / "report.html"
    report.write_text("ok", encoding="utf-8")
    monkeypatch.setattr(collector, "POST_COLLECTION_HEARTBEAT_SECONDS", 0.01)
    monkeypatch.setattr(
        collector,
        "heartbeat_post_collection_job",
        lambda durable_job_id, **kwargs: durable_heartbeats.append({
            "durable_job_id": durable_job_id,
            **kwargs,
        }),
    )

    def record_progress(progress):
        worker_heartbeats.append(progress)
        if len(worker_heartbeats) >= 2:
            renewed.set()

    def generate_report(*_args, **_kwargs):
        assert renewed.wait(timeout=5), "heartbeat must renew while the report is running"
        return report

    monkeypatch.setattr(collector, "generate_recommendation_report", generate_report)

    result = collector._generate_report_with_heartbeat(
        job_id=7,
        servers=["DC1"],
        durable_job_id="durable-7",
        worker_id="post-worker",
        progress_callback=record_progress,
    )

    assert result == report
    assert len(durable_heartbeats) >= 2
    assert worker_heartbeats[-1]["phase"] == "report_running"


def test_report_generation_survives_heartbeat_failure(monkeypatch, tmp_path) -> None:
    from server.jobs import collector

    report = tmp_path / "report.html"
    report.write_text("ok", encoding="utf-8")
    logged: list[str] = []
    progress: list[dict] = []
    monkeypatch.setattr(
        collector,
        "heartbeat_post_collection_job",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("lease unavailable")),
    )
    monkeypatch.setattr(
        collector,
        "log_internal_error",
        lambda _component, code, *_args, **_kwargs: logged.append(code) or "ERR-HB",
    )
    monkeypatch.setattr(
        collector,
        "generate_recommendation_report",
        lambda *_args, **_kwargs: report,
    )

    result = collector._generate_report_with_heartbeat(
        job_id=8,
        servers=["DC1"],
        durable_job_id="durable-8",
        worker_id="post-worker",
        progress_callback=progress.append,
    )

    assert result == report
    assert logged == ["post_collection_heartbeat_failed"]
    assert progress[-1]["phase"] == "report_running"


def test_partial_collection_log_matches_real_post_collection_queueing() -> None:
    from server.jobs.collector import _analysis_queue_log_status

    assert _analysis_queue_log_status("completed") == "queued"
    assert _analysis_queue_log_status("partial") == "queued"
    assert _analysis_queue_log_status("failed") == "not_queued"
