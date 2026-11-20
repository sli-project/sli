"""Split out of ``server.jobs.collector`` (plan 7.2b).

Module-level names of ``collector`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

import server.jobs.collector as _src


def _generate_report_with_heartbeat(
    *,
    job_id: int,
    servers: list[str],
    durable_job_id: str,
    worker_id: str,
    claim_attempt: int | None = None,
    progress_callback: _src.Callable[[dict[str, object]], None] | None = None,
    authorization: _src.CutoverAuthorization | None = None,
) -> _src.Path:
    """Keep the durable lease and worker status fresh during a long report."""
    stopped = _src.threading.Event()
    lease_lost = _src.threading.Event()

    def emit_progress() -> None:
        _src._heartbeat_post_collection_safely(
            durable_job_id=durable_job_id,
            worker_id=worker_id,
            claim_attempt=claim_attempt,
            phase="report_running",
            job_id=job_id,
        )
        if progress_callback is None:
            return
        try:
            progress_callback({
                "durable_job_id": durable_job_id,
                "job_id": job_id,
                "phase": "report_running",
            })
        except Exception as exc:
            _src.log_internal_error(
                "collector",
                "post_collection_progress_callback_failed",
                "Post-collection progress callback failed without stopping report generation.",
                exc=exc,
                job_id=job_id,
                durable_job_id=durable_job_id,
            )

    def publish_report(path: Path, content: str) -> None:
        # Staging is private and complete before waiting for the ownership lock.
        temporary = None
        try:
            with NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=path.parent,
                prefix=f".{path.name}.", suffix=".tmp", delete=False,
            ) as stream:
                temporary = Path(stream.name)
                stream.write(content)
            with _src.post_collection_lease_guard(
                durable_job_id, worker_id=worker_id, claim_attempt=claim_attempt,
            ):
                temporary.replace(path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def pulse() -> None:
        while not stopped.wait(_src.POST_COLLECTION_HEARTBEAT_SECONDS):
            try:
                emit_progress()
            except _src.PostCollectionLeaseLost:
                lease_lost.set()
                return

    emit_progress()
    heartbeat_thread = _src.threading.Thread(
        target=pulse,
        daemon=True,
        name=f"post-collection-heartbeat-{job_id}",
    )
    heartbeat_thread.start()
    try:
        report = _src.generate_recommendation_report(
            job_id,
            servers,
            authorization=authorization,
            report_writer=publish_report,
        )
        if lease_lost.is_set():
            raise _src.PostCollectionLeaseLost(durable_job_id)
        return report
    finally:
        stopped.set()
        heartbeat_thread.join(timeout=1.0)


def create_analysis_job(
    *,
    servers: list[str] | None = None,
    reason: str = "manual",
    authorization: _src.CutoverAuthorization | None = None,
) -> dict:
    if not servers:
        servers = _src.discover_domain_controllers()
    now = _src.utc_now()
    with _src._lock:
        job = _src.Job(
            id=next(_src._counter),
            kind=f"analyze_existing_events:{reason}",
            status="queued",
            servers=servers,
            hours=0,
            max_events_per_channel=0,
            created_at=now,
            updated_at=now,
            message="Задача анализа прошлых событий поставлена в очередь.",
        )
        _src._jobs[job.id] = job
    _src.log_event("jobs", "job_created", "Analysis job created.", job_id=job.id, status=job.status)

    thread = _src.threading.Thread(
        target=_src._run_analysis_job,
        args=(job.id, authorization),
        daemon=True,
    )
    thread.start()
    return _src.asdict(job)


def _run_analysis_job(
    job_id: int,
    authorization: _src.CutoverAuthorization | None = None,
) -> None:
    started = _src.time.monotonic()
    try:
        _src._update_job(job_id, status="running", message="Выполняется анализ уже собранных событий.")
        _src.log_event("jobs", "analysis_started", "Analysis job started.", job_id=job_id, status="running")
        with _src._lock:
            job = _src._jobs[job_id]
            servers = list(job.servers)
        analysis_report = _src.generate_recommendation_report(
            job_id,
            servers,
            authorization=authorization,
        )
        duration_ms = int((_src.time.monotonic() - started) * 1000)
        with _src._lock:
            job = _src._jobs[job_id]
            job.status = "completed"
            job.updated_at = _src.utc_now()
            job.message = "Анализ прошлых событий завершен."
            job.analysis_report_url = f"/reports/{analysis_report.name}"
            job.duration_ms = duration_ms
        _src.log_event("jobs", "analysis_completed", "Analysis job completed.", job_id=job_id, status="completed", duration_ms=duration_ms)
    except Exception as exc:
        error_id = _src.log_internal_error("jobs", "analysis_failed", "Analysis job failed.", exc=exc, job_id=job_id)
        _src._fail_job(job_id, f"{exc} (internal_error_id={error_id})")
