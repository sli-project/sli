"""Split out of ``server.jobs.collector`` (plan 7.2b).

Module-level names of ``collector`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.jobs.collector as _src


def _run_post_collection_job(
    job_id: int,
    servers: list[str],
    trace_id: str,
    durable_job_id: str | None = None,
    worker_id: str | None = None,
    claim_attempt: int | None = None,
    progress_callback: _src.Callable[[dict[str, object]], None] | None = None,
    authorization: _src.CutoverAuthorization | None = None,
) -> None:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    if durable_job_id is None:
        with _src._lock:
            existing = _src._jobs.get(job_id)
            durable_job_id = existing.durable_id if existing else f"runtime-{job_id}"
    started_ms = _src.monotonic_ms()
    worker_id = worker_id or _src.threading.current_thread().name
    findings_result: dict | None = None
    findings_error_id: str | None = None
    try:
        _src.update_post_collection_job(
            durable_job_id, status="running", worker_id=worker_id, claim_attempt=claim_attempt, phase="findings_queued"
        )
        with _src._lock:
            job = _src._jobs.get(job_id)
            if job:
                job.phase = "findings_running"
                job.analysis_status = "running"
                job.findings_status = "running"
                job.report_status = "queued"
                job.analysis_started_at = _src.utc_now()
                job.updated_at = _src.utc_now()
                job.message = "Сбор завершен; выполняется инкрементальное обновление Findings."
        _src.update_post_collection_findings(durable_job_id, status="running", worker_id=worker_id, claim_attempt=claim_attempt)
        _src._heartbeat_post_collection_safely(
            durable_job_id=durable_job_id,
            worker_id=worker_id,
            claim_attempt=claim_attempt,
            phase="findings_running",
            job_id=job_id,
        )
        findings_started_ms = _src.monotonic_ms()
        try:
            findings_result = (
                (
                    _src.refresh_findings_from_events()
                    if authorization is None
                    else _src.refresh_findings_from_events(authorization=authorization)
                )
                if _src.legacy_findings_enabled()
                else {
                    "status": "skipped",
                    "reason": "legacy_event_id_verdict_producer_disabled",
                    "verdict_owner": "semantic_scenarios",
                    "created_findings": 0,
                    "updated_findings": 0,
                    "evidence_added": 0,
                }
            )
            _src.update_post_collection_findings(
                durable_job_id, status="completed", result=findings_result,
                worker_id=worker_id, claim_attempt=claim_attempt
            )
            _src.log_performance_stage(
                "findings_refresh",
                trace_id=trace_id, job_id=job_id, started_ms=findings_started_ms,
                status="completed",
                scanned_events=findings_result.get("scanned_events"),
                matched_events=findings_result.get("matched_events"),
                created_findings=findings_result.get("created_findings"),
                updated_findings=findings_result.get("updated_findings"),
                watermark_before=findings_result.get("watermark_before"),
                watermark_after=findings_result.get("watermark_after"),
            )
            _src.log_event(
                "collector", "findings_refresh_completed",
                "Incremental Findings refresh completed.",
                job_id=job_id, trace_id=trace_id, durable_job_id=durable_job_id,
                **{key: findings_result.get(key) for key in (
                    "scanned_events", "matched_events", "created_findings",
                    "updated_findings", "evidence_added", "watermark_before",
                    "watermark_after", "has_more"
                )},
            )
        except _src.PostCollectionLeaseLost:
            raise
        except Exception as findings_exc:
            findings_error_id = _src.log_internal_error(
                "collector", "findings_refresh_failed",
                "Findings refresh failed; report generation and collection result remain isolated.",
                exc=findings_exc, job_id=job_id, trace_id=trace_id,
                durable_job_id=durable_job_id,
            )
            try:
                _src.update_post_collection_findings(
                    durable_job_id, status="failed",
                    worker_id=worker_id, claim_attempt=claim_attempt,
                    error_id=findings_error_id, error_message=str(findings_exc),
                )
            except _src.PostCollectionLeaseLost:
                raise
            except Exception:
                pass
            _src.log_performance_stage(
                "findings_refresh", trace_id=trace_id, job_id=job_id,
                started_ms=findings_started_ms, status="failed",
                internal_error_id=findings_error_id,
            )

        with _src._lock:
            job = _src._jobs.get(job_id)
            if job:
                job.phase = "report_running"
                job.findings_status = "failed" if findings_error_id else "completed"
                job.findings_result = findings_result
                job.findings_error_id = findings_error_id
                job.report_status = "running"
                job.updated_at = _src.utc_now()
                job.message = (
                    "Сбор завершен; Findings обновлены, формируется отчет."
                    if not findings_error_id
                    else f"Сбор завершен; Findings временно недоступны "
                         f"(internal_error_id={findings_error_id}), формируется отчет по сохраненным данным."
                )
        _src.update_post_collection_job(
            durable_job_id, status="running", worker_id=worker_id, claim_attempt=claim_attempt, phase="report_running"
        )
        _src._heartbeat_post_collection_safely(
            durable_job_id=durable_job_id,
            worker_id=worker_id,
            claim_attempt=claim_attempt,
            phase="report_running",
            job_id=job_id,
        )
        _src.log_event(
            "collector", "post_collection_started",
            "Post-collection report generation started.",
            job_id=job_id, trace_id=trace_id, worker_id=worker_id,
            durable_job_id=durable_job_id,
        )
        report = _src._generate_report_with_heartbeat(
            job_id=job_id,
            servers=servers,
            durable_job_id=durable_job_id,
            worker_id=worker_id,
            claim_attempt=claim_attempt,
            progress_callback=progress_callback,
            authorization=authorization,
        )
        report_url = f"/reports/{report.name}"
        _src.update_post_collection_job(
            durable_job_id, status="completed", report_path=str(report),
            worker_id=worker_id, claim_attempt=claim_attempt, phase="completed"
        )
        try:
            from server.sli.storage.storage_lifecycle import record_storage_snapshot

            storage_snapshot = record_storage_snapshot(
                source="post_collection", source_job_id=job_id,
                source_run_id=durable_job_id
            )
            _src.log_event(
                "storage", "storage_snapshot_recorded",
                "Bounded storage lifecycle snapshot evaluated after post-collection.",
                job_id=job_id, trace_id=trace_id, durable_job_id=durable_job_id,
                snapshot_status=storage_snapshot.get("status"),
                snapshot_reason=storage_snapshot.get("reason"),
            )
        except Exception as storage_exc:
            storage_error_id = _src.log_internal_error(
                "storage", "storage_snapshot_failed",
                "Storage lifecycle snapshot failed without changing collection or report result.",
                exc=storage_exc, job_id=job_id, trace_id=trace_id,
                durable_job_id=durable_job_id,
            )
            _src.log_event(
                "storage", "storage_snapshot_isolated",
                "Storage snapshot failure was isolated from post-collection result.",
                job_id=job_id, trace_id=trace_id, durable_job_id=durable_job_id,
                internal_error_id=storage_error_id,
            )
        with _src._lock:
            job = _src._jobs.get(job_id)
            if job:
                job.phase = "done"
                job.analysis_status = "completed_with_findings_warning" if findings_error_id else "completed"
                job.report_status = "completed"
                job.analysis_finished_at = _src.utc_now()
                job.analysis_report_url = report_url
                job.updated_at = _src.utc_now()
                job.message = (
                    "Сбор завершен; Findings и отчет готовы."
                    if not findings_error_id
                    else f"Сбор и отчет завершены; Findings refresh завершился ошибкой "
                         f"(internal_error_id={findings_error_id})."
                )
        _src.log_performance_stage(
            "analysis_report_generation", trace_id=trace_id, job_id=job_id,
            started_ms=started_ms, status="completed"
        )
        _src.log_event(
            "collector", "post_collection_completed",
            "Post-collection processing completed.",
            job_id=job_id, trace_id=trace_id, durable_job_id=durable_job_id,
            report_url=report_url,
            findings_status="failed" if findings_error_id else "completed",
            findings_error_id=findings_error_id,
        )
    except _src.PostCollectionLeaseLost:
        # Do not publish failure over the newer owner or start another phase.
        with _src._lock:
            job = _src._jobs.get(job_id)
            if job:
                job.analysis_status = "lease_lost"
                job.updated_at = _src.utc_now()
        _src.log_event(
            "collector", "post_collection_lease_lost",
            "Post-collection attempt stopped after losing its lease.",
            job_id=job_id, durable_job_id=durable_job_id,
        )
    except Exception as exc:
        error_id = _src.log_internal_error(
            "collector", "post_collection_failed",
            "Post-collection report generation failed without changing collection result.",
            exc=exc, job_id=job_id, trace_id=trace_id, durable_job_id=durable_job_id
        )
        try:
            _src.update_post_collection_job(
                durable_job_id, status="failed", error_id=error_id,
                error_message=str(exc), worker_id=worker_id, claim_attempt=claim_attempt, phase="failed"
            )
        except Exception:
            pass
        with _src._lock:
            job = _src._jobs.get(job_id)
            if job:
                job.phase = "done"
                job.analysis_status = "failed"
                job.report_status = "failed"
                if job.findings_status in {"queued", "running"}:
                    job.findings_status = "failed"
                job.findings_result = findings_result
                job.findings_error_id = findings_error_id or (error_id if job.findings_status == "failed" else None)
                job.analysis_error_id = error_id
                job.analysis_finished_at = _src.utc_now()
                job.updated_at = _src.utc_now()
                job.message = (
                    f"Сбор завершен; формирование отчета завершилось ошибкой "
                    f"(internal_error_id={error_id})."
                )
        _src.log_performance_stage(
            "analysis_report_generation", trace_id=trace_id, job_id=job_id,
            started_ms=started_ms, status="failed", internal_error_id=error_id
        )
    finally:
        with _src._post_collection_guard:
            _src._post_collection_active.discard(durable_job_id)


def _enqueue_post_collection(job_id: int, servers: list[str], trace_id: str) -> None:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    with _src._lock:
        job = _src._jobs.get(job_id)
        durable_job_id = job.durable_id if job else f"runtime-{job_id}"
    external_worker = _src.external_post_collection_worker_enabled()
    run_inprocess = (not external_worker) and _src.inprocess_post_collection_opt_in_enabled()
    if run_inprocess:
        with _src._post_collection_guard:
            if durable_job_id in _src._post_collection_active:
                return
            _src._post_collection_active.add(durable_job_id)
    try:
        _src.queue_post_collection_job(
            durable_job_id=durable_job_id,
            source_job_id=job_id,
            servers=servers,
        )
        if external_worker:
            _src.log_event(
                "collector", "post_collection_queued_for_external_worker",
                "Post-collection work queued for the independent worker.",
                job_id=job_id, trace_id=trace_id, durable_job_id=durable_job_id,
            )
            return
        if not run_inprocess:
            _src.log_event(
                "collector", "post_collection_inprocess_not_opted_in",
                "Post-collection queued; in-process executor is not opted in, leaving the row for the durable worker.",
                job_id=job_id, trace_id=trace_id, durable_job_id=durable_job_id,
            )
            return
        worker_id = f"inprocess-{_src.uuid.uuid4().hex[:12]}"
        claimed = _src.claim_post_collection_job(durable_job_id, worker_id=worker_id)
        if claimed is None:
            # Another owner (typically the durable worker) already claimed this
            # row through the same atomic claim; standing down here is what
            # makes the two paths structurally unable to double-process a job.
            with _src._post_collection_guard:
                _src._post_collection_active.discard(durable_job_id)
            _src.log_event(
                "collector", "post_collection_claimed_elsewhere",
                "Post-collection row already claimed by another owner; in-process executor stands down.",
                job_id=job_id, trace_id=trace_id, durable_job_id=durable_job_id,
            )
            return
        _src._post_collection_executor.submit(
            _src._run_post_collection_job, job_id, list(servers), trace_id, durable_job_id, worker_id,
            claimed["attempt_count"]
        )
    except Exception as exc:
        with _src._post_collection_guard:
            _src._post_collection_active.discard(durable_job_id)
        error_id = _src.log_internal_error(
            "collector", "post_collection_queue_failed",
            "Collection completed, but post-collection persistence/queueing failed.",
            exc=exc, job_id=job_id, trace_id=trace_id, durable_job_id=durable_job_id,
        )
        with _src._lock:
            current = _src._jobs.get(job_id)
            if current:
                current.analysis_status = "failed"
                current.report_status = "failed"
                current.analysis_error_id = error_id
                current.phase = "done"
                current.updated_at = _src.utc_now()
                current.message = (
                    "Сбор завершен; post-collection задача не поставлена в очередь "
                    f"(internal_error_id={error_id})."
                )


def run_persisted_post_collection_worker_once(
    *,
    worker_id: str,
    limit: int = 1,
    progress_callback: _src.Callable[[dict[str, object]], None] | None = None,
    authorization: _src.CutoverAuthorization | None = None,
) -> dict[str, int]:
    """Claim and execute durable post-collection work in this process.

    It is intentionally synchronous: the caller is already a dedicated worker
    process, so there is no benefit in spawning another local executor.  The
    PostgreSQL lease is the ownership boundary across processes.
    """
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    claimed = _src.claim_queued_post_collection_jobs(worker_id=worker_id, limit=limit)
    completed = 0
    failed = 0
    for row in claimed:
        durable_job_id = str(row.get("durable_job_id") or "")
        if not durable_job_id or durable_job_id.startswith("legacy-"):
            continue
        raw_servers = row.get("servers_json") or []
        if isinstance(raw_servers, str):
            try:
                raw_servers = _src.json.loads(raw_servers)
            except _src.json.JSONDecodeError:
                raw_servers = []
        servers = [str(item) for item in (raw_servers or []) if str(item)]
        local_id = next(_src._counter)
        now = _src.utc_now()
        with _src._lock:
            _src._jobs[local_id] = _src.Job(
                id=local_id,
                durable_id=durable_job_id,
                kind="post_collection_worker",
                status="completed",
                servers=servers,
                hours=0,
                max_events_per_channel=0,
                created_at=now,
                updated_at=now,
                message="Задача принята независимым worker.",
                phase=str(row.get("phase") or "findings_queued"),
                collection_status="completed",
                analysis_status="running",
                report_status="queued",
                trace_id=f"worker-{durable_job_id}",
            )
        _src._run_post_collection_job(
            local_id, servers, f"worker-{durable_job_id}", durable_job_id,
            worker_id=worker_id,
            claim_attempt=row["attempt_count"],
            progress_callback=progress_callback,
            authorization=authorization,
        )
        result = _src.get_job(local_id) or {}
        if result.get("analysis_status") in {"failed", "lease_lost"}:
            failed += 1
        else:
            completed += 1
    return {"claimed": len(claimed), "completed": completed, "failed": failed}


def resume_persisted_post_collection_jobs(
    *,
    limit: int = 1,
    authorization: _src.CutoverAuthorization | None = None,
) -> dict[str, int]:
    """Claim and resume only durable jobs created by the new runtime contract.

    Rows migrated from the old process-local identity are marked ``legacy-*`` and
    are intentionally never executed automatically.
    """
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    worker_id = f"startup-resume-{_src.uuid.uuid4().hex[:12]}"
    claimed = _src.claim_queued_post_collection_jobs(worker_id=worker_id, limit=limit)
    resumed = 0
    for row in claimed:
        durable_job_id = str(row.get("durable_job_id") or "")
        if not durable_job_id or durable_job_id.startswith("legacy-"):
            continue
        raw_servers = row.get("servers_json") or []
        if isinstance(raw_servers, str):
            try:
                raw_servers = _src.json.loads(raw_servers)
            except _src.json.JSONDecodeError:
                raw_servers = []
        servers = [str(item) for item in (raw_servers or []) if str(item)]
        local_id = next(_src._counter)
        now = _src.utc_now()
        with _src._lock:
            _src._jobs[local_id] = _src.Job(
                id=local_id,
                durable_id=durable_job_id,
                kind="post_collection_resume",
                status="completed",
                servers=servers,
                hours=0,
                max_events_per_channel=0,
                created_at=now,
                updated_at=now,
                message="Возобновляется сохраненная post-collection задача.",
                phase=str(row.get("phase") or "findings_queued"),
                collection_status="completed",
                analysis_status="running",
                report_status="queued",
                trace_id=f"resume-{durable_job_id}",
            )
        with _src._post_collection_guard:
            if durable_job_id in _src._post_collection_active:
                continue
            _src._post_collection_active.add(durable_job_id)
        _src._post_collection_executor.submit(
            _src._run_post_collection_job,
            local_id,
            servers,
            f"resume-{durable_job_id}",
            durable_job_id,
            worker_id=worker_id,
            claim_attempt=row["attempt_count"],
            authorization=authorization,
        )
        resumed += 1
    return {"claimed": len(claimed), "resumed": resumed}


def _heartbeat_post_collection_safely(
    *,
    durable_job_id: str,
    worker_id: str,
    claim_attempt: int | None = None,
    phase: str,
    job_id: int,
) -> bool:
    try:
        _src.heartbeat_post_collection_job(
            durable_job_id, worker_id=worker_id, claim_attempt=claim_attempt, phase=phase
        )
        return True
    except _src.PostCollectionLeaseLost:
        raise
    except Exception as exc:
        _src.log_internal_error(
            "collector",
            "post_collection_heartbeat_failed",
            "Post-collection heartbeat failed without stopping post-processing.",
            exc=exc,
            job_id=job_id,
            durable_job_id=durable_job_id,
            phase=phase,
        )
        return False
