from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from typing import Any

from server.sli.core.app_config import load_config
from server.sli.semantic.findings_pg_pipeline import get_findings_refresh_status
from server.sli.storage.storage_policy import resolve_operational_retention


_LEGACY_DURABLE_JOB_PATTERN = "legacy-%"


class PostCollectionLeaseLost(RuntimeError):
    """The claimed attempt no longer owns a live durable lease.

    attempt_count is the fencing generation: worker names may be reused, but
    only an atomic claim may advance the generation or assign an owner.
    """


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _backend() -> str:
    return (load_config().db_backend or "postgres").strip().lower()


def _require_postgres() -> None:
    backend = _backend()
    if backend != "postgres":
        raise RuntimeError(f"PostgreSQL-only runtime rejected backend={backend!r}")


def ensure_post_collection_schema() -> dict[str, object]:
    """Verify the migrated schema; never execute DDL from runtime helpers."""
    _require_postgres()
    from server.sli.ops.postgres_schema_guard import require_table_columns

    return require_table_columns(
        "post_collection_jobs",
        (
            "id", "source_job_id", "durable_job_id", "status", "servers_json",
            "attempt_count", "max_attempts", "heartbeat_at", "worker_lease_until",
            "phase", "findings_status", "updated_at",
        ),
    )


def queue_post_collection_job(*, durable_job_id: str, source_job_id: int, servers: list[str]) -> dict[str, Any]:
    _require_postgres()
    ensure_post_collection_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into post_collection_jobs(
                    durable_job_id, source_job_id, status, phase, findings_status,
                    servers_json, queued_at, updated_at
                )
                values (%s, %s, 'queued', 'queued', 'queued', %s::jsonb, now(), now())
                on conflict (durable_job_id) do update
                set updated_at = post_collection_jobs.updated_at
                returning *
                """,
                (str(durable_job_id), int(source_job_id), json.dumps(servers, ensure_ascii=False)),
            )
            return dict(cur.fetchone())


def update_post_collection_job(
    durable_job_id: str,
    *,
    status: str,
    report_path: str | None = None,
    error_id: str | None = None,
    error_message: str | None = None,
    worker_id: str,
    claim_attempt: int,
    phase: str | None = None,
    lease_seconds: int | None = None,
) -> None:
    _require_postgres()
    ensure_post_collection_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    started = "started_at = coalesce(started_at, now())," if status == "running" else ""
    finished = "finished_at = now()," if status in {"completed", "failed"} else ""
    lease = max(60, int(lease_seconds or os.getenv("ADLOG_POST_COLLECTION_LEASE_SECONDS", "3600")))
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                update post_collection_jobs
                set status = %s,
                    {started}
                    {finished}
                    report_path = coalesce(%s, report_path),
                    error_id = %s,
                    error_message = %s,
                    phase = coalesce(%s, phase),
                    heartbeat_at = case when %s = 'running' then now() else heartbeat_at end,
                    worker_lease_until = case
                        when %s = 'running' then now() + (%s * interval '1 second')
                        when %s in ('completed','failed') then null
                        else worker_lease_until
                    end,
                    updated_at = now()
                where durable_job_id = %s and worker_id = %s and attempt_count = %s
                  and status = 'running' and worker_lease_until > now()
                """,
                (
                    status, report_path, error_id, error_message, phase,
                    status, status, lease, status, str(durable_job_id), worker_id, claim_attempt,
                ),
            )
            if cur.rowcount != 1:
                raise PostCollectionLeaseLost(str(durable_job_id))


def heartbeat_post_collection_job(
    durable_job_id: str,
    *,
    worker_id: str,
    claim_attempt: int,
    phase: str | None = None,
    lease_seconds: int | None = None,
) -> None:
    _require_postgres()
    ensure_post_collection_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    lease = max(60, int(lease_seconds or os.getenv("ADLOG_POST_COLLECTION_LEASE_SECONDS", "3600")))
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update post_collection_jobs
                set heartbeat_at=now(), phase=coalesce(%s, phase),
                    worker_lease_until=now() + (%s * interval '1 second'), updated_at=now()
                where durable_job_id = %s and worker_id = %s and attempt_count = %s
                  and status = 'running' and worker_lease_until > now()
                """,
                (phase, lease, str(durable_job_id), worker_id, claim_attempt),
            )
            if cur.rowcount != 1:
                raise PostCollectionLeaseLost(str(durable_job_id))


def update_post_collection_findings(
    durable_job_id: str,
    *,
    status: str,
    worker_id: str,
    claim_attempt: int,
    result: dict[str, Any] | None = None,
    error_id: str | None = None,
    error_message: str | None = None,
) -> None:
    _require_postgres()
    ensure_post_collection_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    payload = result or {}
    phase = {
        "queued": "findings_queued",
        "running": "findings_running",
        "completed": "report_queued",
        "failed": "report_queued",
    }.get(status)
    payload_json = json.dumps(payload, ensure_ascii=False, default=str)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update post_collection_jobs
                set findings_status=%s,
                    findings_started_at=case when %s='running' then coalesce(findings_started_at, now()) else findings_started_at end,
                    findings_finished_at=case when %s in ('completed','failed') then now() else findings_finished_at end,
                    findings_duration_ms=coalesce(%s, findings_duration_ms),
                    findings_scanned_events=coalesce(%s, findings_scanned_events),
                    findings_matched_events=coalesce(%s, findings_matched_events),
                    findings_created=coalesce(%s, findings_created),
                    findings_updated=coalesce(%s, findings_updated),
                    findings_evidence_added=coalesce(%s, findings_evidence_added),
                    findings_watermark_before=coalesce(%s, findings_watermark_before),
                    findings_watermark_after=coalesce(%s, findings_watermark_after),
                    findings_error_id=%s,
                    findings_error_message=%s,
                    findings_result_json=case when %s::jsonb = '{}'::jsonb then findings_result_json else %s::jsonb end,
                    phase=coalesce(%s, phase),
                    heartbeat_at=now(),
                    updated_at=now()
                where durable_job_id = %s and worker_id = %s and attempt_count = %s
                  and status = 'running' and worker_lease_until > now()
                """,
                (
                    status, status, status,
                    payload.get("duration_ms"), payload.get("scanned_events"), payload.get("matched_events"),
                    payload.get("created_findings"), payload.get("updated_findings"), payload.get("evidence_added"),
                    payload.get("watermark_before"), payload.get("watermark_after"),
                    error_id, error_message, payload_json, payload_json, phase, str(durable_job_id),
                    worker_id, claim_attempt,
                ),
            )
            if cur.rowcount != 1:
                raise PostCollectionLeaseLost(str(durable_job_id))


@contextmanager
def post_collection_lease_guard(
    durable_job_id: str, *, worker_id: str, claim_attempt: int,
):
    """Serialize one short artifact promotion against recovery and reclaims.

    Render/stage outside this context. It locks only this job row, so no
    filesystem lock is held while waiting for a heartbeat/recovery transaction.
    """
    _require_postgres()
    ensure_post_collection_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select worker_lease_until from post_collection_jobs
                where durable_job_id = %s and worker_id = %s and attempt_count = %s
                  and status = 'running'
                for update
                """,
                (str(durable_job_id), worker_id, claim_attempt),
            )
            row = cur.fetchone()
            if row is None:
                raise PostCollectionLeaseLost(str(durable_job_id))
            # Check database wall time after acquiring the lock, not transaction
            # start time: lock acquisition itself may have outlasted the lease.
            cur.execute(
                "select %s::timestamptz > clock_timestamp() as lease_live",
                (row["worker_lease_until"],),
            )
            if not cur.fetchone()["lease_live"]:
                raise PostCollectionLeaseLost(str(durable_job_id))
        yield


def get_post_collection_job(durable_job_id: str) -> dict[str, Any] | None:
    _require_postgres()
    ensure_post_collection_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select * from post_collection_jobs where durable_job_id = %s", (str(durable_job_id),))
            row = cur.fetchone()
            return dict(row) if row else None


def recover_stale_post_collection_jobs() -> dict[str, int]:
    """Requeue only durable, non-legacy jobs whose worker lease expired."""
    _require_postgres()
    ensure_post_collection_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update post_collection_jobs
                set status='queued', started_at=null, worker_id=null, worker_lease_until=null,
                    error_message='requeued_after_expired_worker_lease', updated_at=now()
                where status='running'
                  and durable_job_id not like %s
                  and attempt_count < max_attempts
                  and (worker_lease_until is null or worker_lease_until <= now())
                """,
                (_LEGACY_DURABLE_JOB_PATTERN,),
            )
            requeued = int(cur.rowcount or 0)
            cur.execute(
                """
                update post_collection_jobs
                set status='failed', phase='failed', finished_at=now(), worker_lease_until=null,
                    error_message=coalesce(error_message, 'post_collection_attempts_exhausted'), updated_at=now()
                where status in ('queued','running')
                  and durable_job_id not like %s
                  and attempt_count >= max_attempts
                  and (status = 'queued' or worker_lease_until is null or worker_lease_until <= now())
                """,
                (_LEGACY_DURABLE_JOB_PATTERN,),
            )
            exhausted = int(cur.rowcount or 0)
    return {"requeued": requeued, "exhausted": exhausted}


def claim_queued_post_collection_jobs(
    *,
    worker_id: str,
    limit: int = 1,
    lease_seconds: int | None = None,
) -> list[dict[str, Any]]:
    """Claim persisted jobs using SKIP LOCKED so only one worker owns a job."""
    _require_postgres()
    ensure_post_collection_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    lease = max(60, int(lease_seconds or os.getenv("ADLOG_POST_COLLECTION_LEASE_SECONDS", "3600")))
    requested = max(1, min(int(limit), 10))
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                with candidates as (
                    select id
                    from post_collection_jobs
                    where status='queued'
                      and durable_job_id not like %s
                      and attempt_count < max_attempts
                    order by queued_at, id
                    for update skip locked
                    limit %s
                )
                update post_collection_jobs p
                set status='running', started_at=coalesce(p.started_at, now()),
                    worker_id=%s, heartbeat_at=now(),
                    worker_lease_until=now() + (%s * interval '1 second'),
                    attempt_count=p.attempt_count + 1,
                    phase=case when p.phase='queued' then 'findings_queued' else p.phase end,
                    updated_at=now()
                from candidates c
                where p.id=c.id
                returning p.*
                """,
                (_LEGACY_DURABLE_JOB_PATTERN, requested, worker_id, lease),
            )
            return [dict(row) for row in cur.fetchall()]


def claim_post_collection_job(
    durable_job_id: str,
    *,
    worker_id: str,
    lease_seconds: int | None = None,
) -> dict[str, Any] | None:
    """Atomically claim one specific queued row, or return ``None`` if it is
    already claimed elsewhere (another owner won the race, or it is not
    ``queued`` any more).  Uses the same ``SKIP LOCKED`` contract as
    :func:`claim_queued_post_collection_jobs`, scoped to a single row so a
    caller that just inserted its own row cannot accidentally claim someone
    else's queued work instead.
    """
    _require_postgres()
    ensure_post_collection_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    lease = max(60, int(lease_seconds or os.getenv("ADLOG_POST_COLLECTION_LEASE_SECONDS", "3600")))
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                with candidate as (
                    select id
                    from post_collection_jobs
                    where durable_job_id = %s
                      and status = 'queued'
                      and attempt_count < max_attempts
                    for update skip locked
                    limit 1
                )
                update post_collection_jobs p
                set status='running', started_at=coalesce(p.started_at, now()),
                    worker_id=%s, heartbeat_at=now(),
                    worker_lease_until=now() + (%s * interval '1 second'),
                    attempt_count=p.attempt_count + 1,
                    phase=case when p.phase='queued' then 'findings_queued' else p.phase end,
                    updated_at=now()
                from candidate c
                where p.id=c.id
                returning p.*
                """,
                (str(durable_job_id), worker_id, lease),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def get_post_collection_overview(*, limit: int = 20) -> dict[str, Any]:
    _require_postgres()
    ensure_post_collection_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("select status, count(*) as count from post_collection_jobs group by status")
            summary = {row["status"]: int(row["count"] or 0) for row in cur.fetchall()}
            cur.execute("select * from post_collection_jobs order by id desc limit %s", (max(1, min(limit, 100)),))
            items = [dict(row) for row in cur.fetchall()]
    try:
        stale_minutes = max(1, int(os.getenv("ADLOG_POST_COLLECTION_STALE_MINUTES", "15")))
    except ValueError:
        stale_minutes = 15
    now = datetime.now(timezone.utc)
    stale_count = 0
    for item in items:
        marker = item.get("heartbeat_at") or item.get("updated_at") or item.get("started_at")
        age_minutes = None
        if marker:
            try:
                parsed = marker if isinstance(marker, datetime) else datetime.fromisoformat(str(marker).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                age_minutes = max(0, int((now - parsed.astimezone(timezone.utc)).total_seconds() // 60))
            except (TypeError, ValueError):
                age_minutes = None
        stale = item.get("status") == "running" and age_minutes is not None and age_minutes >= stale_minutes
        item["heartbeat_age_minutes"] = age_minutes
        item["stale_running"] = stale
        if stale:
            stale_count += 1
    summary["stale_running"] = stale_count
    return {
        "backend": "postgres",
        "status": "ok",
        "summary": summary,
        "items": items,
        "findings_refresh": get_findings_refresh_status(),
        "generated_at_utc": utc_now(),
        "stale_threshold_minutes": stale_minutes,
    }


def cleanup_post_collection_jobs() -> int:
    _require_postgres()
    ensure_post_collection_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    retention = resolve_operational_retention("post_collection_jobs")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "delete from post_collection_jobs where status in ('completed','failed') and finished_at < now() - (%s * interval '1 day')",
                (max(1, retention.days),),
            )
            return int(cur.rowcount or 0)
