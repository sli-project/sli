"""Durable history for cycles owned by the independent collection worker."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from server.sli.core.app_config import load_config


def _unique_texts(values: list[Any] | None) -> list[str]:
    """Keep first-seen diagnostic order without repeating identical messages."""
    return list(dict.fromkeys(str(value) for value in (values or []) if str(value)))


def _backend() -> str:
    return (load_config().db_backend or "postgres").strip().lower()


def _require_postgres() -> None:
    backend = _backend()
    if backend != "postgres":
        raise RuntimeError(f"PostgreSQL-only runtime rejected backend={backend!r}")


def ensure_runtime_collection_history_schema() -> dict[str, object]:
    """Verify, but never create, the runtime history table from a live worker."""
    _require_postgres()
    from server.sli.ops.postgres_schema_guard import require_table_columns

    return require_table_columns(
        "runtime_collection_runs",
        (
            "run_id", "worker_id", "job_id", "status", "phase", "servers_json",
            "hours", "max_events_per_channel", "created_at", "started_at", "finished_at",
            "duration_ms", "errors_json", "updated_at",
        ),
        minimum_schema_version=13,
    )


def start_runtime_collection_run(
    *, run_id: str, worker_id: str, hours: int, max_events_per_channel: int
) -> None:
    _require_postgres()
    ensure_runtime_collection_history_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into runtime_collection_runs(
                    run_id, worker_id, status, phase, servers_json,
                    hours, max_events_per_channel, created_at, started_at, updated_at
                ) values (%s, %s, 'running', 'starting', '[]'::jsonb, %s, %s, now(), now(), now())
                """,
                (str(run_id), str(worker_id), int(hours), int(max_events_per_channel)),
            )


def update_runtime_collection_run(
    run_id: str,
    *,
    status: str,
    phase: str,
    job_id: int | None = None,
    servers: list[str] | None = None,
    duration_ms: int | None = None,
    errors: list[str] | None = None,
) -> None:
    _require_postgres()
    ensure_runtime_collection_history_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    terminal = str(status) in {"completed", "partial", "failed", "skipped", "blocked"}
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update runtime_collection_runs
                set status=%s, phase=%s, job_id=coalesce(%s, job_id),
                    servers_json=coalesce(%s::jsonb, servers_json),
                    duration_ms=coalesce(%s, duration_ms),
                    errors_json=coalesce(%s::jsonb, errors_json),
                    finished_at=case when %s then now() else finished_at end,
                    updated_at=now()
                where run_id=%s
                """,
                (
                    str(status), str(phase), job_id,
                    json.dumps(servers, ensure_ascii=False) if servers is not None else None,
                    duration_ms,
                    json.dumps(_unique_texts(errors), ensure_ascii=False) if errors is not None else None,
                    terminal, str(run_id),
                ),
            )


def recent_runtime_collection_runs(*, limit: int = 20) -> list[dict[str, Any]]:
    _require_postgres()
    ensure_runtime_collection_history_schema()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select * from runtime_collection_runs order by created_at desc limit %s",
                (max(1, min(int(limit), 100)),),
            )
            rows = [dict(row) for row in cur.fetchall()]
    for row in rows:
        row["errors_json"] = _unique_texts(row.get("errors_json"))
    return rows


def recent_collector_channel_cycles(*, limit: int = 20) -> list[dict[str, Any]]:
    """Return durable passes produced by the collector serving this app."""
    _require_postgres()
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select
                    concat('collector-job-', coalesce(job_id::text, 'unknown'), '-', server, '-',
                           extract(epoch from created_at)::bigint) as run_id,
                    concat('collector-', server) as worker_id,
                    job_id, server,
                    min(started_utc::timestamptz) as started_at,
                    max(finished_utc::timestamptz) as finished_at,
                    greatest(0, (extract(epoch from (
                        max(finished_utc::timestamptz) - min(started_utc::timestamptz)
                    )) * 1000)::bigint) as duration_ms,
                    case
                        when bool_and(status in ('failed', 'timeout', 'error')) then 'failed'
                        when bool_or(status in ('failed', 'timeout', 'error', 'partial', 'partial_timeout')) then 'partial'
                        else 'completed'
                    end as status,
                    array_agg(channel order by channel) as channels_json,
                    sum(coalesce(inserted, 0)) as inserted,
                    sum(coalesce(skipped, 0)) as skipped,
                    max(limit_used) as max_events_per_channel,
                    array_remove(array_agg(nullif(error, '')), null) as errors_json,
                    created_at
                from collector_channel_runs
                where created_at >= now() - interval '24 hours'
                group by job_id, server, created_at
                order by max(finished_utc::timestamptz) desc nulls last
                limit %s
                """,
                (max(1, min(int(limit), 100)),),
            )
            rows = [dict(row) for row in cur.fetchall()]

    for row in rows:
        channels = [str(value) for value in (row.pop("channels_json", None) or [])]
        row["servers_json"] = [str(row.pop("server"))]
        row["phase"] = channels[0] if len(channels) == 1 else f"{len(channels)} каналов"
        row["errors_json"] = [str(value) for value in (row.get("errors_json") or [])]
        row["inserted"] = int(row.get("inserted") or 0)
        row["skipped"] = int(row.get("skipped") or 0)
        for key in ("created_at", "started_at", "finished_at"):
            value = row.get(key)
            if isinstance(value, datetime):
                row[key] = value.isoformat()
    return rows
