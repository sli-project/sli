"""Payload-free PostgreSQL heartbeats for independently owned runtime loops."""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.ops.runtime_component_registry import Component, list_components
from server.sli.sources.plugin_runtime_heartbeat import read_plugin_heartbeat

# The registry owns Operations visibility. Retired/manual rollback entrypoints
# remain known to the guard without appearing as disabled production workers.
WORKER_SPECS: tuple[tuple[str, str], ...] = tuple(
    (component.name, component.label) for component in list_components()
    if component.visible_in_operations
)
_COMPONENTS_BY_NAME: dict[str, Component] = {
    component.name: component for component in list_components()
}


def _freshness_bound(expected_interval_seconds: int) -> int:
    return max(60, expected_interval_seconds * 2 + 30)


def _detail_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        return None
    return stamp.astimezone(timezone.utc)


def _storage_lifecycle_additions(
    *,
    details: object,
    fresh: bool,
    expected_interval_seconds: int,
    generated: datetime,
) -> dict[str, Any]:
    evidence = details if isinstance(details, dict) else {}
    completed_at = _detail_timestamp(evidence.get("last_cycle_completed_at"))
    result_age_seconds = (
        max(0, int((generated - completed_at).total_seconds()))
        if completed_at is not None else None
    )
    result_is_stale = (
        result_age_seconds > _freshness_bound(expected_interval_seconds)
        if result_age_seconds is not None else None
    )
    last_cycle_status = str(evidence.get("last_cycle_status") or "unknown")
    lifecycle_phase = str(evidence.get("lifecycle_phase") or "")
    watermark_updated_at = _detail_timestamp(evidence.get("watermark_updated_at"))
    last_successful_watermark = evidence.get("last_successful_watermark")
    last_result_digest = evidence.get("last_result_digest")
    has_valid_completed_result = (
        last_cycle_status == "success"
        and evidence.get("last_result_phase") == "completed"
        and isinstance(last_result_digest, str)
        and len(last_result_digest) == 64
        and all(character in "0123456789abcdefABCDEF" for character in last_result_digest)
        and isinstance(last_successful_watermark, str)
        and bool(last_successful_watermark)
    )
    has_valid_not_due_evidence = (
        fresh and lifecycle_phase == "not_due" and has_valid_completed_result
    )
    has_fresh_completed_evidence = (
        has_valid_completed_result
        and watermark_updated_at is not None
        and (generated - watermark_updated_at).total_seconds()
        <= _freshness_bound(expected_interval_seconds)
    )
    progress_is_stalled = (
        fresh
        and lifecycle_phase != "not_due"
        and isinstance(last_successful_watermark, str)
        and bool(last_successful_watermark)
        and watermark_updated_at is not None
        and (generated - watermark_updated_at).total_seconds()
        > _freshness_bound(expected_interval_seconds)
    )
    if last_cycle_status == "success":
        # A nominal success is not healthy without a parseable, fresh result time.
        service_outcome = "ok" if (
            has_valid_not_due_evidence
            or has_fresh_completed_evidence
            or result_is_stale is False
        ) else "degraded"
    elif last_cycle_status in {"failed", "partial", "blocked"}:
        service_outcome = "degraded"
    else:
        service_outcome = "unknown"
    if result_is_stale is True or progress_is_stalled:
        service_outcome = "degraded"
    if last_cycle_status == "failed":
        lifecycle_progress_status = "failed"
    elif progress_is_stalled:
        lifecycle_progress_status = "stalled"
    elif lifecycle_phase == "not_due":
        lifecycle_progress_status = "not_due"
    elif last_cycle_status == "success":
        lifecycle_progress_status = "completed"
    else:
        lifecycle_progress_status = "unknown"
    return {
        # A fresh failed cycle is a degraded service, not a dead process.
        "process_status": "up" if fresh else "stale",
        "service_outcome": service_outcome,
        "result_age_seconds": result_age_seconds,
        "result_is_stale": result_is_stale,
        "progress_is_stalled": progress_is_stalled,
        "lifecycle_progress_status": lifecycle_progress_status,
    }


def record_worker_heartbeat(
    *,
    worker_name: str,
    worker_id: str,
    status: str,
    phase: str | None,
    expected_interval_seconds: int,
    started_at: datetime,
    details: dict[str, Any] | None = None,
    connection_factory: Callable[[], Any] = connect,
) -> dict[str, Any]:
    """Upsert one bounded heartbeat; observability failure never stops work."""
    try:
        with connection_factory() as conn, conn.cursor() as cur:
            cur.execute(
                """
                insert into runtime_worker_heartbeats(
                    worker_name,worker_id,process_pid,status,phase,
                    expected_interval_seconds,details_json,started_at,heartbeat_at,updated_at
                ) values (%s,%s,%s,%s,%s,%s,%s::jsonb,%s,now(),now())
                on conflict(worker_name) do update set
                    worker_id=excluded.worker_id,
                    process_pid=excluded.process_pid,
                    status=excluded.status,
                    phase=excluded.phase,
                    expected_interval_seconds=excluded.expected_interval_seconds,
                    details_json=excluded.details_json,
                    started_at=case
                        when runtime_worker_heartbeats.worker_id=excluded.worker_id
                        then runtime_worker_heartbeats.started_at
                        else excluded.started_at
                    end,
                    heartbeat_at=now(),updated_at=now()
                """,
                (
                    worker_name, worker_id, os.getpid(), status, phase,
                    max(1, min(int(expected_interval_seconds), 86400)),
                    json.dumps(details or {}, ensure_ascii=False, default=str),
                    started_at.astimezone(timezone.utc),
                ),
            )
        return {"status": "ok"}
    except Exception as exc:  # noqa: BLE001 -- Observability must never stop a worker.
        return {"status": "unavailable", "error_type": type(exc).__name__}


def get_semantic_queue_overview(
    *,
    connection_factory: Callable[[], Any] = connect,
) -> dict[str, Any]:
    """Return bounded, read-only queue metrics without event or job payloads."""
    try:
        with connection_factory() as conn, conn.cursor() as cur:
            cur.execute("set transaction read only")
            cur.execute("set local statement_timeout = '3000ms'")
            cur.execute("set local lock_timeout = '1000ms'")
            cur.execute(
                """
                select 'processing' as queue_name,status as queue_status,
                       count(*) as depth,
                       coalesce(sum(greatest(attempt_count-1,0)),0) as retries,
                       count(*) filter (
                           where status='leased' and lease_until<now()
                       ) as expired_leases,
                       coalesce(max(extract(epoch from (now()-created_at)))
                           filter (where status in ('queued','failed')),0)
                           ::bigint as oldest_ready_age_seconds,
                       greatest(0, coalesce(max(extract(epoch from (now()-created_at)))
                           filter (where status in ('queued','failed','leased')),0))
                           ::bigint as oldest_pending_age_seconds,
                       count(*) filter (where status='completed'
                           and completed_at>=now()-interval '1 hour'
                           and completed_at<=now()) as completed_last_hour
                from semantic_processing_outbox
                group by status
                union all
                select 'dispatch',dispatch_status,count(*),
                       coalesce(sum(greatest(attempt_count-1,0)),0),
                       count(*) filter (
                           where dispatch_status='leased' and lease_until<now()
                       ),
                       coalesce(max(extract(epoch from (now()-created_at)))
                           filter (where dispatch_status in ('queued','failed')),0)
                           ::bigint,
                       greatest(0, coalesce(max(extract(epoch from (now()-created_at)))
                           filter (where dispatch_status in ('queued','failed','leased')),0))::bigint,
                       count(*) filter (where dispatch_status='completed'
                           and completed_at>=now()-interval '1 hour'
                           and completed_at<=now())
                from semantic_correlation_dispatch_jobs
                group by dispatch_status
                union all
                select 'risk',evaluation_status,count(*),
                       coalesce(sum(greatest(attempt_count-1,0)),0),
                       count(*) filter (
                           where evaluation_status='leased' and lease_until<now()
                       ),
                       coalesce(max(extract(epoch from (now()-created_at)))
                           filter (where evaluation_status in ('queued','failed')),0)
                           ::bigint,
                       greatest(0, coalesce(max(extract(epoch from (now()-created_at)))
                           filter (where evaluation_status in ('queued','failed','leased')),0))::bigint,
                       count(*) filter (where evaluation_status='completed'
                           and completed_at>=now()-interval '1 hour'
                           and completed_at<=now())
                from semantic_risk_evaluation_jobs
                group by evaluation_status
                order by queue_name,queue_status
                """
            )
            rows = [dict(row) for row in cur.fetchall()]
            quarantined = next((row for row in rows if (
                row["queue_name"] == "processing" and row["queue_status"] == "quarantined"
            )), None)
            if quarantined:
                # Queue diagnostics can load AD semantics; heartbeat writers
                # must remain importable without the optional AD package.
                from server.sli.semantic.semantic_queue_repairs import repaired_quarantine_counts

                repaired, repaired_retries = repaired_quarantine_counts(cur)
                if 0 < repaired <= int(quarantined["depth"]) and repaired_retries <= int(quarantined["retries"]):
                    quarantined["depth"] -= repaired
                    quarantined["retries"] -= repaired_retries
                    if not quarantined["depth"]:
                        rows.remove(quarantined)
                    rows.append({
                        "queue_name": "processing", "queue_status": "repaired",
                        "depth": repaired, "retries": repaired_retries,
                    })
        stages = []
        for name in ("processing", "dispatch", "risk"):
            stage_rows = [row for row in rows if row["queue_name"] == name]
            pending = [row for row in stage_rows if row["queue_status"] in {
                "queued", "failed", "leased",
            }]
            stages.append({
                "queue_name": name,
                "depth": sum(int(row.get("depth") or 0) for row in pending),
                "oldest_pending_age_seconds": max((
                    int(row.get("oldest_pending_age_seconds") or 0)
                    for row in pending
                ), default=0),
                "completed_last_hour": sum(
                    int(row.get("completed_last_hour") or 0) for row in stage_rows
                ),
            })
        return {
            "status": "ok",
            "contains_event_payload": False,
            "window_seconds": 3600,
            "warning_thresholds": {"depth": 1000, "oldest_pending_age_seconds": 900},
            "stages": stages,
            "items": [
                {
                    "queue_name": str(row["queue_name"]),
                    "queue_status": str(row["queue_status"]),
                    "depth": int(row.get("depth") or 0),
                    "retries": int(row.get("retries") or 0),
                    "expired_leases": int(row.get("expired_leases") or 0),
                    "oldest_ready_age_seconds": int(
                        row.get("oldest_ready_age_seconds") or 0
                    ),
                }
                for row in rows
            ],
        }
    except Exception as exc:  # noqa: BLE001 -- Failed metrics remain unavailable, not zero.
        return {
            "status": "unavailable",
            "contains_event_payload": False,
            "error_type": type(exc).__name__,
            "items": [],
        }


def _plugin_worker_item(component: Component, generated: datetime) -> dict[str, Any]:
    """Build one Operations row for a plugin component from its own JSON
    heartbeat file (server.sli.sources.plugin_runtime_heartbeat), not from
    runtime_worker_heartbeats -- a plugin component never writes there (it
    is addressed through a shared host script via `--component <id>`, not
    a dedicated worker script that could call record_worker_heartbeat).

    This mirrors the state contract the PostgreSQL-backed branch below
    computes (not_registered/disabled/blocked/stale/warning/active) from a
    different source, keyed only by `Component.is_plugin` -- there is no
    per-plugin-family special case here, so a future plugin family gets
    the same truthful Operations row for free as long as its host writes
    the same heartbeat shape.
    """
    heartbeat = read_plugin_heartbeat(component.plugin_component_id or component.name)
    if heartbeat is None:
        return {
            "worker_name": component.name,
            "label": component.label,
            "state": "not_registered",
            "status": "not_observed",
            "feature_enabled": True,
            "heartbeat_at": None,
        }
    stamp: datetime | None
    try:
        stamp = datetime.fromisoformat(str(heartbeat.get("heartbeat_at_utc")))
        if stamp.tzinfo is None:
            stamp = None
    except (TypeError, ValueError):
        stamp = None
    age_seconds = (
        max(0, int((generated - stamp.astimezone(timezone.utc)).total_seconds()))
        if stamp else None
    )
    try:
        expected = max(1, int(heartbeat.get("expected_interval_seconds") or component.expected_interval_seconds))
    except (TypeError, ValueError):
        expected = component.expected_interval_seconds
    fresh = age_seconds is not None and age_seconds <= max(60, expected * 2 + 30)
    reported = str(heartbeat.get("status") or "unknown")
    if reported == "blocked":
        state = "blocked"
    elif reported == "stopped":
        # The host writes this only when its loop exits because the
        # component itself was disabled -- an intentionally-off component
        # must not read as "active" (or "stale", which implies it should
        # be running and isn't).
        state = "disabled"
    elif not fresh:
        state = "stale"
    elif reported in {"partial", "warning", "failed", "error"}:
        state = "warning"
    else:
        state = "active"
    return {
        "worker_name": component.name,
        "label": component.label,
        "state": state,
        "status": reported,
        "feature_enabled": True,
        "execution_owner": "plugin_host",
        "worker_id": heartbeat.get("worker_instance_id"),
        "process_pid": heartbeat.get("process_pid"),
        "phase": heartbeat.get("phase"),
        "expected_interval_seconds": expected,
        "heartbeat_age_seconds": age_seconds,
        "heartbeat_at": stamp.isoformat() if stamp else None,
        "started_at": None,
        "details": {"last_result": heartbeat.get("last_result")},
    }


def get_runtime_workers_overview() -> dict[str, Any]:
    """Return one truthful row per known contour, without event payloads."""
    generated = datetime.now(timezone.utc)
    rows: dict[str, dict[str, Any]] = {}
    error_type: str | None = None
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                select worker_name,worker_id,process_pid,status,phase,
                       expected_interval_seconds,details_json,started_at,heartbeat_at
                from runtime_worker_heartbeats
                order by worker_name
                """
            )
            rows = {str(row["worker_name"]): dict(row) for row in cur.fetchall()}
    except Exception as exc:  # noqa: BLE001 -- Other Operations sections must remain readable.
        error_type = type(exc).__name__

    # The web process does not own the supervisor's protected environment.
    # A lifecycle heartbeat is the durable, least-privilege runtime fact.
    lifecycle_enabled = "storage_lifecycle" in rows
    items: list[dict[str, Any]] = []
    for name, label in WORKER_SPECS:
        component = _COMPONENTS_BY_NAME.get(name)
        if component is not None and component.is_plugin:
            items.append(_plugin_worker_item(component, generated))
            continue
        feature_enabled = (
            lifecycle_enabled
            if name == "storage_lifecycle"
            else component.feature_enabled if component is not None else True
        )
        row = rows.get(name)
        if not row:
            state = "not_registered" if feature_enabled else "disabled"
            status = "disabled" if not feature_enabled else "not_observed"
            items.append({
                "worker_name": name,
                "label": label,
                "state": state,
                "status": status,
                "feature_enabled": feature_enabled,
                "heartbeat_at": None,
            })
            continue
        heartbeat = row.get("heartbeat_at")
        if heartbeat is not None and getattr(heartbeat, "tzinfo", None) is None:
            heartbeat = heartbeat.replace(tzinfo=timezone.utc)
        age_seconds = max(0, int((generated - heartbeat.astimezone(timezone.utc)).total_seconds())) if heartbeat else None
        expected = max(1, int(row.get("expected_interval_seconds") or 1))
        fresh = age_seconds is not None and age_seconds <= _freshness_bound(expected)
        reported = str(row.get("status") or "unknown")
        if not feature_enabled:
            state = "disabled"
            reported = "disabled"
        elif reported == "blocked":
            state = "blocked"
        elif not fresh:
            state = "stale"
        elif reported in {"partial", "warning", "failed", "error"}:
            state = "warning"
        else:
            state = "active"
        item: dict[str, Any] = {
            "worker_name": name,
            "label": label,
            "state": state,
            "status": reported,
            "feature_enabled": feature_enabled,
            "execution_owner": "external_worker" if name == "semantic" else "runtime_worker",
            "worker_id": row.get("worker_id"),
            "process_pid": row.get("process_pid"),
            "phase": row.get("phase"),
            "expected_interval_seconds": expected,
            "heartbeat_age_seconds": age_seconds,
            "heartbeat_at": heartbeat.isoformat() if heartbeat else None,
            "started_at": row.get("started_at").isoformat() if row.get("started_at") else None,
            "details": row.get("details_json") or {},
        }
        if name == "storage_lifecycle":
            item.update(_storage_lifecycle_additions(
                details=row.get("details_json"),
                fresh=fresh,
                expected_interval_seconds=expected,
                generated=generated,
            ))
        items.append(item)
    return {
        "status": "ok" if error_type is None else "unavailable",
        "source": "postgres_runtime_worker_heartbeats",
        "error_type": error_type,
        "semantic_queues": get_semantic_queue_overview(),
        "items": items,
    }
