# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``collector_health`` at call time.
from __future__ import annotations

import html
import json
import logging
import math
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from server.sli.core.database import is_postgres_runtime_db, query_rows
from server.sli.core.time_format import format_duration_minutes, format_event_time
from server.sli.ops.logging_config import LOG_PATH, log_event
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.reporting.reporting_common import format_html_escape, format_html_pill
from server.sli.reporting.ui_labels import (
    channel_label,
    field_label,
    severity_label,
    status_label,
    translate_warning,
)
from server.sli.sources.post_collection_pipeline import get_post_collection_overview
from server.sli.storage.archive_state import DEFAULT_CHANNELS, parse_utc, utc_now

LOG_LOOKBACK_HOURS = 24
STALE_WARNING_MINUTES = 30
STALE_HIGH_MINUTES = 120
COLLECTION_CURRENT_MINUTES = 5
COLLECTION_LAGGING_MINUTES = 20

COLLECTION_ERROR_STATUSES = {"failed", "error", "timeout", "unavailable", "blocked", "access_denied"}

_SAFE_CHANNEL_NAMES = {re.sub(r'[\\/:*?"<>| ]+', '_', channel): channel for channel in DEFAULT_CHANNELS}


def get_collector_health(*, log_path: Path = LOG_PATH) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    if not is_postgres_runtime_db():
        raise RuntimeError("Collector health is PostgreSQL-only: the SQLite runtime backend has been removed")
    backend = "postgres"
    cursor_audit = {"summary": {}, "latest": [], "recent": []}
    cursor_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    db_stats = _db_history_stats_pg(now=now)
    state_rows = _collection_state_rows()
    try:
        from server.sli.core.postgres_runtime_pipeline import (
            get_cursor_audit_overview_pg,
        )

        cursor_audit = get_cursor_audit_overview_pg(limit=30)
        cursor_by_key = {
            (str(item.get("server") or ""), str(item.get("channel") or "")): item
            for item in (cursor_audit.get("latest") or [])
        }
    except Exception as exc:
        cursor_audit = {"summary": {}, "latest": [], "recent": [], "status": "unavailable", "error": str(exc)}

    state_rows = _latest_state_rows_by_case_identity(state_rows)

    log_stats = _parse_log_stats(log_path, now=now)
    items = []
    for row in state_rows:
        key = (row.get("server_hostname"), row.get("channel"))
        stats = _merge_stats(db_stats.get(key, {}), log_stats.get(key, {}))
        last_event_time = row.get("last_event_time_utc") or row.get("latest_event_time_utc")
        lag_minutes = _lag_minutes(last_event_time, now)
        collection_lag_minutes = _lag_minutes(row.get("last_successful_collection_utc"), now)
        inserted = int(stats.get("inserted") or 0)
        skipped = int(stats.get("skipped") or 0)
        ratio = _ratio(inserted, skipped)
        raw_status = stats.get("last_status") or _status_from_state(row, lag_minutes)
        display_status = _display_status(row.get("channel"), raw_status, lag_minutes, bool(row.get("recovery_mode") or 0))
        severity = _health_severity(row.get("channel"), raw_status, lag_minutes, inserted, skipped)
        cursor = cursor_by_key.get((str(row.get("server_hostname") or ""), str(row.get("channel") or "")), {})
        target_state = _target_state(row.get("channel"), lag_minutes, bool(row.get("recovery_mode") or 0))
        backlog_eta_minutes = _backlog_eta_minutes(
            lag_minutes=lag_minutes,
            lag_delta_minutes=stats.get("lag_delta_minutes"),
            total_duration_ms=stats.get("total_duration_ms"),
        )
        item_warnings = _warnings(row.get("channel"), raw_status, lag_minutes, inserted, skipped)
        if cursor.get("decision") == "rejected":
            item_warnings.append(str(cursor.get("reason") or "cursor commit rejected"))
            severity = "high" if row.get("channel") == "Security" else "warn"
        items.append({
            "server": row.get("server_hostname"),
            "channel": row.get("channel"),
            "last_collection_start_utc": row.get("last_collection_start_utc"),
            "last_successful_collection_utc": row.get("last_successful_collection_utc"),
            "collection_lag_minutes": collection_lag_minutes,
            "last_event_time_utc": last_event_time,
            "last_event_record_id": row.get("last_event_record_id") or row.get("latest_event_record_id"),
            "last_status": raw_status,
            "failure_reason": (stats.get("backend_reason") or raw_status) if raw_status in COLLECTION_ERROR_STATUSES else None,
            "display_status": display_status,
            "timeouts_24h": _timeout_count(stats.get("timeouts_24h")) or 0,
            "timeouts_24h_available": (
                _timeout_count(stats.get("timeouts_24h")) is not None
                and stats.get("timeouts_24h_available", True) is True
            ),
            "partial_timeouts_24h": int(stats.get("partial_timeouts_24h") or 0),
            "last_partial_count": int(stats.get("last_partial_count") or 0),
            "inserted_24h": inserted,
            "skipped_24h": skipped,
            "inserted_skipped_ratio": ratio,
            "event_count": int(row.get("event_count") or 0),
            "lag_minutes": lag_minutes,
            "severity": severity,
            "warnings": item_warnings,
            "target_state": target_state,
            "backlog_eta_minutes": backlog_eta_minutes,
            "cursor_commit_decision": cursor.get("decision"),
            "cursor_commit_reason": cursor.get("reason"),
            "cursor_old_record_id": cursor.get("old_record_id"),
            "cursor_proposed_record_id": cursor.get("proposed_record_id"),
            "cursor_new_record_id": cursor.get("new_record_id"),
            "cursor_audit_id": cursor.get("id"),
            "cursor_trace_id": cursor.get("trace_id"),
            "adaptive_limit": row.get("current_limit"),
            "recovery_mode": bool(row.get("recovery_mode") or 0),
            "adaptive_action": row.get("last_action"),
            "query_duration_ms": stats.get("query_duration_ms"),
            "import_duration_ms": stats.get("import_duration_ms"),
            "import_queue_wait_ms": stats.get("import_queue_wait_ms"),
            "import_retry_count": stats.get("import_retry_count"),
            "total_duration_ms": stats.get("total_duration_ms"),
            "events_per_second": stats.get("events_per_second"),
            "last_record_id_delta": stats.get("last_record_id_delta"),
            "lag_delta_minutes": stats.get("lag_delta_minutes"),
            "collection_mode": stats.get("collection_mode"),
            "requested_collection_mode": stats.get("requested_collection_mode"),
            "cursor_strategy": stats.get("cursor_strategy"),
            "cursor_fallback_reason": stats.get("cursor_fallback_reason"),
            "collector_backend": stats.get("collector_backend"),
            "backend_reason": stats.get("backend_reason"),
            "cycle_status_label": _cycle_status_label(raw_status),
            "freshness_label": _freshness_label(row.get("channel"), lag_minutes, bool(row.get("recovery_mode") or 0)),
            "event_observation_label": _event_observation_label(
                row.get("channel"),
                raw_status,
                lag_minutes,
                collection_lag_minutes,
                bool(row.get("recovery_mode") or 0),
            ),
            "event_observation_severity": _event_observation_severity(
                row.get("channel"),
                raw_status,
                lag_minutes,
                collection_lag_minutes,
                bool(row.get("recovery_mode") or 0),
            ),
            "collection_state": _collection_state(raw_status, collection_lag_minutes),
            "collection_label": _collection_label(raw_status, collection_lag_minutes),
            "collection_severity": _collection_severity(raw_status, collection_lag_minutes),
            "state_explanation": _state_explanation(row.get("channel"), display_status, lag_minutes, bool(row.get("recovery_mode") or 0)) + _target_state_suffix(target_state, backlog_eta_minutes),
        })
    summary = _summary(items)
    post_collection = _safe_post_collection_overview(backend=backend, limit=10)
    summary["stale_post_collection"] = int((post_collection.get("summary") or {}).get("stale_running") or 0)
    operations_slo = _operations_slo(items, summary, post_collection)
    collection_freshness = summarize_collection_freshness(items)
    runtime_history = _safe_runtime_collection_history(backend=backend)
    storage_v2_outbox = _safe_storage_v2_outbox(backend=backend)
    log_event("collector_health", "collector_health_requested", "Collector health requested.", count=len(items))
    return {
        "generated_at_utc": utc_now(),
        "lookback_hours": LOG_LOOKBACK_HOURS,
        "backend": backend,
        "summary": summary,
        "items": items,
        "post_collection": post_collection,
        "cursor_audit": cursor_audit,
        "operations_slo": operations_slo,
        "collection_freshness": collection_freshness,
        "runtime_history": runtime_history,
        "storage_v2_outbox": storage_v2_outbox,
    }


def _safe_post_collection_overview(*, backend: str, limit: int) -> dict[str, Any]:
    if backend != "postgres":
        return {"backend": backend, "status": "not_applicable", "summary": {}, "items": []}
    try:
        return get_post_collection_overview(limit=limit)
    except Exception as exc:
        log_event(
            "collector_health",
            "post_collection_overview_unavailable",
            "Post-collection overview is unavailable; collector health remains available.",
            level=logging.WARNING,
            error_type=type(exc).__name__,
            error=str(exc),
        )
        return {
            "backend": "postgres",
            "status": "unavailable",
            "summary": {},
            "items": [],
            "error_type": type(exc).__name__,
            "error": str(exc),
        }


def _safe_runtime_collection_history(*, backend: str) -> dict[str, Any]:
    """Expose live scheduler jobs and durable passes from the effective collector."""
    if backend != "postgres":
        return {"status": "not_applicable", "items": []}
    try:
        from server.jobs.collector import list_jobs
        from server.sli.sources.runtime_collection_history import (
            recent_collector_channel_cycles,
        )

        rows = recent_collector_channel_cycles(limit=3)
        live_rows = []
        for job in list_jobs():
            if not str(job.get("kind") or "").startswith("collect_all_dc_logs"):
                continue
            live_rows.append({
                "run_id": str(job.get("durable_id") or job.get("id") or ""),
                "worker_id": "current-collector", "job_id": job.get("id"),
                "status": job.get("status"), "phase": job.get("phase"),
                "servers_json": job.get("servers") or [],
                "created_at": job.get("created_at"), "started_at": job.get("created_at"),
                "finished_at": job.get("updated_at") if job.get("status") in {"completed", "partial", "failed", "skipped"} else None,
                "duration_ms": job.get("duration_ms"),
                "max_events_per_channel": job.get("max_events_per_channel"),
                "errors_json": job.get("errors") or job.get("warnings") or [], "cycle": job.get("cycle"),
                "current_server": job.get("current_server"), "current_channel": job.get("current_channel"),
                "events_collected": job.get("events_collected"),
            })
            if len(live_rows) >= 3:
                break
        return {
            "status": "ok",
            "source": "effective_collector",
            "active_items": live_rows,
            "channel_items": rows,
            "items": live_rows or rows,
        }
    except Exception as exc:
        log_event(
            "collector_health", "runtime_collection_history_unavailable",
            "Independent worker history is unavailable; collector health remains available.",
            level=logging.WARNING, error_type=type(exc).__name__, error=str(exc),
        )
        return {"status": "unavailable", "items": [], "error_type": type(exc).__name__}


def _safe_storage_v2_outbox(*, backend: str) -> dict[str, Any]:
    """Return only queue aggregates; event payload stays outside operations UI."""
    if backend != "postgres":
        return {"status": "not_applicable", "batches": 0, "events": 0, "states": {}}
    try:
        from server.sli.core.postgres_runtime_pipeline import connect

        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                select effective_state as state, count(*) as batches,
                       coalesce(sum(event_count), 0) as events
                from (
                    select event_count, case
                        when state = 'completed' then 'completed'
                        when state = 'quarantined' then 'quarantined'
                        when state = 'leased' and lease_until > now() then 'leased'
                        when state = 'leased' then 'expired_lease'
                        when state in ('pending', 'failed') and available_at <= now() then 'ready'
                        when state in ('pending', 'failed') then 'delayed'
                        else state end as effective_state
                    from storage_v2_outbox
                ) classified group by effective_state
                """
            )
            states = {str(row["state"]): {"batches": int(row["batches"]), "events": int(row["events"])} for row in cur.fetchall()}
        visible_states = {key: value for key, value in states.items() if key != "completed"}
        active = {key: value for key, value in visible_states.items() if key in {"ready", "delayed", "leased"}}
        return {
            "status": "ok", "states": visible_states,
            "batches": sum(int(value["batches"]) for value in active.values()),
            "events": sum(int(value["events"]) for value in active.values()),
            "expired_lease_batches": int((states.get("expired_lease") or {}).get("batches") or 0),
            "expired_lease_events": int((states.get("expired_lease") or {}).get("events") or 0),
            "completed_batches": int((states.get("completed") or {}).get("batches") or 0),
            "completed_events": int((states.get("completed") or {}).get("events") or 0),
        }
    except Exception as exc:
        log_event("collector_health", "storage_v2_outbox_unavailable", "Storage V2 outbox summary is unavailable.", level=logging.WARNING, error_type=type(exc).__name__, error=str(exc))
        return {"status": "unavailable", "batches": 0, "events": 0, "states": {}, "error_type": type(exc).__name__}


def _timeout_count(value: Any) -> int | None:
    """Validate observed counts without turning missing/invalid telemetry into zero."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value):
        try:
            return int(value)
        except ValueError:
            pass
    return None


def _operations_slo(
    items: list[dict[str, Any]],
    summary: dict[str, Any],
    post_collection: dict[str, Any],
) -> dict[str, Any]:
    """Summarise the established freshness thresholds as an operator-facing SLO baseline.

    Check freshness is independent of event age: a quiet channel can still have
    a current successful check. A failed check cannot count as current.
    """
    security_items = [item for item in items if item.get("channel") == "Security"]
    now = datetime.now(timezone.utc)
    current = warning = breached = unknown = 0
    for item in security_items:
        lag = _lag_minutes(item.get("last_successful_collection_utc"), now)
        state = _collection_state(item.get("last_status"), lag)
        if state == "error":
            breached += 1
        elif lag is None:
            unknown += 1
        elif state == "stale":
            breached += 1
        elif state == "lagging":
            warning += 1
        else:
            current += 1

    post_summary = post_collection.get("summary") or {}
    timeouts = int(summary.get("timeouts_24h") or 0)
    partial_timeouts = int(summary.get("partial_timeouts_24h") or 0)
    stale_post_collection = int(summary.get("stale_post_collection") or 0)
    interval_seconds = max(60, int(os.getenv("ADLOG_COLLECTION_INTERVAL_SECONDS", "600") or "600"))
    expected_security_checks = len(security_items) * max(1, 86_400 // interval_seconds)
    objective = 0.99
    allowed_errors = max(1, math.floor(expected_security_checks * (1.0 - objective))) if security_items else 0
    # timeouts_24h already includes partial timeouts. Match the numerator to
    # the scheduled Security-check model; other channels and current analysis
    # backlog remain operational warnings, not failed Security checks. This is
    # a schedule-based estimate, not proof of complete observed run history.
    counts = [_timeout_count(item.get("timeouts_24h")) for item in security_items]
    budget_known = bool(security_items) and all(count is not None for count in counts) and all(
        item.get("timeouts_24h_available", True) is True for item in security_items
    )
    consumed_errors = sum(count for count in counts if count is not None) if budget_known else None
    remaining_errors = max(0, allowed_errors - consumed_errors) if consumed_errors is not None else None
    if not security_items or unknown == len(security_items):
        status = "unknown"
        label = "Недостаточно данных"
    elif breached:
        status = "breached"
        label = "Требует вмешательства"
    elif warning or unknown or timeouts or partial_timeouts or stale_post_collection or not budget_known:
        status = "attention"
        label = "Требует внимания"
    else:
        status = "met"
        label = "В норме"

    return {
        "status": status,
        "label": label,
        "security_channels": len(security_items),
        "basis": "last_successful_collection",
        "freshness_current": current,
        "freshness_warning": warning,
        "freshness_breached": breached,
        "freshness_unknown": unknown,
        "warning_minutes": COLLECTION_CURRENT_MINUTES,
        "breach_minutes": COLLECTION_LAGGING_MINUTES,
        "timeouts_24h": timeouts,
        "partial_timeouts_24h": partial_timeouts,
        "stale_post_collection": stale_post_collection,
        "analysis_queued": int(post_summary.get("queued") or 0),
        "analysis_running": int(post_summary.get("running") or 0),
        "error_budget": {
            "window_hours": 24,
            "objective": objective,
            "schedule_interval_seconds": interval_seconds,
            "expected_security_checks": expected_security_checks,
            "allowed_errors": allowed_errors,
            "consumed_errors": consumed_errors,
            "remaining_errors": remaining_errors,
            "consumed_percent": round(100.0 * consumed_errors / max(1, allowed_errors), 2) if consumed_errors is not None else None,
            "status": "unknown" if consumed_errors is None else ("exhausted" if consumed_errors > allowed_errors else ("attention" if consumed_errors else "available")),
            "method": "scheduled_security_checks_model",
        },
    }






def _storage_v2_outbox_html(outbox: dict[str, Any]) -> str:
    if outbox.get("status") != "ok":
        return ""
    pending = int(outbox.get("events") or 0)
    batches = int(outbox.get("batches") or 0)
    states = outbox.get("states") or {}
    leased = int((states.get("leased") or {}).get("events") or 0)
    label = "очередь пуста" if pending == 0 else "публикация продолжается"
    return f"""
  <section class=\"worker-card worker-{'completed' if pending == 0 else 'running'}\">
    <div class=\"section-title\"><div><div class=\"eyebrow\">STORAGE V2 · независимая публикация</div><h2>Очередь архивирования V2</h2>
    <p class=\"muted\">{label}. Она не блокирует успешный сбор с контроллеров домена.</p></div><span class=\"slo-state\">{_e(label)}</span></div>
    <div class=\"slo-grid\"><div><strong>{pending:,}</strong><span>событий ожидают или обрабатываются</span></div><div><strong>{batches}</strong><span>пакетов в работе</span></div><div><strong>{leased:,}</strong><span>событий сейчас взяты worker</span></div></div>
  </section>"""




def _collection_state_rows() -> list[dict[str, Any]]:
    """Return PostgreSQL collector state without scanning the events table.

    ``collection_channel_state`` already persists the committed event cursor and
    timestamp.  The previous health query recomputed count/max over every event
    for every dashboard refresh, which dominated page load time on multi-million
    row databases.  Runtime inserted totals are read from the small collector run
    history instead; exact event counts remain available in deep event reports.
    """
    return query_rows(
        """
        select
            c.server_hostname,
            c.channel,
            c.archive_start_utc,
            c.last_collection_start_utc,
            c.last_successful_collection_utc,
            c.last_event_time_utc,
            c.last_event_record_id,
            c.backfill_completed,
            c.updated_at,
            coalesce(run_totals.event_count, 0) as event_count,
            c.last_event_time_utc as latest_event_time_utc,
            c.last_event_record_id as latest_event_record_id,
            a.current_limit,
            a.recovery_mode,
            a.last_action,
            a.last_status as adaptive_last_status,
            a.last_lag_minutes
        from collection_channel_state c
        left join (
            select server, channel, sum(coalesce(inserted, 0)) as event_count
            from collector_channel_runs
            group by server, channel
        ) run_totals on run_totals.server = c.server_hostname and run_totals.channel = c.channel
        left join collector_adaptive_state a on a.server = c.server_hostname and a.channel = c.channel
        order by c.server_hostname, case c.channel
            when 'Security' then 1
            when 'System' then 2
            when 'Directory Service' then 3
            when 'Microsoft-Windows-PowerShell/Operational' then 4
            when 'Microsoft-Windows-TaskScheduler/Operational' then 5
            when 'DNS Server' then 6
            else 99 end, c.channel
        """,
    )


def _db_history_stats_pg(*, now: datetime) -> dict[tuple[str, str], dict[str, Any]]:
    """Load 24h aggregates and the latest channel run in one PostgreSQL query."""
    cutoff = (now - timedelta(hours=LOG_LOOKBACK_HOURS)).isoformat()
    rows = query_rows(
        """
        with recent as (
            select *
            from collector_channel_runs
            where coalesce(finished_utc, created_at::text) >= ?
        ),
        aggregate_24h as (
            select
                server,
                channel,
                sum(case when status in ('timeout', 'partial_timeout') then 1 else 0 end) as timeouts_24h,
                sum(case when status = 'partial_timeout' then 1 else 0 end) as partial_timeouts_24h,
                sum(coalesce(inserted, 0)) as inserted,
                sum(coalesce(skipped, 0)) as skipped,
                max(coalesce(partial_count, 0)) as last_partial_count
            from recent
            group by server, channel
        ),
        latest as (
            select distinct on (server, channel)
                server, channel, status as last_status,
                query_duration_ms, import_duration_ms, import_queue_wait_ms, import_retry_count,
                total_duration_ms, events_per_second, last_record_id_delta, lag_delta_minutes,
                collection_mode, requested_collection_mode, cursor_strategy, cursor_fallback_reason,
                collector_backend, backend_reason
            from collector_channel_runs
            order by server, channel, coalesce(finished_utc, created_at::text) desc, id desc
        )
        select
            coalesce(a.server, l.server) as server,
            coalesce(a.channel, l.channel) as channel,
            coalesce(a.timeouts_24h, 0) as timeouts_24h,
            coalesce(a.partial_timeouts_24h, 0) as partial_timeouts_24h,
            coalesce(a.inserted, 0) as inserted,
            coalesce(a.skipped, 0) as skipped,
            coalesce(a.last_partial_count, 0) as last_partial_count,
            l.last_status, l.query_duration_ms, l.import_duration_ms, l.import_queue_wait_ms,
            l.import_retry_count, l.total_duration_ms, l.events_per_second, l.last_record_id_delta,
            l.lag_delta_minutes, l.collection_mode, l.requested_collection_mode, l.cursor_strategy,
            l.cursor_fallback_reason, l.collector_backend, l.backend_reason
        from aggregate_24h a
        full outer join latest l on l.server = a.server and l.channel = a.channel
        """,
        (cutoff,),
    )
    stats: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row["server"], row["channel"])
        stats[key] = {
            "timeouts_24h": _timeout_count(row.get("timeouts_24h")) or 0,
            "timeouts_24h_available": _timeout_count(row.get("timeouts_24h")) is not None,
            "partial_timeouts_24h": int(row.get("partial_timeouts_24h") or 0),
            "inserted": int(row.get("inserted") or 0),
            "skipped": int(row.get("skipped") or 0),
            "last_partial_count": int(row.get("last_partial_count") or 0),
            "last_status": row.get("last_status"),
        }
        for name in ("query_duration_ms", "import_duration_ms", "import_queue_wait_ms", "import_retry_count", "total_duration_ms", "events_per_second", "last_record_id_delta", "lag_delta_minutes", "collection_mode", "requested_collection_mode", "cursor_strategy", "cursor_fallback_reason", "collector_backend", "backend_reason"):
            stats[key][name] = row.get(name)
    return stats


def _latest_db_status_pg(server: str, channel: str) -> str | None:
    rows = query_rows(
        """
        select status from collector_channel_runs
        where server = ? and channel = ?
        order by coalesce(finished_utc, created_at::text) desc, id desc
        limit 1
        """,
        (server, channel),
    )
    return rows[0]["status"] if rows else None


def _latest_db_run_pg(server: str, channel: str) -> dict[str, Any] | None:
    rows = query_rows(
        """
        select query_duration_ms, import_duration_ms, import_queue_wait_ms, import_retry_count, total_duration_ms, events_per_second,
               last_record_id_delta, lag_delta_minutes, collection_mode, requested_collection_mode,
               cursor_strategy, cursor_fallback_reason, collector_backend, backend_reason
        from collector_channel_runs
        where server = ? and channel = ?
        order by coalesce(finished_utc, created_at::text) desc, id desc
        limit 1
        """,
        (server, channel),
    )
    return rows[0] if rows else None


def _merge_stats(primary: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    if not primary:
        return fallback
    merged = dict(primary)
    # Choose one counter source atomically. SQL zero is an observation, not a
    # missing value to overwrite with possibly duplicated log-tail evidence.
    counter_keys = {"timeouts_24h", "partial_timeouts_24h", "timeouts_24h_available"}
    if primary.get("timeouts_24h_available") is not True and fallback.get("timeouts_24h_available") is True:
        for key in counter_keys:
            merged[key] = fallback.get(key)
    for key, value in fallback.items():
        if key in counter_keys:
            continue
        if key not in merged or merged[key] in (None, 0, ""):
            merged[key] = value
    return merged


def _parse_log_stats(log_path: Path, *, now: datetime) -> dict[tuple[str, str], dict[str, Any]]:
    stats: dict[tuple[str, str], dict[str, Any]] = {}
    if not log_path.is_file():
        return stats
    cutoff = now - timedelta(hours=LOG_LOOKBACK_HOURS)
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-5000:]
    except OSError:
        return stats
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = _parse_time(record.get("ts"))
        if ts and ts < cutoff:
            continue
        server = record.get("server") or _server_from_command(record.get("command"))
        if not server:
            continue
        text = "\n".join(str(record.get(name) or "") for name in ("stdout_tail", "stderr_tail", "message", "error"))
        for channel, status, count in _channel_statuses_from_text(text):
            bucket = _bucket(stats, server, channel)
            bucket["last_status"] = status
            bucket["timeouts_24h_available"] = (
                ts is not None and cutoff <= ts <= now
                and bucket.get("timeouts_24h_available") is not False
            )
            if status == "partial_timeout":
                bucket["partial_timeouts_24h"] += 1
                bucket["timeouts_24h"] += 1
                bucket["last_partial_count"] = max(bucket.get("last_partial_count", 0), count)
            elif status == "timeout":
                bucket["timeouts_24h"] += 1
        for channel, inserted, skipped in _import_counts_from_text(text):
            bucket = _bucket(stats, server, channel)
            bucket["inserted"] += inserted
            bucket["skipped"] += skipped
    return stats


def _channel_statuses_from_text(text: str) -> list[tuple[str, str, int]]:
    found: list[tuple[str, str, int]] = []
    for match in re.finditer(r"Timed out channel: (?P<channel>.+?) after \d+s(?: partial_count=(?P<count>\d+))?", text):
        count = int(match.group("count") or 0)
        found.append((match.group("channel").strip(), "partial_timeout" if count else "timeout", count))
    for match in re.finditer(r"Completed channel: (?P<channel>.+?) count=(?P<count>\d+)", text):
        found.append((match.group("channel").strip(), "completed", int(match.group("count") or 0)))
    return found


def _import_counts_from_text(text: str) -> list[tuple[str, int, int]]:
    found = []
    for match in re.finditer(r"(?P<safe>[A-Za-z0-9_.-]+)\.jsonl: inserted=(?P<inserted>\d+), skipped=(?P<skipped>\d+)", text):
        channel = _SAFE_CHANNEL_NAMES.get(match.group("safe"), match.group("safe").replace("_", " "))
        found.append((channel, int(match.group("inserted")), int(match.group("skipped"))))
    return found


def _bucket(stats: dict[tuple[str, str], dict[str, Any]], server: str, channel: str) -> dict[str, Any]:
    key = (server, channel)
    if key not in stats:
        stats[key] = {"timeouts_24h_available": None, "timeouts_24h": 0, "partial_timeouts_24h": 0, "inserted": 0, "skipped": 0, "last_partial_count": 0, "last_status": None}
    return stats[key]


def _server_from_command(command: Any) -> str | None:
    if not command:
        return None
    match = re.search(r"--server\s+(\S+)", str(command))
    return match.group(1) if match else None


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return parse_utc(str(value))
    except Exception:
        return None


def _latest_state_rows_by_case_identity(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse legacy hostname-case duplicates without mutating collector state."""
    selected: dict[tuple[str, str], tuple[int, datetime, dict[str, Any]]] = {}
    minimum = datetime.min.replace(tzinfo=timezone.utc)
    for index, row in enumerate(rows):
        key = (
            str(row.get("server_hostname") or "").casefold(),
            str(row.get("channel") or "").casefold(),
        )
        freshness = max(
            (
                _parse_time(row.get("last_successful_collection_utc")) or minimum,
                _parse_time(row.get("updated_at")) or minimum,
                _parse_time(row.get("last_collection_start_utc")) or minimum,
            )
        )
        previous = selected.get(key)
        if previous is None or freshness > previous[1]:
            selected[key] = (index, freshness, row)
    return [entry[2] for entry in sorted(selected.values(), key=lambda entry: entry[0])]


def _lag_minutes(value: Any, now: datetime) -> int | None:
    parsed = _parse_time(value)
    if parsed is None:
        return None
    return max(0, int((now - parsed).total_seconds() // 60))


def _collection_state(status: str | None, lag_minutes: int | None) -> str:
    if str(status or "").lower() in COLLECTION_ERROR_STATUSES:
        return "error"
    if lag_minutes is None or lag_minutes > COLLECTION_LAGGING_MINUTES:
        return "stale"
    if lag_minutes > COLLECTION_CURRENT_MINUTES:
        return "lagging"
    return "current"


def _collection_label(status: str | None, lag_minutes: int | None) -> str:
    state = _collection_state(status, lag_minutes)
    return {
        "error": "ошибка проверки",
        "stale": "проверка сильно отстаёт",
        "lagging": "есть задержка проверки",
        "current": "проверка актуальна",
    }[state]


def _collection_severity(status: str | None, lag_minutes: int | None) -> str:
    return {"error": "high", "stale": "high", "lagging": "warn", "current": "ok"}[
        _collection_state(status, lag_minutes)
    ]


def summarize_collection_freshness(
    items: list[dict[str, Any]],
    *,
    health_status: str | None = None,
    selected_source: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Describe collector checks without treating a quiet event log as a failed poll."""
    current_time = now or datetime.now(timezone.utc)
    relevant = [
        item for item in items
        if not selected_source or str(item.get("server") or "").lower() == selected_source.lower()
    ]
    health_error = str(health_status or "").lower() in COLLECTION_ERROR_STATUSES
    channel_error_flags = [
        str(item.get("last_status") or "").lower() in COLLECTION_ERROR_STATUSES
        for item in relevant
    ]
    failed_channels = sum(1 for failed in channel_error_flags if failed)
    healthy_channels = sum(1 for failed in channel_error_flags if not failed)
    collection_error = health_error or failed_channels > 0
    lags = [
        _lag_minutes(item.get("last_successful_collection_utc"), current_time)
        for item in relevant
    ]
    known_lags = [lag for lag in lags if lag is not None]
    checked_values = [_parse_time(item.get("last_successful_collection_utc")) for item in relevant]
    event_values = [_parse_time(item.get("last_event_time_utc")) for item in relevant]
    event_lags = [_lag_minutes(item.get("last_event_time_utc"), current_time) for item in relevant]
    worst = max(known_lags) if known_lags else None
    oldest_check = min((value for value in checked_values if value is not None), default=None)
    latest_event = max((value for value in event_values if value is not None), default=None)
    worst_event = max((lag for lag in event_lags if lag is not None), default=None)
    if collection_error and failed_channels > 0 and healthy_channels > 0:
        state, label = "partial", "Частичный сбор"
    elif collection_error:
        state, label = "error", "Ошибка сбора"
    elif worst is None or len(known_lags) != len(relevant) or worst > COLLECTION_LAGGING_MINUTES:
        state, label = "stale", "Данные сильно устарели"
    elif worst > COLLECTION_CURRENT_MINUTES:
        state, label = "lagging", "Есть отставание"
    else:
        state, label = "current", "Данные актуальны"
    return {
        "state": state,
        "label": label,
        "worst_lag_minutes": worst,
        "checked_at_utc": oldest_check.isoformat().replace("+00:00", "Z") if oldest_check else None,
        "latest_event_utc": latest_event.isoformat().replace("+00:00", "Z") if latest_event else None,
        "worst_event_lag_minutes": worst_event,
        "collection_error": collection_error,
        "channels_failed": failed_channels,
        "channels_total": len(relevant),
        "channels_checked": len(known_lags),
        "basis": "last_successful_collection",
    }


def _ratio(inserted: int, skipped: int) -> str:
    if inserted <= 0 and skipped <= 0:
        return "0/0"
    return f"{inserted}/{skipped}"


def _status_from_state(row: dict[str, Any], lag_minutes: int | None) -> str:
    if not row.get("last_successful_collection_utc"):
        return "unknown"
    if lag_minutes is not None and lag_minutes > STALE_HIGH_MINUTES:
        return "stale"
    return "completed"


def _health_severity(channel: str | None, status: str, lag_minutes: int | None, inserted: int, skipped: int) -> str:
    if status in {"timeout", "failed"}:
        return "high" if channel == "Security" else "warn"
    if channel == "Security" and lag_minutes is not None:
        if lag_minutes > STALE_HIGH_MINUTES:
            return "high"
        if lag_minutes > STALE_WARNING_MINUTES:
            return "warn"
    if status == "stale" or (lag_minutes is not None and lag_minutes > STALE_HIGH_MINUTES):
        return "warn"
    if status != "completed" and skipped > max(inserted * 3, 100) and skipped > 0:
        return "warn"
    if status == "partial_timeout":
        return "warn"
    return "ok"


def _warnings(channel: str | None, status: str, lag_minutes: int | None, inserted: int, skipped: int) -> list[str]:
    warnings: list[str] = []
    if status in {"timeout", "partial_timeout"}:
        warnings.append("channel timeout")
    if lag_minutes is not None:
        if channel == "Security":
            if lag_minutes > STALE_HIGH_MINUTES:
                warnings.append("Security lag > 2h")
            elif lag_minutes > STALE_WARNING_MINUTES:
                warnings.append("Security lag > 30m")
        elif lag_minutes > STALE_HIGH_MINUTES:
            warnings.append("channel data stale")
    if status != "completed" and skipped > max(inserted * 3, 100) and skipped > 0:
        warnings.append("possible repeated backlog read")
    return warnings


def _display_status(channel: str | None, raw_status: str, lag_minutes: int | None, recovery_mode: bool) -> str:
    if channel == "Security" and lag_minutes is not None and lag_minutes > STALE_WARNING_MINUTES:
        if raw_status == "completed":
            return "сбор завершён, данные ещё догоняются"
        if recovery_mode:
            return f"{status_label(raw_status)} · режим восстановления"
    if raw_status == "stale":
        return "данные устарели"
    return status_label(raw_status)


def _cycle_status_label(status: str | None) -> str:
    raw = str(status or "unknown")
    if raw == "completed":
        return "сбор завершен"
    if raw == "partial_timeout":
        return "частичный сбор"
    if raw == "timeout":
        return "таймаут"
    if raw == "failed":
        return "ошибка сбора"
    if raw == "stale":
        return "последний сбор был давно"
    return status_label(raw)


def _freshness_label(channel: str | None, lag_minutes: int | None, recovery_mode: bool) -> str:
    if lag_minutes is None:
        return "нет данных о свежести"
    if channel == "Security" and recovery_mode and lag_minutes > STALE_WARNING_MINUTES:
        return "сбор успешен, догоняет backlog"
    if lag_minutes > STALE_HIGH_MINUTES:
        return "данные сильно отстают"
    if lag_minutes > STALE_WARNING_MINUTES:
        return "данные отстают"
    return "данные актуальны"




def _event_observation_severity(
    channel: str | None,
    status: str | None,
    event_lag_minutes: int | None,
    collection_lag_minutes: int | None,
    recovery_mode: bool,
) -> str:
    collection_state = _collection_state(status, collection_lag_minutes)
    if collection_state == "error":
        return "high"
    if collection_state == "stale":
        return "warn"
    if channel == "Security" and (event_lag_minutes is None or event_lag_minutes > STALE_WARNING_MINUTES):
        return "warn" if recovery_mode else "high"
    return "good"


def _target_state(channel: str | None, lag_minutes: int | None, recovery_mode: bool) -> str:
    if lag_minutes is None:
        return "unknown"
    if recovery_mode or lag_minutes > STALE_HIGH_MINUTES:
        return "catching_up"
    if lag_minutes > STALE_WARNING_MINUTES:
        return "near_current"
    return "current"


def _backlog_eta_minutes(*, lag_minutes: Any, lag_delta_minutes: Any, total_duration_ms: Any) -> int | None:
    try:
        lag = int(lag_minutes)
        delta = int(lag_delta_minutes)
        cycle_ms = int(total_duration_ms)
    except (TypeError, ValueError):
        return None
    if lag <= STALE_WARNING_MINUTES:
        return 0
    if delta >= 0 or cycle_ms <= 0:
        return None
    improvement = abs(delta)
    cycles = max(1, (lag - STALE_WARNING_MINUTES + improvement - 1) // improvement)
    return max(1, int((cycles * cycle_ms) / 60000))


def _target_state_suffix(target_state: str, eta_minutes: int | None) -> str:
    labels = {
        "current": "актуален",
        "near_current": "почти актуален",
        "catching_up": "догоняет backlog",
        "unknown": "состояние неизвестно",
    }
    suffix = f" · target: {labels.get(target_state, target_state)}"
    if eta_minutes is not None:
        suffix += f" · ETA ~{eta_minutes} мин"
    elif target_state == "catching_up":
        suffix += " · ETA пока недостаточно данных"
    return suffix


def _backend_label(item: dict[str, Any]) -> str:
    backend = str(item.get("collector_backend") or "—")
    reason = str(item.get("backend_reason") or "")
    if reason:
        return f"{backend} · {reason}"
    return backend








def _sec(value: Any) -> str:
    try:
        if value is None or value == "":
            return "—"
        return f"{round(int(value) / 1000, 1)} с"
    except (TypeError, ValueError):
        return "—"


def _lag_delta(value: Any) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return "—"
    if number > 0:
        return f"хуже на {number} мин"
    if number < 0:
        return f"лучше на {abs(number)} мин"
    return "без изменения"






def _event_url(item: dict[str, Any]) -> str:
    params = {"server": item.get("server"), "channel": item.get("channel"), "limit": 200, "order": "desc"}
    return "/reports/event-details.html?" + urlencode({key: value for key, value in params.items() if value})


def _minutes(value: Any) -> str:
    return format_duration_minutes(value)






def _state_explanation(channel: str | None, display_status: str, lag_minutes: int | None, recovery_mode: bool) -> str:
    if channel == "Security" and lag_minutes is not None and lag_minutes > STALE_WARNING_MINUTES:
        return "Цикл чтения завершился и продвинул позицию, но источник Security еще отдаёт более старые события."
    if lag_minutes is not None and lag_minutes > STALE_HIGH_MINUTES:
        return "Данные устарели; стоит проверить расписание и доступность сбора."
    if display_status in {"завершено", "completed"}:
        return "Последний запуск завершен, новых проблем по каналу не видно."
    return "Требуется проверка статуса collector."


_pill = format_html_pill
_e = format_html_escape



def _style() -> str:
    return report_style()


from server.sli.sources.collector_health_render import (
    _adaptive_action_label,
    _cursor_label,
    _event_observation_label,
    _operations_slo_html,
    _performance_explanation,
    _performance_rows,
    _row_html,
    _runtime_history_html,
    _speed_label,
    _summary,
    render_collector_health_report,
)
