from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SNAPSHOT_TABLE = "storage_lifecycle_snapshots"
SCHEMA_MIGRATION_VERSION = 7
SCHEMA_MIGRATION_NAME = "storage_lifecycle2_measurement_and_backup_rehearsal"
DEFAULT_SNAPSHOT_INTERVAL_MINUTES = 60
BACKUP_RESTORE_LAST = "postgres_backup_restore_last.json"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now_utc()).astimezone(timezone.utc).isoformat()


def _as_utc(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def validate_storage_thresholds(policy: Any | None = None) -> dict[str, Any]:
    """Validate free-disk thresholds and expose safe effective values.

    Collection must not depend on a malformed environment setting.  Invalid
    ordering therefore produces an explicit warning and falls back to the
    documented 15/10/5 thresholds instead of silently inverting the guard.
    """
    if policy is None:
        from server.sli.storage.storage_policy import load_storage_policy

        policy = load_storage_policy()
    configured = {
        "warn_free_percent": _safe_int(getattr(policy, "min_free_disk_percent", 15)),
        "stop_free_percent": _safe_int(getattr(policy, "stop_collection_if_free_disk_percent_below", 10)),
        "critical_free_percent": _safe_int(getattr(policy, "critical_free_disk_percent", 5)),
    }
    issues: list[str] = []
    warn = configured["warn_free_percent"]
    stop = configured["stop_free_percent"]
    critical = configured["critical_free_percent"]
    if not all(0 < value < 100 for value in (warn, stop, critical)):
        issues.append("threshold values must be between 1 and 99 percent")
    if not critical < stop < warn:
        issues.append("threshold ordering must be critical < stop < warn")
    effective = dict(configured)
    source = "configured"
    if issues:
        effective = {
            "warn_free_percent": 15,
            "stop_free_percent": 10,
            "critical_free_percent": 5,
        }
        source = "safe_defaults"
    return {
        "status": "warn" if issues else "ok",
        "configured": configured,
        "effective": effective,
        "source": source,
        "issues": issues,
    }


def ensure_storage_lifecycle_schema() -> dict[str, Any]:
    """Verify the migrated storage schema without executing DDL."""
    from server.sli.ops.postgres_schema_guard import require_table_columns
    from server.sli.core.postgres_runtime_pipeline import connect

    contract = require_table_columns(
        SNAPSHOT_TABLE,
        (
            "id", "captured_at", "source", "source_job_id", "source_run_id",
            "database_bytes", "events_estimated_rows", "events_max_id",
            "events_last_24h", "disk_free_bytes", "disk_free_percent",
            "table_stats_json", "scan_meta_json",
        ),
    )
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(f"select count(*) as snapshot_count, max(captured_at) as latest_captured_at from {SNAPSHOT_TABLE}")
            row = cur.fetchone() or {}
    return {
        "status": "ok",
        "backend": "postgres",
        "table": SNAPSHOT_TABLE,
        "schema_migration_version": contract.get("schema_version") or contract.get("minimum_schema_version"),
        "snapshot_count": _safe_int(row.get("snapshot_count")),
        "latest_captured_at": row.get("latest_captured_at"),
        "ddl_executed": False,
    }


def _filesystem_snapshot(*, deep: bool = False) -> dict[str, Any]:
    from server.sli.core.paths import DATA_DIR, LOG_DIR, REPORTS_DIR, ROOT
    from server.sli.storage.storage_policy import _bounded_dir_size, disk_info

    max_entries = 30000 if deep else 10000
    max_seconds = 8.0 if deep else 3.0
    roots = {
        "raw": DATA_DIR / "raw",
        "raw_archive": DATA_DIR / "raw_archive",
        "backups": DATA_DIR / "backups",
        "logs": LOG_DIR,
        "reports": REPORTS_DIR,
        "artifacts": ROOT / "artifacts",
    }
    sizes: dict[str, dict[str, Any]] = {}
    for name, path in roots.items():
        sizes[name] = _bounded_dir_size(
            path,
            max_entries=max_entries,
            max_seconds=max_seconds,
            skip_dir_names={"__pycache__", ".pytest_cache", ".git"},
        )
    return {"sizes": sizes, "disk": disk_info(ROOT)}


def _postgres_snapshot() -> dict[str, Any]:
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("set local statement_timeout = '15000ms'")
            cur.execute("set local lock_timeout = '1000ms'")
            cur.execute(
                """
                select pg_database_size(current_database())::bigint as database_bytes,
                       current_database() as database_name,
                       now() as checked_at
                """
            )
            database = dict(cur.fetchone() or {})
            event_relation = _physical_event_relation(cur)
            cur.execute(
                """
                select greatest(coalesce(reltuples, 0), 0)::bigint as events_estimated_rows
                from pg_class
                where oid = %s::regclass
                """,
                (event_relation,),
            )
            estimate = dict(cur.fetchone() or {})
            cur.execute(
                f"select coalesce(max(id), 0)::bigint as events_max_id from {event_relation}"
            )
            maximum = dict(cur.fetchone() or {})
            cutoff_utc = (_now_utc() - timedelta(hours=24)).isoformat(timespec="microseconds")
            cur.execute(
                f"""
                select count(*)::bigint as events_last_24h
                from {event_relation}
                where time_created_utc >= %s
                """,
                (cutoff_utc,),
            )
            recent = dict(cur.fetchone() or {})
            cur.execute(
                """
                select relname as table_name,
                       n_live_tup::bigint as live_rows,
                       n_dead_tup::bigint as dead_rows,
                       pg_total_relation_size(relid)::bigint as total_bytes,
                       last_analyze,
                       last_autoanalyze,
                       last_vacuum,
                       last_autovacuum
                from pg_stat_user_tables
                order by pg_total_relation_size(relid) desc, relname
                limit 25
                """
            )
            tables = [dict(row) for row in cur.fetchall()]
    return {
        **database,
        **estimate,
        **maximum,
        **recent,
        "tables": tables,
    }


def _physical_event_relation(cur) -> str:
    cur.execute(
        """select to_regclass('public.events') is not null as v1_available,
                  to_regclass('public.events_v2_core') is not null as v2_available"""
    )
    row = cur.fetchone() or {}
    if row.get("v1_available"):
        return "events"
    if row.get("v2_available"):
        return "events_v2_core"
    raise RuntimeError("no physical event relation is available")


def _snapshot_interval_minutes(value: int | None = None) -> int:
    if value is not None:
        return max(0, int(value))
    try:
        return max(0, int(os.getenv("ADLOG_STORAGE_SNAPSHOT_MIN_INTERVAL_MINUTES", str(DEFAULT_SNAPSHOT_INTERVAL_MINUTES))))
    except ValueError:
        return DEFAULT_SNAPSHOT_INTERVAL_MINUTES


def record_storage_snapshot(
    *,
    source: str,
    source_job_id: int | None = None,
    source_run_id: str | None = None,
    force: bool = False,
    deep: bool = False,
    min_interval_minutes: int | None = None,
) -> dict[str, Any]:
    """Persist a bounded storage snapshot without modifying production data."""
    from server.sli.core.postgres_runtime_pipeline import connect
    from server.sli.storage.storage_policy import fmt_bytes

    ensure_storage_lifecycle_schema()
    interval = _snapshot_interval_minutes(min_interval_minutes)
    with connect() as conn:
        with conn.cursor() as cur:
            if source_run_id:
                cur.execute(f"select * from {SNAPSHOT_TABLE} where source_run_id=%s", (str(source_run_id),))
                existing = cur.fetchone()
                if existing:
                    return {"status": "skipped", "reason": "source_run_already_recorded", "snapshot": dict(existing)}
            cur.execute(f"select captured_at from {SNAPSHOT_TABLE} order by captured_at desc limit 1")
            latest = cur.fetchone()
    latest_at = _as_utc(latest.get("captured_at") if latest else None)
    age_minutes = None
    if latest_at:
        age_minutes = max(0.0, (_now_utc() - latest_at).total_seconds() / 60.0)
    if not force and latest_at and age_minutes is not None and age_minutes < interval:
        return {
            "status": "skipped",
            "reason": "minimum_interval_not_elapsed",
            "latest_captured_at": latest_at.isoformat(),
            "age_minutes": round(age_minutes, 2),
            "minimum_interval_minutes": interval,
        }

    filesystem = _filesystem_snapshot(deep=deep)
    postgres = _postgres_snapshot()
    sizes = filesystem["sizes"]
    disk = filesystem["disk"]
    scan_meta = {
        name: {
            "path": item.get("path"),
            "exists": item.get("exists"),
            "files_seen": item.get("files_seen"),
            "dirs_seen": item.get("dirs_seen"),
            "truncated": item.get("truncated"),
            "reason": item.get("reason"),
            "duration_ms": item.get("duration_ms"),
        }
        for name, item in sizes.items()
    }
    values = {
        "database_bytes": _safe_int(postgres.get("database_bytes")),
        "events_estimated_rows": _safe_int(postgres.get("events_estimated_rows")),
        "events_max_id": _safe_int(postgres.get("events_max_id")),
        "events_last_24h": _safe_int(postgres.get("events_last_24h")),
        "raw_bytes": _safe_int(sizes["raw"].get("bytes")),
        "raw_archive_bytes": _safe_int(sizes["raw_archive"].get("bytes")),
        "backups_bytes": _safe_int(sizes["backups"].get("bytes")),
        "logs_bytes": _safe_int(sizes["logs"].get("bytes")),
        "reports_bytes": _safe_int(sizes["reports"].get("bytes")),
        "artifacts_bytes": _safe_int(sizes["artifacts"].get("bytes")),
        "disk_total_bytes": _safe_int(disk.get("total_bytes")),
        "disk_used_bytes": _safe_int(disk.get("used_bytes")),
        "disk_free_bytes": _safe_int(disk.get("free_bytes")),
        "disk_free_percent": _safe_float(disk.get("free_percent")),
    }
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                insert into {SNAPSHOT_TABLE}(
                    source, source_job_id, source_run_id, database_bytes, events_estimated_rows,
                    events_max_id, events_last_24h, raw_bytes, raw_archive_bytes,
                    backups_bytes, logs_bytes, reports_bytes, artifacts_bytes,
                    disk_total_bytes, disk_used_bytes, disk_free_bytes,
                    disk_free_percent, table_stats_json, scan_meta_json
                ) values (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    %s::jsonb, %s::jsonb
                )
                on conflict(source_run_id) do nothing
                returning *
                """,
                (
                    str(source or "manual")[:80], source_job_id, str(source_run_id) if source_run_id else None,
                    values["database_bytes"], values["events_estimated_rows"],
                    values["events_max_id"], values["events_last_24h"],
                    values["raw_bytes"], values["raw_archive_bytes"],
                    values["backups_bytes"], values["logs_bytes"],
                    values["reports_bytes"], values["artifacts_bytes"],
                    values["disk_total_bytes"], values["disk_used_bytes"],
                    values["disk_free_bytes"], values["disk_free_percent"],
                    json.dumps(postgres.get("tables") or [], ensure_ascii=False, default=str),
                    json.dumps(scan_meta, ensure_ascii=False, default=str),
                ),
            )
            row = cur.fetchone()
            if row is None and source_run_id:
                cur.execute(f"select * from {SNAPSHOT_TABLE} where source_run_id=%s", (str(source_run_id),))
                row = cur.fetchone()
    snapshot = dict(row or {})
    snapshot["database_human"] = fmt_bytes(snapshot.get("database_bytes"))
    snapshot["raw_human"] = fmt_bytes(snapshot.get("raw_bytes"))
    snapshot["raw_archive_human"] = fmt_bytes(snapshot.get("raw_archive_bytes"))
    snapshot["disk_free_human"] = fmt_bytes(snapshot.get("disk_free_bytes"))
    return {
        "status": "ok",
        "backend": "postgres",
        "snapshot": snapshot,
        "minimum_interval_minutes": interval,
        "safety": {
            "read_only_measurement": True,
            "production_tables_modified": False,
            "vacuum_executed": False,
            "reindex_executed": False,
            "drop_executed": False,
        },
    }


def _snapshot_total(row: dict[str, Any]) -> int:
    return sum(
        _safe_int(row.get(name))
        for name in (
            "database_bytes", "raw_bytes", "raw_archive_bytes", "backups_bytes",
            "logs_bytes", "reports_bytes", "artifacts_bytes",
        )
    )


def _growth(current: dict[str, Any], previous: dict[str, Any] | None) -> dict[str, Any]:
    from server.sli.storage.storage_policy import fmt_bytes

    current_at = _as_utc(current.get("captured_at"))
    previous_at = _as_utc(previous.get("captured_at")) if previous else None
    if not current_at or not previous_at:
        return {
            "status": "pending",
            "quality": "baseline_only",
            "reason": "a second snapshot is required for measured growth",
            "elapsed_hours": 0,
        }
    elapsed_seconds = max(1.0, (current_at - previous_at).total_seconds())
    elapsed_hours = elapsed_seconds / 3600.0
    elapsed_days = elapsed_seconds / 86400.0
    fields = (
        "database_bytes", "raw_bytes", "raw_archive_bytes", "backups_bytes",
        "logs_bytes", "reports_bytes", "artifacts_bytes", "disk_used_bytes",
    )
    deltas: dict[str, Any] = {}
    for field in fields:
        delta = _safe_int(current.get(field)) - _safe_int(previous.get(field))
        per_day = int(round(delta / elapsed_days))
        deltas[field] = {
            "delta_bytes": delta,
            "delta_human": fmt_bytes(abs(delta)),
            "direction": "growth" if delta > 0 else "reduction" if delta < 0 else "stable",
            "bytes_per_day": per_day,
            "per_day_human": fmt_bytes(abs(per_day)),
        }
    total_delta = _snapshot_total(current) - _snapshot_total(previous)
    total_per_day = int(round(total_delta / elapsed_days))
    operational_fields = ("database_bytes", "raw_bytes", "raw_archive_bytes", "logs_bytes", "reports_bytes")
    operational_delta = sum(_safe_int(current.get(field)) - _safe_int(previous.get(field)) for field in operational_fields)
    operational_per_day = int(round(operational_delta / elapsed_days))
    quality = "measured_24h" if 20 <= elapsed_hours <= 36 else "measured_partial"
    return {
        "status": "ok",
        "quality": quality,
        "from": previous_at.isoformat(),
        "to": current_at.isoformat(),
        "elapsed_hours": round(elapsed_hours, 2),
        "components": deltas,
        "managed_total_delta_bytes": total_delta,
        "managed_total_delta_human": fmt_bytes(abs(total_delta)),
        "managed_bytes_per_day": total_per_day,
        "managed_per_day_human": fmt_bytes(abs(total_per_day)),
        "operational_delta_bytes": operational_delta,
        "operational_delta_human": fmt_bytes(abs(operational_delta)),
        "operational_bytes_per_day": operational_per_day,
        "operational_per_day_human": fmt_bytes(abs(operational_per_day)),
        "direction": "growth" if operational_delta > 0 else "reduction" if operational_delta < 0 else "stable",
    }


def _fallback_estimate(current: dict[str, Any]) -> dict[str, Any]:
    from server.sli.core.paths import DATA_DIR
    from server.sli.storage.storage_policy import _growth_bytes_per_day, fmt_bytes

    rows = max(1, _safe_int(current.get("events_estimated_rows")), _safe_int(current.get("events_max_id")))
    database_bytes = _safe_int(current.get("database_bytes"))
    events_last_24h = _safe_int(current.get("events_last_24h"))
    bytes_per_event = database_bytes / rows if rows else 0.0
    database_estimate = int(round(events_last_24h * bytes_per_event))
    raw = _growth_bytes_per_day([DATA_DIR / "raw"], lookback_hours=24, max_entries=20000)
    estimated_total = database_estimate + _safe_int(raw.get("bytes"))
    return {
        "status": "ok",
        "quality": "estimated_until_24h_history",
        "database": {
            "events_last_24h": events_last_24h,
            "estimated_bytes_per_event": round(bytes_per_event, 2),
            "estimated_bytes_per_day": database_estimate,
            "estimated_per_day_human": fmt_bytes(database_estimate),
        },
        "raw": raw,
        "estimated_managed_bytes_per_day": estimated_total,
        "estimated_managed_per_day_human": fmt_bytes(estimated_total),
        "limitations": [
            "PostgreSQL growth is estimated from current database bytes per estimated event row until two storage snapshots exist.",
            "Raw growth uses file modification times in the last 24 hours.",
        ],
    }


def _forecast(current: dict[str, Any], growth_bytes_per_day: int, thresholds: dict[str, Any]) -> dict[str, Any]:
    from server.sli.storage.storage_policy import fmt_bytes

    total = _safe_int(current.get("disk_total_bytes"))
    free = _safe_int(current.get("disk_free_bytes"))
    effective = thresholds.get("effective") or {}
    items: dict[str, Any] = {}
    for name, key in (
        ("warn", "warn_free_percent"),
        ("stop", "stop_free_percent"),
        ("critical", "critical_free_percent"),
    ):
        percent = _safe_float(effective.get(key))
        reserve = int(total * percent / 100.0)
        usable = max(0, free - reserve)
        days = None if growth_bytes_per_day <= 0 else round(usable / growth_bytes_per_day, 2)
        items[name] = {
            "free_percent": percent,
            "reserve_bytes": reserve,
            "reserve_human": fmt_bytes(reserve),
            "current_headroom_bytes": usable,
            "current_headroom_human": fmt_bytes(usable),
            "estimated_days": days,
        }
    return {
        "status": "ok" if growth_bytes_per_day > 0 else "stable_or_unknown",
        "growth_bytes_per_day_used": growth_bytes_per_day,
        "growth_per_day_human": fmt_bytes(abs(growth_bytes_per_day)),
        "thresholds": items,
    }


def _read_backup_restore_evidence() -> dict[str, Any] | None:
    from server.sli.core.paths import DATA_DIR

    path = DATA_DIR / "maintenance" / BACKUP_RESTORE_LAST
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    payload["path"] = str(path)
    return payload


def get_storage_lifecycle_status(*, history_limit: int = 48, include_estimate: bool = True) -> dict[str, Any]:
    from server.sli.core.postgres_runtime_pipeline import connect
    from server.sli.storage.storage_policy import fmt_bytes, load_storage_policy

    try:
        schema = ensure_storage_lifecycle_schema()
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"select * from {SNAPSHOT_TABLE} order by captured_at desc limit %s",
                    (max(2, min(int(history_limit), 200)),),
                )
                rows = [dict(row) for row in cur.fetchall()]
    except Exception as exc:
        return {
            "status": "unavailable",
            "backend": "postgres",
            "generated_at_utc": _iso(),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    thresholds = validate_storage_thresholds(load_storage_policy())
    current = rows[0] if rows else None
    previous: dict[str, Any] | None = None
    if current:
        current_at = _as_utc(current.get("captured_at"))
        if current_at:
            eligible: list[tuple[float, dict[str, Any]]] = []
            for row in rows[1:]:
                row_at = _as_utc(row.get("captured_at"))
                if not row_at:
                    continue
                hours = (current_at - row_at).total_seconds() / 3600.0
                if hours > 0:
                    eligible.append((hours, row))
            preferred = [item for item in eligible if item[0] >= 20]
            pool = preferred or eligible
            if pool:
                previous = min(pool, key=lambda item: abs(item[0] - 24.0))[1]
    measured = _growth(current, previous) if current else {"status": "pending", "quality": "no_baseline", "reason": "no snapshots recorded"}
    estimate = _fallback_estimate(current) if current and include_estimate else None
    if measured.get("status") == "ok":
        growth_for_forecast = _safe_int(measured.get("operational_bytes_per_day"))
        forecast_source = measured.get("quality")
    else:
        growth_for_forecast = _safe_int((estimate or {}).get("estimated_managed_bytes_per_day"))
        forecast_source = (estimate or {}).get("quality")
    forecast = _forecast(current, growth_for_forecast, thresholds) if current else {"status": "pending"}
    if current:
        current["database_human"] = fmt_bytes(current.get("database_bytes"))
        current["raw_human"] = fmt_bytes(current.get("raw_bytes"))
        current["raw_archive_human"] = fmt_bytes(current.get("raw_archive_bytes"))
        current["disk_free_human"] = fmt_bytes(current.get("disk_free_bytes"))
        current["managed_total_bytes"] = _snapshot_total(current)
        current["managed_total_human"] = fmt_bytes(current["managed_total_bytes"])
    backup = _read_backup_restore_evidence()
    bloat_warnings: list[dict[str, Any]] = []
    if current:
        for item in current.get("table_stats_json") or []:
            live = _safe_int(item.get("live_rows"))
            dead = _safe_int(item.get("dead_rows"))
            ratio = dead / max(1, live + dead)
            if dead >= 100_000 and ratio >= 0.20:
                bloat_warnings.append({
                    "table_name": item.get("table_name"),
                    "dead_rows": dead,
                    "dead_ratio": round(ratio, 4),
                    "action": "observe_only",
                })
    status = "pending"
    reasons: list[str] = []
    if current:
        status = "ok"
    else:
        reasons.append("record the first storage snapshot")
    if thresholds.get("status") != "ok":
        status = "warn"
        reasons.extend(thresholds.get("issues") or [])
    if not backup or backup.get("status") not in {"ok", "verified"}:
        if status == "ok":
            status = "pending"
        reasons.append("successful PostgreSQL backup/restore rehearsal evidence is not recorded yet")
    if measured.get("quality") != "measured_24h":
        if status == "ok":
            status = "pending"
        reasons.append("24-hour measured growth window is not complete yet")
    return {
        "status": status,
        "backend": "postgres",
        "generated_at_utc": _iso(),
        "schema": schema,
        "thresholds": thresholds,
        "latest_snapshot": current,
        "snapshot_count": len(rows),
        "measured_growth": measured,
        "fallback_estimate": estimate,
        "forecast": {**forecast, "source": forecast_source},
        "backup_restore_rehearsal": backup or {"status": "not_run"},
        "bloat_observation": {
            "status": "warn" if bloat_warnings else "ok",
            "warnings": bloat_warnings,
            "automatic_vacuum": False,
            "automatic_reindex": False,
            "automatic_drop": False,
        },
        "reasons": list(dict.fromkeys(reasons)),
        "safety": {
            "measurement_read_only": True,
            "raw_archive_first": True,
            "vacuum_automatic": False,
            "reindex_automatic": False,
            "drop_production_objects": False,
        },
    }
