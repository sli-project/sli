#!/usr/bin/env python3
"""Collect a compact diagnostics bundle for developer/support analysis.

Safe and fast by default:
- log tails, bounded storage estimates and short DB/health snapshots;
- no raw events, SQLite DB files or secrets;
- every optional heavy block has a timeout/fast fallback.
Use --deep only when a developer explicitly needs slower storage/DB details.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.maintenance.bundle_common import (  # noqa: E402
    DATA_DIR,
    DIAGNOSTICS_DIR,
    LOG_DIR,
    PROJECT_ROOT,
    assess_recent_internal_errors,
    audit_action,
    basic_project_snapshot,
    dir_size_report,
    fmt_bytes,
    redact_env_file,
    run_command,
    tail_lines,
    timestamp,
    write_json,
    write_text,
    zip_dir,
)
from server.sli.core.database import active_backend, is_postgres_runtime_db  # noqa: E402
from server.sli.ops.version import get_release_metadata  # noqa: E402

LOG_FILES = [
    "adlog-monitor.log",
    "internal-errors.log",
    "performance-events.log",
    "self-test.log",
    "release-check.log",
    "audit-actions.log",
]

STATUS_RANK = {"ok": 0, "warn": 1, "warning": 1, "failed": 2, "error": 2, "critical": 2}


def _diag_progress(message: str) -> None:
    if os.environ.get("ADLOG_DIAG_QUIET") != "1":
        print(f"[diag] {message}", file=sys.stderr, flush=True)


def _timed_call(name: str, func: Callable[[], Any]) -> dict[str, Any]:
    _diag_progress(f"{name}...")
    started = time.monotonic()
    try:
        return {"status": "ok", "duration_ms": int((time.monotonic() - started) * 1000), "data": func()}
    except Exception as exc:  # defensive diagnostics path
        return {
            "status": "failed",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error_type": type(exc).__name__,
            "error": str(exc),
            "source": name,
        }


def _worst_status(statuses: list[str]) -> str:
    worst = "ok"
    for status in statuses:
        if STATUS_RANK.get(str(status).lower(), 0) > STATUS_RANK[worst]:
            worst = "failed" if STATUS_RANK.get(str(status).lower(), 0) >= 2 else "warn"
    return worst


def _json_from_command_stdout(command_result: dict[str, Any]) -> dict[str, Any] | None:
    text = str(command_result.get("stdout_tail") or "").strip()
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except Exception:
        return None


def _postgres_db_snapshot(*, deep: bool = False, query_timeout_ms: int = 3000) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {
        "backend": "postgres",
        "exists": False,
        "mode": "deep" if deep else "fast",
        "query_timeout_ms": query_timeout_ms,
    }
    warnings: list[str] = []
    try:
        from server.sli.core.postgres_runtime_pipeline import connect

        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"set local statement_timeout = {max(100, int(query_timeout_ms))}")
                cur.execute("select current_database() as database_name, pg_database_size(current_database()) as size_bytes")
                row = cur.fetchone() or {}
                result["database_name"] = row.get("database_name")
                result["size_bytes"] = int(row.get("size_bytes") or 0)
                result["size_human"] = fmt_bytes(result["size_bytes"])
                cur.execute("select table_name from information_schema.tables where table_schema = 'public' order by table_name")
                result["tables"] = [row.get("table_name") for row in cur.fetchall()]
                if "schema_migrations" in result["tables"]:
                    cur.execute("select coalesce(max(version), 0) as version from schema_migrations")
                    row = cur.fetchone() or {}
                    result["schema_migration_version"] = int(row.get("version") or 0)
                if "events" in result["tables"] or "events_v2_core" in result["tables"]:
                    event_relation = _physical_event_relation(cur)
                    if deep:
                        cur.execute(f"select count(*) as count from {event_relation}")
                        row = cur.fetchone() or {}
                        result["events_total"] = int(row.get("count") or 0)
                        result["events_total_estimated"] = False
                        channel_expression = "channel.value" if event_relation == "events_v2_core" else "e.channel"
                        channel_join = (
                            "join storage_v2_channel channel on channel.id=e.channel_id"
                            if event_relation == "events_v2_core" else ""
                        )
                        cur.execute(
                            f"""
                            select s.hostname as server, {channel_expression} as channel, count(*) as events,
                                   max(e.event_record_id) as max_event_record_id,
                                   max(e.time_created_utc) as latest_event_time_utc
                            from {event_relation} e join servers s on s.id = e.server_id
                            {channel_join}
                            group by s.hostname, {channel_expression}
                            order by events desc, s.hostname, {channel_expression}
                            """
                        )
                        result["events_by_server_channel"] = [dict(row) for row in cur.fetchall()]
                    else:
                        cur.execute(
                            "select greatest(reltuples, 0)::bigint as count from pg_class where oid = %s::regclass",
                            (event_relation,),
                        )
                        row = cur.fetchone() or {}
                        result["events_total"] = int(row.get("count") or 0)
                        result["events_total_estimated"] = True
                        result["events_by_server_channel"] = []
                        warnings.append("events_by_server_channel skipped in fast diagnostics mode; rerun with --deep if needed")
                if "collector_channel_runs" in result["tables"]:
                    result["recent_collector_jobs"] = _recent_collector_jobs_pg(cur)
                result["exists"] = True
    except Exception as exc:
        result["db_probe_error"] = {"error_type": type(exc).__name__, "error": str(exc)}
    if warnings:
        result["warnings"] = warnings
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    return result


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


def _db_snapshot(*, deep: bool = False, query_timeout_ms: int = 3000) -> dict[str, Any]:
    if is_postgres_runtime_db():
        return _postgres_db_snapshot(deep=deep, query_timeout_ms=query_timeout_ms)
    return {
        "exists": False,
        "mode": "deep" if deep else "fast",
        "backend": active_backend(),
        "db_probe_error": {
            "error_type": "UnsupportedBackend",
            "error": "runtime database backend is not postgres; SQLite runtime is removed",
        },
    }


def _recent_collector_jobs_pg(cur, limit: int = 20) -> list[dict[str, Any]]:
    try:
        cur.execute(
            """
            select job_id,
                   min(created_at) as first_seen_utc,
                   max(created_at) as last_seen_utc,
                   count(*) as channel_rows,
                   count(distinct server) as servers,
                   sum(inserted) as inserted,
                   sum(skipped) as skipped,
                   sum(count) as collected,
                   max(import_queue_wait_ms) as max_import_queue_wait_ms,
                   max(import_duration_ms) as max_import_duration_ms,
                   max(total_duration_ms) as max_total_duration_ms,
                   sum(case when status not in ('completed', 'ok') then 1 else 0 end) as non_completed_rows
            from collector_channel_runs
            where job_id is not null
            group by job_id
            order by max(created_at) desc
            limit %s
            """,
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]
    except Exception:
        return []

def _health_snapshots(*, include_system_health: bool = False) -> dict[str, Any]:
    snapshots: dict[str, Any] = {}
    if include_system_health:
        try:
            from server.sli.ops.system_health import get_system_health
            snapshots["system_health"] = _timed_call("system_health", get_system_health)
        except Exception as exc:
            snapshots["system_health"] = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
    else:
        snapshots["system_health"] = {"status": "skipped", "reason": "skipped in fast diagnostics mode; release_check + storage snapshot are used instead"}
    try:
        from server.sli.sources.collector_health import get_collector_health
        snapshots["collector_health"] = _timed_call("collector_health", get_collector_health)
    except Exception as exc:
        snapshots["collector_health"] = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
    try:
        from server.jobs.collector import list_jobs
        snapshots["jobs"] = _timed_call("jobs", lambda: {"items": list_jobs()})
    except Exception as exc:
        snapshots["jobs"] = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
    return snapshots


def _storage_snapshot(*, deep: bool = False) -> dict[str, Any]:
    started = time.monotonic()
    paths = {
        "project": PROJECT_ROOT,
        "data": DATA_DIR,
        "raw": DATA_DIR / "raw",
        "raw_archive": DATA_DIR / "raw_archive",
        "processed": DATA_DIR / "processed",
        "reports": DATA_DIR / "reports",
        "logs": LOG_DIR,
        "backups": DATA_DIR / "backups",
        "legacy_backups": PROJECT_ROOT / "backups",
        "diagnostics": DATA_DIR / "diagnostics",
        "handoff": DATA_DIR / "handoff",
        "report_captures": DATA_DIR / "report_captures",
    }
    limits = {
        "project": (12000 if deep else 4000, 10.0 if deep else 2.5),
        "data": (12000 if deep else 5000, 10.0 if deep else 2.5),
        "raw": (20000 if deep else 3000, 12.0 if deep else 2.0),
        "raw_archive": (5000 if deep else 1000, 5.0 if deep else 1.0),
        "processed": (3000, 2.0),
        "reports": (3000, 1.5),
        "logs": (3000, 1.5),
        "backups": (3000 if deep else 1000, 3.0 if deep else 1.0),
        "legacy_backups": (3000 if deep else 1000, 3.0 if deep else 1.0),
        "diagnostics": (1000, 1.0),
        "handoff": (1000, 1.0),
        "report_captures": (1000, 1.0),
    }
    sizes: dict[str, Any] = {}
    for name, path in paths.items():
        max_entries, max_seconds = limits.get(name, (1000, 1.0))
        sizes[name] = dir_size_report(path, max_entries=max_entries, max_seconds=max_seconds, skip_dir_names={".venv", ".git", "__pycache__", ".pytest_cache", "bin", "obj"})
    return {
        "mode": "deep_bounded" if deep else "fast_bounded",
        "data_dir": str(DATA_DIR),
        "sizes": sizes,
        "data_size_bytes": sizes["data"]["bytes"],
        "data_size_human": sizes["data"]["human"],
        "logs_size_bytes": sizes["logs"]["bytes"],
        "logs_size_human": sizes["logs"]["human"],
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


def _extract_health_warnings(snapshots: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    warnings: list[str] = []
    stale_channels: list[dict[str, Any]] = []
    system_status = (snapshots.get("system_health") or {}).get("status")
    system_data = ((snapshots.get("system_health") or {}).get("data") or {})
    if system_status == "failed":
        warnings.append("system_health snapshot failed")
    if system_data.get("status") in {"warn", "warning", "failed"}:
        warnings.append(f"system_health status={system_data.get('status')}")
    for item in system_data.get("warnings") or []:
        warnings.append(str(item))
    collector_snapshot = snapshots.get("collector_health") or {}
    collector_data = collector_snapshot.get("data") or {}
    if collector_snapshot.get("status") == "failed":
        warnings.append("collector_health snapshot failed")
    summary = collector_data.get("summary") or {}
    for key in ("high", "warn", "security_high", "security_warn", "timeouts_24h", "partial_timeouts_24h"):
        value = int(summary.get(key) or 0)
        if value:
            warnings.append(f"collector summary {key}={value}")
    for item in collector_data.get("items") or []:
        severity = str(item.get("severity") or "ok").lower()
        item_warnings = item.get("warnings") or []
        lag = item.get("lag_minutes")
        if severity in {"warn", "warning", "high", "critical", "failed"} or item_warnings:
            stale_channels.append(
                {
                    "server": item.get("server"),
                    "channel": item.get("channel"),
                    "severity": severity,
                    "lag_minutes": lag,
                    "warnings": item_warnings,
                    "freshness_label": item.get("freshness_label"),
                }
            )
    if stale_channels:
        warnings.append(f"stale or warning collector channels={len(stale_channels)}")
    return warnings, stale_channels


def _top_slow_stages(performance_tail: str, limit: int = 15) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    by_stage: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "total_duration_ms": 0, "max_duration_ms": 0})
    for line in performance_tail.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        duration = item.get("duration_ms")
        stage = item.get("stage")
        if duration is None or not stage:
            continue
        try:
            duration_int = int(duration)
        except Exception:
            continue
        compact = {
            "ts": item.get("ts"),
            "job_id": item.get("job_id"),
            "trace_id": item.get("trace_id"),
            "server": item.get("server"),
            "channel": item.get("channel"),
            "stage": stage,
            "status": item.get("status"),
            "duration_ms": duration_int,
            "events_count": item.get("events_count"),
            "queue_wait_ms": item.get("queue_wait_ms"),
        }
        events.append(compact)
        bucket = by_stage[str(stage)]
        bucket["count"] += 1
        bucket["total_duration_ms"] += duration_int
        bucket["max_duration_ms"] = max(bucket["max_duration_ms"], duration_int)
    for stage, bucket in by_stage.items():
        bucket["stage"] = stage
        bucket["avg_duration_ms"] = int(bucket["total_duration_ms"] / bucket["count"]) if bucket["count"] else 0
    return {
        "top_events": sorted(events, key=lambda item: item["duration_ms"], reverse=True)[:limit],
        "by_stage": sorted(by_stage.values(), key=lambda item: item["max_duration_ms"], reverse=True)[:limit],
    }


def _event_volume_summary(db_snapshot: dict[str, Any], limit: int = 12) -> dict[str, Any]:
    rows = db_snapshot.get("events_by_server_channel") or []
    total = int(db_snapshot.get("events_total") or 0)
    top = []
    for row in rows[:limit]:
        events = int(row.get("events") or 0)
        item = dict(row)
        item["percent"] = round((events / total) * 100, 2) if total else 0
        top.append(item)
    by_channel = Counter()
    for row in rows:
        by_channel[str(row.get("channel") or "unknown")] += int(row.get("events") or 0)
    return {
        "events_total": total,
        "mode": db_snapshot.get("mode"),
        "top_server_channel": top,
        "by_channel": [
            {"channel": channel, "events": count, "percent": round((count / total) * 100, 2) if total else 0}
            for channel, count in by_channel.most_common(limit)
        ],
        "warnings": db_snapshot.get("warnings") or [],
    }


def _diagnostic_decision(
    *,
    checks: dict[str, Any],
    db_snapshot: dict[str, Any],
    health_warnings: list[str],
    internal_tail: str,
    storage: dict[str, Any],
) -> tuple[str, list[str]]:
    statuses = ["ok"]
    reasons: list[str] = []
    if internal_tail:
        statuses.append("warn")
        reasons.append("internal-errors.log has recent content")
    if db_snapshot.get("db_probe_error"):
        statuses.append("warn")
        reasons.append("database snapshot has probe errors")
    for warning in db_snapshot.get("warnings") or []:
        statuses.append("warn")
        reasons.append(str(warning))
    for check_name, check in checks.items():
        exit_code = check.get("exit_code")
        if check.get("timed_out"):
            statuses.append("warn")
            reasons.append(f"{check_name} timed out after {check.get('timeout_seconds')}s")
        elif exit_code not in (0, None):
            statuses.append("failed" if check_name == "compileall_quick" else "warn")
            reasons.append(f"{check_name} exit_code={exit_code}")
        parsed = _json_from_command_stdout(check)
        if parsed:
            parsed_status = str(parsed.get("status") or "ok")
            if parsed_status not in {"ok", ""}:
                statuses.append(parsed_status)
                reasons.append(f"{check_name} status={parsed_status}")
            for warning in parsed.get("warnings") or []:
                statuses.append("warn")
                reasons.append(f"{check_name}: {warning}")
    for warning in health_warnings:
        statuses.append("warn")
        reasons.append(warning)
    sizes = storage.get("sizes") or {}
    raw_bytes = int((sizes.get("raw") or {}).get("bytes") or 0)
    sqlite_bytes = int((sizes.get("processed") or {}).get("bytes") or 0)
    project_bytes = int((sizes.get("project") or {}).get("bytes") or 0)
    if raw_bytes > 1024**3:
        statuses.append("warn")
        extra = " (truncated estimate)" if (sizes.get("raw") or {}).get("truncated") else ""
        reasons.append(f"data/raw size is high: {(sizes.get('raw') or {}).get('human')}{extra}")
    if sqlite_bytes > 10 * 1024**3:
        statuses.append("warn")
        reasons.append(f"processed/SQLite size is high: {(sizes.get('processed') or {}).get('human')}")
    if project_bytes > 5 * 1024**3:
        statuses.append("warn")
        extra = " (truncated estimate)" if (sizes.get("project") or {}).get("truncated") else ""
        reasons.append(f"project size is high: {(sizes.get('project') or {}).get('human')}{extra}")
    return _worst_status(statuses), list(dict.fromkeys(str(item) for item in reasons if item))


def _summary_markdown(summary: dict[str, Any], *, stale_channels: list[dict[str, Any]], top_slow: dict[str, Any], event_volume: dict[str, Any]) -> str:
    reasons = summary.get("reasons") or []
    storage = summary.get("storage") or {}
    sizes = storage.get("sizes") or {}
    db = summary.get("db") or {}
    lines = [
        "# Diagnostics summary",
        "",
        f"Status: **{summary.get('status')}**",
        f"Mode: `{summary.get('mode')}`",
        f"Total duration: `{summary.get('duration_ms')} ms`",
        "",
        "## Reasons / warnings",
    ]
    if reasons:
        lines.extend(f"- {item}" for item in reasons[:30])
    else:
        lines.append("- none")
    lines.extend([
        "",
        "## Storage",
        f"- Project: {(sizes.get('project') or {}).get('human', 'unknown')}" + (" (truncated)" if (sizes.get('project') or {}).get('truncated') else ""),
        f"- Data: {(sizes.get('data') or {}).get('human', 'unknown')}" + (" (truncated)" if (sizes.get('data') or {}).get('truncated') else ""),
        f"- Raw: {(sizes.get('raw') or {}).get('human', 'unknown')}" + (" (truncated)" if (sizes.get('raw') or {}).get('truncated') else ""),
        f"- Processed/SQLite folder: {(sizes.get('processed') or {}).get('human', 'unknown')}",
        f"- Backups: {(sizes.get('backups') or {}).get('human', 'unknown')}",
        f"- Legacy backups: {(sizes.get('legacy_backups') or {}).get('human', 'unknown')}",
        f"- Logs: {(sizes.get('logs') or {}).get('human', 'unknown')}",
        "",
        "## Database",
        f"- Active backend: {db.get('backend', 'unknown')}",
        f"- Database: {db.get('database_name') or db.get('path') or 'unknown'}",
        f"- Size: {db.get('size_human', 'not found')}",
        f"- Events total: {db.get('events_total', '—')}",
        f"- Runtime schema migration version: {db.get('schema_migration_version', 'unknown')}",
        "",
        "## Top event volume by channel",
    ])
    if event_volume.get("by_channel"):
        for item in event_volume.get("by_channel") or []:
            lines.append(f"- {item.get('channel')}: {item.get('events')} ({item.get('percent')}%)")
    else:
        lines.append("- skipped in fast mode or query timed out; rerun with --deep if needed")
    lines.extend(["", "## Stale / warning collector channels"])
    if stale_channels:
        for item in stale_channels[:20]:
            lines.append(f"- {item.get('server')} / {item.get('channel')}: severity={item.get('severity')}, lag={item.get('lag_minutes')} min, {item.get('freshness_label')}")
    else:
        lines.append("- none")
    lines.extend(["", "## Top slow stages"])
    for item in top_slow.get("top_events") or []:
        lines.append(f"- {item.get('stage')} {item.get('server') or ''} {item.get('channel') or ''}: {item.get('duration_ms')} ms, events={item.get('events_count')}")
    lines.extend([
        "",
        "Open snapshots/health_snapshots.json, snapshots/database_snapshot.json, snapshots/storage_snapshot.json, snapshots/performance_summary.json and logs_tail/*.log for details.",
        "",
    ])
    return "\n".join(lines)


def build_diagnostics(
    *,
    out_dir: Path = DIAGNOSTICS_DIR,
    last_lines: int = 1200,
    include_release_check: bool = True,
    release_timeout: int = 45,
    deep: bool = False,
) -> dict[str, Any]:
    started = time.monotonic()
    out_dir.mkdir(parents=True, exist_ok=True)
    operation_id = f"OP-{timestamp()}-collect-diag"
    with __import__("tempfile").TemporaryDirectory(prefix="adlog-diagnostics-") as tmp:
        staging = Path(tmp) / "adlog-diagnostics"
        logs_dir = staging / "logs_tail"
        snapshots_dir = staging / "snapshots"
        staging.mkdir(parents=True, exist_ok=True)
        logs_dir.mkdir(parents=True, exist_ok=True)
        snapshots_dir.mkdir(parents=True, exist_ok=True)

        log_tails: dict[str, str] = {}
        for name in LOG_FILES:
            log_tails[name] = tail_lines(LOG_DIR / name, last_lines)
            write_text(logs_dir / name, log_tails[name])

        snapshots = _health_snapshots(include_system_health=deep)
        db_snapshot = _db_snapshot(deep=deep)
        storage = _storage_snapshot(deep=deep)
        health_warnings, stale_channels = _extract_health_warnings(snapshots)
        top_slow = _top_slow_stages(log_tails.get("performance-events.log") or "")
        event_volume = _event_volume_summary(db_snapshot)

        write_json(snapshots_dir / "health_snapshots.json", snapshots)
        write_json(snapshots_dir / "database_snapshot.json", db_snapshot)
        write_json(snapshots_dir / "storage_snapshot.json", storage)
        write_json(snapshots_dir / "performance_summary.json", top_slow)
        write_json(snapshots_dir / "event_volume_summary.json", event_volume)
        write_text(snapshots_dir / "ENV_REDACTED.txt", redact_env_file(PROJECT_ROOT / ".env"))

        checks: dict[str, Any] = {}
        check_env = {"ADLOG_TOOLKIT_DISABLE_AUDIT": "1", "ADLOG_SELFTEST_NO_LOG": "1"}
        if include_release_check:
            _diag_progress("release_check...")
            checks["release_check"] = run_command([sys.executable, "scripts/maintenance/release_check.py", "--json"], timeout=release_timeout, env_update=check_env)
        _diag_progress("self_test_offline...")
        checks["self_test_offline"] = run_command([sys.executable, "scripts/maintenance/self_test.py", "--offline", "--json"], timeout=45, env_update=check_env)
        _diag_progress("ui_nav_check...")
        checks["ui_nav_check"] = run_command([sys.executable, "scripts/maintenance/ui_nav_check.py", "--json"], timeout=30, env_update=check_env)
        _diag_progress("runtime_watchdog...")
        checks["runtime_watchdog"] = run_command([sys.executable, "scripts/maintenance/runtime_watchdog.py", "--json"], timeout=45, env_update=check_env)
        _diag_progress("storage_cleanup_dry_run...")
        checks["storage_cleanup_dry_run"] = run_command([sys.executable, "scripts/maintenance/storage_cleanup.py", "--dry-run", "--json", "--summary-only", "--no-audit"], timeout=45, env_update=check_env)
        _diag_progress("postgres_readiness...")
        checks["postgres_readiness"] = run_command([sys.executable, "scripts/maintenance/postgres_readiness.py", "--json"], timeout=15, env_update=check_env)
        _diag_progress("compileall_quick...")
        checks["compileall_quick"] = run_command([sys.executable, "-m", "compileall", "-q", "server", "sli_collect", "sli_agent", "scripts"], timeout=120, env_update=check_env)
        _diag_progress("baseline_snapshot...")
        checks["baseline_snapshot"] = run_command([sys.executable, "scripts/maintenance/baseline_snapshot.py", "--json"], timeout=60, env_update=check_env)
        write_json(snapshots_dir / "checks.json", checks)

        internal_errors = assess_recent_internal_errors(
            tail_lines(LOG_DIR / "internal-errors.log", 50),
            activity_text=tail_lines(LOG_DIR / "adlog-monitor.log", 1000),
        )
        internal_tail = internal_errors["active_text"]
        status, reasons = _diagnostic_decision(
            checks=checks,
            db_snapshot=db_snapshot,
            health_warnings=health_warnings,
            internal_tail=internal_tail,
            storage=storage,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        summary = {
            "package_type": "DIAGNOSTIC_BUNDLE",
            "operation_id": operation_id,
            "status": status,
            "mode": "deep_bounded" if deep else "fast_bounded",
            "duration_ms": duration_ms,
            "reasons": reasons,
            "generated_at_utc": basic_project_snapshot()["generated_at_utc"],
            "release_metadata": get_release_metadata(PROJECT_ROOT),
            "active_backend": active_backend(),
            "db": {k: db_snapshot.get(k) for k in ("backend", "exists", "database_name", "path", "size_human", "events_total", "pragma_user_version", "schema_migration_version", "duration_ms")},
            "storage": storage,
            "stale_channels": stale_channels,
            "top_slow_stages": top_slow,
            "event_volume_summary": event_volume,
            "checks_duration_ms": {name: item.get("duration_ms") for name, item in checks.items()},
            "slowest_check": max(({"name": name, "duration_ms": item.get("duration_ms") or 0} for name, item in checks.items()), key=lambda x: x["duration_ms"], default=None),
        }
        write_json(staging / "MANIFEST.json", {**basic_project_snapshot(), **summary})
        write_text(staging / "SUMMARY.md", _summary_markdown(summary, stale_channels=stale_channels, top_slow=top_slow, event_volume=event_volume))
        zip_path = out_dir / f"adlog-diagnostics-{timestamp()}.zip"
        zip_dir(staging, zip_path)
    result = {"status": status, "operation_id": operation_id, "zip_path": str(zip_path), "duration_ms": int((time.monotonic() - started) * 1000), "reasons": reasons}
    audit_action("collect_diagnostics", "completed", operation_id=operation_id, zip_path=str(zip_path), diagnostic_status=status, duration_ms=result["duration_ms"])
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect safe diagnostics bundle for developer analysis.")
    parser.add_argument("--out", type=Path, default=DIAGNOSTICS_DIR)
    parser.add_argument("--last-lines", type=int, default=1200)
    parser.add_argument("--skip-release-check", action="store_true")
    parser.add_argument("--release-timeout", type=int, default=45)
    parser.add_argument("--deep", action="store_true", help="allow slower bounded DB/storage/system-health details")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = build_diagnostics(
        out_dir=args.out,
        last_lines=args.last_lines,
        include_release_check=not args.skip_release_check,
        release_timeout=args.release_timeout,
        deep=args.deep,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Diagnostics bundle created: {result['zip_path']}")
        print(f"Status: {result['status']}")
        print(f"Duration: {result.get('duration_ms')} ms")
        for reason in result.get("reasons") or []:
            print(f"- {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
