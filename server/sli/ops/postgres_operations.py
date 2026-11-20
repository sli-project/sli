from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
from typing import Any

from server.sli.core.database import active_backend


def _human_bytes(value: int | float | None) -> str:
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{int(value or 0)} B"


def _redact_query_preview(value: Any) -> str:
    text = str(value or "")[:500]
    text = re.sub(r"'(?:''|[^'])*'", "'<redacted>'", text)
    text = re.sub(r'\b\d{5,}\b', '<number>', text)
    return text


def _discover_backup_tools() -> dict[str, Any]:
    suffix = ".exe" if os.name == "nt" else ""
    found = {"pg_dump": shutil.which("pg_dump"), "pg_restore": shutil.which("pg_restore")}
    searched = ["PATH"]
    candidates: list[Path] = []
    explicit = os.getenv("ADLOG_PG_BIN_DIR")
    if explicit:
        candidates.append(Path(explicit))
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.getenv(env_name)
        if not root:
            continue
        base = Path(root) / "PostgreSQL"
        if base.is_dir():
            candidates.extend(item / "bin" for item in sorted(base.iterdir(), key=lambda item: item.name, reverse=True) if item.is_dir())
    for directory in candidates:
        searched.append(str(directory))
        for name in tuple(found):
            if found[name]:
                continue
            candidate = directory / f"{name}{suffix}"
            if candidate.is_file():
                found[name] = str(candidate)
    available = bool(found["pg_dump"] and found["pg_restore"])
    return {
        **found,
        "available": available,
        "status": "ready" if available else "not_ready",
        "searched": searched,
        "executed": False,
        "runbook": "docs/POSTGRES_OPERATIONS_RUNBOOK.md",
    }


def get_postgres_operations_status(*, table_limit: int = 20, long_query_seconds: int = 60) -> dict[str, Any]:
    """Return bounded PostgreSQL operations metrics without changing database state."""
    if active_backend() != "postgres":
        return {
            "status": "skipped",
            "backend": active_backend(),
            "available": False,
            "connectivity_status": "not_applicable",
            "metrics_status": "not_applicable",
            "reason": "PostgreSQL operations metrics are only queried for postgres runtime.",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "tables": [],
            "long_running_queries": [],
            "warnings": [],
        }

    clean_limit = max(1, min(int(table_limit or 20), 100))
    threshold = max(5, min(int(long_query_seconds or 60), 3600))
    from server.sli.core.postgres_runtime_pipeline import connect

    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("set local statement_timeout = '3000ms'")
            cur.execute("set local lock_timeout = '1000ms'")
            cur.execute(
                """
                select current_database() as database_name,
                       pg_database_size(current_database()) as database_bytes,
                       now() as checked_at
                """
            )
            database = dict(cur.fetchone() or {})
    except Exception as exc:
        return {
            "status": "failed",
            "backend": "postgres",
            "available": False,
            "connectivity_status": "unavailable",
            "metrics_status": "unavailable",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "error_type": type(exc).__name__,
            "tables": [],
            "long_running_queries": [],
            "warnings": ["PostgreSQL operations metrics could not be read."],
        }

    limitations: list[dict[str, str]] = []
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("set local statement_timeout = '3000ms'")
            cur.execute("set local lock_timeout = '1000ms'")
            cur.execute(
                """
                select stats.relname as table_name,
                       stats.n_live_tup::bigint as live_rows,
                       stats.n_dead_tup::bigint as dead_rows,
                       (greatest(c.relpages, 0)::bigint * current_setting('block_size')::bigint) as total_bytes,
                       stats.last_analyze,
                       stats.last_autoanalyze,
                       stats.last_vacuum,
                       stats.last_autovacuum
                from pg_stat_user_tables stats
                join pg_class c on c.oid=stats.relid
                order by c.relpages desc, stats.relname
                limit %s
                """,
                (clean_limit,),
            )
            tables = [dict(row) for row in cur.fetchall()]
    except Exception as exc:
        tables = []
        limitations.append({"metric": "table_statistics", "error_type": type(exc).__name__})

    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("set local statement_timeout = '3000ms'")
            cur.execute("set local lock_timeout = '1000ms'")
            cur.execute(
                """
                select pid,
                       usename as user_name,
                       application_name,
                       state,
                       extract(epoch from (now() - query_start))::bigint as duration_seconds,
                       left(query, 500) as query_preview
                from pg_stat_activity
                where datname = current_database()
                  and pid <> pg_backend_pid()
                  and state <> 'idle'
                  and query_start is not null
                  and now() - query_start >= (%s * interval '1 second')
                order by query_start
                limit 20
                """,
                (threshold,),
            )
            long_queries = [dict(row) for row in cur.fetchall()]
    except Exception as exc:
        long_queries = []
        limitations.append({"metric": "long_running_queries", "error_type": type(exc).__name__})
    for item in long_queries:
        item["query_preview"] = _redact_query_preview(item.get("query_preview"))

    warnings: list[str] = []
    normalized_tables: list[dict[str, Any]] = []
    for row in tables:
        live = int(row.get("live_rows") or 0)
        dead = int(row.get("dead_rows") or 0)
        total = live + dead
        dead_ratio = round(dead / total, 4) if total else 0.0
        item = dict(row)
        item["total_human"] = _human_bytes(item.get("total_bytes"))
        item["dead_row_ratio"] = dead_ratio
        normalized_tables.append(item)
        if dead >= 100_000 and dead_ratio >= 0.20:
            warnings.append(f"{item.get('table_name')}: high dead tuple ratio {dead_ratio:.1%} ({dead} rows)")
    if long_queries:
        warnings.append(f"Long-running PostgreSQL queries: {len(long_queries)}")
    if any(item["metric"] == "table_statistics" for item in limitations):
        warnings.append("PostgreSQL table statistics are temporarily unavailable.")
    if any(item["metric"] == "long_running_queries" for item in limitations):
        warnings.append("PostgreSQL long-running query metrics are temporarily unavailable.")

    database_bytes = int(database.get("database_bytes") or 0)
    database["database_human"] = _human_bytes(database_bytes)
    backup_tools = _discover_backup_tools()
    if not backup_tools["available"]:
        backup_tools["warning"] = "pg_dump/pg_restore were not found in PATH, ADLOG_PG_BIN_DIR, or standard Windows PostgreSQL locations"
    return {
        "status": "warn" if warnings else "ok",
        "backend": "postgres",
        "available": True,
        "connectivity_status": "ready",
        "metrics_status": "partial" if limitations else "complete",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "database": database,
        "tables": normalized_tables,
        "long_running_queries": long_queries,
        "thresholds": {"table_limit": clean_limit, "long_query_seconds": threshold},
        "warnings": warnings,
        "limitations": limitations,
        "backup_tools": backup_tools,
        "safety": {"read_only": True, "vacuum_executed": False, "analyze_executed": False, "backup_executed": False},
    }
