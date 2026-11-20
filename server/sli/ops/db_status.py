from __future__ import annotations

import html
import os
import time
from pathlib import Path
from typing import Any

from server.sli.core.app_config import load_config, redact_dsn
from server.sli.core.paths import DB_PATH, ROOT
from server.sli.ops.version import get_release_metadata

EXPECTED_TABLES = [
    "schema_migrations",
    "log_sources",
    "collection_channel_state",
    "collector_channel_runs",
    "collector_stage_metrics",
    "events",
    "findings",
    "ai_api_runs",
]


def _fmt_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{value} B"


def _import_psycopg() -> tuple[Any | None, dict[str, Any]]:
    started = time.monotonic()
    try:
        import psycopg  # type: ignore

        return psycopg, {"status": "ok", "duration_ms": int((time.monotonic() - started) * 1000), "module": "psycopg"}
    except Exception as exc:
        return None, {"status": "warn", "duration_ms": int((time.monotonic() - started) * 1000), "error_type": type(exc).__name__, "error": str(exc)}


def _connect(psycopg: Any, dsn: str, timeout_seconds: int):
    return psycopg.connect(dsn, connect_timeout=max(1, int(timeout_seconds)), application_name="ad_log_reports_api_db_status")


def get_db_status(*, connect: bool = True) -> dict[str, Any]:
    """Return a bounded DB backend status for API/UI.

    This is DB-0.1 readiness only. It does not switch backend, migrate data or
    execute heavy event queries.
    """
    started = time.monotonic()
    cfg = load_config()
    dsn = cfg.postgres_dsn or os.getenv("ADLOG_PG_DSN")
    timeout_seconds = int(os.getenv("ADLOG_PG_CONNECT_TIMEOUT_SECONDS") or cfg.postgres_connect_timeout_seconds or 3)
    sqlite_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    result: dict[str, Any] = {
        "status": "ok",
        "mode": "db0_readiness",
        "duration_ms": 0,
        "active_backend": cfg.db_backend,
        "sqlite": {
            "path": str(DB_PATH),
            "exists": DB_PATH.exists(),
            "size_bytes": sqlite_size,
            "size_human": _fmt_bytes(sqlite_size),
        },
        "postgres": {
            "configured": bool(dsn),
            "dsn": redact_dsn(dsn),
            "connect_timeout_seconds": timeout_seconds,
        },
        "safety": {
            "backend_switched": False,
            "migration_running": False,
            "cursor_or_watermark_changed": False,
        },
        "checks": {},
        "release_metadata": get_release_metadata(ROOT),
    }
    if not dsn:
        result["status"] = "warn"
        result["checks"]["dsn"] = {"status": "warn", "reason": "ADLOG_PG_DSN/config database.postgres_dsn is not set"}
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return result
    result["checks"]["dsn"] = {"status": "ok"}
    psycopg, import_check = _import_psycopg()
    result["checks"]["psycopg"] = import_check
    if psycopg is None:
        result["status"] = "warn"
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return result
    if not connect:
        result["checks"]["connection"] = {"status": "skipped", "reason": "connect=false"}
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return result
    try:
        with _connect(psycopg, dsn, timeout_seconds) as conn:
            with conn.cursor() as cur:
                cur.execute("select version(), current_database(), current_user")
                version, database, user = cur.fetchone()
                cur.execute(
                    """
                    select table_name
                    from information_schema.tables
                    where table_schema = 'public'
                    order by table_name
                    """
                )
                tables = [row[0] for row in cur.fetchall()]
                missing = [name for name in EXPECTED_TABLES if name not in tables]
                migrations: list[dict[str, Any]] = []
                if "schema_migrations" in tables:
                    cur.execute("select version, name from schema_migrations order by version")
                    migrations = [{"version": row[0], "name": row[1]} for row in cur.fetchall()]
        result["checks"]["connection"] = {"status": "ok", "database": database, "user": user, "version": version}
        result["checks"]["schema"] = {
            "status": "ok" if not missing else "warn",
            "tables_seen": len(tables),
            "missing_tables": missing,
            "schema_migrations": migrations,
        }
        if missing:
            result["status"] = "warn"
    except Exception as exc:
        result["status"] = "failed"
        result["checks"]["connection"] = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    return result


def render_db_status_report() -> str:
    data = get_db_status()
    pg = data.get("postgres") or {}
    sqlite = data.get("sqlite") or {}
    checks = data.get("checks") or {}
    rows = []
    for name, check in checks.items():
        rows.append(
            f"<tr><td>{html.escape(str(name))}</td><td>{html.escape(str(check.get('status')))}</td>"
            f"<td><pre>{html.escape(str(check))}</pre></td></tr>"
        )
    return f"""<!doctype html>
<html lang=\"ru\">
<head>
  <meta charset=\"utf-8\" />
  <title>DB Backend Status</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #f7f7f7; color: #222; }}
    .card {{ background: white; border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
    table {{ border-collapse: collapse; width: 100%; background: white; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background: #f0f0f0; }}
    pre {{ white-space: pre-wrap; margin: 0; font-size: 12px; }}
    .status {{ font-weight: 700; }}
  </style>
</head>
<body>
  <h1>DB Backend Status</h1>
  <div class=\"card\">
    <p>Stage: <b>DB-0.1 PostgreSQL readiness</b></p>
    <p>Status: <span class=\"status\">{html.escape(str(data.get('status')))}</span></p>
    <p>Active backend: <b>{html.escape(str(data.get('active_backend')))}</b></p>
    <p>Duration: {html.escape(str(data.get('duration_ms')))} ms</p>
  </div>
  <div class=\"card\">
    <h2>SQLite</h2>
    <p>Path: <code>{html.escape(str(sqlite.get('path')))}</code></p>
    <p>Exists: {html.escape(str(sqlite.get('exists')))}</p>
    <p>Size: {html.escape(str(sqlite.get('size_human')))}</p>
  </div>
  <div class=\"card\">
    <h2>PostgreSQL</h2>
    <p>Configured: {html.escape(str(pg.get('configured')))}</p>
    <p>DSN: <code>{html.escape(str(pg.get('dsn') or 'not set'))}</code></p>
    <p>Timeout: {html.escape(str(pg.get('connect_timeout_seconds')))} sec</p>
  </div>
  <h2>Checks</h2>
  <table><tr><th>Check</th><th>Status</th><th>Details</th></tr>{''.join(rows)}</table>
</body>
</html>"""
