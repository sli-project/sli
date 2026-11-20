#!/usr/bin/env python3
"""PostgreSQL readiness probe for DB-0.1.

This script is intentionally safe:
- it does not switch the application backend;
- it does not import or migrate event data;
- it creates PostgreSQL schema only when --create-schema is explicitly passed;
- it redacts DSN/passwords in all output.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.sli.core.app_config import load_config, redact_dsn  # noqa: E402
from server.sli.core.paths import DB_PATH, ROOT  # noqa: E402
from server.sli.ops.version import get_release_metadata  # noqa: E402

SCHEMA_PATH = ROOT / "config" / "postgres_schema.sql"
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


def _status_rank(status: str) -> int:
    return {"ok": 0, "warn": 1, "warning": 1, "failed": 2, "error": 2}.get(str(status).lower(), 1)


def _worst(items: list[str]) -> str:
    worst = "ok"
    for item in items:
        if _status_rank(item) > _status_rank(worst):
            worst = "failed" if _status_rank(item) >= 2 else "warn"
    return worst


def _import_psycopg() -> tuple[Any | None, dict[str, Any]]:
    started = time.monotonic()
    try:
        import psycopg  # type: ignore

        return psycopg, {"status": "ok", "duration_ms": int((time.monotonic() - started) * 1000), "module": "psycopg"}
    except Exception as exc:
        return None, {
            "status": "warn",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error_type": type(exc).__name__,
            "error": str(exc),
            "recommendation": 'Install with: .\\.venv\\Scripts\\python.exe -m pip install "psycopg[binary]"',
        }


def _connect(psycopg: Any, dsn: str, timeout_seconds: int):
    return psycopg.connect(dsn, connect_timeout=max(1, int(timeout_seconds)), application_name="ad_log_reports_db0_readiness")


def _schema_text() -> str:
    return SCHEMA_PATH.read_text(encoding="utf-8")


def _probe_connection(psycopg: Any, dsn: str, timeout_seconds: int) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with _connect(psycopg, dsn, timeout_seconds) as conn:
            with conn.cursor() as cur:
                cur.execute("select version(), current_database(), current_user")
                version, database, user = cur.fetchone()
                cur.execute("show server_encoding")
                encoding = cur.fetchone()[0]
                cur.execute("show TimeZone")
                timezone = cur.fetchone()[0]
        return {
            "status": "ok",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "database": database,
            "user": user,
            "server_encoding": encoding,
            "timezone": timezone,
            "version": version,
        }
    except Exception as exc:
        return {
            "status": "failed",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }


def _schema_probe(psycopg: Any, dsn: str, timeout_seconds: int) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with _connect(psycopg, dsn, timeout_seconds) as conn:
            with conn.cursor() as cur:
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
                row_counts: dict[str, int | None] = {}
                for table in ("events", "collector_channel_runs", "collection_channel_state", "log_sources"):
                    if table in tables:
                        try:
                            cur.execute(f"select count(*) from {table}")
                            row_counts[table] = int(cur.fetchone()[0])
                        except Exception:
                            row_counts[table] = None
        return {
            "status": "ok" if not missing else "warn",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "tables_seen": len(tables),
            "expected_tables": EXPECTED_TABLES,
            "missing_tables": missing,
            "schema_migrations": migrations,
            "row_counts": row_counts,
        }
    except Exception as exc:
        return {
            "status": "failed",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }


def _create_schema(psycopg: Any, dsn: str, timeout_seconds: int) -> dict[str, Any]:
    started = time.monotonic()
    if not SCHEMA_PATH.is_file():
        return {"status": "failed", "duration_ms": 0, "error": f"schema file not found: {SCHEMA_PATH}"}
    try:
        with _connect(psycopg, dsn, timeout_seconds) as conn:
            with conn.cursor() as cur:
                cur.execute(_schema_text())
            conn.commit()
        return {"status": "ok", "duration_ms": int((time.monotonic() - started) * 1000), "schema_file": str(SCHEMA_PATH)}
    except Exception as exc:
        return {
            "status": "failed",
            "duration_ms": int((time.monotonic() - started) * 1000),
            "schema_file": str(SCHEMA_PATH),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }


def _benchmark(psycopg: Any, dsn: str, timeout_seconds: int) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with _connect(psycopg, dsn, timeout_seconds) as conn:
            with conn.cursor() as cur:
                cur.execute("select count(*) from generate_series(1, 10000)")
                rows = int(cur.fetchone()[0])
                cur.execute("select current_timestamp")
                ts = str(cur.fetchone()[0])
        return {"status": "ok", "duration_ms": int((time.monotonic() - started) * 1000), "rows_scanned": rows, "server_time": ts}
    except Exception as exc:
        return {"status": "failed", "duration_ms": int((time.monotonic() - started) * 1000), "error_type": type(exc).__name__, "error": str(exc)}


def run_readiness(*, create_schema: bool = False, benchmark: bool = False, dsn: str | None = None, connect: bool = True) -> dict[str, Any]:
    started = time.monotonic()
    cfg = load_config()
    effective_dsn = dsn or cfg.postgres_dsn or os.getenv("ADLOG_PG_DSN")
    timeout_seconds = int(os.getenv("ADLOG_PG_CONNECT_TIMEOUT_SECONDS") or cfg.postgres_connect_timeout_seconds or 3)
    sqlite_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    result: dict[str, Any] = {
        "package_type": "POSTGRES_READINESS",
        "stage": "DB-0.1",
        "status": "ok",
        "duration_ms": 0,
        "release_metadata": get_release_metadata(ROOT),
        "config": {
            "db_backend": cfg.db_backend,
            "postgres_dsn_present": bool(effective_dsn),
            "postgres_dsn": redact_dsn(effective_dsn),
            "connect_timeout_seconds": timeout_seconds,
            "sqlite_db_path": str(DB_PATH),
            "sqlite_db_exists": DB_PATH.exists(),
            "sqlite_db_size_bytes": sqlite_size,
        },
        "schema_file": {"path": str(SCHEMA_PATH), "exists": SCHEMA_PATH.is_file(), "size_bytes": SCHEMA_PATH.stat().st_size if SCHEMA_PATH.exists() else 0},
        "safety": {
            "switch_backend": False,
            "migrate_data": False,
            "move_cursor_or_watermark": False,
            "create_schema_requires_explicit_flag": True,
        },
        "checks": {},
        "warnings": [],
    }

    if not SCHEMA_PATH.is_file():
        result["checks"]["schema_file"] = {"status": "failed", "error": "config/postgres_schema.sql is missing"}
    else:
        result["checks"]["schema_file"] = {"status": "ok"}

    if not effective_dsn:
        result["checks"]["dsn"] = {"status": "warn", "reason": "ADLOG_PG_DSN/config database.postgres_dsn is not set"}
        result["warnings"].append("PostgreSQL DSN is not set; connection probe skipped")
        connect = False
    else:
        result["checks"]["dsn"] = {"status": "ok", "redacted": redact_dsn(effective_dsn)}

    psycopg, import_check = _import_psycopg()
    result["checks"]["psycopg"] = import_check
    if psycopg is None:
        result["warnings"].append("psycopg is not installed; PostgreSQL connection probe skipped")
        connect = False

    if connect and effective_dsn and psycopg is not None:
        result["checks"]["connection"] = _probe_connection(psycopg, effective_dsn, timeout_seconds)
        if result["checks"]["connection"].get("status") == "ok" and create_schema:
            result["checks"]["create_schema"] = _create_schema(psycopg, effective_dsn, max(timeout_seconds, 10))
        elif create_schema:
            result["checks"]["create_schema"] = {"status": "skipped", "reason": "connection is not ok"}
        if result["checks"].get("connection", {}).get("status") == "ok":
            result["checks"]["schema_probe"] = _schema_probe(psycopg, effective_dsn, timeout_seconds)
        if benchmark and result["checks"].get("connection", {}).get("status") == "ok":
            result["checks"]["benchmark"] = _benchmark(psycopg, effective_dsn, timeout_seconds)

    statuses = [str(item.get("status") or "warn") for item in result["checks"].values() if isinstance(item, dict)]
    worst = _worst(statuses)
    # Missing DSN/driver is warning for install-time readiness; broken connection/schema apply is failed.
    result["status"] = worst
    for name, check in result["checks"].items():
        if isinstance(check, dict) and check.get("status") == "failed":
            result["warnings"].append(f"{name} failed: {check.get('error_type') or ''} {check.get('error') or ''}".strip())
        elif isinstance(check, dict) and check.get("status") == "warn":
            reason = check.get("reason") or check.get("error") or "warning"
            result["warnings"].append(f"{name}: {reason}")
    result["warnings"] = list(dict.fromkeys(str(item) for item in result["warnings"] if item))
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Check DB-0.1 PostgreSQL readiness.")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--dsn", help="PostgreSQL DSN; defaults to ADLOG_PG_DSN/config database.postgres_dsn")
    parser.add_argument("--create-schema", action="store_true", help="create/update PostgreSQL schema from config/postgres_schema.sql")
    parser.add_argument("--benchmark", action="store_true", help="run a tiny PostgreSQL synthetic benchmark")
    parser.add_argument("--no-connect", action="store_true", help="validate config/files/imports without opening a DB connection")
    args = parser.parse_args()
    result = run_readiness(create_schema=args.create_schema, benchmark=args.benchmark, dsn=args.dsn, connect=not args.no_connect)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"PostgreSQL readiness: {result['status']} ({result.get('duration_ms')} ms)")
        print("Version:", (result.get("release_metadata") or {}).get("project_version"))
        print("DSN:", result.get("config", {}).get("postgres_dsn") or "not set")
        for warning in result.get("warnings") or []:
            print(f"- {warning}")
    return 0 if result.get("status") in {"ok", "warn"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
