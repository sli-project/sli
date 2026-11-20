from __future__ import annotations

import os

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

from server.sli.core.app_config import load_config
from server.sli.core.secret_files import postgres_secret_parts, secret_value


def connect_storage_v2_worker():
    """Open a bounded connection and activate the canonical Storage V2 worker role."""
    cfg = load_config()
    parts = postgres_secret_parts("ADLOG_STORAGE_V2_WORKER_DSN")
    if not parts:
        admin_user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
        admin_password = secret_value("ADLOG_PG_ADMIN_PASSWORD")
        if not admin_user or not admin_password:
            raise RuntimeError(
                "ADLOG_STORAGE_V2_WORKER_DSN or local PostgreSQL admin credentials are required"
            )
        parts = conninfo_to_dict(str(cfg.postgres_dsn or ""))
        parts.update(user=admin_user, password=admin_password)

    connect_timeout = max(1, int(cfg.postgres_connect_timeout_seconds))
    statement_timeout = max(1000, int(cfg.postgres_statement_timeout_ms))
    lock_timeout = max(100, min(int(cfg.postgres_lock_timeout_ms), statement_timeout))
    existing_options = str(parts.get("options") or "").strip()
    bounded_options = (
        f"-c statement_timeout={statement_timeout} "
        f"-c lock_timeout={lock_timeout}"
    )
    parts.update(
        connect_timeout=connect_timeout,
        options=f"{existing_options} {bounded_options}".strip(),
    )

    conn = psycopg.connect(**parts, row_factory=dict_row)
    try:
        with conn.cursor() as cur:
            cur.execute("set role adlog_storage_worker")
            cur.execute("select current_user as role")
            row = cur.fetchone()
        if not row or str(row["role"]) != "adlog_storage_worker":
            raise RuntimeError("least-privilege Storage V2 worker role activation failed")
        conn.commit()
        return conn
    except Exception:
        conn.close()
        raise
