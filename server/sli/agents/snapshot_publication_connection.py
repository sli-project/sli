"""Trusted snapshot publication connection; credentials and role stay in core."""
import os

from server.sli.core.app_config import load_config
from server.sli.core.secret_files import postgres_secret_parts


def snapshot_import_connect():
    """Use the installed worker login; retain the Windows import connection."""
    if not any(name in os.environ for name in ("ADLOG_AD_CONTEXT_WORKER_DSN", "ADLOG_AD_CONTEXT_WORKER_DSN_FILE")):
        return _import_connect()

    import psycopg
    from psycopg.rows import dict_row

    parts = postgres_secret_parts("ADLOG_AD_CONTEXT_WORKER_DSN")
    if not parts:
        raise RuntimeError("AD context worker connection is required")
    config = load_config()
    conn = psycopg.connect(
        **parts, row_factory=dict_row,
        application_name="adlog_context_snapshot_import",
        connect_timeout=max(1, int(config.postgres_connect_timeout_seconds)),
        options="-c statement_timeout=300000 -c lock_timeout=10000",
    )
    try:
        with conn.cursor() as cur:
            cur.execute("set role adlog_context_worker")
    except Exception:
        conn.close()
        raise
    return conn

def _import_connect():
    import psycopg
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.rows import dict_row

    config = load_config()
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not user or not password:
        raise RuntimeError("PostgreSQL admin credentials are required for AD context import")
    parts = conninfo_to_dict(config.postgres_dsn or "")
    parts.update(
        user=user,
        password=password,
        application_name="adlog_context_snapshot_import",
    )
    conn = psycopg.connect(
        **parts,
        row_factory=dict_row,
        connect_timeout=max(1, int(config.postgres_connect_timeout_seconds)),
        options="-c statement_timeout=300000 -c lock_timeout=10000",
    )
    with conn.cursor() as cur:
        cur.execute("set role adlog_context_worker")
    return conn
