"""Explicit file-only AD Context import; it never collects or migrates."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.ad_context.contracts import load_bundle
from server.ad_context.repository import import_bundle


def _connect():
    import psycopg
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.rows import dict_row

    from server.sli.core.app_config import load_config

    config = load_config()
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not user or not password:
        raise RuntimeError("local PostgreSQL admin credentials are required for AD Context import")
    parts = conninfo_to_dict(config.postgres_dsn or "")
    parts.update(user=user, password=password, application_name="adlog_context_import")
    conn = psycopg.connect(
        **parts,
        row_factory=dict_row,
        connect_timeout=max(1, int(config.postgres_connect_timeout_seconds)),
        options=(
            f"-c statement_timeout={max(1000, int(config.postgres_statement_timeout_ms))} "
            f"-c lock_timeout={max(100, int(config.postgres_lock_timeout_ms))}"
        ),
    )
    with conn.cursor() as cur:
        cur.execute("set role adlog_context_worker")
    return conn


def _load_protected_supervisor_environment() -> None:
    """Load the current Windows user's DPAPI runtime environment.

    This is an explicit operator path for one-shot imports.  It does not expose
    credential values and cannot be used by another Windows identity because
    the supervisor blob is protected with current-user DPAPI.
    """
    if (
        os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
        and os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    ):
        return

    from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment

    load_supervisor_environment()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument(
        "--load-supervisor-environment",
        action="store_true",
        help=(
            "Load PostgreSQL credentials from the current Windows user's "
            "DPAPI-protected worker-supervisor environment."
        ),
    )
    args = parser.parse_args(argv)
    if args.load_supervisor_environment:
        _load_protected_supervisor_environment()
    bundle = load_bundle(args.bundle.resolve())
    with _connect() as conn:
        result = import_bundle(conn, bundle)
    print(
        json.dumps(
            {
                "status": "ok",
                **result,
                "live_collection_started": False,
                "credential_values_exposed": False,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
