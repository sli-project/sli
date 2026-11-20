"""Runtime-owned entity-state projection cycle.

`scripts/runtime/entity_state_worker.py` previously imported `_connect` and
`run_once` directly from `scripts/maintenance/run_entity_state_projection_once.py`,
making production's recurring entity-state polling loop depend on a
maintenance module for correctness. This module owns that logic instead; the
maintenance CLI (`run_entity_state_projection_once.py`, kept for bounded
manual/one-shot runs) imports back from here to keep its own `--execute`
behavior unchanged. This module must never import `scripts.maintenance.*`.
"""
from __future__ import annotations

import os
import socket
from typing import Any

from server.sli.core.app_config import load_config
from server.sli.core.secret_files import postgres_secret_parts, secret_value
from server.sli.entities.entity_state_projector import (
    claim_projection_jobs,
    complete_projection_job,
    fail_projection_job,
)


def connect_entity_state_worker():
    import psycopg
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.rows import dict_row

    cfg = load_config()
    connect_timeout = max(1, int(cfg.postgres_connect_timeout_seconds))
    statement_timeout = max(1000, int(cfg.postgres_statement_timeout_ms))
    lock_timeout = max(
        100, min(int(cfg.postgres_lock_timeout_ms), statement_timeout)
    )
    parts = postgres_secret_parts("ADLOG_STORAGE_V2_WORKER_DSN")
    if not parts:
        user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
        password = secret_value("ADLOG_PG_ADMIN_PASSWORD")
        if not user or not password:
            raise RuntimeError(
                "ADLOG_STORAGE_V2_WORKER_DSN or local PostgreSQL admin "
                "credentials are required"
            )
        parts = conninfo_to_dict(cfg.postgres_dsn or "")
        parts.update(user=user, password=password)

    existing_options = str(parts.get("options") or "").strip()
    bounded_options = (
        f"-c statement_timeout={statement_timeout} "
        f"-c lock_timeout={lock_timeout}"
    )
    parts.update(
        connect_timeout=connect_timeout,
        application_name="adlog_entity_state_projector",
        options=f"{existing_options} {bounded_options}".strip(),
    )
    conn = psycopg.connect(**parts, row_factory=dict_row)
    try:
        with conn.cursor() as cur:
            cur.execute("set role adlog_storage_worker")
    except BaseException:
        conn.close()
        raise
    # SET ROLE starts a transaction in psycopg.  Commit it so subsequent
    # conn.transaction() blocks are real top-level transactions, not savepoints
    # inside an outer transaction that close() would silently roll back.
    conn.commit()
    return conn


def run_entity_state_projection_cycle(*, limit: int) -> dict[str, Any]:
    worker_id = f"entity-state-{socket.gethostname()}-{os.getpid()}"
    conn = connect_entity_state_worker()
    try:
        completed = failed = quarantined = 0
        actions = {"insert": 0, "replace": 0, "same": 0, "older": 0, "conflict": 0}
        claimed = 0
        # Claim one job immediately before processing it.  This keeps queued
        # work outside a lease and removes the need to heartbeat jobs waiting
        # behind the rest of a claimed batch.
        for _ in range(max(1, min(int(limit), 16))):
            with conn.transaction(), conn.cursor() as cur:
                jobs = claim_projection_jobs(cur, worker_id=worker_id, limit=1)
            if not jobs:
                break
            job = jobs[0]
            claimed += 1
            try:
                with conn.transaction(), conn.cursor() as cur:
                    result = complete_projection_job(cur, job)
                completed += 1
                for key, value in result.items():
                    actions[key] += value
            except Exception as exc:
                with conn.transaction(), conn.cursor() as cur:
                    terminal = fail_projection_job(cur, job, exc)
                failed += 1
                quarantined += int(terminal == "quarantined")
        return {
            "status": "ok" if failed == 0 else "partial",
            "worker_id": worker_id,
            "claimed": claimed, "completed": completed, "failed": failed,
            "quarantined": quarantined, "actions": actions,
        }
    finally:
        conn.close()
