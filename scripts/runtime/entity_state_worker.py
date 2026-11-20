"""Continuously project durable entity-state jobs outside the HTTPS runtime.

The worker owns only the catalog-driven entity-state queue. It never starts DC
collection, Storage V2 publication, semantic processing, or the web server.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import socket
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops import shutdown
from server.sli.entities.entity_state_runtime import (
    connect_entity_state_worker as _connect,
    run_entity_state_projection_cycle as run_once,
)
from server.sli.ops.logging_config import log_event, log_internal_error
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.ops.runtime_workers import record_worker_heartbeat

LOCK_NAME = "ad_log_reports_runtime_entity_state_worker"


@contextmanager
def entity_state_worker_lock() -> Iterator[bool]:
    """Allow only one continuous projector process for this database."""
    with session_advisory_lock(_connect, LOCK_NAME) as acquired:
        yield acquired


def run(*, once: bool, poll_seconds: int, limit: int) -> int:
    worker_id = f"entity-state-runtime-{socket.gethostname()}-{__import__('os').getpid()}"
    started_at = datetime.now(timezone.utc)
    log_event(
        "runtime_worker",
        "entity_state_worker_started",
        "Independent entity-state worker started.",
        worker_id=worker_id,
    )
    with entity_state_worker_lock() as acquired:
        if not acquired:
            result = {"worker_id": worker_id, "status": "skipped", "reason": "entity_state_worker_lock_held"}
            print(json.dumps(result, ensure_ascii=False), flush=True)
            return 0
        while not shutdown.requested():
            record_worker_heartbeat(
                worker_name="entity_state", worker_id=worker_id, status="running", phase="poll",
                expected_interval_seconds=poll_seconds, started_at=started_at,
                details={"limit": limit}, connection_factory=_connect,
            )
            try:
                result = run_once(limit=limit)
                print(json.dumps({"runtime_worker_id": worker_id, **result}, ensure_ascii=False), flush=True)
                record_worker_heartbeat(
                    worker_name="entity_state", worker_id=worker_id,
                    status="failed" if result.get("failed") else "idle", phase="sleep",
                    expected_interval_seconds=poll_seconds, started_at=started_at,
                    details={"last_result": result}, connection_factory=_connect,
                )
                if once:
                    return 1 if result.get("failed") else 0
            except Exception as exc:
                error_id = log_internal_error(
                    "runtime_worker",
                    "entity_state_worker_iteration_failed",
                    "Independent entity-state worker iteration failed.",
                    exc=exc,
                    worker_id=worker_id,
                )
                print(
                    json.dumps(
                        {"runtime_worker_id": worker_id, "status": "failed", "error_id": error_id, "error": str(exc)},
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
                record_worker_heartbeat(
                    worker_name="entity_state", worker_id=worker_id, status="failed", phase="sleep",
                    expected_interval_seconds=poll_seconds, started_at=started_at,
                    details={"error_id": error_id, "error_type": type(exc).__name__}, connection_factory=_connect,
                )
                if once:
                    return 1
            shutdown.wait(poll_seconds, sleep=time.sleep)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the independent durable entity-state projection worker.")
    parser.add_argument("--once", action="store_true", help="Process one bounded iteration, then exit.")
    parser.add_argument("--poll-seconds", type=int, default=30, help="Polling interval in continuous mode (1..300).")
    parser.add_argument("--limit", type=int, default=16, help="Jobs processed per iteration (1..16).")
    parser.add_argument("--load-supervisor-environment", action="store_true")
    args = parser.parse_args(argv)
    if args.load_supervisor_environment:
        from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment

        load_supervisor_environment()
    return run(
        once=bool(args.once),
        poll_seconds=max(1, min(int(args.poll_seconds), 300)),
        limit=max(1, min(int(args.limit), 16)),
    )


if __name__ == "__main__":
    raise SystemExit(main())
