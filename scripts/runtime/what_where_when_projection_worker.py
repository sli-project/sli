#!/usr/bin/env python3
"""Continuously maintain the durable «что где когда» logon projection."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops import shutdown
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.ops.runtime_workers import record_worker_heartbeat
from server.sli.entities.what_where_when_projection import run_projection_cycle

WORKER_NAME = "what_where_when_projection"
LOCK_NAME = "ad_log_reports_runtime_what_where_when_projection"
INTERVAL_SECONDS = 30


def _heartbeat(*, worker_id: str, started_at: datetime, status: str, phase: str, details: dict) -> None:
    record_worker_heartbeat(
        worker_name=WORKER_NAME,
        worker_id=worker_id,
        status=status,
        phase=phase,
        expected_interval_seconds=INTERVAL_SECONDS,
        started_at=started_at,
        details=details,
        connection_factory=connect,
    )


def run(*, once: bool, batch_limit: int, retention_limit: int) -> int:
    worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid4()}"
    started_at = datetime.now(timezone.utc)
    with session_advisory_lock(connect, LOCK_NAME) as acquired:
        if not acquired:
            result = {"status": "skipped", "reason": "worker_lock_held"}
            print(json.dumps(result, ensure_ascii=False), flush=True)
            return 0
        while not shutdown.requested():
            _heartbeat(worker_id=worker_id, started_at=started_at, status="running", phase="projection", details={})
            try:
                result = run_projection_cycle(batch_limit=batch_limit, retention_limit=retention_limit)
                status = "idle" if result.get("status") in {"ok", "skipped"} else "warning"
                _heartbeat(worker_id=worker_id, started_at=started_at, status=status, phase="sleep", details={"last_result": result})
                print(json.dumps(result, ensure_ascii=False, default=str), flush=True)
            except Exception as exc:
                result = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
                _heartbeat(worker_id=worker_id, started_at=started_at, status="failed", phase="sleep", details=result)
                print(json.dumps(result, ensure_ascii=False), file=sys.stderr, flush=True)
                if once:
                    return 1
            if once:
                return 0
            shutdown.wait(INTERVAL_SECONDS, sleep=time.sleep)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--batch-limit", type=int, default=2000)
    parser.add_argument("--retention-limit", type=int, default=10000)
    parser.add_argument("--load-supervisor-environment", action="store_true")
    args = parser.parse_args(argv)
    if args.load_supervisor_environment:
        from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment
        load_supervisor_environment()
    return run(
        once=bool(args.once),
        batch_limit=max(1, min(int(args.batch_limit), 10000)),
        retention_limit=max(1, min(int(args.retention_limit), 50000)),
    )


if __name__ == "__main__":
    raise SystemExit(main())
