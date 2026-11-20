#!/usr/bin/env python3
"""Persist the authorized Users V2 reference snapshot every twelve hours."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
from typing import Any, Callable, Mapping
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.core.report_domain import NOT_CONFIGURED_CODE, ReportDomainNotConfiguredError, report_domain_fqdn
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.ops.runtime_workers import record_worker_heartbeat
from server.sli.reports.users_v2_reporting import CONTRACT_ID, build_users_v2_snapshot

from server.sli.plugins.ad.snapshots.users_persistence import (
    _utc, snapshot_bucket_start, _canonical, persist_users_v2_snapshot,
)

WORKER_NAME = "users_v2_snapshot"
LOCK_NAME = "ad_log_reports_runtime_users_v2_snapshot_worker"
SNAPSHOT_INTERVAL_SECONDS = 12 * 60 * 60

INITIAL_DELAY_SECONDS = 150


def _domain_id(connection: Any) -> int:
    with connection.cursor() as cur:
        cur.execute("select id from domains where lower(fqdn)=%s order by id", (report_domain_fqdn(),))
        rows = [dict(row) for row in cur.fetchall()]
    if len(rows) != 1:
        raise RuntimeError("users_v2_snapshot_requires_one_domain")
    return int(rows[0]["id"])


def run_once(*, captured_at: datetime | None = None, connection_factory: Callable[[], Any] = connect) -> dict[str, Any]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    now = _utc(captured_at or datetime.now(timezone.utc))
    try:
        with connection_factory() as connection:
            domain_id = _domain_id(connection)
    except ReportDomainNotConfiguredError:
        # No report domain in settings: skip this cycle, nothing to snapshot.
        return {"status": "skipped", "reason": NOT_CONFIGURED_CODE}
    snapshot = build_users_v2_snapshot(domain_ids=[domain_id])
    if len(snapshot.get("users") or []) >= 10_000:
        raise RuntimeError("users_v2_snapshot_input_bound_reached")
    with connection_factory() as connection:
        result = persist_users_v2_snapshot(connection, snapshot=snapshot, domain_id=domain_id, captured_at=now)
    return {**result, "captured_at_utc": now.isoformat(), "domain_id": domain_id}


def _heartbeat(*, worker_id: str, status: str, phase: str, started_at: datetime, details: dict[str, Any]) -> None:
    record_worker_heartbeat(worker_name=WORKER_NAME, worker_id=worker_id, status=status, phase=phase, expected_interval_seconds=SNAPSHOT_INTERVAL_SECONDS, started_at=started_at, details=details)


def main() -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from server.sli.sources.ad_gpo_jobs import enabled

    if enabled():
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--no-initial-delay", action="store_true")
    args = parser.parse_args()
    worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid4()}"
    started_at = datetime.now(timezone.utc)
    if not args.once and not args.no_initial_delay:
        time.sleep(INITIAL_DELAY_SECONDS)
    while True:
        try:
            with session_advisory_lock(connect, LOCK_NAME) as acquired:
                result = run_once() if acquired else {"status": "skipped", "reason": "lock_busy"}
            _heartbeat(worker_id=worker_id, status=str(result["status"]), phase="sleeping", started_at=started_at, details=result)
            print(json.dumps(result, ensure_ascii=False, default=str), flush=True)
        except Exception as exc:
            result = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
            _heartbeat(worker_id=worker_id, status="failed", phase="failed", started_at=started_at, details=result)
            print(json.dumps(result, ensure_ascii=False), file=sys.stderr, flush=True)
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(SNAPSHOT_INTERVAL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
