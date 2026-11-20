#!/usr/bin/env python3
"""Materialize the authorized Computers V5 report every twelve hours.

This worker does not collect Active Directory data and does not correlate events.
It stores one immutable, hash-verified V5 read-model payload per UTC 12-hour
bucket, then applies the owner-approved 365-day rolling retention only after a
successful insert and exact readback.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
from typing import Any, Callable, Mapping
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.reports.computers_v5_reporting import get_computers_v5_report
from server.sli.core.report_domain import NOT_CONFIGURED_CODE, ReportDomainNotConfiguredError, report_domain_fqdn
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.ops.runtime_workers import record_worker_heartbeat


WORKER_NAME = "computers_v5_snapshot"
LOCK_NAME = "ad_log_reports_runtime_computers_v5_snapshot_worker"
SNAPSHOT_INTERVAL_SECONDS = 12 * 60 * 60
RETENTION_DAYS = 365
INITIAL_DELAY_SECONDS = 120


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("snapshot timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def snapshot_bucket_start(value: datetime) -> datetime:
    stamp = _utc(value)
    return stamp.replace(hour=12 if stamp.hour >= 12 else 0, minute=0, second=0, microsecond=0)


def snapshot_retention_cutoff(value: datetime) -> datetime:
    return _utc(value) - timedelta(days=RETENTION_DAYS)


def _canonical_json(value: Mapping[str, Any]) -> tuple[str, bytes]:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return text, hashlib.sha256(text.encode("utf-8")).digest()


def _snapshot_payload(report: Mapping[str, Any], captured_at: datetime) -> dict[str, Any]:
    return {
        "contract_id": report.get("contract_id"),
        "report_key": report.get("report_key"),
        "captured_at_utc": _utc(captured_at).isoformat(),
        "state": report.get("state"),
        "coverage": report.get("coverage") or {},
        "summary": report.get("summary") or {},
        "semantic": report.get("semantic") or {},
        "items": report.get("items") or [],
    }


def _source_run_id(report: Mapping[str, Any], domain_id: int) -> UUID | None:
    coverage = report.get("coverage") or {}
    for row in coverage.get("domains") or []:
        if int(row.get("domain_id") or 0) != int(domain_id):
            continue
        value = row.get("run_id")
        return UUID(str(value)) if value else None
    return None


def persist_computers_v5_snapshot(
    connection: Any,
    *,
    report: Mapping[str, Any],
    domain_id: int,
    captured_at: datetime,
) -> dict[str, Any]:
    state = str(report.get("state") or "")
    if state not in {"available", "empty", "partial", "stale"}:
        raise RuntimeError("snapshot_source_not_usable")
    if report.get("contract_id") != "sli.computers-report.v5":
        raise RuntimeError("snapshot_contract_mismatch")
    items = list(report.get("items") or [])
    payload = _snapshot_payload(report, captured_at)
    payload_text, payload_sha256 = _canonical_json(payload)
    scope = {"domain_ids": [int(domain_id)], "report_key": "ad.computers.v5"}
    scope_text, scope_sha256 = _canonical_json(scope)
    observed_text = (report.get("coverage") or {}).get("latest_observed_at_utc")
    observed_at = datetime.fromisoformat(str(observed_text).replace("Z", "+00:00")) if observed_text else None
    bucket = snapshot_bucket_start(captured_at)
    source_run_id = _source_run_id(report, domain_id)
    with connection.cursor() as cur:
        cur.execute(
            """
            insert into computers_report_v5_snapshots(
                domain_id,source_run_id,contract_id,scope_json,scope_sha256,
                bucket_start_utc,captured_at_utc,source_observed_at_utc,object_count,
                payload_json,payload_sha256,source_state
            ) values (%s,%s,%s,%s::jsonb,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
            on conflict(domain_id,scope_sha256,bucket_start_utc,contract_id,schema_version)
            do nothing returning snapshot_id
            """,
            (
                int(domain_id), source_run_id, "sli.computers-report.v5", scope_text,
                scope_sha256, bucket, _utc(captured_at), observed_at, len(items),
                payload_text, payload_sha256, state,
            ),
        )
        inserted = dict(cur.fetchone() or {})
        if not inserted:
            return {"status": "already_captured", "object_count": len(items), "retired_snapshots": 0}
        snapshot_id = int(inserted["snapshot_id"])
        cur.execute(
            "select object_count,payload_sha256 from computers_report_v5_snapshots where snapshot_id=%s",
            (snapshot_id,),
        )
        readback = dict(cur.fetchone() or {})
        readback_hash = bytes(readback.get("payload_sha256") or b"")
        readback_count = readback.get("object_count")
        if readback_count is None or int(readback_count) != len(items) or readback_hash != payload_sha256:
            raise RuntimeError("snapshot_readback_mismatch")
        cur.execute(
            "delete from computers_report_v5_snapshots where captured_at_utc < %s",
            (snapshot_retention_cutoff(captured_at),),
        )
        retired = max(0, int(cur.rowcount or 0))
    return {
        "status": "captured",
        "snapshot_id": snapshot_id,
        "object_count": len(items),
        "retired_snapshots": retired,
    }


def _domain_id(connection: Any) -> int:
    with connection.cursor() as cur:
        cur.execute("select id from domains where lower(fqdn)=%s order by id", (report_domain_fqdn(),))
        rows = [dict(row) for row in cur.fetchall()]
    if len(rows) != 1:
        raise RuntimeError("computers_v5_snapshot_requires_one_domain")
    return int(rows[0]["id"])


def run_once(
    *,
    captured_at: datetime | None = None,
    connection_factory: Callable[[], Any] = connect,
    report_loader: Callable[..., dict[str, Any]] = get_computers_v5_report,
) -> dict[str, Any]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    now = _utc(captured_at or datetime.now(timezone.utc))
    try:
        with connection_factory() as connection:
            domain_id = _domain_id(connection)
    except ReportDomainNotConfiguredError:
        # No report domain in settings: skip this cycle, nothing to snapshot.
        return {"status": "skipped", "reason": NOT_CONFIGURED_CODE}
    report = report_loader(
        domain_ids=[domain_id], view="all", limit=10_000, max_page_limit=10_000,
    )
    if report.get("has_more") or (report.get("limits") or {}).get("input_truncated"):
        raise RuntimeError("snapshot_report_truncated")
    with connection_factory() as connection:
        result = persist_computers_v5_snapshot(
            connection, report=report, domain_id=domain_id, captured_at=now,
        )
    return {**result, "captured_at_utc": now.isoformat(), "domain_id": domain_id}


def _heartbeat(
    *, worker_id: str, status: str, phase: str, started_at: datetime, details: dict[str, Any],
) -> None:
    record_worker_heartbeat(
        worker_name=WORKER_NAME,
        worker_id=worker_id,
        status=status,
        phase=phase,
        expected_interval_seconds=SNAPSHOT_INTERVAL_SECONDS,
        started_at=started_at,
        details=details,
    )


def main() -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
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
                if not acquired:
                    result = {"status": "skipped", "reason": "lock_busy"}
                else:
                    result = run_once()
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
