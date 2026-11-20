"""Independent development worker for bounded TEST/SHADOW semantic jobs.

The worker never collects from AD and refuses to run while finding creation or
an ENABLED risk policy is present.  Production activation therefore remains a
separate future decision even though continuous development processing exists.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import socket
import sys
import time
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops.logging_config import log_event, log_internal_error  # noqa: E402
from server.sli.ops.postgres_session_lock import session_advisory_lock  # noqa: E402
from server.sli.ops.runtime_workers import record_worker_heartbeat  # noqa: E402
from server.sli.semantic.semantic_processing import SemanticFeatureSettings  # noqa: E402
from server.sli.semantic.semantic_worker_connection import (  # noqa: E402
    connect_semantic_worker,
)
from server.sli.semantic.semantic_worker_runtime import (  # noqa: E402
    MAX_SEMANTIC_BATCH,
    process_semantic_dispatch,
    process_semantic_outbox,
    semantic_cycle_has_work,
)
from server.sli.semantic.semantic_risk_runtime_repository import (  # noqa: E402
    claim_risk_evaluation_jobs,
    enqueue_risk_backlog,
    execute_risk_evaluation,
    fail_risk_evaluation_job,
    load_risk_evaluation_work_item,
)
from server.sli.storage.storage_v2_archive import ArchiveReader  # noqa: E402
from server.sli.storage.storage_v2_config import load_storage_v2_settings  # noqa: E402
from server.sli.storage.storage_v2_repository import (  # noqa: E402
    PostgresArchiveManifestStore,
)

LOCK_NAME = "ad_log_reports_runtime_semantic_development_worker"


def _guard_development_scope(conn) -> None:
    settings = SemanticFeatureSettings.from_env()
    if not settings.normalization_enabled:
        raise RuntimeError("semantic normalization must be explicitly enabled")
    if settings.directory_state_enabled:
        raise RuntimeError(
            "semantic directory-state persistence is not accepted for this worker"
        )
    if settings.finding_creation_enabled:
        raise RuntimeError("semantic development worker forbids finding creation")
    with conn.cursor() as cur:
        cur.execute(
            """
            select count(*) as count from schema_migrations
            where (version=54 and name='semantic_worker_runtime_schema_guard')
               or (version=71 and name='semantic_source_retention_decoupling')
            """
        )
        if int(dict(cur.fetchone() or {}).get("count") or 0) != 2:
            raise RuntimeError("semantic worker requires schema migrations 054 and 071")
        cur.execute("select count(*) as count from semantic_risk_policies where lifecycle_status='enabled'")
        if int(dict(cur.fetchone() or {}).get("count") or 0):
            raise RuntimeError("semantic development worker accepts only TEST/SHADOW policies")


def _connect():
    return connect_semantic_worker()


def _prepare_connection(conn) -> None:
    """Run the scope guard without leaving an implicit outer transaction open."""
    _guard_development_scope(conn)
    conn.commit()


def _archive_reader() -> ArchiveReader:
    load_storage_v2_settings(strict=True)
    return ArchiveReader(
        PostgresArchiveManifestStore(_connect),
    )


@contextmanager
def _singleton_lock() -> Iterator[bool]:
    with session_advisory_lock(
        _connect,
        LOCK_NAME,
        prepare=_guard_development_scope,
    ) as acquired:
        yield acquired


def run_once(
    *, limit: int, archive: ArchiveReader | None = None
) -> dict[str, object]:
    limit = max(1, min(int(limit), MAX_SEMANTIC_BATCH))
    conn = _connect()
    archive_reader = archive if archive is not None else _archive_reader()
    settings = SemanticFeatureSettings.from_env()
    completed = failed = queued = 0
    modes = {"test": 0, "shadow": 0}
    try:
        _prepare_connection(conn)
        processing = process_semantic_outbox(
            conn,
            archive=archive_reader,
            settings=settings,
            limit=limit,
        )
        completed += int(processing["completed"])
        failed += int(processing["failed"])
        dispatch = process_semantic_dispatch(
            conn,
            archive=archive_reader,
            settings=settings,
            limit=limit,
        )
        completed += int(dispatch["completed"])
        failed += int(dispatch["failed"])
        if settings.risk_engine_enabled:
            with conn.transaction(), conn.cursor() as cur:
                queued = len(enqueue_risk_backlog(cur, limit=limit))
            for _ in range(limit):
                with conn.transaction(), conn.cursor() as cur:
                    claimed = claim_risk_evaluation_jobs(cur, limit=1)
                if not claimed:
                    break
                job = claimed[0]
                if str(job.get("evaluation_mode")) == "enabled":
                    raise RuntimeError(
                        "enabled semantic job reached development worker"
                    )
                try:
                    with conn.transaction(), conn.cursor() as cur:
                        work = load_risk_evaluation_work_item(
                            cur,
                            job_id=str(job["job_id"]),
                            lease_token=str(job["lease_token"]),
                        )
                        result = execute_risk_evaluation(
                            cur,
                            work=work,
                            evaluation_ms=0,
                        )
                        if result.evaluation_mode not in modes:
                            raise RuntimeError(
                                "non-development semantic result mode"
                            )
                        modes[result.evaluation_mode] += 1
                        completed += 1
                except Exception as exc:
                    with conn.transaction(), conn.cursor() as cur:
                        fail_risk_evaluation_job(
                            cur,
                            job_id=str(job["job_id"]),
                            lease_token=str(job["lease_token"]),
                            attempt_count=int(job["attempt_count"]),
                            max_attempts=int(job["max_attempts"]),
                            error_code=type(exc).__name__,
                            error_detail=str(exc),
                        )
                    failed += 1
    finally:
        conn.close()
    return {
        "status": "ok" if not failed else "partial",
        "processing": processing,
        "dispatch": dispatch,
        "risk_queued": queued,
        "completed": completed,
        "failed": failed,
        "modes": modes,
        "findings_created": 0,
    }


def run(*, once: bool, poll_seconds: int, limit: int) -> int:
    limit = max(1, min(int(limit), MAX_SEMANTIC_BATCH))
    worker_id = f"semantic-development-{socket.gethostname()}-{__import__('os').getpid()}"
    started_at = datetime.now(timezone.utc)
    log_event("runtime_worker", "semantic_worker_started", "Independent semantic development worker started.", worker_id=worker_id)
    with _singleton_lock() as acquired:
        if not acquired:
            print(json.dumps({"worker_id": worker_id, "status": "skipped", "reason": "semantic_worker_lock_held"}), flush=True)
            return 0
        while True:
            record_worker_heartbeat(worker_name="semantic", worker_id=worker_id, status="running", phase="poll", expected_interval_seconds=poll_seconds, started_at=started_at, details={"limit": limit, "allowed_modes": ["test", "shadow"]}, connection_factory=_connect)
            try:
                result = run_once(limit=limit)
                print(json.dumps({"worker_id": worker_id, **result}, ensure_ascii=False), flush=True)
                busy = semantic_cycle_has_work(result)
                record_worker_heartbeat(worker_name="semantic", worker_id=worker_id, status="failed" if result["failed"] else "running" if busy else "idle", phase="drain" if busy else "sleep", expected_interval_seconds=poll_seconds, started_at=started_at, details={"last_result": result, "allowed_modes": ["test", "shadow"]}, connection_factory=_connect)
                if once:
                    return 1 if result["failed"] else 0
                if busy:
                    continue
            except Exception as exc:
                error_id = log_internal_error("runtime_worker", "semantic_worker_iteration_failed", "Independent semantic development worker iteration failed.", exc=exc, worker_id=worker_id)
                print(json.dumps({"worker_id": worker_id, "status": "failed", "error_id": error_id, "error": str(exc)}, ensure_ascii=False), flush=True)
                record_worker_heartbeat(worker_name="semantic", worker_id=worker_id, status="failed", phase="sleep", expected_interval_seconds=poll_seconds, started_at=started_at, details={"error_id": error_id, "error_type": type(exc).__name__}, connection_factory=_connect)
                if once:
                    return 1
            time.sleep(poll_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the bounded semantic TEST/SHADOW development worker.")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=int, default=30)
    parser.add_argument("--limit", type=int, default=MAX_SEMANTIC_BATCH)
    args = parser.parse_args()
    return run(once=bool(args.once), poll_seconds=max(5, min(int(args.poll_seconds), 300)), limit=max(1, min(int(args.limit), MAX_SEMANTIC_BATCH)))


if __name__ == "__main__":
    raise SystemExit(main())
