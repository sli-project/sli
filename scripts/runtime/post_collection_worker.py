"""Core agent inbox and optional durable legacy post-collection executor.

This process deliberately does not start the HTTPS server, scheduler or DC
collection. It imports admitted agent inputs and claims PostgreSQL-backed
post-collection rows using the existing lease protocol. It may run beside the
web process when ``ADLOG_EXTERNAL_POST_COLLECTION_WORKER=1``.

With legacy collection disabled, the same process retains its inbox imports
and process lock but never claims legacy post-collection jobs.
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
from server.sli.ops.logging_config import log_event, log_internal_error
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.ops.runtime_workers import record_worker_heartbeat
from server.sli.storage.runtime_storage import (
    StorageRouteAuthorizationError,
    StorageRouteConsumer,
    resolve_storage_route,
)
from server.sli.storage.storage_v2_transition_controller import (
    CutoverAuthorization,
    is_controller_authorization,
)
from server.sli.agents.consumer import AgentPacketConsumer
from server.sli.plugins.registry import plugin_hook
from server.sli.sources.legacy_collection import legacy_collection_disabled


LOCK_NAME = "ad_log_reports_runtime_post_collection_process"
AGENT_PACKET_BATCH_LIMIT = 16


def run_persisted_post_collection_worker_once(**kwargs):
    # The legacy collector imports AD implementation aliases. Core inbox startup
    # must not load it when the package is absent or acquisition is disabled.
    from server.jobs.collector import run_persisted_post_collection_worker_once as run_legacy

    return run_legacy(**kwargs)


@contextmanager
def post_collection_worker_lock() -> Iterator[bool]:
    with session_advisory_lock(connect, LOCK_NAME) as acquired:
        yield acquired


def _worker_id() -> str:
    return f"post-collection-{socket.gethostname()}-{__import__('os').getpid()}"


def _validated_route_authorization(
    authorization: CutoverAuthorization | None,
) -> CutoverAuthorization | None:
    if authorization is None:
        return None
    if is_controller_authorization(authorization):
        return authorization
    raise StorageRouteAuthorizationError("storage_transition_authorization_invalid")


def _run_locked(
    *,
    once: bool,
    poll_seconds: int,
    limit: int,
    authorization: CutoverAuthorization | None = None,
) -> int:
    authorization = _validated_route_authorization(authorization)
    agent_only = legacy_collection_disabled()
    # Validate the legacy Findings route before claiming a durable job lease.
    # Agent importers enforce their own Storage V2 publication admission.
    if not agent_only:
        resolve_storage_route(
            authorization=authorization, consumer=StorageRouteConsumer.FINDINGS
        )
    worker_id = _worker_id()
    started_at = datetime.now(timezone.utc)
    agent_consumer = AgentPacketConsumer()
    log_event("runtime_worker", "post_collection_worker_started", "Independent post-collection worker started.", worker_id=worker_id)
    while not shutdown.requested():
        record_worker_heartbeat(
            worker_name="post_collection", worker_id=worker_id, status="running", phase="poll",
            expected_interval_seconds=poll_seconds, started_at=started_at, details={"limit": limit},
        )
        # Agent failures retain inbox evidence and never leak into the legacy
        # exception logger, which may include private DB bind diagnostics.
        try:
            agent_result = agent_consumer.run_once(limit=AGENT_PACKET_BATCH_LIMIT)
        except Exception:
            agent_result = {"pending_reasons": {"agent_consumer_unavailable": 1}}
        agent_failed = any(agent_result.get("pending_reasons", {}).get(code)
                           for code in ("agent_consumer_unavailable", "agent_projection_failed"))
        print(json.dumps({"agent_packets": agent_result}), flush=True)
        if shutdown.requested():
            return 0
        try:
            def heartbeat_processing(current: dict[str, object]) -> None:
                record_worker_heartbeat(
                    worker_name="post_collection",
                    worker_id=worker_id,
                    status="running",
                    phase=str(current.get("phase") or "processing"),
                    expected_interval_seconds=poll_seconds,
                    started_at=started_at,
                    details={
                        "limit": limit,
                        "active_job": current,
                    },
                )

            result = {"failed": 0}
            if not agent_only:
                result = run_persisted_post_collection_worker_once(
                    worker_id=worker_id,
                    limit=limit,
                    progress_callback=heartbeat_processing,
                    authorization=authorization,
                )
            if shutdown.requested():
                return 0
            ad_importer = plugin_hook("sli.ad", "run_agent_import_once")
            agent_imported = ad_importer(limit=limit) if ad_importer else 0
            if agent_imported:
                result["agent_packets_imported"] = agent_imported
            if shutdown.requested():
                return 0
            accounting_importer = plugin_hook("sli.remote-access", "run_accounting_import_once")
            accounting_imported = accounting_importer(limit=limit) if accounting_importer else 0
            if accounting_imported:
                result["agent_accounting_packets_imported"] = accounting_imported
            print(json.dumps({"worker_id": worker_id, **result}, ensure_ascii=False), flush=True)
            record_worker_heartbeat(
                worker_name="post_collection", worker_id=worker_id,
                status=("failed" if result.get("failed") or agent_failed else
                        "warning" if agent_result.get("quarantined") else "idle"), phase="sleep",
                expected_interval_seconds=poll_seconds, started_at=started_at,
                details={"last_result": result, "agent_packets": agent_result},
            )
            if once:
                # Preserve the legacy exit contract; in agent-only mode the
                # inbox poll is the work whose failure determines the exit.
                return 1 if result.get("failed") or (agent_only and agent_failed) else 0
            # A full scan means there may be more inbox evidence to visit.
            # Drain bounded batches without an idle delay, including deferred
            # packets, so an old backlog cannot hide newly admitted inputs.
            # The consumer advances its cursor even on failure and returns an
            # empty scan before wrapping, which still waits poll_seconds.
            if agent_result.get("scanned", 0) == AGENT_PACKET_BATCH_LIMIT:
                continue
        except Exception as exc:
            if agent_only:
                # Agent/import/DB diagnostics may include source data. Retain
                # the inbox for retry and expose only a fixed failure code.
                result = {"failed": 1, "reason": "agent_import_iteration_failed"}
                print(json.dumps({"worker_id": worker_id, **result}), flush=True)
                record_worker_heartbeat(
                    worker_name="post_collection", worker_id=worker_id, status="failed", phase="sleep",
                    expected_interval_seconds=poll_seconds, started_at=started_at,
                    details={"last_result": result, "agent_packets": agent_result},
                )
                if once:
                    return 1
                shutdown.wait(poll_seconds, sleep=time.sleep)
                continue
            error_id = log_internal_error(
                "runtime_worker", "post_collection_worker_iteration_failed",
                "Independent post-collection worker iteration failed.", exc=exc, worker_id=worker_id,
            )
            print(json.dumps({"worker_id": worker_id, "error_id": error_id, "error": str(exc)}, ensure_ascii=False), flush=True)
            record_worker_heartbeat(
                worker_name="post_collection", worker_id=worker_id, status="failed", phase="sleep",
                expected_interval_seconds=poll_seconds, started_at=started_at,
                details={"error_id": error_id, "error_type": type(exc).__name__},
            )
            if once:
                return 1
        shutdown.wait(poll_seconds, sleep=time.sleep)

    return 0


def run(
    *,
    once: bool,
    poll_seconds: int,
    limit: int,
    authorization: CutoverAuthorization | None = None,
) -> int:
    with post_collection_worker_lock() as acquired:
        if not acquired:
            print(json.dumps({
                "status": "skipped",
                "reason": "post_collection_process_lock_held",
            }, ensure_ascii=False), flush=True)
            return 9
        return _run_locked(
            once=once,
            poll_seconds=poll_seconds,
            limit=limit,
            authorization=authorization,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run core agent imports and the optional durable post-collection worker without the web server.")
    parser.add_argument("--once", action="store_true", help="Claim and process at most one bounded batch, then exit.")
    parser.add_argument("--poll-seconds", type=int, default=10, help="Polling interval in continuous mode (1..300).")
    parser.add_argument("--limit", type=int, default=1, help="Maximum leased jobs per iteration (1..10).")
    parser.add_argument("--load-supervisor-environment", action="store_true")
    args = parser.parse_args(argv)
    if args.load_supervisor_environment:
        from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment

        load_supervisor_environment()
    return run(once=bool(args.once), poll_seconds=max(1, min(args.poll_seconds, 300)), limit=max(1, min(args.limit, 10)))


if __name__ == "__main__":
    raise SystemExit(main())
