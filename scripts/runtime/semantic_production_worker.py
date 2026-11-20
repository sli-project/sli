"""Continuous fail-closed production semantic worker.

The worker reads only Storage V2 evidence, runs the accepted semantic chain, and
publishes findings only through enabled policy evaluation. It never contacts AD.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import sys
import time
from typing import Iterator

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops import shutdown
from server.sli.ops.logging_config import log_event, log_internal_error  # noqa: E402
from server.sli.core.paths import DATA_DIR  # noqa: E402
from server.sli.core.secret_files import postgres_secret_parts
from server.sli.ops.postgres_session_lock import session_advisory_lock  # noqa: E402
from server.sli.ops.runtime_workers import record_worker_heartbeat  # noqa: E402
from server.sli.semantic.semantic_production_credentials import (  # noqa: E402
    ephemeral_worker_environment,
)
from server.sli.semantic.semantic_production_runtime import (  # noqa: E402
    FACTS_MODE,
    INVESTIGATION_MODE,
    MAX_BATCH_LIMIT,
    PRODUCTION_WORKER_LOCK_NAME,
    prepare_production_connection,
    run_once as run_production_once,
    semantic_runtime_mode_from_env,
    semantic_v2_quarantine_repair_plan_digest_from_env,
    validate_semantic_runtime_settings,
)
from server.sli.semantic.semantic_processing import (  # noqa: E402
    ASSEMBLER_ID,
    ASSEMBLER_VERSION,
    NORMALIZER_ID,
    NORMALIZER_VERSION,
    SEMANTIC_CONTRACT_VERSION,
    SemanticFeatureSettings,
)
from server.sli.semantic.semantic_processing_repository import (  # noqa: E402
    PROCESSOR_ID,
    PROCESSOR_VERSION,
)
from server.sli.semantic.semantic_worker_connection import (  # noqa: E402
    connect_semantic_worker,
)
from server.sli.semantic.semantic_worker_contract import (  # noqa: E402
    semantic_worker_release_fingerprint,
)
from server.sli.semantic.semantic_worker_runtime import (  # noqa: E402
    MAX_SEMANTIC_RECOVERY_BATCH,
    semantic_cycle_has_work,
)
from server.sli.storage.storage_v2_archive import ArchiveReader  # noqa: E402
from server.sli.storage.storage_v2_config import load_storage_v2_settings  # noqa: E402
from server.sli.storage.storage_v2_repository import (  # noqa: E402
    PostgresArchiveManifestStore,
)


LOCK_NAME = PRODUCTION_WORKER_LOCK_NAME
STOP_REQUEST_PATH = DATA_DIR / "runtime" / "semantic-production-stop.json"


def stop_requested(started_at: datetime) -> bool:
    if not STOP_REQUEST_PATH.is_file():
        return False
    try:
        payload = json.loads(STOP_REQUEST_PATH.read_text(encoding="utf-8"))
        requested_at = datetime.fromisoformat(str(payload["requested_at_utc"]))
        if requested_at.tzinfo is None:
            return False
        return requested_at.astimezone(timezone.utc) >= started_at.astimezone(
            timezone.utc
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return False


def _connect():
    return connect_semantic_worker()


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
        prepare=prepare_production_connection,
    ) as acquired:
        yield acquired


def _details(
    *,
    limit: int,
    runtime_mode: str,
    repair_plan_digest: str | None = None,
    result: dict[str, object] | None = None,
) -> dict[str, object]:
    investigation_mode = runtime_mode == INVESTIGATION_MODE
    payload: dict[str, object] = {
        "limit": limit,
        "runtime_mode": runtime_mode,
        "allowed_modes": (
            [] if runtime_mode == FACTS_MODE
            else ["shadow"] if investigation_mode
            else ["shadow", "enabled"]
        ),
        "finding_creation": runtime_mode not in {FACTS_MODE, INVESTIGATION_MODE},
        "manual_runtime": False,
        "processing_contract": {
            "claim_protocol_version": 1,
            "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
            "processor_id": PROCESSOR_ID,
            "processor_version": PROCESSOR_VERSION,
            "normalizer": {"id": NORMALIZER_ID, "version": NORMALIZER_VERSION},
            "assembler": {"id": ASSEMBLER_ID, "version": ASSEMBLER_VERSION},
            "release_fingerprint": semantic_worker_release_fingerprint(),
        },
    }
    if runtime_mode not in {FACTS_MODE, INVESTIGATION_MODE} and result is not None:
        policies = list(result.get("enabled_policies") or [])
        payload["enabled_policies"] = policies
        if len(policies) == 1:
            payload["enabled_policy"] = policies[0]
    if repair_plan_digest is not None:
        payload["repair_scope"] = {
            "job_kind": "semantic_v2_quarantine_repair",
            "repair_plan_digest": repair_plan_digest,
        }
    if result is not None:
        payload["last_result"] = result
    return payload


def run(*, once: bool, poll_seconds: int, limit: int) -> int:
    bounded_limit = max(1, min(int(limit), MAX_BATCH_LIMIT))
    runtime_mode = semantic_runtime_mode_from_env()
    repair_plan_digest = semantic_v2_quarantine_repair_plan_digest_from_env()
    if repair_plan_digest is not None and runtime_mode != INVESTIGATION_MODE:
        raise RuntimeError("semantic v2 quarantine recovery requires investigation mode")
    if repair_plan_digest is not None:
        bounded_limit = min(bounded_limit, MAX_SEMANTIC_RECOVERY_BATCH)
    validate_semantic_runtime_settings(runtime_mode, SemanticFeatureSettings.from_env())
    worker_id = f"semantic-production-{socket.gethostname()}-{os.getpid()}"
    started_at = datetime.now(timezone.utc)
    log_event(
        "runtime_worker",
        "semantic_production_worker_started",
        "Continuous semantic production worker started.",
        worker_id=worker_id,
    )
    # Docker uses a provisioned bounded login; Windows retains its ephemeral login.
    configured = postgres_secret_parts("ADLOG_SEMANTIC_WORKER_DSN")
    with nullcontext() if configured else ephemeral_worker_environment():
        with _singleton_lock() as acquired:
            if not acquired:
                print(
                    json.dumps(
                        {
                            "worker_id": worker_id,
                            "status": "skipped",
                            "reason": "semantic_production_worker_lock_held",
                        }
                    ),
                    flush=True,
                )
                return 0
            archive = _archive_reader()
            while True:
                if shutdown.requested() or stop_requested(started_at):
                    record_worker_heartbeat(
                        worker_name="semantic",
                        worker_id=worker_id,
                        status="stopped",
                        phase="production_stop_requested",
                        expected_interval_seconds=poll_seconds,
                        started_at=started_at,
                        details=_details(limit=bounded_limit, runtime_mode=runtime_mode, repair_plan_digest=repair_plan_digest),
                        connection_factory=_connect,
                    )
                    return 0
                record_worker_heartbeat(
                    worker_name="semantic",
                    worker_id=worker_id,
                    status="running",
                    phase="production_poll",
                    expected_interval_seconds=poll_seconds,
                    started_at=started_at,
                    details=_details(limit=bounded_limit, runtime_mode=runtime_mode, repair_plan_digest=repair_plan_digest),
                    connection_factory=_connect,
                )
                try:
                    result = run_production_once(
                        limit=bounded_limit,
                        connect_factory=_connect,
                        archive=archive,
                        repair_plan_digest=repair_plan_digest,
                    )
                    print(
                        json.dumps(
                            {"worker_id": worker_id, **result},
                            ensure_ascii=False,
                        ),
                        flush=True,
                    )
                    busy = semantic_cycle_has_work(result)
                    record_worker_heartbeat(
                        worker_name="semantic",
                        worker_id=worker_id,
                        status="failed" if result["failed"] else "running" if busy else "idle",
                        phase="production_drain" if busy else "production_sleep",
                        expected_interval_seconds=poll_seconds,
                        started_at=started_at,
                        details=_details(
                            limit=bounded_limit,
                            runtime_mode=runtime_mode,
                            repair_plan_digest=repair_plan_digest,
                            result=result,
                        ),
                        connection_factory=_connect,
                    )
                    if once:
                        return 1 if result["failed"] else 0
                    if busy:
                        continue
                except Exception as exc:
                    error_id = log_internal_error(
                        "runtime_worker",
                        "semantic_production_worker_iteration_failed",
                        "Continuous semantic production worker iteration failed.",
                        exc=exc,
                        worker_id=worker_id,
                    )
                    print(
                        json.dumps(
                            {
                                "worker_id": worker_id,
                                "status": "failed",
                                "error_id": error_id,
                                "error": str(exc),
                            },
                            ensure_ascii=False,
                        ),
                        flush=True,
                    )
                    record_worker_heartbeat(
                        worker_name="semantic",
                        worker_id=worker_id,
                        status="failed",
                        phase="production_sleep",
                        expected_interval_seconds=poll_seconds,
                        started_at=started_at,
                        details={
                            **_details(
                                limit=bounded_limit,
                                runtime_mode=runtime_mode,
                                repair_plan_digest=repair_plan_digest,
                            ),
                            "error_id": error_id,
                            "error_type": type(exc).__name__,
                        },
                        connection_factory=_connect,
                    )
                    if once:
                        return 1
                shutdown.wait(poll_seconds, sleep=time.sleep)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the bounded continuous production semantic worker."
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=int, default=30)
    parser.add_argument("--limit", type=int, default=MAX_BATCH_LIMIT)
    args = parser.parse_args()
    return run(
        once=bool(args.once),
        poll_seconds=max(5, min(int(args.poll_seconds), 300)),
        limit=max(1, min(int(args.limit), MAX_BATCH_LIMIT)),
    )


if __name__ == "__main__":
    raise SystemExit(main())
