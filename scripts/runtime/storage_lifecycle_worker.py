# ruff: noqa: F401 -- re-export hub (plan 7.2b); split parts import names from here.
"""Automatic fail-closed storage lifecycle with permanent ClickHouse history.

The worker is admitted once through the protected supervisor environment.  A
cycle first closes the PostgreSQL-to-ClickHouse gap, freezes and verifies one
cutoff, and only then deletes the exact verified PostgreSQL manifest.  The
canonical archive is never deleted and physical reclaim is never attempted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops import shutdown
from server.sli.core.app_config import load_config
from server.sli.core.paths import DATA_DIR
from server.sli.storage.lifecycle_health import EXPECTED_BLOCK_REASONS, safe_warning_reason
from server.sli.storage.purge_audit import failure_reason
from server.sli.storage.permanent_fact_history import (
    configured_read_port,
    verify_preserved_candidates,
)
from server.sli.storage.postgres_profile_retention import (
    NOISE_DELETE_EVENT_KEYS,
    direct_no_archive_descriptors,
    execute_configured_postgres_profile_retention,
    execute_no_archive_retention,
)
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.ops.runtime_workers import record_worker_heartbeat
from server.sli.storage.storage_lifecycle_bounded_io import iter_json_lines
from server.sli.storage.storage_policy import (
    apply_storage_cleanup_plan,
    build_storage_cleanup_plan,
    get_storage_capacity_profile_resolution,
    get_storage_runtime_capacity_evidence,
    load_storage_policy,
)
from server.sli.storage.tier_retention_delete_executor_runtime import (
    _connect_write as retention_write_connect,
)

LOCK_NAME = "ad_log_reports_runtime_storage_lifecycle_process"
WORKER_NAME = "storage_lifecycle"
ENABLE_ENV = "ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED"
ADMISSION_ENV = "ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION"
WARM_ADMISSION_ENV = "ADLOG_STORAGE_LIFECYCLE_WARM_COPY_ADMISSION"
DELETE_EXECUTION_ENV = "ADLOG_STORAGE_LIFECYCLE_DELETE_EXECUTION_ENABLED"
DELETE_CONFIRMATION = "APPLY-STAGE7-HOT-RETENTION-DELETE"
NO_ARCHIVE_ADMISSION_ENV = "ADLOG_STORAGE_NO_ARCHIVE_DELETE_CONFIRMATION"
NO_ARCHIVE_DELETE_CONFIRMATION = (
    "DELETE_EXPLICIT_NO_ARCHIVE_ROWS_AFTER_SEMANTIC_COMPLETION"
)
WARM_CONFIRMATION = "START-STAGE7-WARM-INCREMENTAL-COPY"
EVIDENCE = DATA_DIR / "artifacts" / "stage7" / "evidence"
LAST_RESULT = DATA_DIR / "runtime" / "storage-lifecycle-last.json"
NO_ARCHIVE_PROGRESS = DATA_DIR / "runtime" / "storage-no-archive-progress.json"
PROCESSED_PACKAGES = DATA_DIR / "runtime" / "storage-lifecycle-processed-packages.jsonl"
WARM_PLAN = EVIDENCE / "warm-tier-incremental-plan.json"
BACKLOG_RETRY_SECONDS = 300
# Production exhausted the 7,200-second child deadline twice with the former
# 200-batch default.  Fifty is a four-times-smaller cycle budget, leaving
# teardown/retry headroom while the existing partial result checkpoints every
# completed package and schedules the next attempt after BACKLOG_RETRY_SECONDS.
DEFAULT_WARM_BATCH_BUDGET = 50
MAX_PROCESSED_LEDGER_BYTES = 32 * 1024 * 1024
MAX_PROCESSED_LEDGER_LINE_BYTES = 256 * 1024
MAX_PROCESSED_LEDGER_ROWS = 100_000
MAX_DECLARATION_IDS = 10_000
MAX_PROCESSED_DECLARATION_IDS = 1_000_000
WARM_CYCLE_RECEIPT_CONTRACT = "sli.storage-lifecycle-warm-cycle-receipt.v1"
MAX_WARM_CYCLE_COPY_EVIDENCE_BYTES = 8 * 1024 * 1024


def _unknown_capacity_evidence(exc: Exception | None = None) -> dict[str, object]:
    evidence: dict[str, object] = {
        "status": "unknown",
        "read_only": True,
        "reason": "capacity_evidence_unavailable",
    }
    if exc is not None:
        evidence["error_type"] = type(exc).__name__
    return evidence


def _capacity_evidence() -> dict[str, object]:
    """Capacity diagnostics are advisory evidence, never a cycle dependency."""
    try:
        evidence = get_storage_runtime_capacity_evidence()
        if not isinstance(evidence, dict):
            raise TypeError("capacity_evidence_not_mapping")
        return dict(evidence)
    except Exception as exc:
        return _unknown_capacity_evidence(exc)


def _heartbeat_result_age(
    completed_at: datetime | None,
    *,
    now: datetime,
) -> int | None:
    if completed_at is None:
        return None
    return max(0, int((now - completed_at).total_seconds()))


def _lifecycle_result_digest(result: dict[str, object]) -> str:
    """Digest the persisted result without making the digest self-referential."""
    payload = {key: value for key, value in result.items() if key != "result_digest"}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _warm_cycle_receipt_digest(receipt: dict[str, object]) -> str:
    """Digest an immutable warm receipt without including its own digest."""
    payload = {
        key: value for key, value in receipt.items() if key != "receipt_digest"
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )












def automation_admitted(environ: dict[str, str] | None = None) -> bool:
    values = environ if environ is not None else os.environ
    return (
        str(values.get(ENABLE_ENV, "")).strip().casefold() in {"1", "true", "yes", "on"}
        and str(values.get(ADMISSION_ENV, "")).strip() == DELETE_CONFIRMATION
    )


def warm_automation_admitted(environ: dict[str, str] | None = None) -> bool:
    """Accept legacy full admission or explicit copy-only warm admission."""
    values = environ if environ is not None else os.environ
    return (
        str(values.get(ENABLE_ENV, "")).strip().casefold() in {"1", "true", "yes", "on"}
        and (
            str(values.get(ADMISSION_ENV, "")).strip() == DELETE_CONFIRMATION
            or str(values.get(WARM_ADMISSION_ENV, "")).strip() == WARM_CONFIRMATION
        )
    )


def delete_execution_admitted(environ: dict[str, str] | None = None) -> bool:
    values = environ if environ is not None else os.environ
    return str(values.get(DELETE_EXECUTION_ENV, "")).strip().casefold() in {
        "1", "true", "yes", "on",
    }


def no_archive_automation_admitted(environ: dict[str, str] | None = None) -> bool:
    values = environ if environ is not None else os.environ
    return (
        str(values.get(ENABLE_ENV, "")).strip().casefold() in {"1", "true", "yes", "on"}
        and str(values.get(NO_ARCHIVE_ADMISSION_ENV, "")).strip()
        == NO_ARCHIVE_DELETE_CONFIRMATION
    )




def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(path.suffix + ".partial")
    partial.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    os.replace(partial, path)










# Reuse the confirmed-assignment kill-on-close Job Object pattern from
# storage_v2_outbox_worker.  Popen cannot hand us a suspended child through
# the current portable call site, so assignment immediately after Popen and
# before the first communicate() is the earliest ownership boundary available.
if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JobObjectExtendedLimitInformation = 9
    _PROCESS_TERMINATE = 0x0001
    _PROCESS_SET_QUOTA = 0x0100

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _kernel32 = ctypes.windll.kernel32
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
    ]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    def _create_kill_on_close_job() -> int | None:
        try:
            handle = _kernel32.CreateJobObjectW(None, None)
            if not handle:
                return None
            info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not _kernel32.SetInformationJobObject(
                handle, _JobObjectExtendedLimitInformation,
                ctypes.byref(info), ctypes.sizeof(info),
            ):
                _kernel32.CloseHandle(handle)
                return None
            return handle
        except Exception:
            return None

    def _assign_process_to_job(job_handle: int, pid: int) -> bool:
        try:
            process_handle = _kernel32.OpenProcess(
                _PROCESS_TERMINATE | _PROCESS_SET_QUOTA, False, int(pid),
            )
            if not process_handle:
                return False
            try:
                return bool(_kernel32.AssignProcessToJobObject(job_handle, process_handle))
            finally:
                _kernel32.CloseHandle(process_handle)
        except Exception:
            return False

    def _terminate_job(job_handle: int) -> None:
        try:
            _kernel32.TerminateJobObject(job_handle, 1)
        except Exception:
            pass

    def _close_job(job_handle: int) -> None:
        try:
            _kernel32.CloseHandle(job_handle)
        except Exception:
            pass
else:
    def _create_kill_on_close_job() -> int | None:
        return None

    def _assign_process_to_job(job_handle: int, pid: int) -> bool:
        return False

    def _terminate_job(job_handle: int) -> None:
        pass

    def _close_job(job_handle: int) -> None:
        pass


def _start_job_protected(pid: int) -> int | None:
    job_handle = _create_kill_on_close_job()
    if job_handle is None:
        return None
    if _assign_process_to_job(job_handle, pid):
        return job_handle
    _close_job(job_handle)
    return None


_POST_KILL_DRAIN_SECONDS = 15












@contextmanager
def lifecycle_lock() -> Iterator[bool]:
    with session_advisory_lock(connect, LOCK_NAME) as acquired:
        yield acquired


def run(*, once: bool, interval_seconds: int) -> int:
    with lifecycle_lock() as acquired:
        if not acquired:
            print(json.dumps({"status": "skipped", "reason": "storage_lifecycle_lock_held"}))
            return 9
        worker_id = f"storage-lifecycle-{socket.gethostname()}-{os.getpid()}"
        started_at = datetime.now(timezone.utc)
        prior_successful_watermark, prior_watermark_updated_at = _prior_successful_watermark()
        cycle_evidence: dict[str, object] = {
            "last_cycle_status": "unknown",
            "last_cycle_started_at": None,
            "last_cycle_completed_at": None,
            "last_success_at": None,
            "last_error_type": None,
            "last_result_digest": None,
            "last_result_phase": None,
            "last_successful_watermark": prior_successful_watermark,
            "watermark_updated_at": prior_watermark_updated_at,
            "copy_only_no_delete": None,
            "delete_execution_admitted": None,
            "deleted_rows": None,
        }
        record_worker_heartbeat(
            worker_name=WORKER_NAME, worker_id=worker_id, status="starting",
            phase="startup", expected_interval_seconds=interval_seconds,
            started_at=started_at,
            details=_lifecycle_heartbeat_details(
                cycle_evidence=cycle_evidence,
                capacity_evidence=_capacity_evidence(),
                process_status="starting",
                lifecycle_phase="startup",
                now=datetime.now(timezone.utc),
            ),
        )
        while not shutdown.requested():
            next_wait_seconds = interval_seconds
            capacity_evidence = _capacity_evidence()

            def heartbeat() -> None:
                record_worker_heartbeat(
                    worker_name=WORKER_NAME, worker_id=worker_id, status="running",
                    phase="processing", expected_interval_seconds=interval_seconds,
                    started_at=started_at,
                    details=_lifecycle_heartbeat_details(
                        cycle_evidence=cycle_evidence,
                        capacity_evidence=capacity_evidence,
                        process_status="running",
                        lifecycle_phase="processing",
                        now=datetime.now(timezone.utc),
                    ),
                )

            heartbeat()
            cycle_started_at = datetime.now(timezone.utc)
            cycle_error: Exception | None = None
            try:
                result = run_cycle(on_wait=heartbeat)
                result_status = str(result.get("status") or "")
                if result_status in {"ok", "disabled"}:
                    status = "idle"
                    if (
                        result_status == "ok"
                        and result.get("warm_backlog_remaining") is True
                    ):
                        next_wait_seconds = BACKLOG_RETRY_SECONDS
                elif result_status == "partial":
                    status = "partial"
                    next_wait_seconds = BACKLOG_RETRY_SECONDS
                else:
                    status = "blocked"
                    next_wait_seconds = BACKLOG_RETRY_SECONDS
                completed_at = datetime.now(timezone.utc)
                cycle_evidence.update({
                    "last_cycle_status": (
                        "success" if result_status in {"ok", "disabled"} else status
                    ),
                    "last_cycle_reason": result.get("reason") or result.get("warning_reason") or (
                        "history_publication_backlog_remaining" if status == "partial" else None
                    ),
                    "last_cycle_started_at": cycle_started_at,
                    "last_cycle_completed_at": completed_at,
                    "last_error_type": None,
                    "copy_only_no_delete": result.get("copy_only_no_delete"),
                    "delete_execution_admitted": result.get("delete_execution_admitted"),
                    "deleted_rows": int(result.get("deleted_rows") or 0),
                })
                if result_status in {"ok", "disabled"}:
                    cycle_evidence.update({"last_success_at": completed_at})
            except Exception as exc:
                next_wait_seconds = BACKLOG_RETRY_SECONDS
                cycle_error = exc
                result = {
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "error": failure_reason(exc),
                }
                status = "failed"
                cycle_evidence.update({
                    "last_cycle_status": "failed",
                    "last_cycle_started_at": cycle_started_at,
                    "last_cycle_completed_at": datetime.now(timezone.utc),
                    "last_error_type": type(exc).__name__,
                    "last_cycle_reason": None,
                })
            completed_at = cycle_evidence["last_cycle_completed_at"]
            assert isinstance(completed_at, datetime)
            result_phase = "completed" if status == "idle" else status
            persisted_result = _persist_lifecycle_result(
                result,
                started_at=cycle_started_at,
                ended_at=completed_at,
                phase=result_phase,
                error=cycle_error,
                prior_successful_watermark=(
                    str(cycle_evidence["last_successful_watermark"])
                    if cycle_evidence["last_successful_watermark"] is not None else None
                ),
                prior_watermark_updated_at=(
                    str(cycle_evidence["watermark_updated_at"])
                    if cycle_evidence["watermark_updated_at"] is not None else None
                ),
            )
            cycle_evidence.update({
                "last_result_digest": persisted_result["result_digest"],
                "last_result_phase": persisted_result["phase"],
                "last_successful_watermark": persisted_result["last_successful_watermark"],
                "watermark_updated_at": persisted_result["watermark_updated_at"],
            })
            print(json.dumps({"worker_id": worker_id, **result}, ensure_ascii=False), flush=True)
            capacity_evidence = _capacity_evidence()
            # Preserve the cycle's blocked/partial phase and watermark while
            # reporting an alive worker waiting on a known condition as warning.
            heartbeat_status = status
            if status == "partial" or (
                status == "blocked" and cycle_evidence["last_cycle_reason"] in EXPECTED_BLOCK_REASONS
            ) or (status == "idle" and result.get("warning_reason")):
                heartbeat_status = "warning"
                cycle_evidence["last_cycle_reason"] = safe_warning_reason(cycle_evidence["last_cycle_reason"])
            record_worker_heartbeat(
                worker_name=WORKER_NAME, worker_id=worker_id, status=heartbeat_status,
                phase="error" if status == "failed" else "sleep",
                expected_interval_seconds=next_wait_seconds,
                started_at=started_at,
                details=_lifecycle_heartbeat_details(
                    cycle_evidence=cycle_evidence,
                    capacity_evidence=capacity_evidence,
                    process_status="running",
                    lifecycle_phase="not_due" if status == "idle" else result_phase,
                    now=datetime.now(timezone.utc),
                ),
            )
            if once:
                return 0 if status in {"idle", "partial"} else 2
            shutdown.wait(next_wait_seconds, sleep=time.sleep)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval-seconds", type=int, default=21_600)
    args = parser.parse_args()
    if os.name == "nt":
        from server.sli.ops.worker_supervisor_secrets import (
            SUPERVISOR_ENV_PATH,
            load_supervisor_environment,
        )
        if SUPERVISOR_ENV_PATH.is_file():
            # A long-lived supervisor may predate the history cutover. Reload
            # the protected profile instead of inheriting its obsolete flags.
            load_supervisor_environment(override_existing=True)
    interval = max(900, min(int(args.interval_seconds), 86_400))
    try:
        return run(once=bool(args.once), interval_seconds=interval)
    except Exception as error:
        # Startup/lock and terminal receipt failures are outside the cycle's
        # handler. Keep their hard failure without exposing connection text.
        print(json.dumps({"status": "failed", "reason": failure_reason(error),
                          "error_type": type(error).__name__}), flush=True)
        return 2


if __name__ == "__main__":
    import sys as _sys

    _sys.modules.setdefault("scripts.runtime.storage_lifecycle_worker", _sys.modules[__name__])
from scripts.runtime.storage_lifecycle_evidence import (  # noqa: F401
    _bound_warm_copy_evidence,
    _record_warm_cycle_receipt,
    _prior_successful_watermark,
    _persist_lifecycle_result,
    _lifecycle_heartbeat_details,
)


from scripts.runtime.storage_lifecycle_declarations import (  # noqa: F401
    _frozen_no_archive_cutoff,
    _declaration_progress_digest,
    _validated_declaration_progress,
    _processed_declaration_ids,
    _commit_processed_package,
)


from scripts.runtime.storage_lifecycle_commands import (  # noqa: F401
    _run_command,
    _invoke,
    _run_no_archive_cycle,
    _run_history_cycle,
)


from scripts.runtime.storage_lifecycle_cycle import (  # noqa: F401
    run_cycle,
)

if __name__ == "__main__":
    raise SystemExit(main())
