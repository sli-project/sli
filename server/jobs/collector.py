# ruff: noqa: F401 -- re-export hub (plan 6.3/7.2b): split-out modules read these
# names through ``server.jobs.collector`` at call time.
from __future__ import annotations

import itertools
import json
import logging
import os
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from server.sli.core.app_config import load_config
from server.sli.core.paths import RAW_SPOOL_DIR, ROOT
from server.sli.core.postgres_runtime_pipeline import connect as _pg_connect
from server.sli.ops.logging_config import (
    log_audit_action,
    log_event,
    log_internal_error,
)
from server.sli.ops.performance import log_performance_stage, monotonic_ms
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.reports.analysis import generate_recommendation_report
from server.sli.semantic.findings import refresh_findings_from_events
from server.sli.sources.collector_adaptive import get_adaptive_plan_for_server
from server.sli.sources.dc_discovery import (
    discover_domain_controllers,
    get_configured_domain_controller_targets,
    resolve_domain_controller_connect_address,
)
from server.sli.sources.post_collection_pipeline import (
    PostCollectionLeaseLost,
    claim_post_collection_job,
    claim_queued_post_collection_jobs,
    heartbeat_post_collection_job,
    post_collection_lease_guard,
    queue_post_collection_job,
    update_post_collection_findings,
    update_post_collection_job,
)
from server.sli.storage.storage_policy import can_start_collection
from server.sli.storage.storage_v2_transition_controller import (
    CutoverAuthorization,
)

JobStatus = Literal["queued", "running", "completed", "partial", "failed", "skipped"]
DEFAULT_COLLECTION_TIMEOUT_SECONDS = 600
# Keep archive catch-up bounded per cycle. An unlimited Security log read can hang
# long enough to miss the most important AD channel; the next scheduled cycles
# continue from the updated EventRecordID watermark.
ARCHIVE_MAX_EVENTS_PER_CHANNEL = int(os.environ.get("ADLOG_ARCHIVE_MAX_EVENTS_PER_CHANNEL", os.environ.get("ADLOG_NON_SECURITY_MAX_EVENTS", "500")))
PARALLEL_DC_WORKERS = max(1, int(os.environ.get("ADLOG_PARALLEL_DC_WORKERS", "2")))
COLLECTOR_BACKEND = os.environ.get("ADLOG_COLLECTOR_BACKEND", "auto").strip().lower()
CONTINUOUS_RECOVERY_ENABLED = os.environ.get("ADLOG_CONTINUOUS_RECOVERY", "true").strip().lower() not in {"0", "false", "no", "off"}
CONTINUOUS_RECOVERY_COOLDOWN_SECONDS = max(0, int(os.environ.get("ADLOG_CONTINUOUS_RECOVERY_COOLDOWN_SECONDS", os.environ.get("ADLOG_SECURITY_RECOVERY_COOLDOWN_SECONDS", "5"))))
CONTINUOUS_RECOVERY_MAX_CYCLES = max(1, int(os.environ.get("ADLOG_CONTINUOUS_RECOVERY_MAX_CYCLES", "20")))
CONTINUOUS_RECOVERY_MAX_JOB_SECONDS = max(60, int(os.environ.get("ADLOG_CONTINUOUS_RECOVERY_MAX_JOB_SECONDS", "1800")))
TAIL_LIMIT = 2000
POST_COLLECTION_HEARTBEAT_SECONDS = 30.0


@dataclass
class Job:
    id: int
    kind: str
    status: JobStatus
    servers: list[str]
    hours: int
    max_events_per_channel: int
    created_at: str
    updated_at: str
    durable_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    message: str = ""
    report_url: str | None = None
    analysis_report_url: str | None = None
    command_outputs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    exit_code: int | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    duration_ms: int | None = None
    failed_servers: list[str] = field(default_factory=list)
    affected_channels: list[str] = field(default_factory=list)
    phase: str = "queued"
    cycle: int = 0
    skipped_reason: str | None = None
    trace_id: str | None = None
    current_server: str | None = None
    current_channel: str | None = None
    channels_in_progress: list[str] = field(default_factory=list)
    events_collected: int = 0
    last_progress_at: str | None = None
    mode: str | None = None
    collection_status: str | None = None
    analysis_status: str | None = None
    report_status: str | None = None
    analysis_started_at: str | None = None
    analysis_finished_at: str | None = None
    analysis_error_id: str | None = None
    findings_status: str | None = None
    findings_result: dict | None = None
    findings_error_id: str | None = None


_lock = threading.Lock()
_counter = itertools.count(1)
_jobs: dict[int, Job] = {}
_scheduler_started = False
_running_collect_lock = threading.Lock()
_post_collection_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="post-collection")
_post_collection_guard = threading.Lock()
_post_collection_active: set[str] = set()


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


# Same PostgreSQL advisory-lock name that scripts/runtime/collection_worker.py
# holds for the duration of one collection cycle (collection_worker_lock()).
# Reused here so the in-process scheduler and the external worker can never
# both run a collection cycle at the same time, regardless of configuration.
COLLECTION_OWNER_LOCK_NAME = "ad_log_reports_runtime_collection_worker"


def inprocess_scheduler_opt_in_enabled() -> bool:
    """Whether the in-process HTTP-server scheduler may run at all.

    The scheduler has no legitimate production consumer: both the documented
    production contour (docs/OPERATIONS_RUNBOOK.md) and every local dev
    environment already keep it disabled, and scripts/runtime/collection_worker.py
    is the sole designated production owner of collection.  This flag exists
    only for rollback/diagnostic use and defaults to off, so a server that
    boots without it (the common case, including a misconfigured one) never
    starts a second collector by accident.
    """
    return _env_truthy("ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER")


def _forced_run_dc_log_pilot_env() -> dict[str, str]:
    """Environment for every ``run_dc_log_pilot.py`` subprocess this module spawns.

    scripts/runtime/collection_worker.py already forces
    ``ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER=1`` for its own process before
    it reaches here, so the child subprocess it launches already inherits the
    safe value. The manual "Collect Now" endpoint and the in-process scheduler
    do not set that variable for themselves, so without this the child would
    inherit whatever the parent process happened to have (commonly unset),
    letting the pilot's own compat-drain silently compete with the dedicated
    scripts/runtime/storage_v2_outbox_worker.py for the same outbox row.
    Forcing it here, regardless of caller, makes Storage V2 publication have
    exactly one live owner no matter which of the three paths spawned the
    subprocess.
    """
    env = os.environ.copy()
    env["ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER"] = "1"
    env.setdefault("ADLOG_DELETE_IMPORTED_RAW", "1")
    return env


def external_post_collection_worker_enabled() -> bool:
    """Whether durable post-collection work is owned by a separate process.

    The default remains the established in-process executor.  This explicit
    switch allows a controlled move to an independent worker without letting
    the web process and worker race for the same queued row.
    """
    return _env_truthy("ADLOG_EXTERNAL_POST_COLLECTION_WORKER")


def inprocess_post_collection_opt_in_enabled() -> bool:
    """Whether the in-process HTTP-server ``ThreadPoolExecutor`` may run
    post-collection work at all.

    scripts/runtime/post_collection_worker.py is the sole designated
    production owner of post-collection.  This flag exists only for local
    dev/rollback use and defaults to off, so a server that boots without it
    (the common case, including a misconfigured one) never silently runs
    post-collection through the in-process path.  The queued row is left in
    place either way, so an external worker (or a later opt-in) can still
    pick it up; nothing is lost, it simply is not executed here.
    """
    from server.sli.sources.legacy_collection import legacy_collection_disabled

    return not legacy_collection_disabled() and _env_truthy("ADLOG_ENABLE_INPROCESS_POST_COLLECTION")


def legacy_findings_enabled() -> bool:
    """Whether the retired Event-ID-as-verdict producer may create Findings.

    The default is deliberately false after semantic TEST/SHADOW acceptance.
    Existing rows remain readable for audit/history, while new verdicts belong
    to the scenario lifecycle.  A rollback requires an explicit process-local
    flag instead of silently reviving the legacy producer.
    """
    return _env_truthy("ADLOG_LEGACY_FINDINGS_ENABLED")


def _analysis_queue_log_status(status: str) -> str:
    return "queued" if status in {"completed", "partial"} else "not_queued"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _csv_env(name: str, default: str) -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip() for item in re.split(r"[,;]", raw) if item.strip()]


def _scheduler_canary_enabled() -> bool:
    return _env_truthy("ADLOG_SCHEDULER_CANARY") or _env_truthy("ADLOG_POSTGRES_SCHEDULER_CANARY")


def _scheduler_profile() -> str:
    raw = os.environ.get("ADLOG_SCHEDULER_PROFILE", "").strip().lower()
    if raw:
        return raw
    if _scheduler_canary_enabled():
        return "canary"
    return "standard"


def _scheduler_canary_config() -> dict:
    requested_max_events = max(1, _env_int("ADLOG_CANARY_MAX_EVENTS", 1000))
    # DB-0.10.1 safety guard: DB-0.10 showed that a 10k scheduled
    # Security profile can block the runtime API on the current host. Keep
    # controlled scheduler expansion capped to the last safe profile unless an
    # operator deliberately changes ADLOG_CANARY_MAX_EVENTS_CAP.
    max_events_cap = max(1, _env_int("ADLOG_CANARY_MAX_EVENTS_CAP", 5000))
    effective_max_events = min(requested_max_events, max_events_cap)
    archive_enabled = _env_truthy("ADLOG_CANARY_ARCHIVE")
    canary_enabled = _scheduler_canary_enabled()
    return {
        "enabled": canary_enabled,
        "profile": _scheduler_profile(),
        "channels": _csv_env("ADLOG_CANARY_CHANNELS", "Security"),
        "requested_max_events_per_channel": requested_max_events,
        "max_events_cap": max_events_cap,
        "max_events_capped": requested_max_events > effective_max_events,
        "max_events_per_channel": effective_max_events,
        "hours": max(1, _env_int("ADLOG_CANARY_HOURS", 1)),
        "archive_enabled": archive_enabled,
        "watermark_enabled": archive_enabled,
        "archive_watermark_canary": canary_enabled and archive_enabled,
        "collection_mode": os.environ.get("ADLOG_CANARY_COLLECTION_MODE", "current").strip().lower() or "current",
        "skip_report": _scheduler_skip_report_enabled(),
        "channel_timeout_seconds": max(30, _env_int("ADLOG_CANARY_CHANNEL_TIMEOUT_SECONDS", 120)),
        "command_timeout_seconds": max(60, _env_int("ADLOG_CANARY_COMMAND_TIMEOUT_SECONDS", 240)),
    }


def _scheduler_effective_job_params(hours: int, max_events_per_channel: int) -> dict:
    canary = _scheduler_canary_config()
    if canary["enabled"]:
        return {
            "profile": canary["profile"],
            "hours": int(canary["hours"]),
            "max_events_per_channel": int(canary["max_events_per_channel"]),
            "channels": list(canary["channels"] or ["Security"]),
            "archive_enabled": bool(canary["archive_enabled"]),
            "collection_mode": str(canary["collection_mode"] or "current"),
        }
    return {
        "profile": "standard",
        "hours": hours,
        "max_events_per_channel": max_events_per_channel,
        "channels": [],
        "archive_enabled": True,
        "collection_mode": "auto",
    }


def _runtime_db_backend() -> str:
    try:
        return (load_config().db_backend or "postgres").strip().lower()
    except Exception as exc:
        log_internal_error(
            "runtime_cutover",
            "backend_config_read_failed",
            "Failed to read runtime DB backend; failing closed to PostgreSQL.",
            exc=exc,
        )
        return "postgres"


def _postgres_collection_enabled() -> bool:
    return _env_truthy("ADLOG_ENABLE_POSTGRES_COLLECTION") or _env_truthy("ADLOG_POSTGRES_RUNTIME_COLLECTION")


def _scheduler_skip_report_enabled() -> bool:
    """Return whether scheduled bounded profiles should skip heavy report generation.

    DB-0.11: manual PostgreSQL imports and the 1k canary showed that the
    collector/importer path works, while DB-0.10/0.10.1 showed that longer
    scheduled runs can leave the HTTP API unresponsive after the collection
    phase.  Keep controlled scheduler cycles focused on collection/import and
    do not run expensive in-process analysis unless an operator explicitly
    disables this guard.
    """
    raw = os.environ.get("ADLOG_SCHEDULER_SKIP_REPORT")
    if raw is not None:
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return _scheduler_canary_enabled()


def post_collection_worker_mode() -> str:
    """Which owner, if any, can currently execute post-collection work.

    ``"external"`` — the durable worker owns it.  ``"in_process"`` — the
    external worker is off, but the in-process executor is opted in and
    will actually claim and run queued rows.  ``"disabled"`` — neither is
    active: a completed job's post-collection row simply stays queued for
    whichever owner shows up later.  Reporting ``"in_process"`` in that
    last case would be a lie the diagnostics tell about themselves.
    """
    from server.sli.sources.legacy_collection import legacy_collection_disabled

    if legacy_collection_disabled():
        return "disabled"
    if external_post_collection_worker_enabled():
        return "external"
    if inprocess_post_collection_opt_in_enabled():
        return "in_process"
    return "disabled"


def _collection_block_reason() -> str | None:
    from server.sli.sources.legacy_collection import legacy_collection_disabled, REASON

    if legacy_collection_disabled():
        return REASON
    from server.sli.sources.ad_dc_agent_import import agent_import_enabled
    try:
        if agent_import_enabled():
            return "ad_dc_agent_collection_owner"
    except ValueError:
        return "agent_ad_dc_import_config_invalid"
    backend = _runtime_db_backend()
    if backend == "postgres":
        try:
            from server.sli.sources.collection_runtime_block import (
                get_active_collection_block,
            )

            durable_block = get_active_collection_block()
        except Exception as exc:
            log_internal_error(
                "collector", "collection_block_contract_unavailable",
                "Collection is fail-closed because the durable block contract is unavailable.",
                exc=exc,
            )
            return "runtime_collection_block_contract_unavailable"
        if durable_block:
            return str(durable_block.get("reason_code") or "runtime_collection_block_active")
    if _env_truthy("ADLOG_DISABLE_COLLECTION"):
        return "collection_disabled_by_ADLOG_DISABLE_COLLECTION"
    if backend == "postgres" and not _postgres_collection_enabled():
        return "postgres_runtime_collection_guard"
    return None


def get_collection_runtime_status() -> dict:
    backend = _runtime_db_backend()
    block_reason = _collection_block_reason()
    status = {
        "active_backend": backend,
        "collection_enabled": block_reason is None,
        "collection_block_reason": block_reason,
        "postgres_collection_enabled": _postgres_collection_enabled(),
        "disable_collection_env": _env_truthy("ADLOG_DISABLE_COLLECTION"),
        "continuous_recovery_enabled": CONTINUOUS_RECOVERY_ENABLED,
        "post_collection_worker_mode": post_collection_worker_mode(),
    }
    if backend == "postgres" and block_reason == "windows_security_context_invalid":
        try:
            from server.sli.sources.collection_runtime_block import (
                get_active_collection_block,
            )

            durable_block = get_active_collection_block() or {}
            status["collection_block"] = {
                "reason_code": durable_block.get("reason_code"),
                "retry_policy": durable_block.get("retry_policy"),
                "operator_action": durable_block.get("operator_action"),
                "observed_count": durable_block.get("observed_count"),
                "first_seen_at": durable_block.get("first_seen_at").isoformat() if durable_block.get("first_seen_at") else None,
                "last_seen_at": durable_block.get("last_seen_at").isoformat() if durable_block.get("last_seen_at") else None,
            }
        except Exception:
            status["collection_block"] = {
                "reason_code": block_reason,
                "retry_policy": "operator_recovery_required",
            }
    if backend == "postgres":
        try:
            from server.sli.core.postgres_runtime_pipeline import (
                get_runtime_pipeline_status,
            )

            status.update(get_runtime_pipeline_status())
        except Exception as exc:
            status.update({"postgres_importer_available": False, "postgres_pipeline_status": "failed", "postgres_pipeline_error": str(exc)})
    return status


def get_scheduler_runtime_status() -> dict:
    from server.sli.sources.legacy_collection import legacy_collection_disabled, REASON

    backend = _runtime_db_backend()
    disabled_reason = None
    if legacy_collection_disabled():
        disabled_reason = REASON
    elif not inprocess_scheduler_opt_in_enabled():
        disabled_reason = "inprocess_scheduler_requires_ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER"
    elif _env_truthy("ADLOG_DISABLE_SCHEDULER"):
        disabled_reason = "scheduler_disabled_by_ADLOG_DISABLE_SCHEDULER"
    elif backend == "postgres" and not _postgres_collection_enabled():
        disabled_reason = "postgres_runtime_collection_guard"
    targets = get_configured_domain_controller_targets()
    return {
        "active_backend": backend,
        "scheduler_enabled": disabled_reason is None,
        "scheduler_started": _scheduler_started,
        "disabled_reason": disabled_reason,
        "postgres_collection_enabled": _postgres_collection_enabled(),
        "disable_scheduler_env": _env_truthy("ADLOG_DISABLE_SCHEDULER"),
        "inprocess_scheduler_opt_in": inprocess_scheduler_opt_in_enabled(),
        "continuous_recovery_enabled": CONTINUOUS_RECOVERY_ENABLED,
        "scheduler_canary_enabled": _scheduler_canary_enabled(),
        "scheduler_profile": _scheduler_profile(),
        "scheduler_skip_report": _scheduler_skip_report_enabled(),
        "post_collection_worker_mode": post_collection_worker_mode(),
        "scheduler_canary": _scheduler_canary_config(),
        "scheduler_archive_watermark_canary_enabled": bool(_scheduler_canary_config().get("archive_watermark_canary")),
        "domain_controller_targets": targets,
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tail(value: str | bytes | None, limit: int = TAIL_LIMIT) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value)[-limit:]


def list_jobs() -> list[dict]:
    with _lock:
        return [asdict(job) for job in sorted(_jobs.values(), key=lambda item: item.id, reverse=True)]


def get_autocollection_status(*, deep: bool = False) -> dict:
    """Return an operator-focused autocollection status snapshot.

    The default API path must be fast and non-blocking.  Earlier Stage 3 code
    called the full collector-health and performance SQL summary from
    /api/autocollection/status; if SQLite was busy or a collector-health query
    was slow, PowerShell/curl could connect and then receive zero bytes until
    timeout.  Keep the default response based on in-memory jobs plus the already
    lightweight archive state.  Deep details remain available for report/debug
    callers that explicitly ask for them.
    """
    started = time.monotonic()
    jobs = list_jobs()
    active = next((job for job in jobs if job.get("status") == "running"), None)
    last_success = next((job for job in jobs if job.get("kind", "").startswith("collect_all_dc_logs") and job.get("status") == "completed"), None)
    skipped = _skipped_overlap_summary(jobs)

    collector_health: dict
    performance: dict
    channels: list[dict]
    if deep:
        collector_health = _safe_collector_health()
        channels = _channel_fairness_summary(collector_health)
        performance = _recent_performance_breakdown(timeout_seconds=0.5)
    else:
        collector_health = {
            "status": "skipped",
            "mode": "fast",
            "reason": "full collector health is skipped in fast autocollection status",
        }
        channels = _archive_channel_summary_fast()
        performance = {
            "status": "skipped",
            "mode": "fast",
            "reason": "performance SQL is skipped in fast autocollection status",
            "stages": [],
        }

    duration_ms = int((time.monotonic() - started) * 1000)
    return {
        "status": "running" if active else "idle",
        "mode": "deep" if deep else "fast",
        "duration_ms": duration_ms,
        "runtime": {
            "scheduler": get_scheduler_runtime_status(),
            "collection": get_collection_runtime_status(),
        },
        "active_job": active,
        "last_successful_cycle": last_success,
        "skipped_overlap_summary": skipped,
        "collector_health": collector_health,
        "channels": channels,
        "performance": performance,
        "last_error": _last_job_error(jobs),
        "explanation": {
            "skipped_overlap": "Это не ошибка: плановый запуск пропускается, если предыдущий сбор еще выполняется.",
            "fairness": "Во время Security recovery не-Security журналы периодически включаются в read-only сбор, если они устарели.",
        },
    }


def get_job(job_id: int) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        return asdict(job) if job else None


def _collection_disk_guard() -> dict:
    """Resolve disk admission without letting observation failure start work."""
    try:
        guard = can_start_collection()
        if not isinstance(guard, dict):
            raise TypeError("collection guard returned a non-object result")
        return guard
    except Exception as exc:
        error_id = log_internal_error(
            "collector",
            "collection_guard_error",
            "Collection stopped because disk admission could not be read.",
            exc=exc,
        )
        return {
            "status": "blocked",
            "collection_allowed": False,
            "reason": "collection_guard_error",
            "error_type": type(exc).__name__,
            "internal_error_id": error_id,
        }


def create_collect_job(
    *,
    servers: list[str] | None = None,
    hours: int = 1,
    max_events_per_channel: int = ARCHIVE_MAX_EVENTS_PER_CHANNEL,
    reason: str = "manual",
) -> dict:
    from server.sli.sources.legacy_collection import legacy_collection_disabled, MESSAGE, REASON

    if legacy_collection_disabled():
        return {"status": "blocked", "reason": REASON, "message": MESSAGE, "collection_allowed": False}
    guard = _collection_disk_guard()
    if not guard.get("collection_allowed"):
        now = utc_now()
        guard_reason = str(guard.get("reason") or "disk_pressure_guard")
        rejection_status = "blocked" if guard_reason == "collection_guard_error" else "skipped"
        result = {
            "kind": f"collect_all_dc_logs:{reason}",
            "status": rejection_status,
            "servers": list(servers or []),
            "hours": hours,
            "max_events_per_channel": max_events_per_channel,
            "created_at": now,
            "updated_at": now,
            "message": f"Сбор не стартовал: {guard_reason}",
            "phase": "admission",
            "skipped_reason": guard_reason,
            "reason": guard_reason,
            "collection_allowed": False,
            "error_type": guard.get("error_type"),
            "disk_guard": guard,
        }
        log_audit_action(
            "manual_collection_start" if reason == "manual" else f"collection_start:{reason}",
            rejection_status,
            job_id=None,
            servers=result["servers"],
            hours=hours,
            max_events_per_channel=max_events_per_channel,
            disk_guard=guard.get("status"),
            reason=guard_reason,
        )
        log_event(
            "collector",
            "collection_blocked_disk_pressure",
            "Collection request blocked before job creation by disk admission.",
            job_id=None,
            status=rejection_status,
            disk_guard_status=guard.get("status"),
            reason=guard_reason,
            error_type=guard.get("error_type"),
        )
        return result

    if not servers:
        servers = discover_domain_controllers()
    now = utc_now()
    block_reason = _collection_block_reason()
    if block_reason:
        with _lock:
            job = Job(
                id=next(_counter),
                kind=f"collect_all_dc_logs:{reason}",
                status="skipped",
                servers=servers,
                hours=hours,
                max_events_per_channel=max_events_per_channel,
                created_at=now,
                updated_at=now,
                message="Collection is disabled by runtime guard; UI/API remains available.",
                phase="skipped",
                skipped_reason=block_reason,
                mode="runtime_guard",
            )
            _jobs[job.id] = job
        log_audit_action(
            "manual_collection_start" if reason == "manual" else f"collection_start:{reason}",
            "skipped",
            job_id=job.id,
            servers=servers,
            hours=hours,
            max_events_per_channel=max_events_per_channel,
            runtime_guard=block_reason,
        )
        log_event(
            "collector",
            "collection_blocked_runtime_guard",
            "Collection job blocked by runtime cutover guard.",
            job_id=job.id,
            status="skipped",
            active_backend=_runtime_db_backend(),
            reason=block_reason,
        )
        return asdict(job)

    status: JobStatus = "queued"
    message = "Задача сбора поставлена в очередь."
    with _lock:
        job = Job(
            id=next(_counter),
            kind=f"collect_all_dc_logs:{reason}",
            status=status,
            servers=servers,
            hours=hours,
            max_events_per_channel=max_events_per_channel,
            created_at=now,
            updated_at=now,
            message=message,
            phase="queued",
            skipped_reason=None,
        )
        _jobs[job.id] = job
    log_audit_action("manual_collection_start" if reason == "manual" else f"collection_start:{reason}", status, job_id=job.id, servers=servers, hours=hours, max_events_per_channel=max_events_per_channel, disk_guard=guard.get("status"))
    log_event("jobs", "job_created", "Collection job created.", job_id=job.id, status=job.status)

    thread = threading.Thread(target=_run_collect_job, args=(job.id, reason), daemon=True)
    thread.start()
    return asdict(job)


def start_scheduler(interval_seconds: int = 600, hours: int = 1, max_events_per_channel: int = ARCHIVE_MAX_EVENTS_PER_CHANNEL) -> dict:
    global _scheduler_started
    from server.sli.sources.legacy_collection import legacy_collection_disabled, MESSAGE, REASON

    if legacy_collection_disabled():
        return {"scheduler_enabled": False, "scheduler_started": _scheduler_started,
                "disabled_reason": REASON, "message": MESSAGE}
    status = get_scheduler_runtime_status()
    if not status.get("scheduler_enabled"):
        log_event(
            "scheduler",
            "scheduler_disabled",
            "Scheduler disabled by runtime guard.",
            active_backend=status.get("active_backend"),
            reason=status.get("disabled_reason"),
        )
        return status
    with _lock:
        if _scheduler_started:
            return get_scheduler_runtime_status()
        _scheduler_started = True

    thread = threading.Thread(
        target=_scheduler_loop,
        args=(interval_seconds, hours, max_events_per_channel),
        daemon=True,
    )
    thread.start()
    result = get_scheduler_runtime_status()
    log_event("scheduler", "scheduler_started", "Collection scheduler started.", duration_ms=interval_seconds * 1000)
    return result


def _wait_for_scheduled_job_terminal(
    job_id: int | None, *, poll_seconds: float = 2.0, max_wait_seconds: float | None = None
) -> None:
    """Block the scheduler's own thread until a scheduled job reaches a terminal status.

    The advisory lock in ``_scheduler_loop`` must cover the whole collection
    cycle, not just the (near-instant) call that creates the job, or the lock
    would be released before the background thread it started has finished
    doing the work it is meant to protect.

    Bounded, deliberately: an unbounded wait would let one stuck cycle hold
    the lock forever and permanently starve ``collection_worker.py`` of it —
    strictly worse than the double-ownership risk this exists to close. The
    bound is generous relative to the collection timeout itself, so it only
    ever fires on a genuine hang, not on a slow-but-normal cycle.
    """
    if job_id is None:
        return
    if max_wait_seconds is None:
        max_wait_seconds = DEFAULT_COLLECTION_TIMEOUT_SECONDS * 3
    terminal = {"completed", "partial", "failed", "skipped"}
    deadline = time.monotonic() + max_wait_seconds
    while True:
        job = get_job(job_id)
        if job is None or job.get("status") in terminal:
            return
        if time.monotonic() >= deadline:
            log_internal_error(
                "scheduler", "scheduler_tick_wait_timed_out",
                "Scheduled collection job did not reach a terminal status in time; "
                "releasing the ownership lock rather than waiting forever.",
                job_id=job_id, max_wait_seconds=max_wait_seconds,
            )
            return
        time.sleep(poll_seconds)


def _scheduler_loop(interval_seconds: int, hours: int, max_events_per_channel: int) -> None:
    while True:
        try:
            effective = _scheduler_effective_job_params(hours, max_events_per_channel)
            log_event(
                "scheduler",
                "scheduler_tick",
                "Scheduler tick started.",
                interval_seconds=interval_seconds,
                hours=effective["hours"],
                max_events_per_channel=effective["max_events_per_channel"],
                scheduler_profile=effective["profile"],
                channels=effective["channels"],
                archive_enabled=effective["archive_enabled"],
                collection_mode=effective["collection_mode"],
            )
            with session_advisory_lock(_pg_connect, COLLECTION_OWNER_LOCK_NAME) as acquired:
                if not acquired:
                    log_event(
                        "scheduler",
                        "scheduler_tick_skipped_external_owner_active",
                        "Scheduler tick skipped: the external collection worker currently holds "
                        "collection ownership.",
                        interval_seconds=interval_seconds,
                    )
                else:
                    job = create_collect_job(
                        hours=int(effective["hours"]),
                        max_events_per_channel=int(effective["max_events_per_channel"]),
                        reason="scheduled",
                    )
                    _wait_for_scheduled_job_terminal(job.get("id"))
        except Exception as exc:
            log_internal_error("scheduler", "scheduler_iteration_failed", "Scheduler iteration failed; next tick will continue.", exc=exc, interval_seconds=interval_seconds)
        time.sleep(interval_seconds)






def _run_collect_job(job_id: int, reason: str = "manual") -> None:
    """Entry point every create_collect_job() caller's background thread runs.

    The scheduler (`_scheduler_loop`) and `collection_worker.py` already
    hold COLLECTION_OWNER_LOCK_NAME themselves for the whole duration of
    their own call into create_collect_job() (see docs/OPERATIONS_RUNBOOK.md
    on the code-level cross-process ownership guarantee) -- adding a second,
    separately-connected acquisition attempt here for those two reasons
    would collide with their own already-held lock and misreport it as
    "owned by someone else". Manual "Collect Now" (`reason == "manual"`,
    server/api/routes/runtime.py) is different: it is a fire-and-forget HTTP
    handler that cannot block the response for the job's whole duration, so
    nothing upstream of this background thread was ever able to hold the
    lock for as long as the job actually runs. This is the one place that
    can: it acquires COLLECTION_OWNER_LOCK_NAME itself, for exactly the
    duration of this thread, so a manual run can never become a second
    concurrent production collection owner alongside the worker or
    scheduler.
    """
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    if reason == "manual":
        with session_advisory_lock(_pg_connect, COLLECTION_OWNER_LOCK_NAME) as acquired:
            if not acquired:
                _skip_job(
                    job_id,
                    "Другой процесс сбора уже владеет циклом; ручной запуск пропущен без ошибки.",
                    reason="external_owner_active",
                )
                log_event(
                    "collector", "collection_skipped_external_owner_active",
                    "Manual collection job skipped because another process currently holds "
                    "collection ownership.",
                    job_id=job_id, status="skipped",
                )
                return
            _run_collect_job_body(job_id)
    else:
        _run_collect_job_body(job_id)


def _run_collect_job_body(job_id: int) -> None:
    if not _running_collect_lock.acquire(blocking=False):
        _skip_job(job_id, "Предыдущий сбор еще выполняется; этот запуск пропущен без ошибки.")
        log_event("collector", "collection_skipped_overlap", "Collection job skipped because another collection is still active.", job_id=job_id, status="skipped")
        return
    started = time.monotonic()
    with _lock:
        durable_job_id = _jobs[job_id].durable_id
    job_trace_id = f"job-{durable_job_id}"
    all_server_results = []
    try:
        _set_job_trace_id(job_id, job_trace_id)
        _update_job(job_id, status="running", message="Выполняется read-only сбор логов с контроллеров домена.", phase="collection")
        log_event("collector", "collection_started", "Collection job started.", job_id=job_id, status="running", trace_id=job_trace_id)
        with _lock:
            job = _jobs[job_id]
            original_servers = list(job.servers)
            hours = job.hours
            max_events = job.max_events_per_channel

        active_servers = list(original_servers)
        cycle = 1
        while active_servers:
            guard = _collection_disk_guard()
            if not guard.get("collection_allowed"):
                guard_reason = str(guard.get("reason") or "disk_pressure_guard")
                _skip_job(
                    job_id,
                    f"Сбор остановлен до запуска subprocess: {guard_reason}",
                    reason=guard_reason,
                )
                log_event(
                    "collector",
                    "collection_blocked_before_subprocess",
                    "Collection job stopped by disk admission before subprocess creation.",
                    job_id=job_id,
                    status="skipped",
                    disk_guard_status=guard.get("status"),
                    reason=guard_reason,
                    error_type=guard.get("error_type"),
                )
                return
            cycle_started_ms = monotonic_ms()
            _set_job_cycle(job_id, cycle)
            _update_job(job_id, status="running", message=f"Recovery/current цикл {cycle}: сбор {', '.join(active_servers)}.", phase="collection")
            log_event("collector", "collection_cycle_started", "Collection cycle started.", job_id=job_id, cycle=cycle, servers=active_servers, trace_id=job_trace_id)
            server_results = _collect_servers_parallel(job_id, active_servers, hours, max_events)
            all_server_results.extend(server_results)
            _apply_server_results(job_id, server_results)
            cycle_status = (
                "failed" if _job_has_errors(job_id)
                else "partial" if _job_has_warnings(job_id)
                else "completed"
            )
            log_performance_stage(
                "collection_cycle_total",
                trace_id=job_trace_id,
                job_id=job_id,
                status=cycle_status,
                started_ms=cycle_started_ms,
                events_count=_events_from_results(server_results),
                servers=active_servers,
                cycle=cycle,
            )

            if _job_has_errors(job_id):
                log_event("collector", "continuous_recovery_stopped_on_error", "Continuous recovery stopped because the cycle has errors.", job_id=job_id, cycle=cycle)
                break
            if not CONTINUOUS_RECOVERY_ENABLED:
                break
            next_servers = _servers_in_recovery(original_servers)
            if not next_servers:
                log_event("collector", "continuous_recovery_done", "No servers remain in recovery mode.", job_id=job_id, cycle=cycle)
                break
            if time.monotonic() - started >= CONTINUOUS_RECOVERY_MAX_JOB_SECONDS:
                _append_warning(
                    job_id,
                    "Continuous recovery stopped at the time budget before the recovery boundary.",
                )
                log_event("collector", "continuous_recovery_time_budget_reached", "Continuous recovery time budget reached.", job_id=job_id, cycle=cycle, max_seconds=CONTINUOUS_RECOVERY_MAX_JOB_SECONDS)
                break
            if cycle >= CONTINUOUS_RECOVERY_MAX_CYCLES:
                _append_warning(
                    job_id,
                    "Continuous recovery stopped at the cycle budget before the recovery boundary.",
                )
                log_event("collector", "continuous_recovery_cycle_budget_reached", "Continuous recovery cycle budget reached.", job_id=job_id, cycle=cycle, max_cycles=CONTINUOUS_RECOVERY_MAX_CYCLES)
                break
            active_servers = next_servers
            cycle += 1
            if CONTINUOUS_RECOVERY_COOLDOWN_SECONDS > 0:
                _update_job(job_id, status="running", message=f"Recovery пауза {CONTINUOUS_RECOVERY_COOLDOWN_SECONDS} сек перед следующим циклом.", phase="cooldown")
                log_performance_stage("continuous_recovery_cooldown", trace_id=job_trace_id, job_id=job_id, duration_ms=CONTINUOUS_RECOVERY_COOLDOWN_SECONDS * 1000, status="completed", servers=active_servers)
                time.sleep(CONTINUOUS_RECOVERY_COOLDOWN_SECONDS)

        if _scheduler_skip_report_enabled():
            duration_ms = int((time.monotonic() - started) * 1000)
            with _lock:
                job = _jobs[job_id]
                job.status = "failed" if job.errors else "partial" if job.warnings else "completed"
                job.phase = "done"
                job.updated_at = utc_now()
                job.message = (
                    "Сбор завершен с ошибками; анализ пропущен scheduler guard."
                    if job.errors
                    else "Сбор завершен частично; успешные каналы сохранены, анализ пропущен scheduler guard."
                    if job.warnings
                    else "Сбор завершен; анализ пропущен scheduler guard."
                )
                job.analysis_report_url = None
                job.collection_status = job.status
                job.analysis_status = "skipped"
                job.report_status = "skipped"
                job.duration_ms = duration_ms
                status = job.status
            log_performance_stage("analysis_report_generation", trace_id=job_trace_id, job_id=job_id, duration_ms=0, status="skipped", reason="scheduler_skip_report")
            log_performance_stage("job_total", trace_id=job_trace_id, job_id=job_id, duration_ms=duration_ms, status=status, cycles=cycle, report_duration_ms=0)
            log_event("collector", "collection_finished", "Collection job finished without in-process analysis report.", job_id=job_id, status=status, duration_ms=duration_ms, cycles=cycle, trace_id=job_trace_id, scheduler_skip_report=True)
            return

        duration_ms = int((time.monotonic() - started) * 1000)
        with _lock:
            job = _jobs[job_id]
            job.status = "failed" if job.errors else "partial" if job.warnings else "completed"
            job.collection_status = job.status
            job.analysis_status = "not_queued" if job.errors else "queued"
            job.report_status = "not_queued" if job.errors else "queued"
            job.phase = "done" if job.errors else "analysis_queued"
            job.updated_at = utc_now()
            job.message = (
                "Сбор завершен с ошибками; анализ не поставлен в очередь."
                if job.errors
                else "Сбор завершен частично; успешные каналы поставлены во внутреннюю очередь анализа."
                if job.warnings
                else "Сбор завершен; анализ поставлен во внутреннюю очередь."
            )
            job.duration_ms = duration_ms
            status = job.status
        if not _job_has_errors(job_id):
            _enqueue_post_collection(job_id, original_servers, job_trace_id)
        log_performance_stage("job_total", trace_id=job_trace_id, job_id=job_id, duration_ms=duration_ms, status=status, cycles=cycle, report_duration_ms=0)
        log_event(
            "collector",
            "collection_finished",
            "Collection job finished; post-collection processing is independent.",
            job_id=job_id,
            status=status,
            duration_ms=duration_ms,
            cycles=cycle,
            trace_id=job_trace_id,
            analysis_status=_analysis_queue_log_status(status),
        )
    except Exception as exc:
        error_id = log_internal_error("collector", "collection_failed", "Collection job failed.", exc=exc, job_id=job_id)
        _fail_job(job_id, f"{exc} (internal_error_id={error_id})")
    finally:
        _running_collect_lock.release()















def _collect_servers_parallel(job_id: int, servers: list[str], hours: int, max_events: int) -> list[tuple[str, subprocess.CompletedProcess[str], int, str, str]]:
    server_results = []
    from server.sli.sources.ad_source_auth import (
        AD_SOURCE_CREDENTIAL_MODE_ENV,
        validate_ad_source_credential_mode,
    )
    from server.sli.sources.collection_failure_policy import classify_collection_failure

    credential_mode = validate_ad_source_credential_mode(os.environ.get(AD_SOURCE_CREDENTIAL_MODE_ENV, "process"))
    # A shared saved account must not be tried concurrently against other DCs
    # after a password/lockout failure. Keep the default process-auth path intact.
    if credential_mode == "process" and len(servers) > 1 and PARALLEL_DC_WORKERS > 1:
        workers = min(PARALLEL_DC_WORKERS, len(servers))
        log_event("collector", "parallel_dc_collection_started", "Parallel DC collection started.", job_id=job_id, workers=workers, servers=servers)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_collect_server_once, job_id, server, hours, max_events) for server in servers]
            for future in as_completed(futures):
                server_results.append(future.result())
    else:
        for server in servers:
            server_results.append(_collect_server_once(job_id, server, hours, max_events))
            if credential_mode != "process":
                _server, result, _duration, stdout, stderr = server_results[-1]
                if result.returncode == 74 or classify_collection_failure([stdout, stderr]).blocked:
                    break
    return server_results


def _collection_result_status(stdout_tail: str) -> str | None:
    prefix = "collection_result="
    for line in reversed((stdout_tail or "").splitlines()):
        if not line.startswith(prefix):
            continue
        try:
            status = str(json.loads(line[len(prefix):]).get("status") or "")
        except (AttributeError, json.JSONDecodeError):
            return None
        return status if status in {"completed", "partial"} else None
    return None


def _apply_server_results(job_id: int, server_results: list[tuple[str, subprocess.CompletedProcess[str], int, str, str]]) -> None:
    for server, result, duration_ms, stdout_tail, stderr_tail in server_results:
        combined_tail = stderr_tail or stdout_tail
        _record_command_result(job_id, result.returncode, stdout_tail, stderr_tail, duration_ms)
        _record_affected_channels(job_id, _extract_affected_channels(stdout_tail + "\n" + stderr_tail))
        if stdout_tail:
            _append_output(job_id, stdout_tail)
        if result.returncode == 4:
            short_warning = combined_tail.strip().splitlines()[-1] if combined_tail.strip() else "успешные каналы импортированы, часть каналов завершилась ошибкой"
            _append_warning(job_id, f"{server}: частичный сбор; {short_warning}")
            _append_output(job_id, f"{server}: успешные каналы импортированы; ошибки остальных каналов сохранены отдельно.")
            log_event(
                "collector",
                "server_collection_partial",
                "Server collection completed partially; successful channels were imported.",
                level=logging.WARNING,
                job_id=job_id,
                server=server,
                exit_code=result.returncode,
                duration_ms=duration_ms,
                stdout_tail=stdout_tail,
                stderr_tail=stderr_tail,
                warning=short_warning,
            )
        elif result.returncode != 0:
            short_error = combined_tail.strip().splitlines()[-1] if combined_tail.strip() else f"код возврата {result.returncode}"
            _append_error(job_id, f"{server}: код возврата {result.returncode}; {short_error}", failed_server=server)
            log_event(
                "collector",
                "server_collection_failed",
                "Server collection failed.",
                level=logging.ERROR,
                job_id=job_id,
                server=server,
                exit_code=result.returncode,
                duration_ms=duration_ms,
                stdout_tail=stdout_tail,
                stderr_tail=stderr_tail,
                error=short_error,
            )
        elif _collection_result_status(stdout_tail) == "partial":
            _append_warning(job_id, f"{server}: bounded collection stopped before the source boundary")
            _append_output(job_id, f"{server}: частичный bounded batch импортирован; recovery продолжается.")
            log_event(
                "collector",
                "server_collection_partial",
                "Server bounded collection stopped before the source boundary.",
                level=logging.WARNING,
                job_id=job_id,
                server=server,
                exit_code=result.returncode,
                duration_ms=duration_ms,
                warning="source_boundary_not_reached",
            )
        else:
            _append_output(job_id, f"{server}: сбор завершен успешно.")
            log_event(
                "collector",
                "server_collection_completed",
                "Server collection completed.",
                job_id=job_id,
                server=server,
                exit_code=result.returncode,
                duration_ms=duration_ms,
            )


def _servers_in_recovery(servers: list[str]) -> list[str]:
    active: list[str] = []
    for server in servers:
        try:
            plan = get_adaptive_plan_for_server(server)
        except Exception as exc:
            log_internal_error("collector", "recovery_plan_check_failed", "Failed to check recovery plan after a cycle.", exc=exc, server=server)
            continue
        if plan.recovery_mode and "Security" in plan.channels:
            active.append(server)
    return active


def _events_from_results(server_results: list[tuple[str, subprocess.CompletedProcess[str], int, str, str]]) -> int:
    total = 0
    for _server, _result, _duration, stdout_tail, _stderr_tail in server_results:
        for match in re.finditer(r"events_collected\":\s*(\d+)", stdout_tail or ""):
            try:
                total += int(match.group(1))
            except ValueError:
                pass
    return total


def _job_has_errors(job_id: int) -> bool:
    with _lock:
        return bool(_jobs[job_id].errors)


def _job_has_warnings(job_id: int) -> bool:
    with _lock:
        return bool(_jobs[job_id].warnings)


def _set_job_cycle(job_id: int, cycle: int) -> None:
    with _lock:
        job = _jobs[job_id]
        job.cycle = cycle
        job.updated_at = utc_now()


def _scheduler_server_collection_message(server: str) -> str:
    canary = _scheduler_canary_config()
    if canary["enabled"]:
        profile = str(canary.get("profile") or _scheduler_profile() or "controlled")
        channels = ", ".join(canary.get("channels") or ["Security"])
        archive_mode = "archive/watermark" if canary.get("archive_enabled") else "без archive/watermark"
        return f"Выполняется PostgreSQL {profile} read-only сбор {channels} с {server} ({archive_mode})."
    return f"Выполняется архивный read-only сбор логов с {server}."


def _collect_server_once(job_id: int, server: str, hours: int, max_events: int) -> tuple[str, subprocess.CompletedProcess[str], int, str, str]:
    _update_job(job_id, status="running", message=_scheduler_server_collection_message(server))
    server_started = time.monotonic()
    _set_job_current_server(job_id, server)
    log_event("collector", "server_collection_started", "Server collection started.", job_id=job_id, server=server)
    result = _run_single_server_collection(server, hours, max_events, job_id=job_id)
    duration_ms = int((time.monotonic() - server_started) * 1000)
    return server, result, duration_ms, _tail(result.stdout), _tail(result.stderr)


def _collection_mode_for_plan(recovery_mode: bool) -> str:
    forced = os.environ.get("ADLOG_COLLECTION_MODE", "auto").strip().lower()
    if forced in {"current", "backfill", "recovery"}:
        return forced
    return "recovery" if recovery_mode else "current"


def _validate_requested_channel_ceiling(
    *, requested_max_events: int, channels: list[str], channel_limits: dict[str, int]
) -> None:
    requested = max(1, int(requested_max_events))
    missing = [channel for channel in channels if channel not in channel_limits]
    invalid = {
        channel: int(channel_limits[channel])
        for channel in channels
        if channel in channel_limits
        and (int(channel_limits[channel]) < 1 or int(channel_limits[channel]) > requested)
    }
    if missing or invalid:
        raise RuntimeError(
            "collection channel contract exceeds requested ceiling: "
            f"requested={requested}, missing={missing}, invalid={invalid}"
        )


def _run_single_server_collection(server: str, hours: int, max_events: int, *, job_id: int | None = None) -> subprocess.CompletedProcess[str]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from server.sli.sources.ad_source_auth import (
        AD_SOURCE_CREDENTIAL_MODE_ENV,
        resolve_ad_source_endpoint,
        validate_ad_source_credential_mode,
    )

    credential_mode = validate_ad_source_credential_mode(
        os.environ.get(AD_SOURCE_CREDENTIAL_MODE_ENV, "process"), backend=COLLECTOR_BACKEND,
    )
    requested_max_events = max(1, int(max_events))
    timeout_seconds = int(os.environ.get("ADLOG_COLLECTION_TIMEOUT_SECONDS", str(DEFAULT_COLLECTION_TIMEOUT_SECONDS)))
    channel_timeout_seconds = int(os.environ.get("ADLOG_CHANNEL_TIMEOUT_SECONDS", "300"))
    connect_address = (
        resolve_ad_source_endpoint(server) if credential_mode != "process"
        else resolve_domain_controller_connect_address(server)
    )
    canary = _scheduler_canary_config()
    if canary["enabled"]:
        channels = list(canary["channels"] or ["Security"])
        max_events = int(canary["max_events_per_channel"])
        requested_max_events = max_events
        hours = int(canary["hours"])
        channel_timeout_seconds = int(canary["channel_timeout_seconds"])
        timeout_seconds = int(canary["command_timeout_seconds"])
        collection_mode = str(canary["collection_mode"] or "current")
        channel_limits = {channel: max_events for channel in channels}
        channel_timeouts = {channel: channel_timeout_seconds for channel in channels}
        plan_recovery_mode = False
        plan_reason = f"fixed_canary:{canary.get('profile') or 'controlled'}"
    else:
        adaptive_plan = get_adaptive_plan_for_server(server)
        min_adaptive_timeout = max(adaptive_plan.channel_timeouts.values() or [channel_timeout_seconds]) * max(1, len(adaptive_plan.channels)) + 120
        if timeout_seconds < min_adaptive_timeout:
            timeout_seconds = min_adaptive_timeout
        channels = list(adaptive_plan.channels)
        channel_limits = dict(adaptive_plan.channel_limits)
        channel_timeouts = dict(adaptive_plan.channel_timeouts)
        collection_mode = _collection_mode_for_plan(adaptive_plan.recovery_mode)
        plan_recovery_mode = adaptive_plan.recovery_mode
        plan_reason = adaptive_plan.reason
    planned_channel_limits = dict(channel_limits)
    channel_limits = {
        channel: min(requested_max_events, max(1, int(limit)))
        for channel, limit in planned_channel_limits.items()
    }
    max_events = min(requested_max_events, max(1, int(max_events)))
    adaptive_limits_capped = any(
        int(planned_channel_limits.get(channel, limit)) > int(limit)
        for channel, limit in channel_limits.items()
    )
    _validate_requested_channel_ceiling(
        requested_max_events=requested_max_events,
        channels=channels,
        channel_limits=channel_limits,
    )
    adaptive_state_mode = "observe" if canary["enabled"] else "update"
    collect_message = os.environ.get("ADLOG_COLLECT_MESSAGE", "false")
    command = [
        sys.executable,
        str(ROOT / "scripts" / "run_dc_log_pilot.py"),
        "--server",
        server,
        "--connect-address",
        connect_address,
        "--hours",
        str(hours),
        "--max-events-per-channel",
        str(max_events),
        "--no-technical-report",
        "--command-timeout-seconds",
        str(timeout_seconds),
        "--channel-timeout-seconds",
        str(channel_timeout_seconds),
        "--channels",
        ",".join(channels),
        "--channel-limits-json",
        json.dumps(channel_limits, ensure_ascii=False),
        "--channel-timeouts-json",
        json.dumps(channel_timeouts, ensure_ascii=False),
        "--collection-mode",
        collection_mode,
        "--adaptive-state-mode",
        adaptive_state_mode,
        "--collect-message",
        collect_message,
        "--collector-backend",
        COLLECTOR_BACKEND,
        "--raw-root",
        str(RAW_SPOOL_DIR),
    ]
    if credential_mode != "process":
        command.extend(["--ad-source-credential-mode", credential_mode])
    if not canary["enabled"] or canary["archive_enabled"]:
        command.append("--archive")
    if job_id is not None:
        command.extend(["--job-id", str(job_id)])
    log_event(
        "collector",
        "adaptive_collection_plan",
        "Adaptive collection plan selected.",
        job_id=job_id,
        server=server,
        connect_address=connect_address,
        channels=channels,
        channel_limits=channel_limits,
        requested_max_events_per_channel=requested_max_events,
        adaptive_limits_capped=adaptive_limits_capped,
        channel_timeouts=channel_timeouts,
        recovery_mode=plan_recovery_mode,
        reason=plan_reason,
        scheduler_canary_enabled=canary["enabled"],
        canary_profile=canary.get("profile"),
        canary_requested_max_events=canary.get("requested_max_events_per_channel"),
        canary_effective_max_events=canary.get("max_events_per_channel"),
        canary_max_events_cap=canary.get("max_events_cap"),
        canary_max_events_capped=canary.get("max_events_capped"),
        canary_archive_enabled=canary["archive_enabled"],
        scheduler_skip_report=_scheduler_skip_report_enabled(),
        collection_mode=collection_mode,
        adaptive_state_mode=adaptive_state_mode,
        collect_message=collect_message,
    )
    return _run_subprocess_live(
        command, timeout_seconds + 60, server=server, job_id=job_id, env=_forced_run_dc_log_pilot_env()
    )






def _run_subprocess_with_internal_logging(command: list[str], timeout_seconds: int, *, server: str = "unknown", job_id: int | None = None) -> subprocess.CompletedProcess[str]:
    """Backward-compatible wrapper for the old collector runner name.

    The live runner is now ``_run_subprocess_live``; keep this alias because
    tests, diagnostics and local integration tools imported the previous name.
    """
    return _run_subprocess_live(command, timeout_seconds, server=server, job_id=job_id)


def _extract_affected_channels(text: str) -> list[str]:
    channels: list[str] = []
    for marker in ("Timed out channel:", "Failed channel:"):
        for line in text.splitlines():
            if marker in line:
                value = line.split(marker, 1)[1].strip()
                value = value.split(" after ", 1)[0].split(" error=", 1)[0].strip()
                if value and value not in channels:
                    channels.append(value)
    return channels


def _record_affected_channels(job_id: int, channels: list[str]) -> None:
    if not channels:
        return
    with _lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        for channel in channels:
            if channel not in job.affected_channels:
                job.affected_channels.append(channel)
        job.updated_at = utc_now()


def _set_job_trace_id(job_id: int, trace_id: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        job.trace_id = trace_id
        job.updated_at = utc_now()


def _set_job_current_server(job_id: int, server: str | None) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        job.current_server = server
        job.updated_at = utc_now()





def _safe_collector_health() -> dict:
    try:
        from server.sli.sources.collector_health import get_collector_health
        return get_collector_health()
    except Exception as exc:
        return {"status": "warn", "error": str(exc), "items": []}


def _archive_channel_summary_fast() -> list[dict]:
    try:
        if _runtime_db_backend() != "postgres":
            raise RuntimeError(f"Unsupported runtime DB backend {_runtime_db_backend()!r}: archive status is PostgreSQL-only")
        from server.sli.core.postgres_runtime_pipeline import get_archive_status_pg

        archive_status = get_archive_status_pg()
    except Exception as exc:
        return [{"status": "warn", "error": str(exc), "source": "archive_state", "backend": _runtime_db_backend()}]

    channels: list[dict] = []
    for item in archive_status.get("channel_states") or []:
        channel = str(item.get("channel") or "")
        if not channel:
            continue
        channels.append({
            "server": item.get("server_hostname") or item.get("server"),
            "channel": channel,
            "last_successful_collection_utc": item.get("last_successful_collection_utc"),
            "last_event_time_utc": item.get("last_event_time_utc"),
            "last_event_record_id": item.get("last_event_record_id"),
            "backfill_completed": item.get("backfill_completed"),
            "stale_reason": "non-security channel can be included by fairness collector" if channel != "Security" else None,
        })
    return channels

def _skipped_overlap_summary(jobs: list[dict]) -> dict:
    items = [job for job in jobs if job.get("status") == "skipped" and job.get("skipped_reason") == "overlap"]
    if not items:
        return {"count": 0, "reason": None, "first_at": None, "last_at": None}
    ordered = sorted(items, key=lambda item: str(item.get("created_at") or ""))
    return {
        "count": len(items),
        "reason": "previous collection still running",
        "first_at": ordered[0].get("created_at"),
        "last_at": ordered[-1].get("created_at"),
        "normal": True,
        "message": "Пропущены плановые запуски, потому что активный сбор уже выполнялся.",
    }


def _last_job_error(jobs: list[dict]) -> dict | None:
    for job in jobs:
        errors = job.get("errors") or []
        if errors:
            return {"job_id": job.get("id"), "status": job.get("status"), "error": errors[-1], "updated_at": job.get("updated_at")}
    return None


def _channel_fairness_summary(collector_health: dict) -> list[dict]:
    channels: list[dict] = []
    for item in collector_health.get("channels") or collector_health.get("items") or []:
        channel = str(item.get("channel") or "")
        if not channel:
            continue
        channels.append({
            "server": item.get("server") or item.get("server_hostname"),
            "channel": channel,
            "severity": item.get("severity"),
            "lag_minutes": item.get("lag_minutes"),
            "stale_reason": "non-security channel can be included by fairness collector" if channel != "Security" and item.get("severity") in {"warn", "high"} else None,
        })
    return channels


def _recent_performance_breakdown(*, timeout_seconds: float = 0.5) -> dict:
    try:
        if _runtime_db_backend() != "postgres":
            raise RuntimeError(f"Unsupported runtime DB backend {_runtime_db_backend()!r}: performance breakdown is PostgreSQL-only")
        from server.sli.core.database import query_rows

        rows = query_rows(
            """
            select stage, server, channel, max(duration_ms) as duration_ms, max(created_at)::text as last_seen
            from collector_stage_metrics
            where stage in (
                'collection_backend_command', 'evt_next_read', 'render_parse_write_jsonl',
                'import_queue_wait', 'import_postgres', 'archive_state_update_postgres',
                'collector_history_record_postgres', 'analysis_report_generation', 'dc_pipeline_total', 'collection_cycle_total'
            )
            group by stage, server, channel
            order by duration_ms desc
            limit 20
            """
        )
        return {"stages": rows, "backend": "postgres"}
    except Exception as exc:
        return {"stages": [], "error": str(exc), "backend": _runtime_db_backend()}


def _update_job(job_id: int, *, status: JobStatus, message: str, phase: str | None = None) -> None:
    with _lock:
        job = _jobs[job_id]
        job.status = status
        if phase is not None:
            job.phase = phase
        job.updated_at = utc_now()
        job.message = message


def _append_output(job_id: int, output: str) -> None:
    with _lock:
        job = _jobs[job_id]
        job.command_outputs.append(output[-4000:])
        job.updated_at = utc_now()


def _append_error(job_id: int, error: str, *, failed_server: str | None = None) -> None:
    with _lock:
        job = _jobs[job_id]
        if error not in job.errors:
            job.errors.append(error)
        if failed_server and failed_server not in job.failed_servers:
            job.failed_servers.append(failed_server)
        job.updated_at = utc_now()


def _append_warning(job_id: int, warning: str) -> None:
    with _lock:
        job = _jobs[job_id]
        if warning not in job.warnings:
            job.warnings.append(warning)
        job.updated_at = utc_now()


def _record_command_result(job_id: int, exit_code: int, stdout_tail: str, stderr_tail: str, duration_ms: int) -> None:
    with _lock:
        job = _jobs[job_id]
        job.exit_code = exit_code if job.exit_code is None or exit_code != 0 else job.exit_code
        job.stdout_tail = stdout_tail
        job.stderr_tail = stderr_tail
        job.duration_ms = duration_ms
        job.updated_at = utc_now()


def _fail_job(job_id: int, message: str) -> None:
    with _lock:
        job = _jobs[job_id]
        job.status = "failed"
        job.phase = "failed"
        job.updated_at = utc_now()
        job.message = message
        job.errors.append(message)


def _skip_job(job_id: int, message: str, *, reason: str = "overlap") -> None:
    with _lock:
        job = _jobs[job_id]
        job.status = "skipped"
        job.phase = "skipped"
        job.updated_at = utc_now()
        job.message = message
        job.skipped_reason = reason
        job.exit_code = 0


from server.jobs.collector_analysis import (
    _generate_report_with_heartbeat,
    _run_analysis_job,
    create_analysis_job,
)
from server.jobs.collector_post_collection import (
    _enqueue_post_collection,
    _heartbeat_post_collection_safely,
    _run_post_collection_job,
    resume_persisted_post_collection_jobs,
    run_persisted_post_collection_worker_once,
)
from server.jobs.collector_subprocess import (
    _run_subprocess_live,
    _terminate_process_tree,
    _update_job_progress_from_line,
)
