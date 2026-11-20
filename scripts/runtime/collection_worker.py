"""Run bounded collection outside the HTTPS server process.

One worker owns the PostgreSQL advisory lock for the entire collection cycle.
That prevents an accidental second process from duplicating a scheduled run.
The web server must have ``ADLOG_DISABLE_SCHEDULER=1`` before this worker is
enabled in continuous mode.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timezone
import getpass
import json
import os
import socket
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.app_config import load_config
from server.sli.sources.collection_failure_policy import AD_SOURCE_OPERATOR_FAILURE_CODES, classify_collection_failure
from server.sli.sources.collection_runtime_block import (
    REASON_WINDOWS_EVENT_LOG_ACCESS_DENIED,
    REASON_WINDOWS_SECURITY_CONTEXT,
    activate_collection_block,
    get_active_collection_block,
    record_probe_and_clear,
)
from server.sli.ops.logging_config import log_event, log_internal_error
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.sources.runtime_collection_history import start_runtime_collection_run, update_runtime_collection_run
from server.sli.ops.runtime_workers import record_worker_heartbeat
from server.jobs.collector import create_collect_job, get_job

LOCK_NAME = "ad_log_reports_runtime_collection_worker"
PROCESS_LOCK_NAME = "ad_log_reports_runtime_collection_process"
TERMINAL_STATES = {"completed", "partial", "failed", "skipped"}
RUNNING_HEARTBEAT_SECONDS = 30
NPS_EVENT_IDS_JSON = "[6272,6273]"
NPS_MAX_EVENTS = 50_000
NPS_CHANNEL_TIMEOUT_SECONDS = 60
NPS_COMMAND_TIMEOUT_SECONDS = 90
NPS_OUTER_MARGIN_SECONDS = 60


def nps_stage_enabled() -> bool:
    value = os.environ.get("ADLOG_NPS_EVENTLOG_ENABLED", "").strip().casefold()
    if value in {"", "0"}:
        return False
    if value == "1":
        return True
    raise RuntimeError("nps_eventlog_enabled_value_invalid")


def _nps_collection_status(stdout: str) -> str | None:
    prefix = "collection_result="
    for line in reversed(stdout.splitlines()):
        if not line.startswith(prefix):
            continue
        try:
            status = str(json.loads(line[len(prefix):]).get("status") or "")
        except (AttributeError, json.JSONDecodeError):
            return None
        return status if status in {"completed", "partial"} else None
    return None


def _nps_output_tail(result: object) -> str:
    return str(getattr(result, "stdout", "") or getattr(result, "stderr", ""))[-2000:]


def run_nps_stage(
    *,
    dc_servers: list[object],
    max_events: int,
    heartbeat_callback: Callable[[dict[str, object]], None] | None,
) -> dict[str, object]:
    """Run the registered NPS source serially while the collection lock is held."""
    started = time.monotonic()
    if not nps_stage_enabled():
        return {"status": "disabled"}
    from server.sli.plugins.registry import plugin_hook

    source_provider = plugin_hook("sli.remote-access", "nps_source")
    if source_provider is None:
        return {"status": "not_installed", "phase": "nps", "reason": "plugin_not_installed"}
    from scripts.run_dc_log_pilot import postgres_import_timeout_seconds, run_command
    from server.sli.core.postgres_runtime_pipeline import get_collection_plan_for_server_pg
    source = source_provider()
    if any(str(server or "").strip().casefold() == source.casefold() for server in dc_servers):
        raise RuntimeError("nps_eventlog_dc_target_overlap")
    plan = get_collection_plan_for_server_pg(source, channels=["Security"])
    security = plan.get("Security") if isinstance(plan, dict) else None
    start_time_utc = str((security or {}).get("start_time_utc") or "").strip()
    if not start_time_utc:
        raise RuntimeError("nps_eventlog_security_cursor_missing")
    end_time_utc = datetime.now(timezone.utc).isoformat()
    command = [
        sys.executable, str(ROOT / "scripts" / "run_dc_log_pilot.py"),
        "--nps-continuous", "--server", source, "--connect-address", source,
        "--channels", "Security", "--archive", "--use-record-id-cursor", "true",
        "--adaptive-state-mode", "observe", "--collect-message", "false",
        "--max-events-per-channel", str(min(NPS_MAX_EVENTS, max(1, max_events))),
        "--channel-timeout-seconds", str(NPS_CHANNEL_TIMEOUT_SECONDS),
        "--command-timeout-seconds", str(NPS_COMMAND_TIMEOUT_SECONDS),
        "--collector-backend", "python", "--ad-source-credential-mode", "dpapi_current_user",
        "--event-ids-json", NPS_EVENT_IDS_JSON, "--start-time-utc", start_time_utc,
        "--end-time-utc", end_time_utc, "--no-technical-report",
    ]
    outer_timeout = NPS_COMMAND_TIMEOUT_SECONDS + postgres_import_timeout_seconds() + NPS_OUTER_MARGIN_SECONDS
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="nps-eventlog") as executor:
        future = executor.submit(run_command, command, timeout_seconds=outer_timeout)
        while True:
            try:
                completed = future.result(timeout=RUNNING_HEARTBEAT_SECONDS)
                break
            except TimeoutError:
                if heartbeat_callback is not None:
                    heartbeat_callback({"status": "running", "phase": "nps", "source": source})
    output = _nps_output_tail(completed)
    collection_status = _nps_collection_status(str(getattr(completed, "stdout", "") or ""))
    if getattr(completed, "returncode", 1) != 0 or collection_status not in {"completed", "partial"}:
        decision = classify_collection_failure([output])
        return {
            "status": "failed", "phase": "nps",
            "reason": decision.code or "nps_eventlog_collection_failed",
            "output_tail": output, "collection_status": collection_status,
            "blocked": decision.blocked, "operator_action": decision.operator_action,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    return {
        "status": collection_status, "phase": "nps", "source": source, "output_tail": output,
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


def preflight_windows_collection_context(*, server: str, worker_id: str) -> dict[str, object]:
    """Verify the worker's real Windows token once before creating any job."""
    from server.sli.sources.windows_event_probe import probe_windows_event_context
    from server.sli.sources.windows_runtime_identity import verify_collection_identity

    identity = verify_collection_identity()
    if identity.get("status") != "ok":
        result = {
            "status": "failed",
            "server": server,
            "failure_code": REASON_WINDOWS_SECURITY_CONTEXT,
            "identity": identity,
        }
    else:
        # Credential failures are never auto-recovered by a worker restart.
        # Only the explicit collection_block_control operator probe may retry.
        active_block = get_active_collection_block()
        if active_block and active_block.get("reason_code") in AD_SOURCE_OPERATOR_FAILURE_CODES:
            return {
                "status": "failed", "server": server,
                "failure_code": active_block["reason_code"], "reason": active_block["reason_code"],
                "operator_action": active_block.get("operator_action"),
            }
        from server.sli.sources.ad_source_auth import AD_SOURCE_CREDENTIAL_MODE_ENV, validate_ad_source_credential_mode

        try:
            mode = validate_ad_source_credential_mode(
                os.environ.get(AD_SOURCE_CREDENTIAL_MODE_ENV, "process"),
                backend=os.environ.get("ADLOG_COLLECTOR_BACKEND", "auto"),
            )
            result = probe_windows_event_context(server, ad_source_credential_mode=mode, configured_dc=True)
        except RuntimeError as exc:
            result = {"status": "failed", "server": server,
                      "failure_code": classify_collection_failure([exc]).code or "windows_context_preflight_failed"}
    if result.get("status") == "ok":
        log_event(
            "runtime_worker", "collection_worker_context_preflight_succeeded",
            "Collection worker Windows context preflight succeeded.",
            worker_id=worker_id, server=server,
        )
        return result

    failure_code = str(result.get("failure_code") or "windows_context_preflight_failed")
    operator_action = (
        "Запустите worker в интерактивной Windows-сессии точной учётной записи "
        "с подтверждённым правом чтения журналов DC."
    )
    decision = classify_collection_failure([failure_code])
    if decision.operator_action:
        operator_action = decision.operator_action
    if decision.blocked or failure_code in {
        REASON_WINDOWS_SECURITY_CONTEXT,
        REASON_WINDOWS_EVENT_LOG_ACCESS_DENIED,
    }:
        block = activate_collection_block(
            reason_code=failure_code,
            operator_action=operator_action,
            source_worker_id=worker_id,
            source_server=server,
            evidence={
                "failure_code": failure_code,
                "failure_scope": "worker_identity",
                "collector_backend": "python",
                "identity_reasons": list(identity.get("reasons") or []),
            },
        )
        operator_action = str(block.get("operator_action") or operator_action)
    log_event(
        "runtime_worker", "collection_worker_context_preflight_failed",
        "Collection worker stopped before job creation because its Windows context is invalid.",
        level=40, worker_id=worker_id, server=server, reason=failure_code,
    )
    return {**result, "reason": failure_code, "operator_action": operator_action}


def clear_matching_block_after_successful_preflight(*, server: str) -> dict[str, object] | None:
    """Reuse the mandatory worker preflight as the explicit recovery proof."""
    block = get_active_collection_block()
    if not block:
        return None
    reason = str(block.get("reason_code") or "")
    if reason not in {
        REASON_WINDOWS_SECURITY_CONTEXT,
        REASON_WINDOWS_EVENT_LOG_ACCESS_DENIED,
    }:
        raise RuntimeError(f"active collection block cannot be cleared by Windows preflight: {reason}")
    return record_probe_and_clear(
        probe_server=server,
        cleared_by=f"worker-preflight:{getpass.getuser()}",
    )


@contextmanager
def collection_worker_lock() -> Iterator[bool]:
    """Hold one session-scoped PostgreSQL advisory lock for a cycle."""
    with session_advisory_lock(connect, LOCK_NAME) as acquired:
        yield acquired


@contextmanager
def collection_process_lock() -> Iterator[bool]:
    """Keep exactly one continuous collection process alive per database."""
    with session_advisory_lock(connect, PROCESS_LOCK_NAME) as acquired:
        yield acquired


def run_cycle(
    *,
    hours: int,
    max_events: int,
    wait_seconds: int,
    worker_id: str | None = None,
    heartbeat_callback: Callable[[dict[str, object]], None] | None = None,
) -> dict[str, object]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    cfg = load_config()
    if (cfg.db_backend or "").strip().lower() != "postgres":
        return {"status": "blocked", "reason": "postgres_runtime_required"}
    active_block = get_active_collection_block()
    if active_block:
        return {
            "status": "blocked",
            "phase": "operator_action_required",
            "reason": active_block.get("reason_code"),
            "operator_action": active_block.get("operator_action"),
            "observed_count": active_block.get("observed_count"),
        }
    with collection_worker_lock() as acquired:
        if not acquired:
            return {"status": "skipped", "reason": "collection_worker_lock_held"}
        run_id = uuid.uuid4().hex
        owner = worker_id or f"collection-{socket.gethostname()}-{os.getpid()}"
        start_runtime_collection_run(run_id=run_id, worker_id=owner, hours=hours, max_events_per_channel=max_events)
        try:
            job = create_collect_job(hours=hours, max_events_per_channel=max_events, reason="external_worker")
            if job.get("id") is None:
                rejection_status = str(job.get("status") or "skipped")
                rejection_reason = str(job.get("reason") or job.get("skipped_reason") or "collection_guard_error")
                result = {
                    "status": rejection_status,
                    "phase": str(job.get("phase") or "admission"),
                    "reason": rejection_reason,
                    "run_id": run_id,
                }
                update_runtime_collection_run(
                    run_id,
                    status=str(result["status"]),
                    phase=str(result["phase"]),
                    errors=[rejection_reason] if rejection_status in {"blocked", "failed", "error"} else [],
                )
                return result
            job_id = int(job["id"])
            update_runtime_collection_run(run_id, status="running", phase="collection", job_id=job_id, servers=list(job.get("servers") or []))
            last_heartbeat_at = time.monotonic()
            while True:
                current = get_job(job_id) or job
                if str(current.get("status")) in TERMINAL_STATES:
                    errors = list(current.get("errors") or [])
                    warnings = list(current.get("warnings") or [])
                    decision = classify_collection_failure(errors)
                    durable_block = get_active_collection_block() or {}
                    blocked = decision.blocked or bool(durable_block)
                    result = {
                        "status": "blocked" if blocked else str(current.get("status")),
                        "job_id": job_id,
                        "phase": decision.phase or ("operator_action_required" if durable_block else current.get("phase")),
                        "duration_ms": current.get("duration_ms"),
                        "errors": errors,
                        "warnings": warnings,
                        "run_id": run_id,
                    }
                    if str(current.get("status")) == "skipped" and current.get("skipped_reason"):
                        result["reason"] = str(current["skipped_reason"])
                    if blocked:
                        result.update({
                            "reason": decision.code or durable_block.get("reason_code"),
                            "operator_action": decision.operator_action or durable_block.get("operator_action"),
                            "original_status": str(current.get("status")),
                        })
                    # NPS is a separate registered source, never another DC
                    # target or collector job.  Run it only after a fully
                    # successful DC job and while this worker still owns its
                    # one advisory lock.
                    if str(current.get("status")) in {"completed", "partial"} and not blocked:
                        try:
                            nps = (
                                {"status": "disabled"}
                                if not nps_stage_enabled()
                                else run_nps_stage(
                                    dc_servers=list(job.get("servers") or []),
                                    max_events=max_events,
                                    heartbeat_callback=heartbeat_callback,
                                )
                            )
                        except Exception as exc:
                            decision = classify_collection_failure([str(exc)])
                            nps = {
                                "status": "failed", "phase": "nps",
                                "reason": decision.code or "nps_eventlog_stage_failed",
                                "output_tail": str(exc)[:2000],
                                "blocked": decision.blocked, "operator_action": decision.operator_action,
                                "duration_ms": 0,
                            }
                        if nps.get("status") != "disabled":
                            result["nps"] = nps
                            result["dc_status"] = str(current.get("status"))
                            result["phase"] = "nps"
                            nps_duration = int(nps.get("duration_ms") or 0)
                            result["duration_ms"] = int(current.get("duration_ms") or 0) + nps_duration
                        if nps.get("status") == "partial":
                            result["status"] = "partial"
                        elif nps.get("status") == "failed":
                            if nps.get("blocked"):
                                block = activate_collection_block(
                                    reason_code=str(nps.get("reason") or "nps_eventlog_terminal_failure"),
                                    operator_action=str(nps.get("operator_action") or "Выполните явную контрольную проверку collection_block_control."),
                                    source_worker_id=owner, source_job_id=job_id,
                                    source_server=str(nps.get("source") or "nps"),
                                    evidence={
                                        "failure_code": nps.get("reason"), "failure_scope": "worker_identity",
                                        "collector_backend": "python",
                                    },
                                )
                                result["status"] = "blocked"
                                result["phase"] = str(nps.get("phase") or "nps")
                                result["reason"] = block.get("reason_code") or nps.get("reason")
                                result["operator_action"] = block.get("operator_action") or nps.get("operator_action")
                            else:
                                result["status"] = "failed"
                                result["phase"] = "nps"
                                result["reason"] = nps.get("reason")
                    update_runtime_collection_run(
                        run_id,
                        status=str(result["status"]),
                        phase=str(result.get("phase") or "done"),
                        duration_ms=result.get("duration_ms"),
                        errors=list(result.get("errors") or result.get("warnings") or ([str(result["reason"])] if result.get("status") == "failed" and result.get("reason") else [])),
                    )
                    return result
                now = time.monotonic()
                if heartbeat_callback is not None and now - last_heartbeat_at >= RUNNING_HEARTBEAT_SECONDS:
                    heartbeat_callback({
                        "job_id": job_id,
                        "status": str(current.get("status") or "running"),
                        "phase": str(current.get("phase") or "collection"),
                    })
                    last_heartbeat_at = now
                time.sleep(wait_seconds)
        except Exception as exc:
            decision = classify_collection_failure([str(exc)])
            update_runtime_collection_run(
                run_id,
                status="blocked" if decision.blocked else "failed",
                phase=decision.phase or "worker_failed",
                errors=[str(exc)],
            )
            raise


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one bounded PostgreSQL collection worker outside the web server.")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit; otherwise repeat at the configured interval.")
    parser.add_argument("--interval-seconds", type=int)
    parser.add_argument("--hours", type=int, default=1)
    parser.add_argument(
        "--max-events-per-channel",
        type=int,
        default=None,
        help=(
            "Абсолютный потолок на канал. Рабочее значение по умолчанию 50000; "
            "5000 применяется только явно для диагностики или аварийного режима."
        ),
    )
    parser.add_argument("--wait-seconds", type=int, default=2)
    parser.add_argument(
        "--preflight-server",
        default=None,
        help="DC used for one mandatory Windows Event Log session check before job creation.",
    )
    parser.add_argument("--load-supervisor-environment", action="store_true")
    return parser.parse_args(argv)


def _main_locked(args: argparse.Namespace | None = None) -> int:
    args = args or parse_args()
    # This entry point is the external-worker runtime composition. Storage V2
    # publication and post-collection reporting have their own durable workers.
    # Enforce both boundaries here as well as in the supervisor so a manually
    # started collector cannot silently run either workload in-process.
    os.environ["ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER"] = "1"
    os.environ["ADLOG_EXTERNAL_POST_COLLECTION_WORKER"] = "1"
    worker_id = f"collection-{socket.gethostname()}-{os.getpid()}"
    interval_seconds = (
        args.interval_seconds
        if args.interval_seconds is not None
        else int(os.environ.get("ADLOG_COLLECTOR_INTERVAL_SECONDS", "600"))
    )
    max_events_per_channel = (
        args.max_events_per_channel
        if args.max_events_per_channel is not None
        else int(os.environ.get("ADLOG_COLLECTION_MAX_EVENTS_PER_CHANNEL", "50000"))
    )
    interval = max(30, min(interval_seconds, 86400))
    wait_seconds = max(1, min(args.wait_seconds, 30))
    started_at = datetime.now(timezone.utc)
    preflight_server = str(
        args.preflight_server
        if args.preflight_server is not None
        else os.environ.get("ADLOG_COLLECTION_PREFLIGHT_SERVER", "")
    ).strip()
    if not preflight_server:
        print(json.dumps({
            "worker_id": worker_id,
            "status": "blocked",
            "reason": "windows_context_preflight_server_required",
            "operator_action": "Укажите --preflight-server с контроллером домена перед запуском worker.",
        }, ensure_ascii=False), flush=True)
        return 2
    preflight = preflight_windows_collection_context(server=preflight_server, worker_id=worker_id)
    if preflight.get("status") != "ok":
        print(json.dumps({"worker_id": worker_id, "status": "blocked", **preflight}, ensure_ascii=False), flush=True)
        record_worker_heartbeat(
            worker_name="collection", worker_id=worker_id, status="blocked",
            phase="security_context_preflight", expected_interval_seconds=interval,
            started_at=started_at,
            details={key: preflight.get(key) for key in ("server", "reason", "operator_action", "error_type")},
        )
        return 2
    try:
        cleared_block = clear_matching_block_after_successful_preflight(server=preflight_server)
    except Exception as exc:
        print(json.dumps({
            "worker_id": worker_id,
            "status": "blocked",
            "reason": "collection_block_clear_failed",
            "error_type": type(exc).__name__,
        }, ensure_ascii=False), flush=True)
        record_worker_heartbeat(
            worker_name="collection",
            worker_id=worker_id,
            status="blocked",
            phase="collection_block_recovery",
            expected_interval_seconds=interval,
            started_at=started_at,
            details={"server": preflight_server, "reason": "collection_block_clear_failed"},
        )
        return 2
    if cleared_block is not None:
        log_event(
            "runtime_worker",
            "collection_worker_block_cleared_by_preflight",
            "Mandatory worker preflight cleared the matching Windows-context block.",
            worker_id=worker_id,
            server=preflight_server,
        )
    log_event("runtime_worker", "collection_worker_started", "Independent collection worker started.", worker_id=worker_id)
    while True:
        record_worker_heartbeat(
            worker_name="collection", worker_id=worker_id, status="running", phase="cycle",
            expected_interval_seconds=interval, started_at=started_at,
            details={
                "hours": max(1, args.hours),
                "max_events_per_channel": max(1, max_events_per_channel),
                "storage_v2_publication": "external_worker",
                "post_collection": "external_worker",
            },
        )
        try:
            def heartbeat_running(current: dict[str, object]) -> None:
                record_worker_heartbeat(
                    worker_name="collection",
                    worker_id=worker_id,
                    status="running",
                    phase=str(current.get("phase") or "collection"),
                    expected_interval_seconds=interval,
                    started_at=started_at,
                    details={
                        "hours": max(1, args.hours),
                        "max_events_per_channel": max(1, max_events_per_channel),
                        "storage_v2_publication": "external_worker",
                        "post_collection": "external_worker",
                        "active_job": current,
                    },
                )

            result = run_cycle(
                hours=max(1, args.hours),
                max_events=max(1, max_events_per_channel),
                wait_seconds=wait_seconds,
                worker_id=worker_id,
                heartbeat_callback=heartbeat_running,
            )
            print(json.dumps({"worker_id": worker_id, **result}, ensure_ascii=False), flush=True)
            record_worker_heartbeat(
                worker_name="collection", worker_id=worker_id, status=str(result.get("status") or "idle"),
                phase=str(result.get("phase") or "sleep") if result.get("status") == "blocked" else "sleep",
                expected_interval_seconds=interval, started_at=started_at,
                details={"last_result": {key: result.get(key) for key in (
                    "status", "job_id", "phase", "duration_ms", "reason", "operator_action", "dc_status", "nps"
                )}},
            )
            if result.get("status") == "blocked":
                log_event(
                    "runtime_worker",
                    "collection_worker_blocked",
                    "Collection worker stopped after a non-retryable Windows security-context failure.",
                    level=40,
                    worker_id=worker_id,
                    reason=result.get("reason"),
                    operator_action=result.get("operator_action"),
                )
                return 2
            if args.once:
                return 0 if result.get("status") in {"completed", "partial", "skipped"} else 1
        except Exception as exc:
            decision = classify_collection_failure([str(exc)])
            error_id = log_internal_error("runtime_worker", "collection_worker_cycle_failed", "Independent collection worker cycle failed.", exc=exc, worker_id=worker_id)
            failure_status = "blocked" if decision.blocked else "failed"
            print(json.dumps({
                "worker_id": worker_id, "status": failure_status, "error_id": error_id,
                "error": str(exc), "reason": decision.code, "operator_action": decision.operator_action,
            }, ensure_ascii=False), flush=True)
            record_worker_heartbeat(
                worker_name="collection", worker_id=worker_id, status=failure_status,
                phase=decision.phase or "sleep",
                expected_interval_seconds=interval, started_at=started_at,
                details={
                    "error_id": error_id, "error_type": type(exc).__name__,
                    "reason": decision.code, "operator_action": decision.operator_action,
                },
            )
            if decision.blocked:
                return 2
            if args.once:
                return 1
        time.sleep(interval)


def main(argv: list[str] | None = None) -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    args = parse_args(argv)
    if args.load_supervisor_environment:
        from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment

        load_supervisor_environment()
    with collection_process_lock() as acquired:
        if not acquired:
            print(json.dumps({
                "status": "skipped",
                "reason": "collection_process_lock_held",
            }, ensure_ascii=False), flush=True)
            return 9
        return _main_locked(args)


if __name__ == "__main__":
    raise SystemExit(main())
