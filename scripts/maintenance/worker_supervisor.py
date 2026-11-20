#!/usr/bin/env python3
"""Supervisor/watchdog for the external SLI runtime workers.

WHY THIS EXISTS
---------------
The recurring collection outage was an OPERATIONAL defect, not a code defect:

  * `collection_worker.py` needs a real interactive Windows security context.
    A service account or sandbox context fails with
    `windows_security_context_invalid` (observed 5 times, 22.07-24.07).
    Therefore the worker CANNOT be a Windows service.
  * Because it lives in an interactive session, it dies when the session ends,
    the terminal closes or the machine reboots — and nothing restarted it.
  * Nothing noticed. Heartbeats went 31 hours stale while the UI kept saying
    "collection broken" without anyone being told.
  * Manual restarts produced duplicates (two listeners, orphan processes),
    because nobody checked what was already running.

This supervisor closes exactly those four gaps. It does NOT touch surveyed
systems: it only starts/observes local project workers.

CONTRACT
--------
  * Exactly one supervisor: guarded by a PostgreSQL advisory lock.
  * Verifies the real Windows principal before starting collection; refuses on
    a mismatch instead of producing another `windows_security_context_invalid`.
  * NEVER bypasses the durable collection block. If the block is active it
    reports and waits for the operator's bounded recovery probe.
  * Starts a worker only through `worker_guard.py`, so a duplicate is
    impossible by construction.
  * Restarts a worker only when its heartbeat is stale AND no live process
    exists — a slow worker is not a dead worker.
  * Emergency ceiling 5000 is never made persistent: the ceiling is passed
    explicitly on every start and defaults to the normal 50000.
  * A continuous instance is intended for Task Scheduler; `--once` remains a
    diagnostic evaluation only.

INTENDED DEPLOYMENT (no change to surveyed systems)
---------------------------------------------------
Windows Task Scheduler task, owned by the exact interactive account:
    Trigger:  At log on of EXAMPLE\\operator  (+ optional repeat)
    Action:   <project>\\.venv\\Scripts\\python.exe
              <project>\\scripts\\maintenance\\worker_supervisor.py
    Settings: "Run only when user is logged on"   <-- REQUIRED
              Do NOT use "Run whether user is logged on or not": that yields a
              non-interactive context and reintroduces error 1749.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.app_config import load_config  # noqa: E402
from server.sli.ops.runtime_component_registry import list_components  # noqa: E402
from server.sli.semantic.semantic_production_runtime import (  # noqa: E402
    INVESTIGATION_MODE,
    semantic_runtime_mode_from_env,
    semantic_v2_quarantine_repair_plan_digest_from_env,
)
from server.sli.sources.windows_runtime_identity import verify_collection_identity  # noqa: E402
from server.sli.ops.worker_supervisor_secrets import (  # noqa: E402
    load_supervisor_environment,
    remove_supervisor_environment_keys,
    provision_supervisor_environment,
    update_supervisor_environment,
    update_supervisor_environment_with_removals,
)
from scripts.maintenance import control_center_lifecycle, worker_guard  # noqa: E402

PY = ROOT / ".venv" / "Scripts" / "python.exe"
RUNTIME = ROOT / "scripts" / "runtime"
SUPERVISOR_LOCK = "ad_log_reports_worker_supervisor_v1"

NORMAL_COLLECTION_CEILING = 50000
SUPERVISOR_LOG = ROOT / "data" / "logs" / "worker-supervisor.log"

# Static launch-time flags per worker (not part of a component's identity,
# just the arguments the supervisor happens to pass at start). Anything not
# listed here starts with no extra static args; `_start()` still appends
# per-environment args (collection ceiling, ad_context settings) at launch.
_LAUNCH_ARGS: dict[str, list[str]] = {
    # The coordinator itself waits for the next Novosibirsk wall-clock slot;
    # do not add a supervisor-relative startup delay that would shift it.
    "ad_snapshot_manifest_coordinator": ["--no-initial-delay"],
    "computers_v6_source": [
        "--collect-ad-site",
        "--collect-exact-last-logon",
    ],
    "storage_lifecycle": ["--interval-seconds", "21600"],
    "collection": [
        "--interval-seconds", "600",
        "--max-events-per-channel", str(NORMAL_COLLECTION_CEILING),
    ],
}


def _launch_args(component) -> list[str]:
    if component.plugin_component_id:
        return ["--component", component.plugin_component_id]
    return list(_LAUNCH_ARGS.get(component.name, []))


# worker name -> (script, extra args) - a thin view over the canonical
# registry; this module owns no worker composition data of its own beyond
# the static launch args above.
MANAGED: dict[str, tuple[str, list[str]]] = {
    component.name: (component.script, _launch_args(component))
    for component in list_components()
    if component.supervised
}

# A child is eligible for lifecycle termination only while this supervisor
# instance still owns its Popen handle. No control path discovers or targets
# arbitrary process identifiers.
OWNED_CHILDREN: dict[str, object] = {}

# Start order matters: publication and post-processing must be up before
# collection, otherwise collected events never reach Storage V2 and the reports
# stay empty while everything "looks" healthy.
START_ORDER = (
    "semantic",
    "storage_lifecycle",
    "entity_state",
    "what_where_when_projection",
    "post_collection",
    "collection",
    "ad_snapshot_manifest_coordinator",
    "plugin_radius_session_observation",
    "plugin_radius_acquisition",
)


def storage_lifecycle_admitted(environ: dict[str, str] | None = None) -> bool:
    values = environ if environ is not None else os.environ
    enabled = str(values.get("ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED", "")).strip().casefold()
    if enabled not in {"1", "true", "yes", "on"}:
        return False
    return (
        str(values.get("ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION", "")).strip()
        == "APPLY-STAGE7-HOT-RETENTION-DELETE"
        or str(values.get("ADLOG_STORAGE_NO_ARCHIVE_DELETE_CONFIRMATION", "")).strip()
        == "DELETE_EXPLICIT_NO_ARCHIVE_ROWS_AFTER_SEMANTIC_COMPLETION"
        or str(values.get("ADLOG_STORAGE_LIFECYCLE_WARM_COPY_ADMISSION", "")).strip()
        == "START-STAGE7-WARM-INCREMENTAL-COPY"
    )


def semantic_production_admitted(
    environ: dict[str, str] | None = None,
) -> bool:
    values = environ if environ is not None else os.environ
    enabled = str(values.get("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "")).strip().casefold() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not enabled:
        return False
    return str(values.get("ADLOG_SEMANTIC_RUNTIME_MODE", "")).strip() in {
        "",
        "facts-v1",
        "investigation-v1",
        "findings-v1",
    }

# `START_ORDER` is an ordering, not a second composition list: it must name
# exactly the components the registry marks as supervised, no more, no less.
assert set(START_ORDER) == set(MANAGED), "START_ORDER and MANAGED have drifted"


def _log(event: str, **fields: object) -> None:
    payload = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
    encoded = json.dumps(payload, ensure_ascii=False, default=str)
    print(encoded, flush=True)
    try:
        SUPERVISOR_LOG.parent.mkdir(parents=True, exist_ok=True)
        with SUPERVISOR_LOG.open("a", encoding="utf-8") as handle:
            handle.write(encoded + "\n")
    except OSError:
        pass


def _guard(worker: str) -> tuple[int, dict[str, object]]:
    """Single-worker convenience wrapper over the batched guard cycle.

    Kept for manual/maintenance consumers that check one worker at a
    time outside the supervisor's own loop. The supervisor's own per-cycle
    evaluation calls `worker_guard.evaluate_cycle()` directly instead of
    going through this, so it still pays for exactly one process inventory
    scan and one DB connection per cycle, not one per worker.
    """
    result = worker_guard.evaluate_cycle([worker]).get(worker, {})
    return int(result.get("code", 1)), result


def _main_checkout_root() -> Path:
    """Locate Main without embedding a machine-specific checkout path."""
    return ROOT.parent.parent if ROOT.parent.name == ".worktrees" else ROOT


def _require_exact_main_runtime_file(value: str, *, relative_path: Path) -> Path:
    """Accept only an existing absolute Main runtime file, never a worktree peer."""
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise RuntimeError("semantic_runtime_path_must_be_absolute")
    try:
        resolved = candidate.resolve(strict=True)
        expected = (_main_checkout_root() / relative_path).resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("semantic_runtime_path_is_not_an_existing_main_file") from exc
    if not resolved.is_file() or resolved != expected:
        raise RuntimeError("semantic_runtime_path_is_not_the_exact_main_file")
    return resolved


def _start(worker: str, *, interpreter: Path | None = None) -> dict[str, object]:
    from server.sli.sources.legacy_collection import legacy_collection_disabled, REASON

    # post_collection remains the core inbox executor when legacy is disabled.
    if legacy_collection_disabled() and MANAGED[worker][0] in {
        "collection_worker.py", "ad_context_snapshot_worker.py",
        "ad_snapshot_manifest_coordinator_worker.py", "ad_snapshot_projection_worker.py",
        "computers_v6_source_worker.py", "users_report_v2_snapshot_worker.py",
        "computers_report_v5_snapshot_worker.py", "computers_report_v6_snapshot_worker.py",
        "remote_access_plugin_host.py",
    }:
        return {"started": False, "reason": REASON}
    if interpreter is not None and worker != "semantic":
        raise RuntimeError("semantic_interpreter_override_is_semantic_only")
    script, extra = MANAGED[worker]
    args = [str(interpreter or PY), str(RUNTIME / script), *extra]
    if worker == "collection":
        server = os.environ.get("ADLOG_COLLECTION_PREFLIGHT_SERVER", "").strip()
        if not server:
            return {"started": False, "reason": "preflight_server_not_configured"}
        args += ["--preflight-server", server]
    if worker in {"ad_context_snapshot", "ad_snapshot_manifest_coordinator"}:
        settings = {
            "directory_server": (
                os.environ.get("ADLOG_AD_CONTEXT_DIRECTORY_SERVER")
                or os.environ.get("ADLOG_COLLECTION_PREFLIGHT_SERVER")
                or ""
            ).strip(),
            "domain": os.environ.get("ADLOG_AD_CONTEXT_DOMAIN", "").strip(),
            "search_base": os.environ.get("ADLOG_AD_CONTEXT_SEARCH_BASE", "").strip(),
            "privileged_group_sids": os.environ.get(
                "ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS", ""
            ).strip(),
            "vpn_group_references": os.environ.get(
                "ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES", ""
            ).strip(),
        }
        missing = sorted(name for name, value in settings.items() if not value)
        if missing:
            return {
                "started": False,
                "reason": f"{worker}_configuration_missing",
                "missing": missing,
            }
        if worker == "ad_context_snapshot":
            interval = os.environ.get("ADLOG_AD_CONTEXT_INTERVAL_SECONDS", "1800").strip()
            args += [
                "--directory-server", settings["directory_server"],
                "--domain", settings["domain"],
                "--search-base", settings["search_base"],
                "--privileged-group-sids", settings["privileged_group_sids"],
                "--vpn-group-references", settings["vpn_group_references"],
                "--interval-seconds", interval,
            ]
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    log_path = ROOT / "data" / "logs" / f"runtime-{worker}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as output:
        proc = subprocess.Popen(
            args,
            cwd=str(ROOT),
            creationflags=creationflags,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
    OWNED_CHILDREN[worker] = proc
    return {"started": True, "pid": proc.pid, "args": args[1:]}


def _owned_child_running(worker: str) -> object | None:
    """Return only a live child that this supervisor still owns directly."""
    child = OWNED_CHILDREN.get(worker)
    if child is None:
        return None
    try:
        if getattr(child, "poll")() is None:
            return child
    except Exception:
        pass
    OWNED_CHILDREN.pop(worker, None)
    return None


def _intent_effective_state(intent: dict[str, object]) -> str:
    effective = intent.get("effective")
    return str(effective.get("state") or "") if isinstance(effective, dict) else ""


def _record_lifecycle_effect(
    worker: str,
    intent: dict[str, object],
    *,
    state: str,
    evidence: str,
    resolve_to_running: bool = False,
) -> None:
    request_id = str(intent.get("request_id") or "")
    if request_id:
        control_center_lifecycle.record_worker_effective(
            worker,
            request_id,
            state=state,
            evidence=evidence,
            resolve_to_running=resolve_to_running,
        )


def _stop_from_lifecycle_intent(
    worker: str,
    intent: dict[str, object],
    guard: dict[str, object],
) -> dict[str, object]:
    """Stop only a currently owned child; unowned processes remain pending."""
    child = _owned_child_running(worker)
    effective_state = _intent_effective_state(intent)
    if child is not None:
        if effective_state == "stopping":
            return {"action": "stopping", "reason": "owned_child_exit_pending"}
        try:
            # This is a Popen handle retained at launch by this supervisor,
            # not a PID discovered by a control request.
            getattr(child, "terminate")()
        except Exception as exc:
            _record_lifecycle_effect(
                worker,
                intent,
                state="stop_failed",
                evidence=f"owned_child_terminate_failed:{type(exc).__name__}",
            )
            return {"action": "stop_failed", "reason": "owned_child_terminate_failed"}
        _record_lifecycle_effect(
            worker,
            intent,
            state="stopping",
            evidence="supervisor_requested_stop_of_its_owned_child",
        )
        return {"action": "stop_requested", "reason": "owned_child_termination_requested"}

    code = int(guard.get("code", 1))
    if code == 0:
        _record_lifecycle_effect(
            worker,
            intent,
            state="stopped",
            evidence="guard_observed_no_live_worker_after_stop_request",
        )
        return {"action": "stopped", "reason": "no_live_worker_observed"}
    if code == 9:
        _record_lifecycle_effect(
            worker,
            intent,
            state="pending_unowned_process",
            evidence="live_worker_not_owned_by_this_supervisor_instance",
        )
        return {"action": "stop_pending", "reason": "live_worker_not_owned"}
    _record_lifecycle_effect(
        worker,
        intent,
        state="pending_guard_refused",
        evidence=f"guard:{guard.get('decision') or 'unknown'}",
    )
    return {"action": "stop_pending", "reason": "guard_cannot_confirm_worker_absent"}


def _start_from_lifecycle_intent(
    worker: str,
    intent: dict[str, object],
    guard: dict[str, object],
    *,
    interpreter: Path | None = None,
) -> dict[str, object]:
    """Start after the guard clears it; restart is never reported complete here."""
    action = str(intent.get("action") or "start")
    desired_state = str(intent.get("desired_state") or "")
    restart = desired_state == "restart" or action == "restart"
    child = _owned_child_running(worker)
    if child is not None:
        effective_state = _intent_effective_state(intent)
        if restart and effective_state != "restart_stopping":
            try:
                getattr(child, "terminate")()
            except Exception as exc:
                _record_lifecycle_effect(
                    worker,
                    intent,
                    state="restart_stop_failed",
                    evidence=f"owned_child_terminate_failed:{type(exc).__name__}",
                )
                return {"action": "restart_stop_failed", "reason": "owned_child_terminate_failed"}
            _record_lifecycle_effect(
                worker,
                intent,
                state="restart_stopping",
                evidence="supervisor_requested_restart_stop_of_its_owned_child",
            )
            return {"action": "restart_stop_requested", "reason": "owned_child_termination_requested"}
        return {
            "action": "restart_stopping" if restart else "start_pending",
            "reason": "owned_child_exit_pending" if restart else "owned_child_still_running",
        }

    code = int(guard.get("code", 1))
    if code == 0:
        started = _start(worker, interpreter=interpreter) if interpreter is not None else _start(worker)
        started_ok = bool(started.get("started"))
        _record_lifecycle_effect(
            worker,
            intent,
            state="restart_start_attempted" if restart and started_ok else (
                "start_attempted" if started_ok else "start_refused"
            ),
            evidence="supervisor_launch_attempt_completed; worker readiness is not yet verified",
            resolve_to_running=started_ok,
        )
        return {
            "action": "restart_start_attempted" if restart else "start_attempted",
            "guard": guard.get("decision"),
            **started,
        }
    if code == 9:
        _record_lifecycle_effect(
            worker,
            intent,
            state="pending_unowned_process",
            evidence="guard_observed_live_worker_not_owned_by_this_supervisor_instance",
        )
        return {
            "action": "restart_pending" if restart else "start_pending",
            "reason": "live_worker_not_owned",
            "guard": guard.get("decision"),
        }
    _record_lifecycle_effect(
        worker,
        intent,
        state="pending_guard_refused",
        evidence=f"guard:{guard.get('decision') or 'unknown'}",
    )
    return {
        "action": "restart_pending" if restart else "start_pending",
        "reason": "guard_cannot_authorize_launch",
        "guard": guard.get("decision"),
    }


def evaluate_once() -> dict[str, object]:
    identity = verify_collection_identity()
    ok = identity.get("status") == "ok"
    result: dict[str, object] = {"collection_identity": identity, "workers": {}}
    workers: dict[str, object] = result["workers"]  # type: ignore[assignment]

    # One guard cycle for every managed worker: one process inventory scan
    # and one DB connection for the whole cycle, not one of each per worker
    # (see `worker_guard.evaluate_cycle`).
    guard_cycle = worker_guard.evaluate_cycle(list(MANAGED))

    for worker in START_ORDER:
        payload = guard_cycle.get(worker, {})
        try:
            lifecycle_intent = control_center_lifecycle.read_worker_intent(worker)
        except control_center_lifecycle.ControlStateError as exc:
            workers[worker] = {
                "action": "refused",
                "reason": str(exc),
            }
            _log("supervisor_refused_control_state", worker=worker, reason=str(exc))
            continue
        desired_state = (
            str(lifecycle_intent.get("desired_state") or "")
            if lifecycle_intent is not None
            else ""
        )
        if lifecycle_intent is not None and desired_state == "stopped":
            workers[worker] = _stop_from_lifecycle_intent(
                worker,
                lifecycle_intent,
                payload,
            )
            continue
        if lifecycle_intent is not None and desired_state not in {
            "",
            "running",
            "start",
            "restart",
        }:
            workers[worker] = {
                "action": "refused",
                "reason": "control_state_desired_state_invalid",
            }
            continue
        if worker == "semantic" and not semantic_production_admitted():
            workers[worker] = {
                "action": "disabled",
                "reason": "semantic_production_admission_missing",
            }
            continue
        if worker == "storage_lifecycle" and not storage_lifecycle_admitted():
            workers[worker] = {
                "action": "disabled",
                "reason": "one_time_storage_admission_missing",
            }
            continue
        if worker in {
            "collection",
            "ad_context_snapshot",
            "ad_snapshot_manifest_coordinator",
            "computers_v6_source",
            "plugin_radius_acquisition",
            "plugin_radius_session_observation",
        } and not ok:
            workers[worker] = {
                "action": "refused",
                "reason": "windows_collection_identity_invalid",
                "detail": identity,
            }
            _log("supervisor_refused_principal", worker=worker, detail=identity)
            continue
        if lifecycle_intent is not None and desired_state in {"start", "restart"}:
            workers[worker] = _start_from_lifecycle_intent(
                worker,
                lifecycle_intent,
                payload,
            )
            continue
        code = int(payload.get("code", 1))
        decision = str(payload.get("decision") or "unknown")
        if code == 0:
            started = _start(worker)
            workers[worker] = {"action": "started", "guard": decision, **started}
            _log("supervisor_started", worker=worker, **started)
            # Let the new process register its heartbeat before the next guard.
            time.sleep(8)
        elif code == 10:
            workers[worker] = {"action": "waiting_operator", "guard": decision,
                               "reason_code": payload.get("reason_code")}
            _log("supervisor_blocked", worker=worker, detail=payload)
        elif code == 9:
            workers[worker] = {"action": "healthy_or_running", "guard": decision}
        else:
            workers[worker] = {"action": "undetermined", "guard": decision, "detail": payload}
            _log("supervisor_undetermined", worker=worker, detail=payload)
    return result


def evaluate_semantic_once(*, interpreter: Path | None = None) -> dict[str, object]:
    """Evaluate only the admitted semantic worker without collection identity."""
    worker = "semantic"
    result: dict[str, object] = {"workers": {}}
    workers: dict[str, object] = result["workers"]  # type: ignore[assignment]
    payload = worker_guard.evaluate_cycle([worker]).get(worker, {})
    try:
        lifecycle_intent = control_center_lifecycle.read_worker_intent(worker)
    except control_center_lifecycle.ControlStateError as exc:
        workers[worker] = {"action": "refused", "reason": str(exc)}
        _log("supervisor_refused_control_state", worker=worker, reason=str(exc))
        return result

    desired_state = (
        str(lifecycle_intent.get("desired_state") or "")
        if lifecycle_intent is not None
        else ""
    )
    if lifecycle_intent is not None and desired_state == "stopped":
        workers[worker] = _stop_from_lifecycle_intent(worker, lifecycle_intent, payload)
        return result
    if lifecycle_intent is not None and desired_state not in {"", "running", "start", "restart"}:
        workers[worker] = {"action": "refused", "reason": "control_state_desired_state_invalid"}
        return result
    if lifecycle_intent is not None and desired_state in {"start", "restart"}:
        workers[worker] = _start_from_lifecycle_intent(
            worker, lifecycle_intent, payload, interpreter=interpreter,
        )
        return result

    code = int(payload.get("code", 1))
    decision = str(payload.get("decision") or "unknown")
    if code == 0:
        started = _start(worker, interpreter=interpreter) if interpreter is not None else _start(worker)
        workers[worker] = {"action": "started", "guard": decision, **started}
        _log("supervisor_started", worker=worker, **started)
    elif code == 10:
        workers[worker] = {
            "action": "waiting_operator",
            "guard": decision,
            "reason_code": payload.get("reason_code"),
        }
        _log("supervisor_blocked", worker=worker, detail=payload)
    elif code == 9:
        workers[worker] = {"action": "healthy_or_running", "guard": decision}
    else:
        safe_guard = {
            "action": "undetermined",
            "guard": decision,
            "code": code,
            "reason_code": payload.get("reason_code"),
        }
        workers[worker] = safe_guard
        _log("supervisor_undetermined", worker=worker, **safe_guard)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true",
                        help="Single evaluation, then exit (Task Scheduler mode).")
    parser.add_argument(
        "--semantic-only",
        action="store_true",
        help="Run one admitted semantic quarantine-repair evaluation without collection workers.",
    )
    parser.add_argument(
        "--environment-file",
        help="Exact existing Main CurrentUser-DPAPI profile for one semantic-only evaluation.",
    )
    parser.add_argument(
        "--semantic-python",
        help="Exact existing Main Python interpreter for the semantic child only.",
    )
    parser.add_argument("--interval-seconds", type=int, default=120)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--provision-environment",
        action="store_true",
        help="Protect the current worker environment with current-user DPAPI and exit.",
    )
    parser.add_argument(
        "--admit-storage-lifecycle",
        action="store_true",
        help="Merge the accepted storage lifecycle admission into the existing DPAPI payload.",
    )
    parser.add_argument(
        "--admit-storage-lifecycle-copy-only",
        action="store_true",
        help="Admit warm copy while explicitly denying both retention delete lanes.",
    )
    parser.add_argument(
        "--admit-raw-cleanup",
        action="store_true",
        help="Enable removal of a raw batch only after its PostgreSQL import and cursor update succeed.",
    )
    parser.add_argument(
        "--admit-semantic-production",
        action="store_true",
        help="Merge the exact semantic production flags into the DPAPI payload.",
    )
    parser.add_argument(
        "--admit-semantic-facts",
        action="store_true",
        help="Merge the exact facts-only semantic mode into the DPAPI payload.",
    )
    parser.add_argument(
        "--admit-semantic-investigation",
        action="store_true",
        help="Merge the exact investigation-only semantic mode into the DPAPI payload.",
    )
    parser.add_argument(
        "--revoke-semantic-production",
        action="store_true",
        help="Disable the complete semantic chain in the DPAPI payload.",
    )
    parser.add_argument(
        "--arm-semantic-v2-quarantine-repair",
        metavar="REPAIR_PLAN_DIGEST",
        help=(
            "Store one exact v2 quarantine repair digest in the DPAPI payload; "
            "does not launch a worker and takes effect only after a controlled worker restart."
        ),
    )
    parser.add_argument(
        "--disarm-semantic-v2-quarantine-repair",
        action="store_true",
        help=(
            "Remove only the armed v2 quarantine repair digest from the DPAPI payload; "
            "does not stop or launch a worker and takes effect only after a controlled worker restart."
        ),
    )
    parser.add_argument("--confirmation")
    args = parser.parse_args()

    action_requested = any((
        args.provision_environment,
        args.admit_storage_lifecycle,
        args.admit_storage_lifecycle_copy_only,
        args.admit_raw_cleanup,
        args.admit_semantic_production,
        args.admit_semantic_facts,
        args.admit_semantic_investigation,
        args.revoke_semantic_production,
        args.arm_semantic_v2_quarantine_repair,
        args.disarm_semantic_v2_quarantine_repair,
    ))
    if args.semantic_only and action_requested:
        print(json.dumps({
            "status": "blocked",
            "reason": "semantic_only_conflicts_with_action_flags",
        }, ensure_ascii=False, indent=2))
        return 2
    if args.semantic_only and not args.once:
        print(json.dumps({
            "status": "blocked",
            "reason": "semantic_only_requires_once",
        }, ensure_ascii=False, indent=2))
        return 2
    if (args.environment_file or args.semantic_python) and not (args.semantic_only and args.once):
        print(json.dumps({
            "status": "blocked",
            "reason": "semantic_runtime_path_requires_semantic_only_once",
        }, ensure_ascii=False, indent=2))
        return 2

    environment_file: Path | None = None
    semantic_python: Path | None = None
    if args.semantic_only:
        try:
            if args.environment_file:
                environment_file = _require_exact_main_runtime_file(
                    args.environment_file,
                    relative_path=Path("data/runtime/worker-supervisor.env.dpapi"),
                )
            if args.semantic_python:
                semantic_python = _require_exact_main_runtime_file(
                    args.semantic_python,
                    relative_path=Path(".venv/Scripts/python.exe"),
                )
        except RuntimeError as exc:
            _log("semantic_only_refused", reason=str(exc))
            return 1

    if args.provision_environment:
        result = provision_supervisor_environment()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.arm_semantic_v2_quarantine_repair:
        digest = str(args.arm_semantic_v2_quarantine_repair).strip()
        if (
            len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
            or args.confirmation != "ARM-SEMANTIC-V2-QUARANTINE-REPAIR:" + digest
        ):
            print(json.dumps({
                "status": "blocked",
                "reason": "exact_semantic_v2_quarantine_repair_arm_required",
            }, ensure_ascii=False, indent=2))
            return 2
        result = update_supervisor_environment({
            "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST": digest,
        })
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.disarm_semantic_v2_quarantine_repair:
        if args.confirmation != "DISARM-SEMANTIC-V2-QUARANTINE-REPAIR":
            print(json.dumps({
                "status": "blocked",
                "reason": "exact_semantic_v2_quarantine_repair_disarm_required",
            }, ensure_ascii=False, indent=2))
            return 2
        result = remove_supervisor_environment_keys({
            "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST",
        })
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.admit_storage_lifecycle:
        if args.confirmation != "ENABLE-STORAGE-LIFECYCLE-AUTOMATION":
            print(json.dumps({
                "status": "blocked",
                "reason": "exact_storage_lifecycle_admission_required",
            }, ensure_ascii=False, indent=2))
            return 2
        result = update_supervisor_environment({
            "ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED": "1",
            "ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION": "APPLY-STAGE7-HOT-RETENTION-DELETE",
            "ADLOG_STORAGE_LIFECYCLE_DELETE_EXECUTION_ENABLED": "1",
        })
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.admit_storage_lifecycle_copy_only:
        if args.confirmation != "ENABLE-STORAGE-LIFECYCLE-COPY-ONLY":
            print(json.dumps({
                "status": "blocked",
                "reason": "exact_storage_lifecycle_copy_only_admission_required",
            }, ensure_ascii=False, indent=2))
            return 2
        result = update_supervisor_environment({
            "ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED": "1",
            "ADLOG_STORAGE_LIFECYCLE_WARM_COPY_ADMISSION": "START-STAGE7-WARM-INCREMENTAL-COPY",
            "ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION": "0",
            "ADLOG_STORAGE_NO_ARCHIVE_DELETE_CONFIRMATION": "0",
            "ADLOG_STORAGE_LIFECYCLE_DELETE_EXECUTION_ENABLED": "0",
        })
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.admit_raw_cleanup:
        if args.confirmation != "ENABLE-CONFIRMED-RAW-CLEANUP":
            print(json.dumps({
                "status": "blocked",
                "reason": "exact_raw_cleanup_admission_required",
            }, ensure_ascii=False, indent=2))
            return 2
        result = update_supervisor_environment({
            "ADLOG_DELETE_IMPORTED_RAW": "1",
        })
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.admit_semantic_production:
        if args.confirmation != "ENABLE-CONTINUOUS-SEMANTIC-PRODUCTION":
            print(json.dumps({
                "status": "blocked",
                "reason": "exact_semantic_production_admission_required",
            }, ensure_ascii=False, indent=2))
            return 2
        result = update_supervisor_environment({
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
            "ADLOG_SEMANTIC_RUNTIME_MODE": "findings-v1",
            "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
            "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1",
            "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
            "ADLOG_SEMANTIC_CORRELATION_ENABLED": "1",
            "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "1",
            "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "1",
        })
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.admit_semantic_facts:
        if args.confirmation != "ENABLE-CONTINUOUS-SEMANTIC-FACTS":
            print(json.dumps({
                "status": "blocked",
                "reason": "exact_semantic_facts_admission_required",
            }, ensure_ascii=False, indent=2))
            return 2
        result = update_supervisor_environment({
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
            "ADLOG_SEMANTIC_RUNTIME_MODE": "facts-v1",
            "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
            "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1",
            "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
            "ADLOG_SEMANTIC_CORRELATION_ENABLED": "0",
            "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "0",
            "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0",
        })
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.admit_semantic_investigation:
        if args.confirmation != "ENABLE-CONTINUOUS-SEMANTIC-INVESTIGATION":
            print(json.dumps({
                "status": "blocked",
                "reason": "exact_semantic_investigation_admission_required",
            }, ensure_ascii=False, indent=2))
            return 2
        result = update_supervisor_environment({
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
            "ADLOG_SEMANTIC_RUNTIME_MODE": "investigation-v1",
            "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
            "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1",
            "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
            "ADLOG_SEMANTIC_CORRELATION_ENABLED": "1",
            "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "0",
            "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0",
        })
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.revoke_semantic_production:
        if args.confirmation != "DISABLE-CONTINUOUS-SEMANTIC-PRODUCTION":
            print(json.dumps({
                "status": "blocked",
                "reason": "exact_semantic_production_revoke_required",
            }, ensure_ascii=False, indent=2))
            return 2
        result = update_supervisor_environment_with_removals({
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "0",
            "ADLOG_SEMANTIC_RUNTIME_MODE": "disabled",
            "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "0",
            "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "0",
            "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
            "ADLOG_SEMANTIC_CORRELATION_ENABLED": "0",
            "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "0",
            "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0",
        }, {"ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST"})
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    try:
        # The sealed DPAPI payload is the canonical environment for the
        # managed scheduled task.  Inherited user/machine values may be stale
        # across a controlled route switch and must not override it.
        load_result = load_supervisor_environment(
            path=environment_file, override_existing=True,
        ) if environment_file is not None else load_supervisor_environment(override_existing=True)
        _log("supervisor_environment_loaded", keys=load_result.get("keys"))
    except RuntimeError as exc:
        if args.semantic_only:
            _log("semantic_only_refused", reason="canonical_environment_not_loaded")
            return 1
        # Interactive/manual development runs may already carry the complete
        # environment.  The scheduled task has none and therefore still fails
        # closed below when the required DSN is absent.
        _log("supervisor_environment_not_loaded", reason=str(exc))

    if args.semantic_only:
        try:
            canonical_keys = set(load_result.get("keys") or [])
            required_canonical_keys = {
                "ADLOG_PG_DSN",
                "ADLOG_SEMANTIC_PRODUCTION_ENABLED",
                "ADLOG_SEMANTIC_RUNTIME_MODE",
                "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST",
            }
            if not required_canonical_keys.issubset(canonical_keys):
                raise RuntimeError("semantic_only_canonical_profile_incomplete")
            if not semantic_production_admitted():
                raise RuntimeError("semantic_production_admission_missing")
            if semantic_runtime_mode_from_env() != INVESTIGATION_MODE:
                raise RuntimeError("semantic_investigation_mode_required")
            if semantic_v2_quarantine_repair_plan_digest_from_env() is None:
                raise RuntimeError("semantic_v2_quarantine_repair_digest_missing")
        except RuntimeError as exc:
            _log("semantic_only_refused", reason=str(exc))
            return 1

    dsn = os.getenv("ADLOG_PG_DSN") or load_config().postgres_dsn
    if not dsn:
        _log("supervisor_refused", reason="dsn_missing")
        return 1
    try:
        import psycopg
    except Exception as exc:
        _log("supervisor_refused", reason="psycopg_missing", error=str(exc))
        return 1

    # Exactly one supervisor, enforced by PostgreSQL rather than by convention.
    with psycopg.connect(str(dsn), autocommit=True, connect_timeout=5,
                         application_name="sli_worker_supervisor") as conn:
        with conn.cursor() as cur:
            cur.execute("select pg_try_advisory_lock(hashtext(%s))", (SUPERVISOR_LOCK,))
            if not bool(cur.fetchone()[0]):
                _log("supervisor_refused", reason="another_supervisor_holds_lock")
                return 9
            try:
                interval = max(30, min(args.interval_seconds, 3600))
                while True:
                    report = (
                        evaluate_semantic_once(interpreter=semantic_python)
                        if args.semantic_only and semantic_python is not None
                        else evaluate_semantic_once()
                        if args.semantic_only
                        else evaluate_once()
                    )
                    if args.json:
                        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
                    if args.once:
                        return 0
                    time.sleep(interval)
            finally:
                cur.execute("select pg_advisory_unlock(hashtext(%s))", (SUPERVISOR_LOCK,))


if __name__ == "__main__":
    raise SystemExit(main())
