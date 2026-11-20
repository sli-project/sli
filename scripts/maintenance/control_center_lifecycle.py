#!/usr/bin/env python3
"""Bounded Control Center V2 lifecycle contract.

This module deliberately owns only durable local intent under
``data/control-center``.  It never searches for or targets arbitrary process
identifiers.  Web-runtime mutations are delegated only to the existing
``server_control`` controller after an exact action confirmation.  Named-worker
mutations are requests; the worker supervisor owns their observation and any
transition of children it started itself.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import sys
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

STATE_PATH = ROOT / "data" / "control-center" / "lifecycle-intents.json"
CONTRACT_VERSION = "control-center-lifecycle.v2"
PROJECT_ACTIONS = ("status", "start", "stop", "restart")
WORKER_ACTIONS = ("status", "stop", "restart")
_STATE_VERSION = 1
_LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_POLL_SECONDS = 0.05


class ControlStateError(RuntimeError):
    """Raised when durable control state cannot be trusted."""


def confirmation_token(scope: str, action: str, worker: str | None = None) -> str:
    """Return the exact token required for one mutation and one target."""
    if scope == "project" and worker is None:
        return f"CONTROL-CENTER:project:{action}"
    if scope == "worker" and worker:
        return f"CONTROL-CENTER:worker:{action}:{worker}"
    raise ValueError("confirmation_scope_or_target_invalid")


def managed_worker_names() -> tuple[str, ...]:
    """Read the allowlist from the supervisor's canonical current registry."""
    from scripts.maintenance import worker_supervisor

    return tuple(worker_supervisor.MANAGED)


_MANAGED_WORKER_LABELS_RU = {
    "collection": "Сбор событий",
    "ad_snapshot_manifest_coordinator": "Координатор снимков Active Directory",
    "storage_v2_outbox": "Публикация хранилища V2",
    "storage_lifecycle": "Жизненный цикл хранилища",
    "post_collection": "Обработка после сбора",
    "entity_state": "Состояние сущностей",
    "what_where_when_projection": "Проекция «что–где–когда»",
    "plugin_radius_acquisition": "Получение данных RADIUS",
    "plugin_radius_session_observation": "Наблюдение сеансов RADIUS",
    "semantic": "Семантическая обработка",
}


def managed_workers_selector() -> dict[str, object]:
    """Return current managed workers with Russian UI labels; no state is changed."""
    return {
        "contract_version": CONTRACT_VERSION,
        "action": "managed-workers",
        "status": "ok",
        "read_only": True,
        "workers": [
            {
                "name": name,
                "label_ru": _MANAGED_WORKER_LABELS_RU.get(
                    name, f"Управляемый обработчик № {index}"
                ),
            }
            for index, name in enumerate(managed_worker_names(), start=1)
        ],
    }


def _state_template() -> dict[str, object]:
    return {"version": _STATE_VERSION, "workers": {}, "project": None}


def _resolve_state_path(state_path: Path | None) -> Path:
    return Path(state_path) if state_path is not None else STATE_PATH


def _load_state(state_path: Path | None = None) -> dict[str, object]:
    path = _resolve_state_path(state_path)
    if not path.exists():
        return _state_template()
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlStateError("control_state_unreadable") from exc
    if (
        not isinstance(loaded, dict)
        or loaded.get("version") != _STATE_VERSION
        or not isinstance(loaded.get("workers"), dict)
    ):
        raise ControlStateError("control_state_invalid")
    return loaded



def _try_state_lock(handle) -> None:
    """Acquire a nonblocking OS lock on the stable sibling file."""
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
            raise BlockingIOError("control_state_lock_busy") from exc
        raise


@contextmanager
def _state_lock(state_path: Path | None = None) -> Iterator[None]:
    """Serialize every document mutation, including observation ID checks.

    Keep the sibling lock file: deleting it permits separate locked inodes.
    Locking the JSON itself would likewise fail when atomic replace changes it.
    Closing the handle releases the OS lock, including on process exit. Readers
    need no lock because they only read the atomically replaced JSON snapshot.
    """
    path = _resolve_state_path(state_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.with_name(path.name + ".lock").open("a+b")
    except OSError as exc:
        raise ControlStateError("control_state_lock_failed") from exc
    with handle:
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        while True:
            try:
                _try_state_lock(handle)
                break
            except BlockingIOError as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ControlStateError("control_state_lock_timeout") from exc
                time.sleep(min(_LOCK_POLL_SECONDS, remaining))
            except OSError as exc:
                raise ControlStateError("control_state_lock_failed") from exc
        yield

def _write_state(state: dict[str, object], state_path: Path | None = None) -> None:
    path = _resolve_state_path(state_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        temporary.write_text(
            json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    except OSError as exc:
        raise ControlStateError("control_state_write_failed") from exc


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _worker_intent_from_state(state: dict[str, object], worker: str) -> dict[str, object] | None:
    workers = state["workers"]
    assert isinstance(workers, dict)
    value = workers.get(worker)
    return dict(value) if isinstance(value, dict) else None


def read_worker_intent(worker: str, *, state_path: Path | None = None) -> dict[str, object] | None:
    """Return durable requested/effective state without inspecting a process or DB."""
    return _worker_intent_from_state(_load_state(state_path), worker)


def _request_intent(
    state: dict[str, object],
    *,
    worker: str,
    desired_state: str,
    action: str,
    request_id: str,
    project_request_id: str | None = None,
) -> dict[str, object]:
    workers = state["workers"]
    assert isinstance(workers, dict)
    intent: dict[str, object] = {
        "worker": worker,
        "action": action,
        "desired_state": desired_state,
        "request_id": request_id,
        "requested_at_utc": _now(),
        "effective": {
            "state": "pending_supervisor",
            "evidence": "Requested locally; only worker_supervisor may perform or verify a worker transition.",
        },
    }
    if project_request_id is not None:
        intent["project_request_id"] = project_request_id
    workers[worker] = intent
    return intent


def request_worker_action(
    action: str,
    worker: str,
    *,
    confirmation: str | None,
    state_path: Path | None = None,
) -> dict[str, object]:
    """Persist a supervised named-worker stop/restart request after exact consent."""
    if action not in {"stop", "restart"}:
        return {"status": "rejected", "reason": "worker_action_not_supported", "action": action}
    allowed_workers = managed_worker_names()
    if worker not in allowed_workers:
        return {
            "status": "rejected",
            "reason": "worker_not_supervised",
            "worker": worker,
            "allowed_workers": list(allowed_workers),
        }
    required = confirmation_token("worker", action, worker)
    if confirmation != required:
        return {
            "status": "blocked",
            "reason": "exact_action_and_worker_confirmation_required",
            "required_confirmation": required,
            "worker": worker,
            "action": action,
        }
    try:
        with _state_lock(state_path):
            state = _load_state(state_path)
            desired_state = "stopped" if action == "stop" else "restart"
            intent = _request_intent(
                state,
                worker=worker,
                desired_state=desired_state,
                action=action,
                request_id=uuid.uuid4().hex,
            )
            _write_state(state, state_path)
    except ControlStateError as exc:
        return {"status": "blocked", "reason": str(exc), "worker": worker, "action": action}
    return {
        "status": "requested",
        "worker": worker,
        "action": action,
        "requested": {key: intent[key] for key in ("request_id", "requested_at_utc", "desired_state")},
        "effective": intent["effective"],
        "target_scope": "one_current_supervisor_managed_worker",
    }


def record_worker_effective(
    worker: str,
    request_id: str,
    *,
    state: str,
    evidence: str,
    resolve_to_running: bool = False,
    state_path: Path | None = None,
) -> bool:
    """Record a supervisor observation; never claims worker health/completion."""
    try:
        with _state_lock(state_path):
            document = _load_state(state_path)
            intent = _worker_intent_from_state(document, worker)
            if intent is None or intent.get("request_id") != request_id:
                return False
            intent["effective"] = {
                "state": state,
                "observed_at_utc": _now(),
                "evidence": evidence,
            }
            if resolve_to_running:
                intent["desired_state"] = "running"
            workers = document["workers"]
            assert isinstance(workers, dict)
            workers[worker] = intent
            _write_state(document, state_path)
    except ControlStateError:
        return False
    return True


def worker_status(worker: str, *, state_path: Path | None = None) -> dict[str, object]:
    """Report local intent only; it does not infer a live worker from a PID or DB."""
    allowed_workers = managed_worker_names()
    if worker not in allowed_workers:
        return {
            "status": "rejected",
            "reason": "worker_not_supervised",
            "worker": worker,
        }
    try:
        intent = read_worker_intent(worker, state_path=state_path)
    except ControlStateError as exc:
        return {
            "status": "unknown",
            "worker": worker,
            "reason": str(exc),
            "effective": {"state": "unknown"},
        }
    effective = intent.get("effective") if intent else {"state": "unknown"}
    return {
        "status": "unknown" if not intent else "requested_or_pending",
        "worker": worker,
        "target_scope": "one_current_supervisor_managed_worker",
        "requested": intent,
        "effective": effective,
        "evidence": "This contract does not treat a process inventory or web health as worker completion.",
    }


def web_runtime_status() -> dict[str, object]:
    """Reuse the bounded V1 loopback probe for the web-runtime portion only."""
    from scripts.maintenance import local_control_center_status

    snapshot = local_control_center_status.status(
        local_control_center_status.DEFAULT_WEB_URL,
        2.0,
    )
    component = snapshot["components"]["local_web_runtime"]
    assert isinstance(component, dict)
    return dict(component)


def project_status(*, state_path: Path | None = None) -> dict[str, object]:
    """Report both scopes while refusing to promote web health to project success."""
    try:
        web = web_runtime_status()
    except Exception:
        web = {"state": "unknown", "evidence": "Local web-runtime status could not be read."}
    workers = {
        worker: worker_status(worker, state_path=state_path)
        for worker in managed_worker_names()
    }
    worker_states = [
        str((value.get("effective") or {}).get("state", "unknown"))
        for value in workers.values()
    ]
    supervision_state = "pending" if any(state != "unknown" for state in worker_states) else "unknown"
    return {
        "contract_version": CONTRACT_VERSION,
        "action": "status",
        "scope": "web_runtime_and_worker_supervision",
        "status": "pending" if supervision_state == "pending" else "unknown",
        "full_project_success": False,
        "web_runtime": {"target_scope": "web_runtime_only", **web},
        "worker_supervision": {
            "scope": "all_current_supervisor_managed_workers",
            "state": supervision_state,
            "workers": workers,
            "evidence": "Web status alone is never evidence of whole-project lifecycle success.",
        },
    }


def _project_worker_request(
    action: str,
    *,
    state_path: Path | None = None,
) -> tuple[str, list[str]]:
    desired_state = {"start": "start", "stop": "stopped", "restart": "restart"}[action]
    names = managed_worker_names()
    with _state_lock(state_path):
        document = _load_state(state_path)
        project_request_id = uuid.uuid4().hex
        document["project"] = {
            "action": action,
            "request_id": project_request_id,
            "requested_at_utc": _now(),
            "effective": {"state": "pending_supervisor"},
        }
        for worker in names:
            _request_intent(
                document,
                worker=worker,
                desired_state=desired_state,
                action=action,
                request_id=uuid.uuid4().hex,
                project_request_id=project_request_id,
            )
        _write_state(document, state_path)
    return project_request_id, list(names)


def _web_plan(action: str) -> dict[str, object]:
    return {
        "controller": "scripts/maintenance/server_control.py",
        "target_scope": "web_runtime_only",
        "action": action,
        "state": "planned",
    }


def invoke_web_controller(action: str) -> dict[str, object]:
    """Delegate actual web mutation to its canonical controller after outer consent."""
    from scripts.maintenance import server_control

    if action == "start":
        return server_control.start()
    if action == "stop":
        return server_control.stop()
    if action == "restart":
        return server_control.restart()
    raise ValueError("project_action_not_supported")


def request_project_action(
    action: str,
    *,
    confirmation: str | None,
    dry_run: bool = False,
    state_path: Path | None = None,
) -> dict[str, object]:
    """Guard and compose the web controller with durable supervisor requests."""
    if action not in {"start", "stop", "restart"}:
        return {"status": "rejected", "reason": "project_action_not_supported", "action": action}
    required = confirmation_token("project", action)
    if not dry_run and confirmation != required:
        return {
            "status": "blocked",
            "reason": "exact_project_action_confirmation_required",
            "required_confirmation": required,
            "action": action,
        }
    worker_names = list(managed_worker_names())
    if dry_run:
        return {
            "contract_version": CONTRACT_VERSION,
            "status": "dry_run",
            "action": action,
            "full_project_success": False,
            "web_runtime": _web_plan(action),
            "worker_supervision": {
                "scope": "all_current_supervisor_managed_workers",
                "state": "planned_request_only",
                "workers": worker_names,
            },
        }
    try:
        project_request_id, worker_names = _project_worker_request(action, state_path=state_path)
    except ControlStateError as exc:
        return {"status": "blocked", "reason": str(exc), "action": action}
    try:
        web_result = invoke_web_controller(action)
    except Exception as exc:
        web_result: dict[str, object] = {
            "status": "failed",
            "failure_reason": "canonical_web_controller_failed",
            "error_type": type(exc).__name__,
        }
    web_status = str(web_result.get("status") or "failed")
    return {
        "contract_version": CONTRACT_VERSION,
        "status": "pending" if web_status not in {"failed"} else "failed",
        "action": action,
        "full_project_success": False,
        "web_runtime": {
            "target_scope": "web_runtime_only",
            "controller": "scripts/maintenance/server_control.py",
            "result": web_result,
        },
        "worker_supervision": {
            "scope": "all_current_supervisor_managed_workers",
            "state": "requested",
            "project_request_id": project_request_id,
            "workers": worker_names,
            "evidence": "Supervisor acknowledgement/effectiveness remains pending; this is not a full-project success.",
        },
    }


def _state_path_from_argument(state_dir: Path | None) -> Path | None:
    if state_dir is None:
        return None
    return state_dir / STATE_PATH.name


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded local Control Center lifecycle contract.")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--dry-run", action="store_true", help="plan only; never writes or calls a controller")
    parser.add_argument("--state-dir", type=Path, help="test-only alternate local state directory")
    target = parser.add_subparsers(dest="target", required=True)
    target.add_parser("managed-workers")
    project = target.add_parser("project")
    project.add_argument("action", choices=PROJECT_ACTIONS)
    project.add_argument("--confirm", help="exact action-bound confirmation token")
    worker = target.add_parser("worker")
    worker.add_argument("action", choices=WORKER_ACTIONS)
    worker.add_argument("--worker", required=True)
    worker.add_argument("--confirm", help="exact action-bound confirmation token")
    args = parser.parse_args()
    state_path = _state_path_from_argument(args.state_dir)
    if args.target == "managed-workers":
        result = managed_workers_selector()
    elif args.target == "project":
        result = (
            project_status(state_path=state_path)
            if args.action == "status"
            else request_project_action(
                args.action,
                confirmation=args.confirm,
                dry_run=args.dry_run,
                state_path=state_path,
            )
        )
    else:
        result = (
            worker_status(args.worker, state_path=state_path)
            if args.action == "status"
            else (
                {
                    "status": "dry_run",
                    "action": args.action,
                    "worker": args.worker,
                    "full_project_success": False,
                    "target_scope": "one_current_supervisor_managed_worker",
                }
                if args.dry_run
                else request_worker_action(
                    args.action,
                    args.worker,
                    confirmation=args.confirm,
                    state_path=state_path,
                )
            )
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True) if args.json else json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 2 if result.get("status") in {"blocked", "rejected", "failed"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
