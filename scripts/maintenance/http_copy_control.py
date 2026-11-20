#!/usr/bin/env python3
"""Control the single loopback HTTP verification copy.

Restart loads the current user's DPAPI-protected runtime environment, then
forces the HTTP copy guards: no scheduler, no collection, no recovery and no
TLS. Status is strictly read-only and does not require access to those secrets.
The command never targets the production HTTPS listener.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.ops.worker_supervisor_secrets import (  # noqa: E402
    HTTP_FORBIDDEN_ENVIRONMENT,
    load_supervisor_environment,
    strip_http_forbidden_environment,
)

STATE_PATH = ROOT / "data" / "runtime" / "http-copy-control.json"


def _require_candidate_react_dir(react_dir: Path) -> Path:
    resolved = react_dir.resolve()
    if ROOT.resolve() not in (resolved, *resolved.parents):
        raise RuntimeError("React build directory must resolve inside the candidate root")
    if not (resolved / "index.html").is_file():
        raise RuntimeError(f"React build index.html not found: {resolved}")
    return resolved


def _configure(react_dir: Path, *, environment_file: Path | None = None) -> Path:
    resolved_react_dir = _require_candidate_react_dir(react_dir)
    sealed = (
        load_supervisor_environment(path=environment_file, override_existing=True)
        if environment_file is not None
        else load_supervisor_environment(override_existing=True)
    )
    if not isinstance(sealed, dict) or sealed.get("status") != "ok":
        raise RuntimeError("protected runtime environment could not be loaded")
    strip_http_forbidden_environment()
    if not str(os.environ.get("ADLOG_PG_DSN") or "").strip():
        raise RuntimeError("runtime PostgreSQL DSN is required for the HTTP copy")
    if str(os.environ.get("ADLOG_DB_BACKEND") or "").strip().lower() != "postgres":
        raise RuntimeError("runtime PostgreSQL backend is required for the HTTP copy")
    if str(os.environ.get("ADLOG_AUTH_REQUIRED") or "").strip().lower() not in {"1", "true", "yes", "on"}:
        raise RuntimeError("authentication must be enabled for the HTTP copy")
    if any(str(os.environ.get(name) or "") for name in HTTP_FORBIDDEN_ENVIRONMENT):
        raise RuntimeError("privileged worker credentials must not reach the HTTP copy")
    os.environ.update(
        {
            "ADLOG_DISABLE_SCHEDULER": "1",
            "ADLOG_DISABLE_COLLECTION": "1",
            "ADLOG_CONTINUOUS_RECOVERY": "false",
            "ADLOG_RESTORE_SMOKE_MODE": "1",
            "ADLOG_AUTH_ALLOW_INSECURE_HTTP": "1",
            "ADLOG_AUTH_COOKIE_SECURE": "0",
            "ADLOG_TLS_CERT_PATH": "",
            "ADLOG_TLS_KEY_PATH": "",
            "ADLOG_REACT_WEB_DIR": str(resolved_react_dir),
            "ADLOG_LOG_DIR": str(ROOT / "data" / "logs"),
            "ADLOG_SERVER_RUNTIME_LOG": str(ROOT / "data" / "logs" / "http-copy-runtime.log"),
        }
    )
    return resolved_react_dir


def _runtime_identity(result: dict[str, object]) -> dict[str, object]:
    health_summary = (
        result.get("summary")
        if isinstance(result.get("summary"), dict)
        else {}
    )
    identity = result.get("runtime_identity")
    if isinstance(identity, dict):
        return identity
    nested = health_summary.get("runtime_identity")
    return nested if isinstance(nested, dict) else {}


def _write_runtime_state(
    react_dir: Path,
    result: dict[str, object],
    *,
    state_path: Path | None = None,
) -> None:
    state_path = state_path or STATE_PATH
    identity = _runtime_identity(result)
    runtime_instance_id = str(identity.get("runtime_instance_id") or "").strip()
    process_pid = int(identity.get("process_pid") or 0)
    if not runtime_instance_id or process_pid <= 0:
        raise RuntimeError("HTTP copy restart returned no stable runtime identity")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "react_dir": str(react_dir.resolve()),
        "runtime_instance_id": runtime_instance_id,
        "process_pid": process_pid,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    temporary = state_path.with_suffix(state_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.replace(temporary, state_path)


def _read_verified_runtime_state(
    identity: dict[str, object],
    *,
    state_path: Path | None = None,
) -> tuple[str | None, str]:
    state_path = state_path or STATE_PATH
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1:
            return None, "unsupported"
        if (
            str(payload.get("runtime_instance_id") or "")
            != str(identity.get("runtime_instance_id") or "")
            or int(payload.get("process_pid") or 0)
            != int(identity.get("process_pid") or 0)
        ):
            return None, "stale"
        react_dir = Path(str(payload.get("react_dir") or "")).resolve()
        if ROOT.resolve() not in (react_dir, *react_dir.parents):
            return None, "outside_project"
        if not (react_dir / "index.html").is_file():
            return None, "missing_index"
        return str(react_dir), "verified"
    except FileNotFoundError:
        return None, "missing"
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None, "invalid"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "restart", "serve"))
    parser.add_argument(
        "--react-dir",
        type=Path,
        default=ROOT / "frontend" / ".sli-v4-stage6-r28",
    )
    parser.add_argument(
        "--environment-file",
        type=Path,
        help="CurrentUser DPAPI runtime-environment profile for this candidate.",
    )
    args = parser.parse_args()

    react_dir = args.react_dir.resolve()
    url = "http://127.0.0.1:18082/api/health"
    if args.action == "serve":
        try:
            react_dir = _configure(react_dir, environment_file=args.environment_file)
            from scripts.maintenance import server_control

            listeners = server_control._listening_pids(18082)
            if listeners:
                raise RuntimeError("HTTP candidate port 18082 already has a listener")
            runtime_instance_id = uuid.uuid4().hex
            os.environ["ADLOG_RUNTIME_INSTANCE_ID"] = runtime_instance_id
            os.environ["ADLOG_BUILD_ID"] = f"serve-{runtime_instance_id[:12]}"
            _write_runtime_state(react_dir, {"runtime_identity": {
                "runtime_instance_id": runtime_instance_id,
                "process_pid": os.getpid(),
            }})
            print(json.dumps({
                "status": "serving",
                "url": url,
                "react_dir": str(react_dir),
                "process_pid": os.getpid(),
            }, ensure_ascii=False), flush=True)
            from scripts.run_server import _load_storage_route_authorization
            from server.api.http_server import run_server

            run_server(
                "127.0.0.1",
                18082,
                storage_route_authorization=_load_storage_route_authorization(),
            )
            return 0
        except Exception as exc:
            print(json.dumps({
                "status": "failed",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }, ensure_ascii=False))
            return 1
    if args.action == "status":
        from scripts.maintenance import server_control

        result = server_control.health(url)
        listeners = server_control._listening_pids(18082)
        runtime_identity = _runtime_identity(result)
        health_pid = int(runtime_identity.get("process_pid") or 0)
        port_owner_verified = (
            result.get("status") == "ok"
            and len(listeners) == 1
            and listeners[0] == health_pid
        )
        result.update(
            {
                "listening_pids": listeners,
                "identity_verified": port_owner_verified,
                "port_owner_verified": port_owner_verified,
            }
        )
        if result.get("status") == "ok" and not port_owner_verified:
            result["status"] = "failed"
            result["failure_reason"] = "http_copy_port_owner_mismatch"
    else:
        react_dir = _configure(react_dir, environment_file=args.environment_file)
        # Import only after DPAPI loading and HTTP-child credential stripping:
        # server_control owns listener/process handling for the canonical port.
        from scripts.maintenance import server_control

        legacy_listeners = server_control._listening_pids(8081)
        if legacy_listeners:
            result = {
                "status": "failed",
                "failure_reason": "legacy_http_copy_listener_present",
                "legacy_http_copy_listening_pids": legacy_listeners,
            }
        else:
            command = subprocess.list2cmdline(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "run_server.py"),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "18082",
                ]
            )
            result = server_control.restart(
                command=command,
                pattern="scripts/run_server.py",
                url=url,
                target_port=18082,
                timeout=60,
                total_timeout=90,
            )
            if result.get("status") == "ok":
                _write_runtime_state(react_dir, result)

    runtime_identity = _runtime_identity(result)
    if args.action == "status":
        reported_react_dir, react_dir_state = _read_verified_runtime_state(
            runtime_identity
        )
    else:
        reported_react_dir, react_dir_state = str(react_dir), (
            "verified" if result.get("status") == "ok" else "not_recorded"
        )
    summary = {
        "status": result.get("status"),
        "failure_reason": result.get("failure_reason"),
        "url": url,
        "react_dir": reported_react_dir,
        "react_dir_state": react_dir_state,
        "runtime_identity": runtime_identity,
        "listening_pids": result.get("listening_pids"),
        "identity_verified": result.get("identity_verified"),
        "process_tree_verified": result.get("process_tree_verified"),
        "port_owner_verified": result.get("port_owner_verified"),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
