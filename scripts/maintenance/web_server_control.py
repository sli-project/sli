from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.sli.ops.worker_supervisor_secrets import (
    HTTP_FORBIDDEN_ENVIRONMENT,
    load_supervisor_environment,
    strip_http_forbidden_environment,
)


DEFAULT_RESULT_FILE = PROJECT_ROOT / "data" / "maintenance" / "web-server-autostart.json"
HEALTH_URL = "https://127.0.0.1:8080/api/health"
TARGET_PORT = 8080
_TRUTHY = {"1", "true", "yes", "on"}
_WEB_FORBIDDEN_ENVIRONMENT = HTTP_FORBIDDEN_ENVIRONMENT


def _is_truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in _TRUTHY


def _load_runtime_environment() -> dict[str, object]:
    try:
        sealed = load_supervisor_environment(override_existing=True)
    except Exception as exc:
        return {
            "status": "failed",
            "failure_reason": "protected_environment_load_failed",
            "error_type": type(exc).__name__,
            "credential_values_exposed": False,
        }

    # Worker maintenance credentials share the sealed source profile, but the
    # HTTP process has no consumer for them.  Remove them before any server
    # modules are imported or the child runtime is launched.
    strip_http_forbidden_environment()
    os.environ.setdefault("ADLOG_AUTH_REQUIRED", "1")

    cert_path = Path(os.environ.get("ADLOG_TLS_CERT_PATH", "")).expanduser()
    key_path = Path(os.environ.get("ADLOG_TLS_KEY_PATH", "")).expanduser()
    checks = {
        "protected_environment_loaded": sealed.get("status") == "ok",
        "postgres_dsn_present": bool(os.environ.get("ADLOG_PG_DSN")),
        "postgres_backend_selected": os.environ.get("ADLOG_DB_BACKEND", "").strip().lower() == "postgres",
        "authentication_required": _is_truthy(os.environ.get("ADLOG_AUTH_REQUIRED")),
        "tls_certificate_present": bool(str(cert_path)) and cert_path.is_file(),
        "tls_private_key_present": bool(str(key_path)) and key_path.is_file(),
        "inprocess_scheduler_disabled": _is_truthy(os.environ.get("ADLOG_DISABLE_SCHEDULER")),
        "post_collection_worker_external": _is_truthy(os.environ.get("ADLOG_EXTERNAL_POST_COLLECTION_WORKER")),
        "storage_outbox_worker_external": _is_truthy(os.environ.get("ADLOG_EXTERNAL_STORAGE_V2_OUTBOX_WORKER")),
        "storage_read_mode_present": bool(os.environ.get("ADLOG_STORAGE_READ_MODE")),
        "storage_write_mode_present": bool(os.environ.get("ADLOG_STORAGE_WRITE_MODE")),
        "ui_mode_present": bool(os.environ.get("ADLOG_UI_MODE")),
        "privileged_credentials_absent": not any(
            os.environ.get(name) for name in _WEB_FORBIDDEN_ENVIRONMENT
        ),
    }
    failed_checks = sorted(name for name, passed in checks.items() if not passed)
    return {
        "status": "ok" if not failed_checks else "failed",
        "failure_reason": None if not failed_checks else "runtime_environment_invalid",
        "checks": checks,
        "failed_checks": failed_checks,
        "protected_environment_keys_loaded": sorted(
            str(name)
            for name in sealed.get("keys", [])
            if str(name) not in _WEB_FORBIDDEN_ENVIRONMENT
        ),
        "credential_values_exposed": False,
    }


def _runtime_command() -> str:
    return subprocess.list2cmdline(
        [
            str(PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"),
            str(PROJECT_ROOT / "scripts" / "run_server.py"),
            "--host",
            "127.0.0.1",
            "--port",
            str(TARGET_PORT),
        ]
    )


def _public_runtime_result(result: Mapping[str, object]) -> dict[str, object]:
    health = result.get("health") if isinstance(result.get("health"), Mapping) else {}
    runtime_identity = result.get("runtime_identity")
    if not isinstance(runtime_identity, Mapping):
        payload = health.get("payload") if isinstance(health, Mapping) else None
        runtime_identity = payload.get("runtime_identity") if isinstance(payload, Mapping) else None
    safe_health = {
        "status": health.get("status") if isinstance(health, Mapping) else None,
        "http_code": health.get("http_code") if isinstance(health, Mapping) else None,
    }
    return {
        "status": result.get("status"),
        "failure_reason": result.get("failure_reason"),
        "operation_id": result.get("operation_id"),
        "already_running": bool(result.get("already_running")),
        "started": bool(result.get("started")),
        "port": result.get("port"),
        "target_pid": result.get("target_pid"),
        "listening_pids": list(result.get("listening_pids") or []),
        "matching_runtime_pids": list(result.get("matching_runtime_pids") or []),
        "identity_verified": bool(result.get("identity_verified")),
        "process_tree_verified": bool(result.get("process_tree_verified")),
        "port_owner_verified": bool(result.get("port_owner_verified")),
        "runtime_identity": dict(runtime_identity) if isinstance(runtime_identity, Mapping) else None,
        "health": safe_health,
    }


def validate_environment() -> dict[str, object]:
    environment = _load_runtime_environment()
    return {
        "status": "validated" if environment.get("status") == "ok" else "failed",
        "action": "validate",
        "failure_reason": environment.get("failure_reason"),
        "environment": environment,
        "health_url": HEALTH_URL,
        "target_port": TARGET_PORT,
        "credential_values_exposed": False,
    }


def ensure_web_server(*, timeout: int = 60, total_timeout: float = 120.0) -> dict[str, object]:
    environment = _load_runtime_environment()
    if environment.get("status") != "ok":
        return {
            "status": "failed",
            "action": "ensure",
            "failure_reason": environment.get("failure_reason"),
            "environment": environment,
            "credential_values_exposed": False,
        }

    from scripts.maintenance import server_control

    runtime = server_control.ensure_running(
        command=_runtime_command(),
        pattern=str(PROJECT_ROOT / "scripts" / "run_server.py"),
        url=HEALTH_URL,
        timeout=timeout,
        insecure=True,
        target_port=TARGET_PORT,
        total_timeout=total_timeout,
    )
    public_runtime = _public_runtime_result(runtime)
    return {
        "status": public_runtime.get("status"),
        "action": "ensure",
        "failure_reason": public_runtime.get("failure_reason"),
        "environment": environment,
        "runtime": public_runtime,
        "credential_values_exposed": False,
    }


def _resolve_result_path(path: Path) -> Path:
    from server.sli.core.paths import DATA_DIR

    result_path = path if path.is_absolute() else PROJECT_ROOT / path
    resolved = result_path.resolve()
    if not (resolved.is_relative_to(PROJECT_ROOT) or resolved.is_relative_to(DATA_DIR.resolve())):
        raise ValueError("result file must resolve inside the project root or data directory")
    return result_path


def _write_result(path: Path, result: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary_path.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate or ensure the local SLI web runtime.")
    parser.add_argument("--result-file", type=Path, default=DEFAULT_RESULT_FILE)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("validate")
    ensure_parser = sub.add_parser("ensure")
    ensure_parser.add_argument("--timeout", type=int, default=60)
    ensure_parser.add_argument("--total-timeout", type=float, default=120.0)
    args = parser.parse_args()

    try:
        result = (
            validate_environment()
            if args.action == "validate"
            else ensure_web_server(timeout=args.timeout, total_timeout=args.total_timeout)
        )
        result_path = _resolve_result_path(args.result_file)
        _write_result(result_path, result)
    except Exception as exc:
        result = {
            "status": "failed",
            "action": args.action,
            "failure_reason": "web_server_control_failed",
            "error_type": type(exc).__name__,
            "credential_values_exposed": False,
        }
        try:
            result_path = _resolve_result_path(args.result_file)
            _write_result(result_path, result)
        except Exception:
            result_path = None

    print(
        json.dumps(
            {
                "status": result.get("status"),
                "action": result.get("action"),
                "failure_reason": result.get("failure_reason"),
                "result_file": str(result_path) if result_path is not None else None,
                "credential_values_exposed": False,
            },
            ensure_ascii=False,
        )
    )
    return 0 if result.get("status") in {"ok", "validated"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
