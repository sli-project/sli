#!/usr/bin/env python3
"""Autostart host for one isolated remote-access plugin component.

This is the sole production runtime owner for RADIUS: `worker_supervisor.py`
starts one of these per registered component
(`plugin_radius_acquisition`/`plugin_radius_session_observation`, see
`server/sli/ops/runtime_component_registry.py`), and each supervised host
process then runs its own bounded-cycle loop indefinitely (component
`interval_seconds` sleep between cycles) until stopped.

That indefinite outer loop is exactly what the RADIUS manual-control
contract (`config/stage9_radius_manual_control_v1.json`) now names this
process as: its `host_runtime` block describes this file as the sole,
long-running, supervised, autostarted runtime owner. The contract's
separate `lease` block bounds the ephemeral Postgres credential/activation
*lease* granted per cycle, not this host process's own lifetime. Every
cycle here runs in a fresh, short-lived, Job-Object-bounded child process
(`_run_bounded_cycle`) that acquires exactly one such lease and tears it
down before exiting -- `lease.activation_mode: "single_invocation_per_lease"`
describes that lease, not the supervising host. See
`docs/adr/0007-radius-manual-control-contract-host-lease-split.md` for why
the contract is shaped this way, and
`docs/adr/0001-radius-runtime-consolidation.md` for the full chain and the
history of this distinction.

There used to be a second, older continuous-worker entrypoint
(`remote_access_plugin_worker.py`) that ran the same nominal cycles inline
via a different (maintenance-module-backed) implementation. It had no live
consumer and was retired -- see the ADR above.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import site
import socket
import sys
import time
from typing import Any, Callable, Iterator
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if Path(sys.prefix).resolve() != (ROOT / ".venv").resolve():
    site.addsitedir(str(ROOT / ".venv" / "Lib" / "site-packages"))

from server.sli.ops import shutdown
from server.sli.sources.windows_plugin_job import (  # noqa: E402
    WindowsPluginJob,
    WindowsPluginJobLimits,
)
from server.sli.ops.worker_supervisor_secrets import (  # noqa: E402
    load_supervisor_environment,
)
from server.sli.sources.windows_runtime_identity import expected_collection_identity  # noqa: E402
from server.sli.sources.radius_plugin_runtime import (  # noqa: E402
    current_windows_account,
    connect_acquisition_admin,
    acquisition_worker_dsn,
    run_acquisition_cycle as run_acquisition,
    consumer_ephemeral_login,
    consumer_worker_dsn,
    run_consumer_cycle as run_consumer,
)
from server.source_packs.radius.accounting_manual_control import (  # noqa: E402
    bounded_manual_activation,
)
from server.sli.sources.plugin_runtime_heartbeat import plugin_heartbeat_path  # noqa: E402
from server.sli.sources.acquisition_mode import acquisition_disabled


PLUGIN_ID = "sli.remote-access"
PYTHON_CHILD_EXECUTABLE = str(
    Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
)
TEMP_DIR = ROOT / "data" / "tmp"
COMPONENTS: dict[str, dict[str, Any]] = {
    "radius-acquisition": {
        "runner": run_acquisition,
        "interval_seconds": 300,
        "timeout_ms": 180_000,
        "memory_bytes": 512 * 1024 * 1024,
        "cpu_percent": 50,
    },
    "radius-session-observation": {
        "runner": run_consumer,
        "interval_seconds": 30,
        "timeout_ms": 90_000,
        "memory_bytes": 256 * 1024 * 1024,
        "cpu_percent": 50,
    },
}


class RemoteAccessPluginHostError(RuntimeError):
    pass


def _validated_failure_metadata(value: dict[str, Any]) -> dict[str, str]:
    stage = str(value.get("failure_stage") or "unknown_stage")
    if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", stage) is None:
        stage = "unknown_stage"
    error_type = str(value.get("error_type") or "UnknownError")
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", error_type) is None:
        error_type = "UnknownError"
    error_code = str(value.get("error_code") or "no_code")
    if re.fullmatch(r"[a-z][a-z0-9_:.-]{0,127}", error_code) is None:
        error_code = "invalid_code"
    return {
        "failure_stage": stage,
        "error_type": error_type,
        "error_code": error_code,
    }


def _safe_host_failure_metadata(exc: Exception) -> dict[str, str]:
    if isinstance(exc, RemoteAccessPluginHostError):
        matched = re.fullmatch(
            r"plugin_component_cycle_failed:"
            r"([a-z][a-z0-9_]{0,63}):"
            r"([A-Za-z][A-Za-z0-9_]{0,63}):"
            r"([a-z][a-z0-9_:.-]{0,127})",
            str(exc),
        )
        if matched is not None:
            return _validated_failure_metadata(
                {
                    "failure_stage": matched.group(1),
                    "error_type": matched.group(2),
                    "error_code": matched.group(3),
                }
            )
    error_code = str(getattr(exc, "code", "") or "host_control_failure")
    return _validated_failure_metadata(
        {
            "failure_stage": "host_control",
            "error_type": type(exc).__name__,
            "error_code": error_code,
        }
    )


def _child_python_path() -> str:
    site_packages = ROOT / ".venv" / "Lib" / "site-packages"
    entries = (
        site_packages,
        site_packages / "win32",
        site_packages / "win32" / "lib",
    )
    if not all(path.is_dir() for path in entries):
        raise RemoteAccessPluginHostError("child_dependency_paths_missing")
    return os.pathsep.join(str(path.resolve()) for path in entries)


def _result_path(component_id: str) -> Path:
    token = component_id.replace("radius-", "").replace("-", "_")
    return TEMP_DIR / f"plugin-cycle-{token}-{os.getpid()}-{uuid4().hex}.json"


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _safe_cycle_result(component_id: str, value: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        key: value.get(key)
        for key in (
            "status", "records", "claimed", "processed", "evidence_rows",
            "observation_rows", "outbox_rows", "cursor_revision_before",
            "cursor_revision_after",
        )
        if key in value
    }
    return {
        "status": "passed",
        "component_id": component_id,
        "worker_result": allowed,
        "contains_secret_material": False,
    }


def _child_plugin_dsn() -> str:
    prohibited = sorted(
        name for name in (
            "ADLOG_PG_DSN", "ADLOG_PG_ADMIN_USER", "ADLOG_PG_ADMIN_PASSWORD",
        )
        if str(os.environ.get(name) or "").strip()
    )
    if prohibited:
        raise RemoteAccessPluginHostError(
            "admin_database_environment_reached_plugin_child"
        )
    dsn = str(os.environ.get("SLI_PLUGIN_PG_DSN") or "").strip()
    if not dsn:
        raise RemoteAccessPluginHostError("plugin_child_dsn_missing")
    return dsn


def _child_environment(plugin_dsn: str, *, component_id: str | None = None) -> dict[str, str]:
    expected_account, expected_sid = expected_collection_identity()
    if not expected_account or not expected_sid:
        raise RemoteAccessPluginHostError("plugin_child_identity_missing")
    expected_domain, _separator, expected_username = expected_account.partition("\\")
    powershell_dir = (
        Path(os.environ.get("SystemRoot", r"C:\Windows"))
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
    ).resolve(strict=True)
    environment = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONPATH": _child_python_path(),
        "PATH": str(powershell_dir),
        "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
        "WINDIR": os.environ.get("WINDIR", r"C:\Windows"),
        "TEMP": os.environ.get("TEMP", str(TEMP_DIR)),
        "TMP": os.environ.get("TMP", str(TEMP_DIR)),
        "SLI_PLUGIN_PG_DSN": plugin_dsn,
        "ADLOG_COLLECTION_PRINCIPAL": expected_account,
        "ADLOG_COLLECTION_PRINCIPAL_SID": expected_sid,
        "USERNAME": expected_username,
        "USERDOMAIN": expected_domain,
    }
    if component_id == "radius-acquisition":
        from server.sli.sources.vpn_source_auth import (
            VPN_SOURCE_CREDENTIAL_MODE_ENV, validate_vpn_source_credential_mode,
        )
        environment[VPN_SOURCE_CREDENTIAL_MODE_ENV] = validate_vpn_source_credential_mode(
            os.environ.get(VPN_SOURCE_CREDENTIAL_MODE_ENV, "process")
        )
    return environment


@contextmanager
def _component_worker_dsn(component_id: str) -> Iterator[str]:
    """Core-owned broker materializes one short-lived component login.

    For radius-acquisition, the caller must hold bounded_manual_activation
    active while the worker process runs, so the temporary login is not
    revoked mid-execution. See _run_bounded_cycle for usage.
    """
    if component_id == "radius-acquisition":
        # For radius-acquisition, the activation lease is held by the caller
        # to prevent the temporary login from being revoked while the child
        # process runs. See _run_bounded_cycle.
        raise RemoteAccessPluginHostError(
            "radius_acquisition_requires_held_lease"
        )
    if component_id == "radius-session-observation":
        with consumer_ephemeral_login() as (role, password):
            yield consumer_worker_dsn(role, password)
        return
    raise RemoteAccessPluginHostError("plugin_component_unknown")


def run_cycle_child(component_id: str, output: Path) -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    target = output.resolve()
    if target.parent != TEMP_DIR.resolve() or not target.name.startswith(
        "plugin-cycle-"
    ):
        raise RemoteAccessPluginHostError("cycle_result_path_invalid")
    failure_stage = "child_environment"
    try:
        _child_plugin_dsn()
        failure_stage = "identity"
        expected_account, _expected_sid = expected_collection_identity()
        if not expected_account or current_windows_account().casefold() != expected_account.casefold():
            raise PermissionError("current_windows_account_is_not_approved_owner")
        runner: Callable[[], dict[str, Any]] = COMPONENTS[component_id]["runner"]
        failure_stage = "component_runner"
        value = runner()
        failure_stage = "result_validation"
        accepted = (
            {"committed", "no_new_complete_records"}
            if component_id == "radius-acquisition"
            else {"completed"}
        )
        if value.get("status") not in accepted:
            raise RemoteAccessPluginHostError("component_cycle_result_invalid")
        safe = _safe_cycle_result(component_id, value)
        _atomic_json(target, safe)
        return 0
    except Exception as exc:
        error_code = str(getattr(exc, "code", ""))[:128]
        if isinstance(exc, OSError) and isinstance(exc.errno, int):
            error_code = f"os_error:{exc.errno}"
        _atomic_json(
            target,
            {
                "status": "failed",
                "component_id": component_id,
                "failure_stage": failure_stage,
                "error_type": type(exc).__name__,
                "error_code": error_code,
                "contains_secret_material": False,
            },
        )
        return 1


def _run_bounded_cycle_with_dsn(
    component_id: str,
    plugin_dsn: str,
) -> dict[str, Any]:
    profile = COMPONENTS[component_id]
    result_path = _result_path(component_id)
    if result_path.exists():
        raise RemoteAccessPluginHostError("stale_cycle_result_exists")
    limits = WindowsPluginJobLimits(
        active_processes=2,
        process_memory_bytes=int(profile["memory_bytes"]),
        kill_on_job_close=True,
        cpu_hard_limit=int(profile["cpu_percent"]),
    )
    job = WindowsPluginJob(limits)
    child = None
    try:
        child = job.start(
            [
                PYTHON_CHILD_EXECUTABLE,
                str(Path(__file__).resolve()),
                "--cycle-child",
                "--component",
                component_id,
                "--cycle-result",
                str(result_path),
            ],
            cwd=ROOT,
            environment=_child_environment(plugin_dsn, component_id=component_id),
        )
        assigned = job.status()
        if not child.wait(int(profile["timeout_ms"])):
            raise TimeoutError("plugin_component_cycle_timeout")
        exit_code = child.exit_code()
        completed = job.status()
        value = json.loads(result_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("contains_secret_material") is not False:
            raise RemoteAccessPluginHostError("cycle_result_invalid")
        if exit_code != 0 or value.get("status") != "passed":
            stage = str(value.get("failure_stage") or "unknown_stage")
            if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", stage) is None:
                stage = "unknown_stage"
            error_type = str(value.get("error_type") or "UnknownError")
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", error_type) is None:
                error_type = "UnknownError"
            error_code = str(value.get("error_code") or "no_code")
            if re.fullmatch(r"[a-z][a-z0-9_:.-]{0,127}", error_code) is None:
                error_code = "invalid_code"
            raise RemoteAccessPluginHostError(
                "plugin_component_cycle_failed:"
                f"{stage}:{error_type}:{error_code}"
            )
        return {
            **value,
            "job": {
                "assigned": assigned,
                "completed": completed,
            },
        }
    finally:
        job.close_job()
        job.close_child_handles()
        if result_path.exists():
            result_path.unlink()


def _run_bounded_cycle(component_id: str) -> dict[str, Any]:
    """Run one bounded cycle for a component.

    For radius-acquisition, this function holds bounded_manual_activation
    active during the entire child process execution, ensuring the
    temporary login is not revoked mid-execution. The lease is released
    after the child process completes.
    """
    if component_id == "radius-acquisition":
        with connect_acquisition_admin() as admin:
            with bounded_manual_activation(admin) as lease:
                plugin_dsn = acquisition_worker_dsn(lease)
                result = _run_bounded_cycle_with_dsn(component_id, plugin_dsn)
        return {**result, "credential_lease_released": True}
    # For other components, use the standard _component_worker_dsn context manager
    with _component_worker_dsn(component_id) as plugin_dsn:
        result = _run_bounded_cycle_with_dsn(component_id, plugin_dsn)
    return {**result, "credential_lease_released": True}


def _plugin_enabled(dsn: str, component_id: str) -> bool:
    import psycopg

    with psycopg.connect(
        dsn,
        autocommit=True,
        connect_timeout=5,
        application_name=f"sli_plugin_host_state_{component_id}",
        options="-c statement_timeout=10000 -c lock_timeout=5000",
    ) as conn, conn.cursor() as cur:
        if component_id == "radius-session-observation":
            cur.execute("select finish_remote_access_plugin_drain_v1()")
        cur.execute(
            """
            select desired_activation,component_runtime,admission_mode
            from read_plugin_component_runtime_guard_v1(%s,%s)
            """,
            (PLUGIN_ID, component_id),
        )
        row = cur.fetchone()
    if not row:
        return False
    if tuple(row) == ("enabled_manual", "running", "open"):
        return True
    return bool(
        component_id == "radius-session-observation"
        and tuple(row) == ("disabled", "draining", "drain_only")
    )


def _record_cycle_observation(dsn: str, component_id: str, result: dict[str, Any]) -> None:
    import psycopg

    from server.sli.sources.plugin_state import remote_access_configured

    received = component_id == "radius-acquisition" and int(
        (result.get("worker_result") or {}).get("outbox_rows") or 0
    ) > 0
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5,
        options="-c statement_timeout=10000 -c lock_timeout=5000") as conn, conn.cursor() as cur:
        cur.execute("select observe_remote_access_plugin_v1(%s,%s)", (remote_access_configured(), received))


def _write_heartbeat(
    component_id: str,
    *,
    status: str,
    phase: str,
    interval_seconds: int,
    result: dict[str, Any] | None = None,
    failure: dict[str, Any] | None = None,
) -> None:
    job = dict((result or {}).get("job") or {}).get("completed") or {}
    last_result = None
    if failure is not None:
        last_result = {
            "status": "failed",
            **_validated_failure_metadata(failure),
        }
    elif result is not None:
        last_result = {
            "status": result.get("status"),
            "worker_result": result.get("worker_result"),
            "peak_process_memory_bytes": job.get(
                "peak_process_memory_bytes"
            ),
            "peak_job_memory_bytes": job.get("peak_job_memory_bytes"),
        }
    _atomic_json(
        plugin_heartbeat_path(component_id),
        {
            "schema_version": 1,
            "plugin_id": PLUGIN_ID,
            "component_id": component_id,
            "worker_instance_id": (
                f"{component_id}-{socket.gethostname().lower()}-{os.getpid()}"
            ),
            "process_pid": os.getpid(),
            "status": status,
            "phase": phase,
            "expected_interval_seconds": interval_seconds,
            "heartbeat_at_utc": datetime.now(timezone.utc).isoformat(),
            "last_result": last_result,
            "contains_secret_material": False,
        },
    )


def run_host(component_id: str, *, once: bool = False) -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from server.sli.core.job_executor import pilot_enabled

    if pilot_enabled():
        _write_heartbeat(component_id, status="idle", phase="core_executor_pilot",
                         interval_seconds=int(COMPONENTS[component_id]["interval_seconds"]))
        return 0
    # The Windows host uses DPAPI, identity checks and Job Objects even for
    # observation. Keep it live but inactive when acquisition is disabled.
    if acquisition_disabled():
        interval = int(COMPONENTS[component_id]["interval_seconds"])
        while not shutdown.requested():
            _write_heartbeat(
                component_id, status="idle", phase="acquisition_disabled",
                interval_seconds=interval,
            )
            if once:
                return 0
            shutdown.wait(interval, sleep=time.sleep)
        return 0
    load_supervisor_environment()
    expected_account, _expected_sid = expected_collection_identity()
    if not expected_account or current_windows_account().casefold() != expected_account.casefold():
        raise PermissionError("current_windows_account_is_not_approved_owner")
    dsn = os.environ.get("ADLOG_PG_DSN", "")
    if not dsn:
        raise RemoteAccessPluginHostError("core_broker_dsn_missing")
    import psycopg

    lock_name = f"sli.remote-access:{component_id}:host:v1"
    interval = int(COMPONENTS[component_id]["interval_seconds"])
    with psycopg.connect(
        dsn,
        autocommit=True,
        connect_timeout=5,
        application_name=f"sli_plugin_host_lock_{component_id}",
        options="-c statement_timeout=10000 -c lock_timeout=5000",
    ) as lock_conn, lock_conn.cursor() as lock_cur:
        lock_cur.execute("select pg_try_advisory_lock(hashtext(%s))", (lock_name,))
        if not bool(lock_cur.fetchone()[0]):
            raise RemoteAccessPluginHostError("component_host_already_running")
        try:
            while not shutdown.requested() and _plugin_enabled(dsn, component_id):
                _write_heartbeat(
                    component_id,
                    status="running",
                    phase="cycle",
                    interval_seconds=interval,
                )
                try:
                    result = _run_bounded_cycle(component_id)
                    _record_cycle_observation(dsn, component_id, result)
                except Exception as exc:
                    _write_heartbeat(
                        component_id,
                        status="blocked",
                        phase="cycle_failed",
                        interval_seconds=interval,
                        failure=_safe_host_failure_metadata(exc),
                    )
                    raise
                _write_heartbeat(
                    component_id,
                    status="idle",
                    phase="sleep",
                    interval_seconds=interval,
                    result=result,
                )
                if once:
                    return 0
                shutdown.wait(interval, sleep=time.sleep)
        finally:
            lock_cur.execute(
                "select pg_advisory_unlock(hashtext(%s))", (lock_name,)
            )
    _write_heartbeat(
        component_id,
        status="stopped",
        phase="disabled",
        interval_seconds=interval,
    )
    return 0


def contract_self_check() -> dict[str, Any]:
    return {
        "status": "contract_valid",
        "plugin_id": PLUGIN_ID,
        "components": sorted(COMPONENTS),
        "base_python": PYTHON_CHILD_EXECUTABLE,
        "job_active_processes": 2,
        "component_advisory_lock": True,
        "ephemeral_login_per_cycle": True,
        "credential_materialized_only_to_bounded_child": True,
        "admin_environment_present_only_in_core_host": True,
        "admin_environment_passed_to_handler": False,
        "source_contacted": False,
        "database_accessed": False,
        "process_started": False,
    }


def main() -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=sorted(COMPONENTS))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--contract-self-check", action="store_true")
    parser.add_argument("--cycle-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--cycle-result", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.contract_self_check:
        print(json.dumps(contract_self_check(), ensure_ascii=False))
        return 0
    if args.component is None:
        raise RemoteAccessPluginHostError("component_required")
    if args.cycle_child:
        if args.cycle_result is None:
            raise RemoteAccessPluginHostError("cycle_result_required")
        return run_cycle_child(args.component, args.cycle_result)
    return run_host(args.component, once=bool(args.once))


if __name__ == "__main__":
    raise SystemExit(main())
