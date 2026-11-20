#!/usr/bin/env python3
"""Conservative local server control with verified Windows process handling."""

from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import io
import ipaddress
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
import urllib.request
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.maintenance.bundle_common import PROJECT_ROOT, audit_action, timestamp  # noqa: E402
from server.sli.ops.tls_client import tls_context_for_url  # noqa: E402

_TLS_CONFIGURED = bool(os.environ.get("ADLOG_TLS_CERT_PATH", "").strip() and os.environ.get("ADLOG_TLS_KEY_PATH", "").strip())
DEFAULT_HEALTH_URL = os.environ.get(
    "ADLOG_SERVER_HEALTH_URL",
    f"{'https' if _TLS_CONFIGURED else 'http'}://127.0.0.1:8080/api/health",
)
DEFAULT_START_COMMAND = os.environ.get(
    "ADLOG_SERVER_START_COMMAND",
    subprocess.list2cmdline(
        [
            str(PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"),
            str(PROJECT_ROOT / "scripts" / "run_server.py"),
            "--host",
            "127.0.0.1",
            "--port",
            "8080",
        ]
    ),
)
DEFAULT_PROCESS_MATCH = os.environ.get("ADLOG_SERVER_PROCESS_MATCH", "scripts/run_server.py")
STATUS_TAIL_CHARS = int(os.environ.get("ADLOG_SERVER_STATUS_TAIL_CHARS", "12000"))
EARLY_EXIT_GRACE_SECONDS = float(os.environ.get("ADLOG_SERVER_EARLY_EXIT_GRACE_SECONDS", "2.0"))
STOP_VERIFY_SECONDS = float(os.environ.get("ADLOG_SERVER_STOP_VERIFY_SECONDS", "12"))
SUBPROCESS_TIMEOUT_SECONDS = float(os.environ.get("ADLOG_SERVER_SUBPROCESS_TIMEOUT_SECONDS", "10"))
# Failed-start safety cleanup has a separate 15-second caller-budget allowance.
FAILED_START_CLEANUP_SECONDS = 15.0
DEFAULT_TOTAL_TIMEOUT_SECONDS = float(os.environ.get("ADLOG_SERVER_TOTAL_TIMEOUT_SECONDS", "90"))


class OperationDeadlineExceeded(RuntimeError):
    """Raised when a runtime-control operation exhausts its total budget."""


class OperationDeadline:
    def __init__(self, seconds: float):
        self.started_at = time.monotonic()
        self.ends_at = self.started_at + max(0.1, float(seconds))

    def remaining(self, *, cap: float | None = None, stage: str = "operation") -> float:
        remaining = self.ends_at - time.monotonic()
        if remaining <= 0:
            raise OperationDeadlineExceeded(f"total runtime-control deadline exceeded during {stage}")
        if cap is not None:
            remaining = min(remaining, max(0.1, float(cap)))
        return max(0.1, remaining)


def _subprocess_timeout(deadline: OperationDeadline | None, *, stage: str) -> float:
    if deadline is None:
        return max(0.1, SUBPROCESS_TIMEOUT_SECONDS)
    return deadline.remaining(cap=SUBPROCESS_TIMEOUT_SECONDS, stage=stage)


_WINDOWS_WAIT_OBJECT_0 = 0x00000000
_WINDOWS_WAIT_ABANDONED = 0x00000080
_WINDOWS_WAIT_TIMEOUT = 0x00000102
_WINDOWS_WAIT_FAILED = 0xFFFFFFFF


def _ensure_mutex_name(target_port: int) -> str:
    """Return a deterministic Windows mutex name for one project listener."""

    project_key = str(PROJECT_ROOT.resolve()).replace("\\", "/").casefold()
    digest = hashlib.sha256(f"{project_key}|{int(target_port)}".encode("utf-8")).hexdigest()
    return f"Local\\SLIWebServerEnsure-{digest[:32]}"


@contextmanager
def _ensure_critical_section(target_port: int, deadline: OperationDeadline):
    """Serialize an ensure precheck and launch for one Windows project port."""

    if os.name != "nt":
        yield
        return

    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_mutex = kernel32.CreateMutexW
    create_mutex.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    create_mutex.restype = wintypes.HANDLE
    wait_for_single_object = kernel32.WaitForSingleObject
    wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    wait_for_single_object.restype = wintypes.DWORD
    release_mutex = kernel32.ReleaseMutex
    release_mutex.argtypes = [wintypes.HANDLE]
    release_mutex.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = create_mutex(None, False, _ensure_mutex_name(target_port))
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateMutexW failed for server ensure")

    acquired = False
    try:
        wait_timeout_ms = max(
            1,
            min(
                _WINDOWS_WAIT_FAILED - 1,
                int(deadline.remaining(stage="ensure mutex acquisition") * 1000),
            ),
        )
        wait_result = int(wait_for_single_object(handle, wait_timeout_ms))
        if wait_result == _WINDOWS_WAIT_TIMEOUT:
            raise OperationDeadlineExceeded(
                "total runtime-control deadline exceeded during ensure mutex acquisition"
            )
        if wait_result == _WINDOWS_WAIT_FAILED:
            raise OSError(ctypes.get_last_error(), "WaitForSingleObject failed for server ensure")
        if wait_result not in {_WINDOWS_WAIT_OBJECT_0, _WINDOWS_WAIT_ABANDONED}:
            raise RuntimeError(f"unexpected ensure mutex wait result: {wait_result}")
        # An abandoned mutex transfers ownership after a crashed launcher; the
        # bounded verification below re-establishes the listener contract.
        acquired = True
        yield
    finally:
        release_error: OSError | None = None
        if acquired and not release_mutex(handle):
            release_error = OSError(ctypes.get_last_error(), "ReleaseMutex failed for server ensure")
        close_handle(handle)
        if release_error is not None:
            raise release_error


def _normalize_command_text(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").replace("\\", "/").strip()).casefold()


def _runtime_identity(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    identity = payload.get("runtime_identity")
    if isinstance(identity, dict):
        return identity
    runtime = payload.get("runtime")
    if isinstance(runtime, dict) and isinstance(runtime.get("identity"), dict):
        return dict(runtime["identity"])
    return {}


def _summarize_health_body(body: str) -> dict[str, object]:
    summary: dict[str, object] = {"body_length": len(body)}
    try:
        payload = json.loads(body)
    except Exception:
        summary["body_tail"] = body[-500:]
        return summary
    if isinstance(payload, dict):
        for key in ("status", "system_status", "version", "project_version"):
            if key in payload:
                summary[key] = payload.get(key)
        identity = _runtime_identity(payload)
        if identity:
            summary["runtime_identity"] = identity
        collectors = payload.get("collectors") or payload.get("collector_state") or payload.get("channels")
        if isinstance(collectors, list):
            summary["items_count"] = len(collectors)
            warning_items = sum(
                1 for item in collectors
                if isinstance(item, dict) and str(item.get("status", "")).lower() in {"warn", "warning", "failed", "error"}
            )
            if warning_items:
                summary["warning_items"] = warning_items
        elif isinstance(collectors, dict):
            summary["items_count"] = len(collectors)
    else:
        summary["json_type"] = type(payload).__name__
    return summary


def _health_probe(
    url: str = DEFAULT_HEALTH_URL,
    timeout: int | float = 5,
    *,
    insecure: bool = False,
    deadline: OperationDeadline | None = None,
) -> dict[str, object]:
    try:
        request_timeout = (
            deadline.remaining(cap=float(timeout), stage="health probe")
            if deadline is not None
            else max(0.1, float(timeout))
        )
        context = tls_context_for_url(url, insecure=insecure)
        with urllib.request.urlopen(url, timeout=request_timeout, context=context) as response:
            body = response.read().decode("utf-8", errors="replace")
            try:
                payload: object = json.loads(body)
            except Exception:
                payload = None
            return {
                "status": "ok",
                "url": url,
                "code": response.status,
                "summary": _summarize_health_body(body),
                "payload": payload,
            }
    except Exception as exc:
        return {"status": "failed", "url": url, "error_type": type(exc).__name__, "error": str(exc)}


def _compact_health(result: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in result.items() if key != "payload"}


def health(url: str = DEFAULT_HEALTH_URL, timeout: int = 5, *, insecure: bool = False) -> dict[str, object]:
    """Return bounded health evidence without copying the complete API payload."""

    return _compact_health(_health_probe(url, timeout, insecure=insecure))


def _parse_wmic_csv(text: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff\r\n")))
    for item in reader:
        lowered = {str(key or "").strip().casefold(): value for key, value in item.items()}
        pid = str(lowered.get("processid") or "").strip()
        if not pid.isdigit():
            continue
        rows.append({
            "pid": pid,
            "parent_pid": str(lowered.get("parentprocessid") or "").strip(),
            "cmd": str(lowered.get("commandline") or "").strip(),
            "inventory_source": "wmic",
        })
    return rows


def _parse_cim_json(text: str) -> list[dict[str, object]]:
    raw = text.strip().lstrip("\ufeff")
    if not raw:
        return []
    payload = json.loads(raw)
    items = payload if isinstance(payload, list) else [payload]
    rows: list[dict[str, object]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        pid = item.get("ProcessId") if "ProcessId" in item else item.get("processid")
        if pid is None:
            continue
        rows.append({
            "pid": str(pid),
            "parent_pid": str(item.get("ParentProcessId") if "ParentProcessId" in item else item.get("parentprocessid") or ""),
            "cmd": str(item.get("CommandLine") if "CommandLine" in item else item.get("commandline") or ""),
            "inventory_source": "powershell_cim",
        })
    return rows


def _windows_processes_via_cim(deadline: OperationDeadline | None = None) -> list[dict[str, object]]:
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,ParentProcessId,CommandLine | "
        "ConvertTo-Json -Compress"
    )
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        errors="replace",
        capture_output=True,
        timeout=_subprocess_timeout(deadline, stage="PowerShell CIM process inventory"),
    )
    if proc.returncode != 0:
        raise RuntimeError(f"PowerShell CIM process inventory failed with exit code {proc.returncode}: {proc.stderr[-500:]}")
    return _parse_cim_json(proc.stdout)


def _list_processes(deadline: OperationDeadline | None = None) -> list[dict[str, object]]:
    if os.name == "nt":
        try:
            proc = subprocess.run(
                ["wmic", "process", "get", "ProcessId,ParentProcessId,CommandLine", "/FORMAT:CSV"],
                text=True,
                errors="replace",
                capture_output=True,
                timeout=_subprocess_timeout(deadline, stage="WMIC process inventory"),
            )
        except (FileNotFoundError, OSError):
            return _windows_processes_via_cim(deadline)
        if proc.returncode == 0:
            rows = _parse_wmic_csv(proc.stdout)
            if rows:
                return rows
        return _windows_processes_via_cim(deadline)
    proc = subprocess.run(
        ["ps", "-eo", "pid=,ppid=,args="],
        text=True,
        capture_output=True,
        timeout=_subprocess_timeout(deadline, stage="POSIX process inventory"),
    )
    rows = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        rows.append({
            "pid": parts[0],
            "parent_pid": parts[1],
            "cmd": parts[2] if len(parts) > 2 else "",
            "inventory_source": "ps",
        })
    return rows


def matching_processes(
    pattern: str = DEFAULT_PROCESS_MATCH,
    *,
    deadline: OperationDeadline | None = None,
) -> list[dict[str, object]]:
    this_pid = str(os.getpid())
    normalized_pattern = _normalize_command_text(pattern)
    if not normalized_pattern:
        return []
    rows = _list_processes(deadline) if deadline is not None else _list_processes()
    return [
        row for row in rows
        if normalized_pattern in _normalize_command_text(row.get("cmd")) and str(row.get("pid", "")) != this_pid
    ]


def _extract_port(url: str) -> int | None:
    parsed = urlparse(url)
    if parsed.port:
        return int(parsed.port)
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def _parse_json_scalar_or_list(text: str) -> list[int]:
    raw = text.strip().lstrip("\ufeff")
    if not raw:
        return []
    payload = json.loads(raw)
    items = payload if isinstance(payload, list) else [payload]
    result: list[int] = []
    for value in items:
        try:
            result.append(int(value))
        except (TypeError, ValueError):
            continue
    return sorted(set(result))


def _listener_endpoint_port(endpoint: str) -> int:
    """Validate numeric/wildcard TCP local endpoints before port filtering."""
    host, separator, port = endpoint.rpartition(":")
    if not separator or not port.isdigit() or not 0 < int(port) <= 65535:
        raise RuntimeError("POSIX listener ownership unavailable: malformed local endpoint")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host != "*":
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise RuntimeError("POSIX listener ownership unavailable: malformed local endpoint") from exc
    return int(port)


def _listening_pids(port: int | None, deadline: OperationDeadline | None = None) -> list[int]:
    if not port:
        return []
    if os.name == "nt":
        script = (
            "$ErrorActionPreference = 'Stop'; "
            f"@(Get-NetTCPConnection -State Listen -LocalPort {int(port)} -ErrorAction Stop | "
            "Select-Object -ExpandProperty OwningProcess | Sort-Object -Unique) | ConvertTo-Json -Compress"
        )
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                text=True,
                errors="replace",
                capture_output=True,
                timeout=_subprocess_timeout(deadline, stage=f"listener inventory for port {port}"),
            )
            if proc.returncode == 0:
                return _parse_json_scalar_or_list(proc.stdout)
        except (OperationDeadlineExceeded, subprocess.TimeoutExpired):
            raise
        except Exception:
            pass
        try:
            proc = subprocess.run(
                ["netstat", "-ano", "-p", "tcp"],
                text=True,
                errors="replace",
                capture_output=True,
                timeout=_subprocess_timeout(deadline, stage=f"netstat listener inventory for port {port}"),
            )
        except (OperationDeadlineExceeded, subprocess.TimeoutExpired):
            raise
        except Exception:
            return []
        if proc.returncode != 0:
            raise RuntimeError(f"netstat listener inventory failed with exit code {proc.returncode}: {proc.stderr[-500:]}")
        pids: set[int] = set()
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[0].upper() != "TCP" or parts[3].upper() != "LISTENING":
                continue
            local = parts[1]
            if local.rsplit(":", 1)[-1] != str(port):
                continue
            try:
                pids.add(int(parts[-1]))
            except ValueError:
                pass
        return sorted(pids)
    # Filter in the tool and again in its output. Missing ownership visibility
    # is unknown, never evidence that the target port is free.
    commands = (
        ["ss", "-H", "-ltnp", "sport", "=", f":{port}"],
        ["lsof", "-nP", "-a", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fpfn"],
    )
    for command in commands:
        try:
            proc = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=_subprocess_timeout(deadline, stage=f"POSIX listener inventory for port {port}"),
            )
        except (OperationDeadlineExceeded, subprocess.TimeoutExpired):
            raise
        except OSError:
            continue
        if proc.returncode != 0:
            # lsof documents exit 1 for an empty selection. Diagnostic output
            # must not be mistaken for that normal empty case.
            if command[0] == "lsof" and proc.returncode == 1 and not proc.stdout.strip() and not proc.stderr.strip():
                return []
            continue
        pids: set[int] = set()
        if command[0] == "ss":
            for line in proc.stdout.splitlines():
                parts = line.split()
                if not parts:
                    continue
                if len(parts) < 5 or parts[0] != "LISTEN":
                    raise RuntimeError("POSIX listener ownership unavailable: malformed ss output")
                if _listener_endpoint_port(parts[3]) != port:
                    continue
                owners = {int(pid) for pid in re.findall(r"pid=(\d+)", line) if int(pid) > 0}
                if not owners:
                    raise RuntimeError("POSIX listener ownership unavailable for target port")
                pids.update(owners)
        else:
            current_pid: int | None = None
            process_has_file = False
            file_started = False
            file_has_name = False

            def require_complete_record(pid: int | None, has_file: bool, started: bool, has_name: bool) -> None:
                if (pid is not None and not has_file) or (started and not has_name):
                    raise RuntimeError("POSIX listener ownership unavailable: incomplete lsof record")

            for line in proc.stdout.splitlines():
                if line.startswith("p") and line[1:].isdigit() and int(line[1:]) > 0:
                    require_complete_record(current_pid, process_has_file, file_started, file_has_name)
                    current_pid = int(line[1:])
                    process_has_file = False
                    file_started = False
                    file_has_name = False
                elif line.startswith("f") and line[1:].isdigit():
                    if current_pid is None or (file_started and not file_has_name):
                        raise RuntimeError("POSIX listener ownership unavailable: incomplete lsof file")
                    process_has_file = True
                    file_started = True
                    file_has_name = False
                elif line.startswith("n"):
                    if not file_started or file_has_name:
                        raise RuntimeError("POSIX listener ownership unavailable: missing lsof file descriptor")
                    endpoint = line[1:]
                    if endpoint.endswith(" (LISTEN)"):
                        endpoint = endpoint.removesuffix(" (LISTEN)")
                    endpoint_port = _listener_endpoint_port(endpoint)
                    file_has_name = True
                    if endpoint_port == port:
                        pids.add(current_pid)
                elif line.strip():
                    raise RuntimeError("POSIX listener ownership unavailable: malformed lsof output")
            require_complete_record(current_pid, process_has_file, file_started, file_has_name)
        return sorted(pids)
    raise RuntimeError("POSIX listener ownership unavailable: no successful inventory")


def _terminate_pid_tree(pid: int, deadline: OperationDeadline | None = None) -> dict[str, object]:
    try:
        if os.name == "nt":
            proc = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=_subprocess_timeout(deadline, stage=f"terminate PID {pid}"),
            )
            return {"pid": pid, "exit_code": proc.returncode, "stdout_tail": proc.stdout[-500:], "stderr_tail": proc.stderr[-500:]}
        os.kill(pid, signal.SIGTERM)
        return {"pid": pid, "exit_code": 0}
    except Exception as exc:
        return {"pid": pid, "error_type": type(exc).__name__, "error": str(exc)}


def _command_targets_project_runtime(command: object, target_port: int) -> bool:
    normalized = _normalize_command_text(command)
    expected_script = _normalize_command_text(PROJECT_ROOT / "scripts" / "run_server.py")
    expected_python = _normalize_command_text(
        PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"
    )
    absolute_script_pattern = (
        rf'(?:^|[\s"\']){re.escape(expected_script)}(?:$|[\s"\'])'
    )
    # A previously accepted launcher used the project-relative script path.
    # That form is still unambiguous when and only when the executable is the
    # exact Python from this project's .venv.  A generic/foreign Python with a
    # relative script must remain rejected.
    project_python_pattern = (
        rf'(?:^|[\s"\']){re.escape(expected_python)}(?:$|[\s"\'])'
    )
    relative_script_pattern = (
        r'(?:^|[\s"\'])scripts/run_server\.py(?:$|[\s"\'])'
    )
    port_pattern = rf'(?:^|\s)--port(?:\s+|=)["\']?{int(target_port)}(?:["\']?(?:\s|$))'
    script_matches = bool(
        re.search(absolute_script_pattern, normalized)
        or (
            re.search(project_python_pattern, normalized)
            and re.search(relative_script_pattern, normalized)
        )
    )
    return bool(script_matches and re.search(port_pattern, normalized))


def _verified_destructive_target(
    *,
    target_port: int,
    url: str,
    insecure: bool,
    deadline: OperationDeadline,
) -> dict[str, object]:
    listeners = _listening_pids(target_port, deadline)
    if not listeners:
        return {"status": "absent", "target_port": target_port, "listening_pids": []}
    if len(listeners) != 1:
        return {
            "status": "failed",
            "target_port": target_port,
            "listening_pids": listeners,
            "failure_reason": "target_port_has_multiple_owners",
        }

    target_pid = listeners[0]
    process_rows = _list_processes(deadline)
    target_rows = [row for row in process_rows if str(row.get("pid") or "") == str(target_pid)]
    if len(target_rows) != 1:
        return {
            "status": "failed",
            "target_port": target_port,
            "listening_pids": listeners,
            "failure_reason": "target_listener_process_identity_unavailable",
        }
    target_row = target_rows[0]
    if not _command_targets_project_runtime(target_row.get("cmd"), target_port):
        return {
            "status": "failed",
            "target_port": target_port,
            "listening_pids": listeners,
            "target_process": target_row,
            "failure_reason": "target_listener_command_mismatch",
        }

    probe = _health_probe(url, 5, insecure=insecure, deadline=deadline)
    identity = _runtime_identity(probe.get("payload"))
    health_pid = int(identity.get("process_pid") or 0) if str(identity.get("process_pid") or "").isdigit() else 0
    if probe.get("status") != "ok" or health_pid != target_pid:
        return {
            "status": "failed",
            "target_port": target_port,
            "listening_pids": listeners,
            "target_process": target_row,
            "health": _compact_health(probe),
            "runtime_identity": identity,
            "failure_reason": "target_health_identity_mismatch",
        }
    return {
        "status": "verified",
        "target_port": target_port,
        "listening_pids": listeners,
        "target_pid": target_pid,
        "target_process": target_row,
        "health": _compact_health(probe),
        "runtime_identity": identity,
    }


def stop(
    pattern: str = DEFAULT_PROCESS_MATCH,
    *,
    dry_run: bool = False,
    target_port: int | None = None,
    url: str = DEFAULT_HEALTH_URL,
    insecure: bool = False,
    deadline: OperationDeadline | None = None,
) -> dict[str, object]:
    """Stop only the verified SLI runtime that owns the requested port.

    ``pattern`` remains in the API for compatibility and diagnostics, but it is
    deliberately not a destructive authorization boundary.
    """

    operation_deadline = deadline or OperationDeadline(DEFAULT_TOTAL_TIMEOUT_SECONDS)
    port = int(target_port or _extract_port(url) or 0)
    if not port:
        return {"status": "failed", "failure_reason": "target_port_required"}
    try:
        target = _verified_destructive_target(
            target_port=port,
            url=url,
            insecure=insecure,
            deadline=operation_deadline,
        )
        if target.get("status") == "failed":
            return {
                "status": "failed",
                "target": target,
                "failure_reason": str(target.get("failure_reason") or "target_verification_failed"),
            }
        if target.get("status") == "absent":
            return {
                "status": "dry_run" if dry_run else "ok",
                "target": target,
                "matched": [],
                "root_matches": [],
                "stopped": [],
                "remaining": [],
            }
        if dry_run:
            return {
                "status": "dry_run",
                "target": target,
                "matched": [target["target_process"]],
                "root_matches": [target["target_process"]],
                "stopped": [],
                "remaining": [target["target_process"]],
            }

        target_pid = int(target["target_pid"])
        stopped = [_terminate_pid_tree(target_pid, operation_deadline)]
        remaining_pids = _listening_pids(port, operation_deadline)
        stop_verify_deadline = min(
            operation_deadline.ends_at,
            time.monotonic() + max(0.0, STOP_VERIFY_SECONDS),
        )
        while target_pid in remaining_pids and time.monotonic() < stop_verify_deadline:
            time.sleep(min(0.5, max(0.0, stop_verify_deadline - time.monotonic())))
            remaining_pids = _listening_pids(port, operation_deadline)
        remaining = [target["target_process"]] if target_pid in remaining_pids else []
        return {
            "status": "ok" if not remaining_pids else "failed",
            "target": target,
            "matched": [target["target_process"]],
            "root_matches": [target["target_process"]],
            "stopped": stopped,
            "remaining": remaining,
            "remaining_listening_pids": remaining_pids,
            "failure_reason": "target_port_still_in_use" if remaining_pids else None,
        }
    except (OperationDeadlineExceeded, subprocess.TimeoutExpired) as exc:
        return {
            "status": "failed",
            "target_port": port,
            "failure_reason": "deadline_exceeded",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
    except Exception as exc:
        return {
            "status": "failed",
            "target_port": port,
            "failure_reason": "target_verification_failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }


def _runtime_log_path() -> Path:
    configured = os.environ.get("ADLOG_SERVER_RUNTIME_LOG")
    path = Path(configured) if configured else PROJECT_ROOT / "data" / "logs" / "server-runtime.log"
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _command_argv(command: str) -> list[str]:
    default_script = str(PROJECT_ROOT / "scripts" / "run_server.py")
    normalized = command.strip()
    if not normalized:
        return [sys.executable, default_script]
    parts = shlex.split(normalized, posix=(os.name != "nt"))
    cleaned = [part[1:-1] if len(part) >= 2 and part[0] == part[-1] == '"' else part for part in parts]
    if not cleaned:
        raise ValueError("empty server start command")
    return cleaned


def _read_log_delta(path: Path, offset: int, max_chars: int = STATUS_TAIL_CHARS) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(max(0, offset))
            data = handle.read()
        return data.decode("utf-8", errors="replace")[-max_chars:]
    except Exception as exc:
        return f"runtime_log_read_failed: {exc}"


def _spawn(command: str, *, env_overrides: dict[str, str] | None = None) -> tuple[subprocess.Popen[Any], dict[str, object], int]:
    log_path = _runtime_log_path()
    argv = _command_argv(command)
    marker = f"\n=== SERVER_START {timestamp()} pid_parent={os.getpid()} argv={json.dumps(argv, ensure_ascii=False)} ===\n".encode("utf-8")
    with log_path.open("ab", buffering=0) as log_handle:
        log_handle.write(marker)
        offset = log_handle.tell()
        child_env = os.environ.copy()
        child_env.setdefault("PYTHONUNBUFFERED", "1")
        if env_overrides:
            child_env.update({str(key): str(value) for key, value in env_overrides.items()})
        kwargs: dict[str, object] = {
            "cwd": str(PROJECT_ROOT),
            "shell": False,
            "stdin": subprocess.DEVNULL,
            "stdout": log_handle,
            "stderr": subprocess.STDOUT,
            "env": child_env,
            "close_fds": True,
        }
        if os.name == "nt":
            flags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
            # CREATE_NO_WINDOW is ignored when combined with DETACHED_PROCESS.
            # A Windows child does not depend on the short-lived launcher
            # process, so a new process group plus CREATE_NO_WINDOW gives us
            # both persistence and no visible console.
            flags |= int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
            process = subprocess.Popen(argv, creationflags=flags, **kwargs)
        else:
            process = subprocess.Popen(argv, start_new_session=True, **kwargs)
    result: dict[str, object] = {
        "status": "started",
        "command": command,
        "argv": argv,
        "pid": process.pid,
        "detached": True,
        "runtime_log": str(log_path),
        "runtime_log_offset": offset,
        "shell": False,
    }
    return process, result, offset


def start(command: str = DEFAULT_START_COMMAND) -> dict[str, object]:
    runtime_instance_id = uuid.uuid4().hex
    process, result, offset = _spawn(command, env_overrides={"ADLOG_RUNTIME_INSTANCE_ID": runtime_instance_id})
    result["expected_runtime_instance_id"] = runtime_instance_id
    time.sleep(max(0.1, EARLY_EXIT_GRACE_SECONDS))
    exit_code = process.poll()
    if exit_code is not None:
        result.update({
            "status": "failed",
            "early_exit": True,
            "process_exit_code": exit_code,
            "runtime_log_tail": _read_log_delta(_runtime_log_path(), offset),
        })
    else:
        result["early_exit"] = False
    return result


def _pid_belongs_to_tree(pid: int, root_pid: int, rows: list[dict[str, object]]) -> bool:
    if pid == root_pid:
        return True
    parents = {
        int(str(row["pid"])): int(str(row.get("parent_pid") or 0))
        for row in rows
        if str(row.get("pid", "")).isdigit() and str(row.get("parent_pid") or "0").isdigit()
    }
    seen: set[int] = set()
    current = pid
    while current and current not in seen:
        seen.add(current)
        current = parents.get(current, 0)
        if current == root_pid:
            return True
    return False


def _matching_project_runtime_processes(
    target_port: int,
    deadline: OperationDeadline | None = None,
) -> list[dict[str, object]]:
    """Return only exact project server commands for one requested port."""

    rows = _list_processes(deadline) if deadline is not None else _list_processes()
    return [
        row for row in rows
        if _command_targets_project_runtime(row.get("cmd"), target_port)
    ]


def _start_verified_runtime(
    command: str,
    *,
    url: str,
    timeout: int | float,
    target_port: int,
    insecure: bool,
    deadline: OperationDeadline,
    build_id_prefix: str,
    require_exclusive_port_owner: bool,
) -> dict[str, object]:
    """Spawn one child and retain it only after bounded identity verification."""

    expected_instance_id = uuid.uuid4().hex
    expected_build_id = f"{build_id_prefix}-{expected_instance_id[:12]}"
    spawned_process: subprocess.Popen[Any] | None = None
    started: dict[str, object] | None = None
    spawned_offset: int | None = None
    last: dict[str, object] = {
        "status": "failed",
        "url": url,
        "error": "health probe not run",
    }
    identity: dict[str, Any] = {}
    stale_identity_responses = 0
    exit_code: int | None = None

    try:
        deadline.remaining(stage="runtime spawn")
        spawned_process, started, spawned_offset = _spawn(
            command,
            env_overrides={
                "ADLOG_RUNTIME_INSTANCE_ID": expected_instance_id,
                "ADLOG_BUILD_ID": expected_build_id,
            },
        )
        health_deadline = min(
            deadline.ends_at,
            time.monotonic() + max(0.1, float(timeout)),
        )
        while time.monotonic() < health_deadline:
            exit_code = spawned_process.poll()
            if exit_code is not None:
                break
            probe_timeout = min(
                5.0,
                max(0.1, health_deadline - time.monotonic()),
            )
            last = _health_probe(
                url,
                probe_timeout,
                insecure=insecure,
                deadline=deadline,
            )
            identity = _runtime_identity(last.get("payload"))
            if (
                last.get("status") == "ok"
                and identity.get("runtime_instance_id") == expected_instance_id
                and identity.get("build_id") == expected_build_id
            ):
                break
            if last.get("status") == "ok":
                stale_identity_responses += 1
            sleep_for = min(
                1.0,
                max(0.0, health_deadline - time.monotonic()),
            )
            if sleep_for:
                time.sleep(sleep_for)

        identity_verified = bool(
            last.get("status") == "ok"
            and identity.get("runtime_instance_id") == expected_instance_id
            and identity.get("build_id") == expected_build_id
        )
        runtime_pid = (
            int(identity.get("process_pid") or 0)
            if str(identity.get("process_pid") or "").isdigit()
            else 0
        )
        process_rows = _list_processes(deadline)
        process_tree_verified = bool(
            runtime_pid
            and _pid_belongs_to_tree(runtime_pid, spawned_process.pid, process_rows)
        )
        listening_pids = _listening_pids(target_port, deadline)
        port_owner_verified = (
            listening_pids == [runtime_pid]
            if require_exclusive_port_owner
            else runtime_pid in listening_pids
        )
        ok = (
            identity_verified
            and process_tree_verified
            and port_owner_verified
            and exit_code is None
        )
        if started is not None:
            started["process_exit_code"] = exit_code
        result: dict[str, object] = {
            "status": "ok" if ok else "failed",
            "start": started,
            "started": True,
            "health": _compact_health(last),
            "expected_runtime_instance_id": expected_instance_id,
            "expected_build_id": expected_build_id,
            "runtime_identity": identity,
            "identity_verified": identity_verified,
            "process_tree_verified": process_tree_verified,
            "port_owner_verified": port_owner_verified,
            "listening_pids": listening_pids,
            "stale_identity_responses": stale_identity_responses,
        }
        if ok:
            return result
        result["runtime_log_tail"] = _read_log_delta(
            _runtime_log_path(),
            spawned_offset or 0,
        )
        if exit_code is not None:
            result["failure_reason"] = "process_exited_before_verified_health"
        elif not identity_verified:
            result["failure_reason"] = "health_runtime_identity_mismatch"
        elif not process_tree_verified:
            result["failure_reason"] = "health_pid_not_in_started_process_tree"
        else:
            result["failure_reason"] = "health_port_owner_mismatch"
    except (OperationDeadlineExceeded, subprocess.TimeoutExpired) as exc:
        result = {
            "status": "failed",
            "start": started,
            "started": bool(spawned_process),
            "health": _compact_health(last),
            "expected_runtime_instance_id": expected_instance_id,
            "expected_build_id": expected_build_id,
            "runtime_identity": identity,
            "identity_verified": False,
            "process_tree_verified": False,
            "port_owner_verified": False,
            "listening_pids": [],
            "stale_identity_responses": stale_identity_responses,
            "failure_reason": "deadline_exceeded",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
    except Exception as exc:
        result = {
            "status": "failed",
            "start": started,
            "started": bool(spawned_process),
            "health": _compact_health(last),
            "expected_runtime_instance_id": expected_instance_id,
            "expected_build_id": expected_build_id,
            "runtime_identity": identity,
            "identity_verified": False,
            "process_tree_verified": False,
            "port_owner_verified": False,
            "listening_pids": [],
            "stale_identity_responses": stale_identity_responses,
            "failure_reason": "runtime_control_failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    if spawned_process is not None:
        if spawned_offset is not None:
            result["runtime_log_tail"] = _read_log_delta(
                _runtime_log_path(),
                spawned_offset,
            )
        # The launch budget may already be exhausted. Cleanup owns a separate,
        # fixed allowance; only the child created by this invocation is targeted.
        cleanup_deadline = OperationDeadline(FAILED_START_CLEANUP_SECONDS)
        cleanup = _terminate_pid_tree(spawned_process.pid, cleanup_deadline)
        cleanup.update({
            "status": "failed",
            "termination_verified": False,
            "verification_scope": "spawned_child_exit",
            "cleanup_budget_seconds": FAILED_START_CLEANUP_SECONDS,
        })
        try:
            cleanup["process_exit_code"] = spawned_process.wait(
                timeout=cleanup_deadline.remaining(stage="failed-start child exit verification"),
            )
            cleanup["termination_verified"] = True
            if cleanup.get("exit_code") == 0 and not cleanup.get("error_type"):
                cleanup["status"] = "ok"
        except (OSError, OperationDeadlineExceeded, subprocess.TimeoutExpired) as cleanup_exc:
            cleanup["verification_error_type"] = type(cleanup_exc).__name__
            cleanup["verification_error"] = str(cleanup_exc)
        result["failed_start_cleanup"] = cleanup
    return result


def ensure_running(
    command: str = DEFAULT_START_COMMAND,
    pattern: str = DEFAULT_PROCESS_MATCH,
    url: str = DEFAULT_HEALTH_URL,
    timeout: int = 60,
    *,
    insecure: bool = False,
    target_port: int | None = None,
    total_timeout: float | None = None,
) -> dict[str, object]:
    """Ensure one verified runtime is available without stopping any listener.

    A verified existing listener is retained.  Any listener that cannot be
    proven to be this project's runtime blocks a new launch rather than being
    stopped or overlapped.  The scheduler's ``IgnoreNew`` policy prevents task
    overlap; this process-level check also makes manual/recovery invocations
    fail closed when a second owner appears.
    """

    operation_id = f"OP-{timestamp()}-ensure-server"
    port = int(target_port or _extract_port(url) or 0)
    operation_deadline = OperationDeadline(
        total_timeout
        if total_timeout is not None
        else max(float(timeout) + 20.0, DEFAULT_TOTAL_TIMEOUT_SECONDS)
    )

    def existing_result(target: dict[str, object]) -> dict[str, object]:
        return {
            "status": "ok",
            "operation_id": operation_id,
            "target": target,
            "start": None,
            "already_running": True,
            "started": False,
            "health": target.get("health"),
            "runtime_identity": target.get("runtime_identity") or {},
            "identity_verified": True,
            # No new child was launched, so process-tree ancestry is not an
            # applicable proof.  The exact listener command and health PID are
            # instead verified by _verified_destructive_target().
            "process_tree_verified": None,
            "port_owner_verified": True,
            "listening_pids": target.get("listening_pids") or [],
        }

    if not port:
        result: dict[str, object] = {
            "status": "failed",
            "operation_id": operation_id,
            "failure_reason": "target_port_required",
            "already_running": False,
            "started": False,
        }
        audit_action(
            "ensure_server",
            "failed",
            operation_id=operation_id,
            pattern=pattern,
            command=command,
            failure_reason=result["failure_reason"],
        )
        return result

    try:
        with _ensure_critical_section(port, operation_deadline):
            target = _verified_destructive_target(
                target_port=port,
                url=url,
                insecure=insecure,
                deadline=operation_deadline,
            )
            if target.get("status") == "verified":
                result = existing_result(target)
            elif target.get("status") != "absent":
                result = {
                    "status": "failed",
                    "operation_id": operation_id,
                    "target": target,
                    "already_running": False,
                    "started": False,
                    "listening_pids": target.get("listening_pids") or [],
                    "failure_reason": str(
                        target.get("failure_reason") or "target_verification_failed"
                    ),
                }
            else:
                # Recheck immediately before spawning.  The named mutex keeps
                # this precheck and _start_verified_runtime() atomic across
                # Windows launcher processes for this project and port.
                pre_start_listeners = _listening_pids(port, operation_deadline)
                if pre_start_listeners:
                    refreshed_target = _verified_destructive_target(
                        target_port=port,
                        url=url,
                        insecure=insecure,
                        deadline=operation_deadline,
                    )
                    if refreshed_target.get("status") == "verified":
                        result = existing_result(refreshed_target)
                    else:
                        result = {
                            "status": "failed",
                            "operation_id": operation_id,
                            "target": refreshed_target,
                            "already_running": False,
                            "started": False,
                            "listening_pids": pre_start_listeners,
                            "failure_reason": str(
                                refreshed_target.get("failure_reason")
                                or "target_port_became_occupied"
                            ),
                        }
                else:
                    matching_runtime_processes = _matching_project_runtime_processes(
                        port,
                        operation_deadline,
                    )
                    matching_runtime_pids = sorted(
                        {
                            int(str(row.get("pid") or "0"))
                            for row in matching_runtime_processes
                            if str(row.get("pid") or "").isdigit()
                        }
                    )
                    if matching_runtime_pids:
                        result = {
                            "status": "failed",
                            "operation_id": operation_id,
                            "target": target,
                            "already_running": False,
                            "started": False,
                            "listening_pids": [],
                            "matching_runtime_pids": matching_runtime_pids,
                            "failure_reason": "project_runtime_without_verified_listener",
                        }
                    else:
                        verification = _start_verified_runtime(
                            command,
                            url=url,
                            timeout=timeout,
                            target_port=port,
                            insecure=insecure,
                            deadline=operation_deadline,
                            build_id_prefix="ensure",
                            require_exclusive_port_owner=True,
                        )
                        result = {
                            **verification,
                            "operation_id": operation_id,
                            "target": target,
                            "already_running": False,
                        }
    except (OperationDeadlineExceeded, subprocess.TimeoutExpired) as exc:
        result = {
            "status": "failed",
            "operation_id": operation_id,
            "target_port": port,
            "already_running": False,
            "started": False,
            "failure_reason": "deadline_exceeded",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
    except Exception as exc:
        result = {
            "status": "failed",
            "operation_id": operation_id,
            "target_port": port,
            "already_running": False,
            "started": False,
            "failure_reason": "runtime_control_failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    audit_action(
        "ensure_server",
        str(result.get("status") or "failed"),
        operation_id=operation_id,
        pattern=pattern,
        command=command,
        failure_reason=result.get("failure_reason"),
        identity_verified=result.get("identity_verified", False),
        process_tree_verified=result.get("process_tree_verified", False),
        port_owner_verified=result.get("port_owner_verified", False),
    )
    return result


def restart(
    command: str = DEFAULT_START_COMMAND,
    pattern: str = DEFAULT_PROCESS_MATCH,
    url: str = DEFAULT_HEALTH_URL,
    timeout: int = 60,
    dry_run: bool = False,
    *,
    insecure: bool = False,
    target_port: int | None = None,
    total_timeout: float | None = None,
) -> dict[str, object]:
    operation_id = f"OP-{timestamp()}-restart-server"
    port = int(target_port or _extract_port(url) or 0)
    operation_deadline = OperationDeadline(
        total_timeout if total_timeout is not None else max(float(timeout) + 20.0, DEFAULT_TOTAL_TIMEOUT_SECONDS)
    )
    stopped = stop(
        pattern,
        dry_run=dry_run,
        target_port=port,
        url=url,
        insecure=insecure,
        deadline=operation_deadline,
    )
    if dry_run:
        dry_run_ok = stopped.get("status") == "dry_run"
        result = {
            "status": "dry_run" if dry_run_ok else "failed",
            "operation_id": operation_id,
            "stop": stopped,
            "failure_reason": None if dry_run_ok else str(stopped.get("failure_reason") or "target_verification_failed"),
        }
        audit_action("restart_server", str(result["status"]), operation_id=operation_id, pattern=pattern)
        return result
    try:
        pre_start_listeners = _listening_pids(port, operation_deadline)
        if stopped.get("status") != "ok" or stopped.get("remaining") or pre_start_listeners:
            result = {
                "status": "failed",
                "operation_id": operation_id,
                "stop": stopped,
                "port": port,
                "pre_start_listening_pids": pre_start_listeners,
                "failure_reason": (
                    str(stopped.get("failure_reason") or "old_runtime_not_fully_stopped")
                    if stopped.get("status") != "ok" or stopped.get("remaining")
                    else "health_port_still_in_use"
                ),
            }
            audit_action("restart_server", "failed", operation_id=operation_id, pattern=pattern, failure_reason=result["failure_reason"])
            return result

        verification = _start_verified_runtime(
            command,
            url=url,
            timeout=timeout,
            target_port=port,
            insecure=insecure,
            deadline=operation_deadline,
            build_id_prefix="restart",
            require_exclusive_port_owner=False,
        )
        result = {
            **verification,
            "operation_id": operation_id,
            "stop": stopped,
        }
    except (OperationDeadlineExceeded, subprocess.TimeoutExpired) as exc:
        result = {
            "status": "failed",
            "operation_id": operation_id,
            "stop": stopped,
            "port": port,
            "failure_reason": "deadline_exceeded",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        status = "failed"
    except Exception as exc:
        result = {
            "status": "failed",
            "operation_id": operation_id,
            "stop": stopped,
            "port": port,
            "failure_reason": "runtime_control_failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        status = "failed"
    audit_action(
        "restart_server",
        str(result.get("status") or "failed"),
        operation_id=operation_id,
        pattern=pattern,
        command=command,
        failure_reason=result.get("failure_reason"),
        identity_verified=result.get("identity_verified", False),
        process_tree_verified=result.get("process_tree_verified", False),
        port_owner_verified=result.get("port_owner_verified", False),
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Check/start/stop/restart local AD Log Reports server.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_health = sub.add_parser("status"); p_health.add_argument("--url", default=DEFAULT_HEALTH_URL); p_health.add_argument("--insecure", action="store_true")
    p_start = sub.add_parser("start"); p_start.add_argument("--command", default=DEFAULT_START_COMMAND)
    p_stop = sub.add_parser("stop"); p_stop.add_argument("--pattern", default=DEFAULT_PROCESS_MATCH); p_stop.add_argument("--url", default=DEFAULT_HEALTH_URL); p_stop.add_argument("--target-port", type=int); p_stop.add_argument("--dry-run", action="store_true"); p_stop.add_argument("--insecure", action="store_true")
    p_ensure = sub.add_parser("ensure"); p_ensure.add_argument("--command", default=DEFAULT_START_COMMAND); p_ensure.add_argument("--url", default=DEFAULT_HEALTH_URL); p_ensure.add_argument("--target-port", type=int); p_ensure.add_argument("--timeout", type=int, default=60); p_ensure.add_argument("--total-timeout", type=float); p_ensure.add_argument("--insecure", action="store_true")
    p_restart = sub.add_parser("restart"); p_restart.add_argument("--command", default=DEFAULT_START_COMMAND); p_restart.add_argument("--pattern", default=DEFAULT_PROCESS_MATCH); p_restart.add_argument("--url", default=DEFAULT_HEALTH_URL); p_restart.add_argument("--target-port", type=int); p_restart.add_argument("--timeout", type=int, default=60); p_restart.add_argument("--total-timeout", type=float); p_restart.add_argument("--dry-run", action="store_true"); p_restart.add_argument("--insecure", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--result-file",
        type=Path,
        help="Persist the complete JSON result inside the project and print only a bounded summary.",
    )
    args = parser.parse_args()
    if args.cmd == "status": result = health(args.url, insecure=args.insecure)
    elif args.cmd == "start": result = start(args.command)
    elif args.cmd == "stop": result = stop(args.pattern, dry_run=args.dry_run, target_port=args.target_port, url=args.url, insecure=args.insecure)
    elif args.cmd == "ensure": result = ensure_running(command=args.command, url=args.url, timeout=args.timeout, insecure=args.insecure, target_port=args.target_port, total_timeout=args.total_timeout)
    else: result = restart(args.command, args.pattern, args.url, args.timeout, args.dry_run, insecure=args.insecure, target_port=args.target_port, total_timeout=args.total_timeout)
    if args.result_file is not None:
        result_path = args.result_file
        if not result_path.is_absolute():
            result_path = PROJECT_ROOT / result_path
        from server.sli.core.paths import DATA_DIR

        if not (result_path.is_relative_to(PROJECT_ROOT) or result_path.is_relative_to(DATA_DIR.resolve())):
            parser.error("--result-file must resolve inside the project root or data directory")
        result_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = result_path.with_name(f".{result_path.name}.{uuid.uuid4().hex}.tmp")
        temporary_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary_path.replace(result_path)
        print(json.dumps({
            "status": result.get("status"),
            "operation_id": result.get("operation_id"),
            "failure_reason": result.get("failure_reason"),
            "result_file": str(result_path),
        }, ensure_ascii=False))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("status") in {"ok", "started", "dry_run"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
