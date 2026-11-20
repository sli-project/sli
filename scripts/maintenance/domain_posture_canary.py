"""One-shot bounded domain-posture LDAP canary with aggregate-only evidence."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CONFIRMATIONS = {
    1: "START-DOMAIN-POSTURE-READONLY-CANARY",
    2: "START-DOMAIN-POSTURE-READONLY-CANARY-ATTEMPT2",
    3: "START-DOMAIN-POSTURE-READONLY-CANARY-ATTEMPT3",
}
MODULE = ROOT / "scripts" / "ad_context" / "DomainPosture.psm1"
EVIDENCE_PATHS = {
    1: ROOT / "artifacts" / "stage8" / "evidence"
       / "domain-posture-readonly-canary.json",
    2: ROOT / "artifacts" / "stage8" / "evidence"
       / "domain-posture-readonly-canary-attempt2.json",
    3: ROOT / "artifacts" / "stage8" / "evidence"
       / "domain-posture-readonly-canary-attempt3.json",
}
SERVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
DN_RE = re.compile(r"^DC=[^,\r\n]+(?:,DC=[^,\r\n]+)+$", re.IGNORECASE)
EXPECTED_CHECKS = (
    "domain_password_policy",
    "dcsync_domain_dacl",
    "delegation",
    "user_service_principal_names",
    "kerberos_preauth_disabled",
    "sid_history",
    "domain_trusts",
    "domain_controllers",
)
METRIC_KEYS = frozenset({
    "check", "duration_ms", "record_count", "response_bytes",
    "time_limit_seconds", "record_limit", "response_bytes_limit",
})

def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def _evidence_path(attempt: int) -> Path:
    try:
        return EVIDENCE_PATHS[attempt]
    except KeyError as exc:
        raise ValueError("unsupported_canary_attempt") from exc


def _write_evidence(payload: dict[str, Any], evidence: Path) -> None:
    evidence.parent.mkdir(parents=True, exist_ok=True)
    temporary = evidence.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8",
    )
    temporary.replace(evidence)

def _trusted_powershell() -> Path:
    if os.name != "nt":
        raise RuntimeError("windows_host_required")
    executable = (
        Path(os.environ.get("WINDIR") or r"C:\Windows")
        / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    ).resolve()
    if not executable.is_file():
        raise RuntimeError("trusted_windows_powershell_not_found")
    return executable

def _validate(args: argparse.Namespace) -> None:
    if not SERVER_RE.fullmatch(args.directory_server):
        raise ValueError("invalid_directory_server")
    if not DN_RE.fullmatch(args.domain_dn):
        raise ValueError("invalid_domain_dn")
    if not MODULE.is_file() or "'" in str(MODULE):
        raise RuntimeError("domain_posture_module_unavailable")
    exporter = ROOT / "scripts" / "ad_context" / "Export-AdAuditContextBundle.ps1"
    exporter_source = exporter.read_text(encoding="utf-8")
    if MODULE.name in exporter_source or "Invoke-SLIDomainPostureRead" in exporter_source:
        raise RuntimeError("running_exporter_references_domain_posture")

def _command(executable: Path, args: argparse.Namespace) -> list[str]:
    script = (
        "$ErrorActionPreference='Stop';"
        "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
        f"Import-Module '{MODULE}' -Force;"
        f"@(Invoke-SLIDomainPostureRead -Server '{args.directory_server}' "
        f"-DomainDn '{args.domain_dn}')|ConvertTo-Json -Depth 6 -Compress"
    )
    return [
        str(executable), "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-Command", script,
    ]

def _safe_error_type(stderr: str, returncode: int) -> str:
    folded = stderr.casefold()
    if any(marker in folded for marker in (
        "insufficient access", "access is denied", "unauthorizedaccess",
    )):
        return "PowerShellPreflightAccessDenied"
    if "time_ceiling_exceeded" in folded or "timed out" in folded:
        return "PowerShellPreflightTimeout"
    if "record_ceiling_exceeded" in folded:
        return "PowerShellPreflightRecordCeiling"
    if "response_size_ceiling_exceeded" in folded:
        return "PowerShellPreflightResponseCeiling"
    return f"PowerShellPreflightFailed_{returncode}"

def _validated_metrics(stdout: str) -> list[dict[str, int | str]]:
    decoded = json.loads(stdout)
    rows = decoded if isinstance(decoded, list) else [decoded]
    if len(rows) != len(EXPECTED_CHECKS):
        raise ValueError("incomplete_check_result")
    clean: list[dict[str, int | str]] = []
    for expected, raw in zip(EXPECTED_CHECKS, rows, strict=True):
        if not isinstance(raw, dict) or set(raw) != METRIC_KEYS:
            raise ValueError("unexpected_check_result_shape")
        if raw.get("check") != expected:
            raise ValueError("unexpected_check_order")
        row: dict[str, int | str] = {"check": expected}
        for key in METRIC_KEYS - {"check"}:
            value = int(raw.get(key) or 0)
            if value < 0:
                raise ValueError("negative_check_metric")
            row[key] = value
        if int(row["duration_ms"]) > int(row["time_limit_seconds"]) * 1000:
            raise ValueError("time_ceiling_exceeded")
        if int(row["record_count"]) > int(row["record_limit"]):
            raise ValueError("record_ceiling_exceeded")
        if int(row["response_bytes"]) > int(row["response_bytes_limit"]):
            raise ValueError("response_size_ceiling_exceeded")
        clean.append(row)
    return clean


def run(args: argparse.Namespace) -> dict[str, Any]:
    _validate(args)
    evidence = _evidence_path(args.attempt)
    lock = evidence.with_suffix(".lock")
    if not args.execute:
        return {
            "status": "validated_only",
            "read_only": True,
            "check_count": len(EXPECTED_CHECKS),
            "attempt": args.attempt,
        }
    confirmation = CONFIRMATIONS[args.attempt]
    if args.confirmation != confirmation:
        raise PermissionError(f"execute_requires_{confirmation}")
    if evidence.exists():
        raise FileExistsError("canary_evidence_already_exists")
    evidence.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError("domain_posture_canary_lock_exists") from exc
    os.close(lock_fd)
    started_at = _utc()
    started = time.monotonic()
    base: dict[str, Any] = {
        "status": "stopped",
        "classification": "bounded_read_only_ldap",
        "attempt": args.attempt,
        "started_at_utc": started_at,
        "live_ad_contacted": False,
        "database_changed": False,
        "runtime_changed": False,
        "surveyed_system_changed": False,
        "raw_attribute_values_persisted": False,
        "security_descriptor_persisted": False,
    }
    try:
        process = subprocess.run(
            _command(_trusted_powershell(), args),
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=250,
        )
        base["live_ad_contacted"] = True
        if process.returncode != 0:
            base.update(
                error_type=_safe_error_type(process.stderr, process.returncode),
                error_code=process.returncode,
            )
            _write_evidence(base, evidence)
            return base
        checks = _validated_metrics(process.stdout)
        base.update(
            status="done",
            finished_at_utc=_utc(),
            duration_ms=round((time.monotonic() - started) * 1000),
            checks=checks,
            totals={
                "record_count": sum(int(row["record_count"]) for row in checks),
                "response_bytes": sum(int(row["response_bytes"]) for row in checks),
            },
        )
        _write_evidence(base, evidence)
        return base
    except subprocess.TimeoutExpired:
        base.update(error_type="PowerShellPreflightTimeout", error_code=124)
        _write_evidence(base, evidence)
        return base
    except Exception as exc:
        base.update(
            error_type=f"LocalResultValidation{type(exc).__name__}",
            error_code=1,
            finished_at_utc=_utc(),
        )
        _write_evidence(base, evidence)
        return base
    finally:
        lock.unlink(missing_ok=True)


def finalize_stopped(result_path: Path) -> dict[str, Any]:
    evidence = _evidence_path(1)
    if evidence.exists():
        raise FileExistsError("canary_evidence_already_exists")
    wrapper = json.loads(result_path.read_text(encoding="utf-8"))
    payload = wrapper.get("payload") or {}
    if (
        wrapper.get("task") != "36b-domain-posture-canary"
        or wrapper.get("exit_code") != 2
        or payload.get("status") != "stopped"
        or payload.get("error_type") != "ValueError"
    ):
        raise ValueError("runner_result_not_eligible_for_stopped_finalization")
    result = {
        "status": "stopped",
        "classification": "bounded_read_only_ldap",
        "started_at_utc": wrapper.get("started_utc"),
        "finished_at_utc": wrapper.get("finished_utc"),
        "duration_ms": round(float(wrapper.get("duration_s") or 0) * 1000),
        "live_ad_contacted": True,
        "metrics_available": False,
        "error_type": "LocalResultValidationValueError",
        "error_code": 1,
        "reconstructed_from_runner_result": True,
        "database_changed": False,
        "runtime_changed": False,
        "surveyed_system_changed": False,
        "raw_attribute_values_persisted": False,
        "security_descriptor_persisted": False,
    }
    _write_evidence(result, evidence)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory-server", required=True)
    parser.add_argument("--domain-dn", required=True)
    parser.add_argument("--attempt", type=int, choices=tuple(CONFIRMATIONS), default=1)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--finalize-stopped-from-runner", type=Path)
    parser.add_argument("--confirmation", default="")
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        result = finalize_stopped(args.finalize_stopped_from_runner) if args.finalize_stopped_from_runner else run(args)
    except Exception as exc:  # safe summary only; no stderr or attributes
        result = {
            "status": "stopped",
            "error_type": type(exc).__name__,
            "error_code": 1,
        }
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0 if result.get("status") in {"done", "validated_only"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
