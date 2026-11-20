"""One-shot bounded read-only Get-GPPermission canary with aggregate evidence."""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONFIRMATION = "START-GPO-PERMISSION-READONLY-CANARY"
MODULE = ROOT / "scripts" / "ad_context" / "GpoReportContract.psm1"
EXPORTER = ROOT / "scripts" / "ad_context" / "Export-AdAuditContextBundle.ps1"
EVIDENCE = (
    ROOT / "artifacts" / "stage8" / "evidence"
    / "gpo-permission-readonly-canary.json"
)
ATTEMPT2_EVIDENCE = EVIDENCE.with_name(
    "gpo-permission-readonly-canary-attempt2.json"
)
ATTEMPT3_EVIDENCE = EVIDENCE.with_name(
    "gpo-permission-readonly-canary-attempt3.json"
)
LOCK = EVIDENCE.with_suffix(".lock")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
POLICY_KEYS = frozenset({
    "kind", "sequence", "duration_ms", "response_bytes", "permission_count",
    "apply_allow_count", "apply_deny_count", "denied_count",
    "inherited_count", "custom_count", "effective_access_evaluated",
})
COUNT_KEYS = tuple(sorted(POLICY_KEYS - {
    "kind", "sequence", "effective_access_evaluated",
}))
CEILINGS = {
    "policy_limit": 72,
    "per_policy_permission_limit": 4096,
    "total_permission_limit": 65_536,
    "per_policy_time_limit_seconds": 30,
    "total_time_limit_seconds": 900,
    "single_response_bytes_limit": 2_097_152,
    "total_response_bytes_limit": 67_108_864,
}
VALIDATION_CODES = frozenset({
    "missing_inventory_header",
    "contract_ceiling_mismatch",
    "unexpected_policy_metric_shape",
    "unexpected_policy_metric_order",
    "negative_policy_metric",
    "unexpected_effective_access_claim",
    "time_ceiling_exceeded",
    "permission_count_ceiling_exceeded",
    "response_size_ceiling_exceeded",
})


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write(payload: dict[str, Any]) -> None:
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    temporary = EVIDENCE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8",
    )
    temporary.replace(EVIDENCE)


def _powershell() -> Path:
    if os.name != "nt":
        raise RuntimeError("windows_host_required")
    path = (
        Path(os.environ.get("WINDIR") or r"C:\Windows")
        / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    ).resolve()
    if not path.is_file():
        raise RuntimeError("trusted_windows_powershell_not_found")
    return path


def _validate(args: argparse.Namespace) -> None:
    if not NAME_RE.fullmatch(args.directory_server) or not NAME_RE.fullmatch(
        args.domain
    ):
        raise ValueError("invalid_directory_target")
    if not MODULE.is_file() or "'" in str(MODULE):
        raise RuntimeError("gpo_permission_module_unavailable")
    exporter = EXPORTER.read_text(encoding="utf-8")
    if (
        MODULE.name in exporter
        or "Invoke-SLIBoundedGpoPermissionRead" in exporter
    ):
        raise RuntimeError("running_exporter_references_gpo_permission_contract")
    encoded = base64.b64encode(_command(args).encode()).decode()
    probe = (
        "if(-not(Get-Module -ListAvailable GroupPolicy)){"
        "throw 'GroupPolicy unavailable'};"
        f"[void][ScriptBlock]::Create([Text.Encoding]::UTF8.GetString("
        f"[Convert]::FromBase64String('{encoded}')))"
    )
    subprocess.run(
        [str(_powershell()), "-NoProfile", "-NonInteractive", "-Command", probe],
        cwd=ROOT, capture_output=True, text=True, timeout=15, check=True,
    )


def _command(args: argparse.Namespace) -> str:
    return f"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Import-Module '{MODULE}' -Force -ErrorAction Stop
$contract=Get-SLIGpoPermissionContract
$inventory=Start-Job -ScriptBlock {{
  param($DomainName,$DirectoryServer)
  Import-Module GroupPolicy -ErrorAction Stop
  @(Get-GPO -All -Domain $DomainName -Server $DirectoryServer |
    Sort-Object Id | ForEach-Object {{ $_.Id.ToString() }})
}} -ArgumentList '{args.domain}','{args.directory_server}'
try {{
  $null=Wait-Job $inventory -Timeout $contract.per_policy_time_limit_seconds
  if ($inventory.State -ne 'Completed') {{
    Stop-Job $inventory
    throw 'inventory_time_ceiling_exceeded'
  }}
  $ids=@(Receive-Job $inventory -ErrorAction Stop)
}} finally {{ Remove-Job $inventory -Force -ErrorAction SilentlyContinue }}
if ($ids.Count -gt $contract.policy_limit) {{
  throw 'policy_count_ceiling_exceeded'
}}
[pscustomobject]@{{kind='header';policy_count=$ids.Count;ceilings=$contract}} |
  ConvertTo-Json -Compress -Depth 6
$total=[Diagnostics.Stopwatch]::StartNew()
$totalBytes=0L
$totalPermissions=0L
$sequence=0
foreach ($id in $ids) {{
  $sequence+=1
  if ($total.Elapsed.TotalSeconds -gt $contract.total_time_limit_seconds) {{
    throw 'total_time_ceiling_exceeded'
  }}
  $read=Invoke-SLIBoundedGpoPermissionRead -Guid ([guid]$id) `
    -Domain '{args.domain}' -Server '{args.directory_server}'
  $totalBytes+=[long]$read.response_bytes
  $totalPermissions+=[long]$read.facts.permission_count
  if ($totalBytes -gt $contract.total_response_bytes_limit) {{
    throw 'total_response_size_ceiling_exceeded'
  }}
  if ($totalPermissions -gt $contract.total_permission_limit) {{
    throw 'total_permission_count_ceiling_exceeded'
  }}
  $permissions=@($read.facts.permissions)
  [pscustomobject][ordered]@{{
    kind='policy';sequence=$sequence;duration_ms=[long]$read.duration_ms
    response_bytes=[long]$read.response_bytes
    permission_count=[int]$read.facts.permission_count
    apply_allow_count=@($read.facts.gpo_apply_allow_sids).Count
    apply_deny_count=@($read.facts.gpo_apply_deny_sids).Count
    denied_count=@($permissions | Where-Object {{ $_.denied }}).Count
    inherited_count=@($permissions | Where-Object {{ $_.inherited }}).Count
    custom_count=@(
      $permissions | Where-Object {{ $_.permission -eq 'GpoCustom' }}
    ).Count
    effective_access_evaluated=[bool]$read.facts.effective_access_evaluated
  }} | ConvertTo-Json -Compress -Depth 4
}}
"""


def _parse_rows(stdout: str) -> tuple[int, list[dict[str, Any]]]:
    decoded = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    if not decoded or decoded[0].get("kind") != "header":
        raise ValueError("missing_inventory_header")
    policy_count = int(decoded[0].get("policy_count") or 0)
    received = decoded[0].get("ceilings") or {}
    for key, value in CEILINGS.items():
        if int(received.get(key) or 0) != value:
            raise ValueError("contract_ceiling_mismatch")
    rows: list[dict[str, Any]] = []
    for expected, raw in enumerate(decoded[1:], 1):
        if not isinstance(raw, dict) or set(raw) != POLICY_KEYS:
            raise ValueError("unexpected_policy_metric_shape")
        if raw["kind"] != "policy" or int(raw["sequence"]) != expected:
            raise ValueError("unexpected_policy_metric_order")
        clean: dict[str, Any] = {
            "sequence": expected,
            "effective_access_evaluated": bool(
                raw["effective_access_evaluated"]
            ),
        }
        for key in COUNT_KEYS:
            clean[key] = int(raw.get(key) or 0)
            if clean[key] < 0:
                raise ValueError("negative_policy_metric")
        if clean["effective_access_evaluated"]:
            raise ValueError("unexpected_effective_access_claim")
        if (
            clean["duration_ms"]
            > CEILINGS["per_policy_time_limit_seconds"] * 1000
        ):
            raise ValueError("time_ceiling_exceeded")
        if clean["permission_count"] > CEILINGS["per_policy_permission_limit"]:
            raise ValueError("permission_count_ceiling_exceeded")
        if clean["response_bytes"] > CEILINGS["single_response_bytes_limit"]:
            raise ValueError("response_size_ceiling_exceeded")
        rows.append(clean)
    return policy_count, rows


def _safe_error(stderr: str, returncode: int) -> str:
    folded = stderr.casefold()
    if "access" in folded or "unauthorized" in folded:
        return "GpoPermissionAccessDenied"
    for marker, code in (
        ("time_ceiling", "GpoPermissionTimeCeiling"),
        ("response_size_ceiling", "GpoPermissionResponseCeiling"),
        ("permission_count_ceiling", "GpoPermissionCountCeiling"),
        ("policy_count_ceiling", "GpoPermissionPolicyCountCeiling"),
    ):
        if marker in folded:
            return code
    return f"GpoPermissionPowerShellFailed_{returncode}"


def _safe_validation_code(exc: Exception) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return "invalid_json_line"
    code = str(exc)
    return code if code in VALIDATION_CODES else "unclassified_local_validation"


def _archive_stopped_access_evidence() -> None:
    if ATTEMPT2_EVIDENCE.exists():
        raise FileExistsError("stopped_access_retry_already_used")
    try:
        current = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FileExistsError("existing_canary_evidence_is_not_retryable") from exc
    if not (
        current.get("status") == "stopped"
        and current.get("classification")
        == "bounded_read_only_gpo_permission"
        and current.get("error_type") == "GpoPermissionAccessDenied"
        and current.get("validation_code") == "missing_inventory_header"
        and current.get("database_changed") is False
        and current.get("runtime_changed") is False
        and current.get("surveyed_system_changed") is False
        and current.get("raw_permission_rows_persisted") is False
        and current.get("trustee_sids_persisted") is False
        and current.get("account_names_persisted") is False
    ):
        raise FileExistsError("existing_canary_evidence_is_not_retryable")
    EVIDENCE.replace(ATTEMPT2_EVIDENCE)


def _archive_fixed_job_boundary_evidence() -> None:
    if not ATTEMPT2_EVIDENCE.exists():
        raise FileExistsError("fixed_boundary_retry_missing_attempt2")
    if ATTEMPT3_EVIDENCE.exists():
        raise FileExistsError("fixed_boundary_retry_already_used")
    try:
        current = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FileExistsError("existing_canary_evidence_is_not_retryable") from exc
    if not (
        current.get("status") == "stopped"
        and current.get("classification")
        == "bounded_read_only_gpo_permission"
        and current.get("policy_count") == 72
        and current.get("processed_count") == 0
        and current.get("stopped_at_policy_index") == 1
        and current.get("error_type") == "GpoPermissionPowerShellFailed_1"
        and current.get("database_changed") is False
        and current.get("runtime_changed") is False
        and current.get("surveyed_system_changed") is False
        and current.get("raw_permission_rows_persisted") is False
        and current.get("trustee_sids_persisted") is False
        and current.get("account_names_persisted") is False
    ):
        raise FileExistsError("existing_canary_evidence_is_not_retryable")
    EVIDENCE.replace(ATTEMPT3_EVIDENCE)


def run(args: argparse.Namespace) -> dict[str, Any]:
    _validate(args)
    if not args.execute:
        return {"status": "validated_only", "read_only": True, "ceilings": CEILINGS}
    if args.confirmation != CONFIRMATION:
        raise PermissionError(f"execute_requires_{CONFIRMATION}")
    if EVIDENCE.exists():
        if args.archive_fixed_job_boundary_evidence:
            _archive_fixed_job_boundary_evidence()
        elif args.archive_stopped_access_evidence:
            _archive_stopped_access_evidence()
        else:
            raise FileExistsError("canary_evidence_already_exists")
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    os.close(lock_fd)
    started = time.monotonic()
    base: dict[str, Any] = {
        "status": "stopped",
        "classification": "bounded_read_only_gpo_permission",
        "started_at_utc": _utc(),
        "live_ad_contacted": False,
        "database_changed": False,
        "runtime_changed": False,
        "surveyed_system_changed": False,
        "raw_permission_rows_persisted": False,
        "trustee_sids_persisted": False,
        "account_names_persisted": False,
        "effective_access_evaluated": False,
        "ceilings": CEILINGS,
    }
    try:
        process = subprocess.run(
            [
                str(_powershell()), "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", _command(args),
            ],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=930,
        )
        base["live_ad_contacted"] = True
        try:
            policy_count, rows = _parse_rows(process.stdout)
        except (ValueError, json.JSONDecodeError) as exc:
            base.update(
                error_type=(
                    _safe_error(process.stderr, process.returncode)
                    if process.returncode != 0
                    else "LocalResultValidation"
                ),
                error_code=process.returncode or 1,
                validation_code=_safe_validation_code(exc),
            )
            _write(base)
            return base
        base.update(
            policy_count=policy_count,
            processed_count=len(rows),
            stopped_at_policy_index=(
                None if process.returncode == 0 else len(rows) + 1
            ),
            per_policy=rows,
            totals={
                "duration_ms": round((time.monotonic() - started) * 1000),
                "response_bytes": sum(row["response_bytes"] for row in rows),
                "permission_count": sum(row["permission_count"] for row in rows),
            },
            aggregates={
                key: sum(row[key] for row in rows)
                for key in (
                    "apply_allow_count", "apply_deny_count", "denied_count",
                    "inherited_count", "custom_count",
                )
            },
        )
        if process.returncode != 0:
            base.update(
                error_type=_safe_error(process.stderr, process.returncode),
                error_code=process.returncode,
            )
        elif len(rows) != policy_count:
            base.update(error_type="GpoPermissionPolicyCountMismatch", error_code=1)
        else:
            base.update(status="done", finished_at_utc=_utc())
        _write(base)
        return base
    except subprocess.TimeoutExpired:
        base.update(error_type="GpoPermissionTotalTimeout", error_code=124)
        _write(base)
        return base
    except Exception as exc:
        base.update(
            error_type=f"LocalResultValidation{type(exc).__name__}",
            error_code=1,
            validation_code=_safe_validation_code(exc),
        )
        _write(base)
        return base
    finally:
        LOCK.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory-server", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirmation", default="")
    parser.add_argument("--archive-stopped-access-evidence", action="store_true")
    parser.add_argument(
        "--archive-fixed-job-boundary-evidence", action="store_true",
    )
    return parser.parse_args()


def main() -> int:
    try:
        result = run(parse_args())
    except Exception as exc:
        result = {
            "status": "stopped",
            "error_type": type(exc).__name__,
            "error_code": 1,
        }
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0 if result.get("status") in {"done", "validated_only"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
