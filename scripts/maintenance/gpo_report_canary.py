"""One-shot bounded read-only Get-GPOReport canary with aggregate-only evidence."""
from __future__ import annotations

import argparse
import base64
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
CONFIRMATION = "START-GPO-REPORT-READONLY-CANARY"
MODULE = ROOT / "scripts" / "ad_context" / "GpoReportContract.psm1"
EXPORTER = ROOT / "scripts" / "ad_context" / "Export-AdAuditContextBundle.ps1"
EVIDENCE = ROOT / "artifacts" / "stage8" / "evidence" / "gpo-report-readonly-canary.json"
LOCK = EVIDENCE.with_suffix(".lock")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
POLICY_KEYS = frozenset({
    "kind", "sequence", "duration_ms", "response_bytes", "link_count",
    "link_enabled_count", "link_enforced_count", "security_filtering_collected",
    "wmi_filter_present", "computer_enabled", "user_enabled",
    "startup_script_count", "logon_script_count", "scheduled_task_count",
    "service_count", "local_group_count",
})
COUNT_KEYS = tuple(sorted(POLICY_KEYS - {
    "kind", "sequence", "security_filtering_collected", "wmi_filter_present",
    "computer_enabled", "user_enabled",
}))
CEILINGS = {
    "policy_limit": 72,
    "per_policy_time_limit_seconds": 30,
    "total_time_limit_seconds": 900,
    "single_response_bytes_limit": 33_554_432,
    "total_response_bytes_limit": 268_435_456,
}
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
    if not NAME_RE.fullmatch(args.directory_server) or not NAME_RE.fullmatch(args.domain):
        raise ValueError("invalid_directory_target")
    if not MODULE.is_file() or "'" in str(MODULE):
        raise RuntimeError("gpo_report_module_unavailable")
    exporter = EXPORTER.read_text(encoding="utf-8")
    if MODULE.name in exporter or "Invoke-SLIBoundedGpoReportRead" in exporter:
        raise RuntimeError("running_exporter_references_gpo_report_contract")
    encoded = base64.b64encode(_command(_powershell(), args)[-1].encode()).decode()
    probe = (
        "if(-not(Get-Module -ListAvailable GroupPolicy)){throw 'GroupPolicy unavailable'};"
        f"[void][ScriptBlock]::Create([Text.Encoding]::UTF8.GetString("
        f"[Convert]::FromBase64String('{encoded}')))"
    )
    subprocess.run(
        [str(_powershell()), "-NoProfile", "-NonInteractive", "-Command", probe],
        cwd=ROOT, capture_output=True, text=True, timeout=15, check=True,
    )
def _command(executable: Path, args: argparse.Namespace) -> list[str]:
    script = f"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Import-Module '{MODULE}' -Force -ErrorAction Stop
$contract=Get-SLIGpoReportContract
$inventory=Start-Job -ScriptBlock {{
  param($DomainName,$DirectoryServer)
  Import-Module GroupPolicy -ErrorAction Stop
  @(Get-GPO -All -Domain $DomainName -Server $DirectoryServer |
    Sort-Object Id | ForEach-Object {{ $_.Id.ToString() }})
}} -ArgumentList '{args.domain}','{args.directory_server}'
try {{
  $null=Wait-Job $inventory -Timeout $contract.per_policy_time_limit_seconds
  if ($inventory.State -ne 'Completed') {{ Stop-Job $inventory; throw 'inventory_time_ceiling_exceeded' }}
  $ids=@(Receive-Job $inventory -ErrorAction Stop)
}} finally {{ Remove-Job $inventory -Force -ErrorAction SilentlyContinue }}
if ($ids.Count -gt $contract.policy_limit) {{ throw 'policy_count_ceiling_exceeded' }}
[pscustomobject]@{{kind='header';policy_count=$ids.Count;ceilings=$contract}} |
  ConvertTo-Json -Compress -Depth 6
$total=[Diagnostics.Stopwatch]::StartNew()
$totalBytes=0L
$sequence=0
foreach ($id in $ids) {{
  $sequence+=1
  if ($total.Elapsed.TotalSeconds -gt $contract.total_time_limit_seconds) {{
    throw 'total_time_ceiling_exceeded'
  }}
  $read=Invoke-SLIBoundedGpoReportRead -Guid ([guid]$id) `
    -Domain '{args.domain}' -Server '{args.directory_server}'
  $totalBytes+=[long]$read.response_bytes
  if ($totalBytes -gt $contract.total_response_bytes_limit) {{
    throw 'total_response_size_ceiling_exceeded'
  }}
  $a=$read.facts.attributes
  [pscustomobject][ordered]@{{
    kind='policy';sequence=$sequence;duration_ms=[long]$read.duration_ms
    response_bytes=[long]$read.response_bytes;link_count=[int]$a.link_count
    link_enabled_count=[int]$a.gpo_link_enabled_count
    link_enforced_count=[int]$a.gpo_link_enforced_count
    security_filtering_collected=[bool]$a.gpo_security_filtering_collected
    wmi_filter_present=[bool]$a.gpo_wmi_filter_present
    computer_enabled=$a.gpo_computer_enabled;user_enabled=$a.gpo_user_enabled
    startup_script_count=[int]$a.gpo_startup_script_count
    logon_script_count=[int]$a.gpo_logon_script_count
    scheduled_task_count=[int]$a.gpo_scheduled_task_count
    service_count=[int]$a.gpo_service_count
    local_group_count=[int]$a.gpo_local_group_count
  }} | ConvertTo-Json -Compress -Depth 4
}}
"""
    return [
        str(executable), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
        "Bypass", "-Command", script,
    ]
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
        clean = {
            key: raw[key] for key in (
                "sequence", "security_filtering_collected", "wmi_filter_present",
                "computer_enabled", "user_enabled",
            )
        }
        for key in COUNT_KEYS:
            clean[key] = int(raw.get(key) or 0)
            if clean[key] < 0:
                raise ValueError("negative_policy_metric")
        if clean["duration_ms"] > CEILINGS["per_policy_time_limit_seconds"] * 1000:
            raise ValueError("time_ceiling_exceeded")
        if clean["response_bytes"] > CEILINGS["single_response_bytes_limit"]:
            raise ValueError("response_size_ceiling_exceeded")
        rows.append(clean)
    return policy_count, rows
def _safe_error(stderr: str, returncode: int) -> str:
    folded = stderr.casefold()
    if "access" in folded or "unauthorized" in folded:
        return "GpoReportAccessDenied"
    for marker, code in (
        ("time_ceiling", "GpoReportTimeCeiling"),
        ("response_size_ceiling", "GpoReportResponseCeiling"),
        ("policy_count_ceiling", "GpoReportPolicyCountCeiling"),
    ):
        if marker in folded:
            return code
    return f"GpoReportPowerShellFailed_{returncode}"
def run(args: argparse.Namespace) -> dict[str, Any]:
    _validate(args)
    if not args.execute:
        return {"status": "validated_only", "read_only": True, "ceilings": CEILINGS}
    if args.confirmation != CONFIRMATION:
        raise PermissionError(f"execute_requires_{CONFIRMATION}")
    if EVIDENCE.exists():
        raise FileExistsError("canary_evidence_already_exists")
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    os.close(lock_fd)
    started = time.monotonic()
    base: dict[str, Any] = {
        "status": "stopped", "classification": "bounded_read_only_gpo_report",
        "started_at_utc": _utc(), "live_ad_contacted": False,
        "database_changed": False, "runtime_changed": False,
        "surveyed_system_changed": False, "raw_policy_values_persisted": False,
        "account_names_persisted": False, "sysvol_paths_persisted": False,
        "ceilings": CEILINGS,
    }
    try:
        process = subprocess.run(
            _command(_powershell(), args), cwd=ROOT, capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=930,
        )
        base["live_ad_contacted"] = True
        policy_count, rows = _parse_rows(process.stdout)
        base.update(
            policy_count=policy_count, processed_count=len(rows),
            stopped_at_policy_index=(
                None if process.returncode == 0 else len(rows) + 1
            ),
            per_policy=rows,
            totals={
                "duration_ms": round((time.monotonic() - started) * 1000),
                "response_bytes": sum(row["response_bytes"] for row in rows),
            },
            aggregates={
                key: sum(row[key] for row in rows)
                for key in COUNT_KEYS if key not in {"duration_ms", "response_bytes"}
            },
        )
        if process.returncode != 0:
            base.update(
                error_type=_safe_error(process.stderr, process.returncode),
                error_code=process.returncode,
            )
        elif policy_count != CEILINGS["policy_limit"] or len(rows) != policy_count:
            base.update(error_type="GpoReportPolicyCountMismatch", error_code=1)
        else:
            base.update(status="done", finished_at_utc=_utc())
        _write(base)
        return base
    except subprocess.TimeoutExpired as exc:
        base.update(error_type="GpoReportTotalTimeout", error_code=124)
        try:
            count, rows = _parse_rows(str(exc.stdout or ""))
            base.update(policy_count=count, processed_count=len(rows), per_policy=rows)
        except Exception:
            pass
        _write(base)
        return base
    except Exception as exc:
        base.update(
            error_type=f"LocalResultValidation{type(exc).__name__}", error_code=1,
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
    return parser.parse_args()
def main() -> int:
    try:
        result = run(parse_args())
    except Exception as exc:
        result = {"status": "stopped", "error_type": type(exc).__name__, "error_code": 1}
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0 if result.get("status") in {"done", "validated_only"} else 2
if __name__ == "__main__":
    raise SystemExit(main())
