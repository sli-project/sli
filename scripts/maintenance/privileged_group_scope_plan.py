#!/usr/bin/env python3
"""Bounded read-only inventory of candidate privileged AD groups."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
ROOT = Path(__file__).resolve().parents[2]
SNAPSHOTS = ROOT / "data" / "runtime" / "ad_context_snapshot"
CANDIDATES = [
    {"name": "DnsAdmins", "sid": None, "scope": "domain", "nested": "important"},
    {"name": "DHCP Administrators", "sid": None, "scope": "host_or_domain", "nested": "possible"},
    {"name": "DHCP Users", "sid": None, "scope": "host_or_domain", "nested": "possible"},
    {"name": "Account Operators", "sid": "S-1-5-32-548", "scope": "builtin", "nested": "important"},
    {"name": "Server Operators", "sid": "S-1-5-32-549", "scope": "builtin", "nested": "possible"},
    {"name": "Print Operators", "sid": "S-1-5-32-550", "scope": "builtin", "nested": "possible"},
    {"name": "Backup Operators", "sid": "S-1-5-32-551", "scope": "builtin", "nested": "possible"},
    {"name": "Cert Publishers", "sid": "{domain_sid}-517", "scope": "domain", "nested": "possible"},
    {"name": "Organization Management", "sid": None, "scope": "exchange", "nested": "important"},
    {"name": "Exchange Trusted Subsystem", "sid": None, "scope": "exchange", "nested": "important"},
    {"name": "Exchange Windows Permissions", "sid": None, "scope": "exchange", "nested": "important"},
]
PS_QUERY = r"""
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory
$domain = Get-ADDomain -Identity $env:SLI_SCOPE_DOMAIN
$dc = Get-ADDomainController -Discover -DomainName $domain.DNSRoot -Writable
$server = [string]@($dc.HostName)[0]
$candidates = $env:SLI_SCOPE_CANDIDATES | ConvertFrom-Json
$result = @()
foreach ($candidate in $candidates) {
    $started = [System.Diagnostics.Stopwatch]::StartNew()
    $group = $null
    if ($candidate.sid) {
        try {
            $group = Get-ADGroup -Identity $candidate.sid -Server $server `
                -Properties member,objectSid,groupScope,groupCategory -ErrorAction Stop
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {}
    }
    if (-not $group) {
        $found = @(Get-ADGroup -LDAPFilter "(sAMAccountName=$($candidate.name))" `
            -SearchBase $domain.DistinguishedName -Server $server `
            -Properties member,objectSid,groupScope,groupCategory)
        if ($found.Count -gt 1) { throw "non_unique_exact_group:$($candidate.name)" }
        if ($found.Count -eq 1) { $group = $found[0] }
    }
    $started.Stop()
    if ($group) {
        $count = @($group.member).Count
        $result += [pscustomobject]@{
            requested_name = [string]$candidate.name
            exists_in_domain = $true
            sam_account_name = [string]$group.SamAccountName
            sid = [string]$group.SID
            distinguished_name = [string]$group.DistinguishedName
            group_scope = [string]$group.GroupScope
            group_category = [string]$group.GroupCategory
            direct_member_count = $count
            lookup_ms = [math]::Round($started.Elapsed.TotalMilliseconds, 3)
        }
    } else {
        $result += [pscustomobject]@{
            requested_name = [string]$candidate.name
            exists_in_domain = $false
            direct_member_count = 0
            lookup_ms = [math]::Round($started.Elapsed.TotalMilliseconds, 3)
        }
    }
}
[pscustomobject]@{
    domain_dns = $domain.DNSRoot
    domain_sid = [string]$domain.DomainSID
    directory_server = $server
    groups = $result
} | ConvertTo-Json -Depth 5 -Compress
"""
def _identity() -> str:
    return subprocess.check_output(["whoami"], text=True, encoding="utf-8").strip()
def _latest_bundle() -> tuple[Path, dict[str, Any]]:
    files = sorted(
        SNAPSHOTS.glob("*/privileged_membership-*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not files:
        raise FileNotFoundError("privileged_membership_bundle_not_found")
    return files[0], json.loads(files[0].read_text(encoding="utf-8-sig"))
def _magnitude(count: int) -> str:
    if count == 0:
        return "0"
    if count < 10:
        return "1-9"
    if count < 100:
        return "10-99"
    if count < 1000:
        return "100-999"
    return "1000+"
def measure(*, expected_identity: str) -> dict[str, Any]:
    expected = str(expected_identity or "").strip().casefold()
    if not expected:
        raise ValueError("expected_windows_identity_required")
    identity = _identity().casefold()
    if identity != expected:
        raise PermissionError(f"wrong_windows_identity:{identity}")
    bundle_path, bundle = _latest_bundle()
    domain_sid = str(bundle["domain"]["sid"])
    domain_dns = str(bundle["domain"]["dns_name"])
    candidates = [
        {**item, "sid": item["sid"].format(domain_sid=domain_sid) if item["sid"] else None}
        for item in CANDIDATES
    ]
    env = dict(os.environ)
    env["SLI_SCOPE_DOMAIN"] = domain_dns
    env["SLI_SCOPE_CANDIDATES"] = json.dumps(candidates, ensure_ascii=False)
    started = time.perf_counter()
    proc = subprocess.run(
        [
            str(Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"),
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-Command", PS_QUERY,
        ],
        cwd=ROOT, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or "ad_group_query_failed")
    live = json.loads(proc.stdout)
    by_name = {item["requested_name"]: item for item in live["groups"]}
    measured_groups = []
    direct_members = 0
    for candidate in candidates:
        actual = by_name[candidate["name"]]
        count = int(actual.get("direct_member_count") or 0)
        direct_members += count
        measured_groups.append({
            **candidate,
            **actual,
            "member_count_order": _magnitude(count),
            "sid_contract": candidate["sid"] or "directory-assigned; exact SID must be read live",
            "nested_membership": candidate["nested"],
        })
    section = next(item for item in bundle["sections"] if item["name"] == "privileged_membership")
    records = int(section["record_count"])
    bytes_per_record = round(bundle_path.stat().st_size / records, 1)
    existing = sum(1 for item in measured_groups if item["exists_in_domain"])
    upper_extra_records = existing + 2 * direct_members
    return {
        "status": "measured",
        "identity": identity,
        "domain": live["domain_dns"],
        "directory_server": live["directory_server"],
        "current_cycle": {
            "group_count": len(bundle["scope"]["privileged_group_sids"]),
            "records": records,
            "duration_ms": int(section["duration_ms"]),
            "bundle_bytes": bundle_path.stat().st_size,
            "bytes_per_record": bytes_per_record,
        },
        "candidates": measured_groups,
        "ceiling": {
            "current": 10,
            "candidate_union_max": 15,
            "classification": "validation safety bound, not a transaction-shape dependency",
            "worker_max_records": 50_000,
            "bundle_max_bytes": 25 * 1024 * 1024,
            "contract_max_records": 200_000,
            "raise_cost": "validation/tests plus linear group/member query and bundle growth; importer transaction shape is unchanged",
        },
        "conservative_delta": {
            "existing_candidate_groups": existing,
            "direct_members": direct_members,
            "upper_extra_records": upper_extra_records,
            "upper_extra_bundle_bytes": round(upper_extra_records * bytes_per_record),
            "live_lookup_total_ms": round((time.perf_counter() - started) * 1000, 3),
            "collection_delta_is_estimate": True,
        },
        "nested_warning": "Direct membership only. Exchange and Account Operators require a separate bounded nested-path design before completeness can be claimed.",
        "query_contract": "11 exact SID or sAMAccountName lookups; group/member values read only; no recursive expansion; no writes",
        "authority": [
            "Microsoft Security Identifiers: built-in RIDs 548-551 and domain RID 517",
            "Microsoft Exchange permissions: Organization Management, Exchange Trusted Subsystem, Exchange Windows Permissions",
        ],
    }
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-identity", required=True, help=r"Explicit approved Windows identity (DOMAIN\user)")
    args = parser.parse_args()
    try:
        print(json.dumps(measure(expected_identity=args.expected_identity), ensure_ascii=False, indent=2))
    except Exception as exc:
        print(json.dumps({"status": "failed", "error": f"{type(exc).__name__}:{exc}"}, ensure_ascii=False))
        raise SystemExit(1)
