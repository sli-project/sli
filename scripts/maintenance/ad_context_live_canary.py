"""One-shot, read-only live AD Context canary. It never imports or schedules."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.ad_context.contracts import load_bundle
from server.sli.sources.radius_plugin_runtime import current_windows_account
from server.source_packs.adapters import AdContextRequest, build_ad_context_command


CONFIRMATION = "ADCTX-LIVE-CANARY-READ-ONLY"
POWERSHELL_RUNTIME = "windows-powershell-5.1-system32"
DEFAULT_OUTPUT_ROOT = ROOT / "artifacts" / "ad_context_live_canary"
SID_RE = re.compile(r"^S-1-(?:\d+-){1,14}\d+$", re.IGNORECASE)
DNS_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
SERVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
MAX_GROUP_REFERENCES = 50
SUPPORTED_SECTIONS = ("privileged_membership", "directory_accounts", "vpn_membership", "gpo_governance", "domain_posture", "domain_health")
SECTION_PROFILES = {
    "privileged_membership": "privileged_membership_v1",
    "directory_accounts": "directory_security_v1",
    "vpn_membership": "vpn_security_v1",
    "gpo_governance": "gpo_governance_v4",
    "domain_posture": "domain_posture_v1",
    "domain_health": "domain_health_v1",
}
SECTION_PACK_VERSIONS = {
    "privileged_membership": "0.5.0",
    "directory_accounts": "0.10.0",
    "vpn_membership": "0.10.0",
    "gpo_governance": "0.10.0",
    "domain_posture": "0.10.0",
    "domain_health": "0.10.0",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_utc(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def validate_request(args: argparse.Namespace) -> dict[str, Any]:
    if not SERVER_RE.fullmatch(args.directory_server):
        raise ValueError("directory_server must be one hostname, FQDN or IP address")
    if not DNS_RE.fullmatch(args.domain):
        raise ValueError("domain must be a DNS domain name")
    if not args.search_base.upper().startswith("DC=") or "\n" in args.search_base or "\r" in args.search_base:
        raise ValueError("search_base must be one bounded directory DN")
    sections = tuple(dict.fromkeys(args.section or ("privileged_membership",)))
    if not sections or any(value not in SUPPORTED_SECTIONS for value in sections):
        raise ValueError("provide only supported AD Context sections")
    if len(sections) != 1:
        raise ValueError("live canary requires exactly one section per approved execution")
    groups = tuple(dict.fromkeys(value.upper() for value in args.group_sid))
    if "privileged_membership" in sections:
        if not groups or len(groups) > MAX_GROUP_REFERENCES or any(not SID_RE.fullmatch(value) for value in groups):
            raise ValueError("provide between one and fifty exact privileged group SIDs")
    elif groups:
        raise ValueError("privileged group SIDs require the privileged_membership section")
    vpn_groups = tuple(dict.fromkeys(value.upper() for value in args.vpn_group_sid))
    if "vpn_membership" in sections:
        if not vpn_groups or len(vpn_groups) > MAX_GROUP_REFERENCES or any(not SID_RE.fullmatch(value) for value in vpn_groups):
            raise ValueError("provide between one and fifty exact VPN group SIDs")
    elif vpn_groups:
        raise ValueError("VPN group SIDs require the vpn_membership section")
    if not 5 <= args.timeout_seconds <= 300:
        raise ValueError("timeout_seconds must be between 5 and 300")
    if not 1 <= args.max_records <= 5000:
        raise ValueError("max_records must be between 1 and 5000 for the live canary")
    if not 1024 <= args.max_bundle_bytes <= 25 * 1024 * 1024:
        raise ValueError("max_bundle_bytes must be between 1024 and 26214400")
    section_limits = {
        "max_directory_accounts": args.max_directory_accounts,
        "max_directory_users": (
            args.max_directory_users
            if args.max_directory_users is not None
            else args.max_directory_accounts // 2
        ),
        "max_directory_computers": (
            args.max_directory_computers
            if args.max_directory_computers is not None
            else args.max_directory_accounts - (args.max_directory_accounts // 2)
        ),
        "max_vpn_members": args.max_vpn_members,
        "max_gpos": args.max_gpos,
    }
    relevant_limits = []
    if "directory_accounts" in sections:
        relevant_limits.append(section_limits["max_directory_accounts"])
        if (
            section_limits["max_directory_users"] < 1
            or section_limits["max_directory_computers"] < 1
            or section_limits["max_directory_users"] + section_limits["max_directory_computers"]
            > min(args.max_records, args.max_directory_accounts)
        ):
            raise ValueError("independent directory limits exceed the approved total limit")
    if "vpn_membership" in sections:
        relevant_limits.append(section_limits["max_vpn_members"])
    if "gpo_governance" in sections:
        relevant_limits.append(section_limits["max_gpos"])
    if any(value < 1 or value > args.max_records for value in relevant_limits):
        raise ValueError("section limits must be positive and not exceed max_records")
    if "gpo_governance" in sections and args.max_gpos > 72:
        raise ValueError("GPO governance exceeds the proven 72-policy contract")
    if not str(args.expected_account or "").strip():
        raise ValueError("expected_account is required; credentials are never accepted")
    if any(value in str(args.expected_account) for value in ("\r", "\n")):
        raise ValueError("expected_account must be one Windows account name")
    not_before = parse_utc(args.not_before_utc, "not_before_utc")
    not_after = parse_utc(args.not_after_utc, "not_after_utc")
    if not_before >= not_after:
        raise ValueError("not_before_utc must be earlier than not_after_utc")
    if not_after - not_before > timedelta(hours=2):
        raise ValueError("the approved execution window cannot exceed two hours")
    output_root = args.output_root.resolve()
    allowed_root = DEFAULT_OUTPUT_ROOT.resolve()
    if output_root != allowed_root and allowed_root not in output_root.parents:
        raise ValueError("output_root must stay under artifacts/ad_context_live_canary")
    return {
        "directory_server": args.directory_server,
        "domain": args.domain.lower(),
        "search_base": args.search_base,
        "sections": sections,
        "collection_mode": "targeted" if sections[0] in {"privileged_membership", "vpn_membership"} else "full",
        "collection_profile": SECTION_PROFILES[sections[0]],
        "source_pack_version": SECTION_PACK_VERSIONS[sections[0]],
        "group_sids": groups,
        "vpn_group_sids": vpn_groups,
        "expected_account": args.expected_account,
        "timeout_seconds": args.timeout_seconds,
        "max_records": args.max_records,
        "max_bundle_bytes": args.max_bundle_bytes,
        **section_limits,
        "not_before_utc": not_before.isoformat(),
        "not_after_utc": not_after.isoformat(),
        "powershell_runtime": POWERSHELL_RUNTIME,
        "output_root": output_root,
    }


def approval_request(requested: dict[str, Any]) -> dict[str, Any]:
    return {
        key: str(value) if isinstance(value, Path) else value
        for key, value in sorted(requested.items())
    }


def approval_request_sha256(requested: dict[str, Any]) -> str:
    payload = json.dumps(approval_request(requested), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def trusted_windows_powershell() -> Path:
    if os.name != "nt":
        raise RuntimeError("trusted Windows PowerShell is available only on Windows")
    windows_root = Path(os.environ.get("WINDIR") or r"C:\Windows").resolve()
    expected = (windows_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe").resolve()
    if not expected.is_file():
        raise RuntimeError("trusted system Windows PowerShell was not found")
    return expected


def powershell_version(executable: Path) -> str:
    result = subprocess.run(
        [str(executable), "-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    return result.stdout.strip()


def terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, text=True, timeout=5)
        except Exception:
            process.kill()
    else:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def summarize_bundle(path: Path, expected: dict[str, Any], run_id: str) -> dict[str, Any]:
    transport_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    bundle = load_bundle(path)
    if bundle["run_id"] != run_id:
        raise ValueError("collector returned an unexpected run_id")
    if bundle["domain"]["dns_name"].casefold() != expected["domain"].casefold():
        raise ValueError("collector returned an unexpected domain")
    if bundle["scope"]["search_base"].casefold() != expected["search_base"].casefold():
        raise ValueError("collector returned an unexpected search_base")
    if bundle["source_pack_version"] != expected["source_pack_version"]:
        raise ValueError("collector source pack version differs from the approved scope")
    if bundle["mode"] != expected["collection_mode"]:
        raise ValueError("collector mode differs from the approved scope")
    if bundle["scope"].get("collection_profile") != expected["collection_profile"]:
        raise ValueError("collector profile differs from the approved scope")
    actual_groups = {value.casefold() for value in bundle["scope"]["privileged_group_sids"]}
    expected_groups = {value.casefold() for value in expected["group_sids"]}
    if actual_groups != expected_groups:
        raise ValueError("collector group SID scope differs from the approved scope")
    actual_vpn_groups = {value.casefold() for value in bundle["scope"]["vpn_group_sids"]}
    expected_vpn_groups = {value.casefold() for value in expected["vpn_group_sids"]}
    if actual_vpn_groups != expected_vpn_groups:
        raise ValueError("collector VPN group SID scope differs from the approved scope")
    actual_sections = tuple(item["name"] for item in bundle["sections"])
    if actual_sections != expected["sections"]:
        raise ValueError("collector sections differ from the approved scope")
    if len(bundle["records"]) > expected["max_records"] or path.stat().st_size > expected["max_bundle_bytes"]:
        raise ValueError("collector output exceeded the approved budget")
    counts = {"entity": 0, "relation": 0, "data_quality": 0}
    kinds: dict[str, int] = {}
    for record in bundle["records"]:
        counts[record["record_type"]] += 1
        if record["record_type"] == "entity":
            kind = record["identity"]["kind"]
            kinds[kind] = kinds.get(kind, 0) + 1
    return {
        "run_id": run_id,
        "observed_at_utc": bundle["observed_at_utc"],
        "section_status": bundle["sections"][0]["status"] if len(bundle["sections"]) == 1 else None,
        "section_statuses": {item["name"]: item["status"] for item in bundle["sections"]},
        "collector_duration_ms": max((item["duration_ms"] for item in bundle["sections"]), default=0),
        "record_counts": counts,
        "entity_kind_counts": kinds,
        "bundle_bytes": path.stat().st_size,
        "transport_file_sha256": transport_sha256,
        "normalized_content_sha256": bundle["bundle_sha256"],
    }


def require_complete_sections(
    measurements: dict[str, Any], expected: dict[str, Any]
) -> None:
    statuses = dict(measurements.get("section_statuses") or {})
    incomplete = [
        f"{section}={statuses.get(section, 'missing')}"
        for section in expected["sections"]
        if statuses.get(section) != "complete"
    ]
    if incomplete:
        raise RuntimeError(
            "AD Context collector did not complete the approved section: "
            + ", ".join(incomplete)
        )


def run(args: argparse.Namespace) -> dict[str, Any]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    requested = validate_request(args)
    approved_scope = approval_request(requested)
    request_sha256 = approval_request_sha256(requested)
    base = {
        "package_type": "ADCTX-LIVE-CANARY-1",
        "generated_at_utc": utc_now(),
        "mode": "execute" if args.execute else "validate_only",
        "approved_scope": approved_scope,
        "approval_request_sha256": request_sha256,
        "output_root": str(requested["output_root"]),
        "database_imported": False,
        "scheduler_changed": False,
        "runtime_restarted": False,
        "gpo_changed": False,
        "html_generated": False,
        "credentials_accepted": False,
        "live_ad_contacted": False,
        "approval_hash_verified": False,
    }
    if not args.execute:
        return {**base, "status": "validated_only"}
    if args.confirmation != CONFIRMATION:
        raise ValueError(f"execute requires --confirmation {CONFIRMATION}")
    supplied_approval = str(args.approved_request_sha256 or "").strip().lower()
    if not SHA256_RE.fullmatch(supplied_approval) or supplied_approval != request_sha256:
        raise PermissionError("execute requires the owner-approved SHA-256 of this exact request")
    now = datetime.now(timezone.utc)
    not_before = parse_utc(requested["not_before_utc"], "not_before_utc")
    not_after = parse_utc(requested["not_after_utc"], "not_after_utc")
    if not not_before <= now <= not_after:
        raise PermissionError("the approved live-canary execution window is not active")
    if os.name != "nt":
        raise RuntimeError("live AD canary execution is supported only on the Windows SLI host")
    account = current_windows_account()
    if account.casefold() != requested["expected_account"].casefold():
        raise PermissionError("current Windows account differs from expected_account")
    executable = trusted_windows_powershell()
    base["approval_hash_verified"] = True
    base["powershell_executable"] = str(executable)
    base["powershell_version"] = powershell_version(executable)

    output_root: Path = requested["output_root"]
    output_root.mkdir(parents=True, exist_ok=True)
    lock_path = output_root / "ADCTX-LIVE-CANARY-1.lock"
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(f"canary lock already exists: {lock_path}") from exc
    os.write(lock_fd, f"pid={os.getpid()} started={utc_now()}\n".encode("utf-8"))
    os.close(lock_fd)

    run_id = str(uuid4())
    bundle_path = output_root / f"ad_context_live_canary_{run_id}.json"
    evidence_path = output_root / f"ADCTX_LIVE_CANARY_{run_id}.json"
    stdout_path = output_root / f"ADCTX_LIVE_CANARY_{run_id}.stdout.log"
    stderr_path = output_root / f"ADCTX_LIVE_CANARY_{run_id}.stderr.log"
    started = time.monotonic()
    result = dict(base)
    try:
        command = build_ad_context_command(
            AdContextRequest(
                powershell_executable=str(executable),
                output_path=bundle_path,
                run_id=run_id,
                directory_server=requested["directory_server"],
                search_base=requested["search_base"],
                domain=requested["domain"],
                sections=requested["sections"],
                privileged_groups=requested["group_sids"],
                vpn_groups=requested["vpn_group_sids"],
                mode=requested["collection_mode"],
                max_records=requested["max_records"],
                max_bundle_bytes=requested["max_bundle_bytes"],
                max_directory_accounts=requested["max_directory_accounts"],
                max_directory_users=requested["max_directory_users"],
                max_directory_computers=requested["max_directory_computers"],
                max_vpn_members=requested["max_vpn_members"],
                max_gpos=requested["max_gpos"],
            )
        )
        with stdout_path.open("w", encoding="utf-8") as stdout_file, stderr_path.open("w", encoding="utf-8") as stderr_file:
            process = subprocess.Popen(command, cwd=ROOT, stdout=stdout_file, stderr=stderr_file, text=True)
            result["live_ad_contacted"] = True
            try:
                exit_code = process.wait(timeout=requested["timeout_seconds"])
            except subprocess.TimeoutExpired as exc:
                terminate_process_tree(process)
                raise TimeoutError("AD Context collector exceeded the approved timeout") from exc
        if exit_code != 0:
            raise RuntimeError(f"AD Context collector failed with exit code {exit_code}; inspect local stderr log")
        measurements = summarize_bundle(bundle_path, requested, run_id)
        result.update(
            elapsed_ms=round((time.monotonic() - started) * 1000),
            windows_account=account,
            bundle_path=str(bundle_path),
            stdout_log=str(stdout_path),
            stderr_log=str(stderr_path),
            measurements=measurements,
        )
        require_complete_sections(measurements, requested)
        result["status"] = "accepted"
        return result
    except Exception as exc:
        result.update(
            status="failed",
            elapsed_ms=round((time.monotonic() - started) * 1000),
            error_type=type(exc).__name__,
            error=str(exc),
            bundle_path=str(bundle_path),
            stdout_log=str(stdout_path),
            stderr_log=str(stderr_path),
        )
        raise
    finally:
        evidence_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        lock_path.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory-server", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--search-base", required=True)
    parser.add_argument("--section", action="append", choices=SUPPORTED_SECTIONS, default=[])
    parser.add_argument("--group-sid", action="append", default=[])
    parser.add_argument("--vpn-group-sid", action="append", default=[])
    parser.add_argument("--expected-account", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--max-records", type=int, default=2000)
    parser.add_argument("--max-bundle-bytes", type=int, default=2 * 1024 * 1024)
    parser.add_argument("--max-directory-accounts", type=int, default=2000)
    parser.add_argument("--max-directory-users", type=int)
    parser.add_argument("--max-directory-computers", type=int)
    parser.add_argument("--max-vpn-members", type=int, default=500)
    parser.add_argument("--max-gpos", type=int, default=72)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--not-before-utc", required=True)
    parser.add_argument("--not-after-utc", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true")
    mode.add_argument("--validate-only", action="store_true")
    parser.add_argument("--confirmation", default="")
    parser.add_argument("--approved-request-sha256", default="")
    return parser.parse_args()


if __name__ == "__main__":
    try:
        report = run(parse_args())
        print(json.dumps(report, ensure_ascii=False, indent=2))
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}, ensure_ascii=False, indent=2))
        raise SystemExit(1)
