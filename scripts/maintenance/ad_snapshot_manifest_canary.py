#!/usr/bin/env python3
"""Bounded validate/execute canary for the exact coordinator one-shot path."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.runtime.ad_snapshot_manifest_coordinator_worker import AD_FAMILIES, _default_cycle
from server.sli.plugins.ad.snapshots.coordinator import (
    latest_due_scheduled_slot,
    scheduled_slot_from_utc,
)

EXECUTE_TOKEN = "EXECUTE-AD-SNAPSHOT-MANIFEST-CANARY-SOURCE-AND-DB"
REQUEST_KEYS = frozenset({"account", "slot_start_utc", "window_start_utc", "window_end_utc", "domain_dns"})


def request_sha256(request: Mapping[str, Any]) -> str:
    payload = json.dumps(dict(request), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _utc(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label}_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label}_timezone_required")
    return parsed.astimezone(timezone.utc)


def _validate_request(request: Mapping[str, Any], request_hash: str, current_account: str) -> dict[str, Any]:
    if set(request) != REQUEST_KEYS:
        raise ValueError("canary_request_shape_invalid")
    calculated = request_sha256(request)
    if request_hash.casefold() != calculated:
        raise RuntimeError("canary_request_hash_mismatch")
    if str(request["account"]).casefold() != str(current_account).casefold():
        raise RuntimeError("canary_windows_account_mismatch")
    start = _utc(request["window_start_utc"], "window_start_utc")
    end = _utc(request["window_end_utc"], "window_end_utc")
    slot = _utc(request["slot_start_utc"], "slot_start_utc")
    if end <= start or (end - start).total_seconds() > 1800:
        raise ValueError("canary_window_must_be_positive_and_at_most_30_minutes")
    scheduled_slot = scheduled_slot_from_utc(slot)
    domain = str(request["domain_dns"]).strip().lower()
    if not domain or "." not in domain:
        raise ValueError("canary_domain_dns_invalid")
    return {"request_sha256": calculated, "slot_start_utc": scheduled_slot.slot_start_utc,
            "window_start_utc": start, "window_end_utc": end, "domain_dns": domain}


def run(
    *, request: Mapping[str, Any], request_hash: str, execute: bool,
    confirmation: str | None, current_account: str,
    coordinator: Callable[..., dict[str, Any]],
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    validated = _validate_request(request, request_hash, current_account)
    base = {**validated, "scheduler_changed": False, "processes_changed": False,
            "source_contacted": False, "database_modified": False}
    if not execute:
        return {**base, "status": "validated", "required_confirmation": EXECUTE_TOKEN}
    if confirmation != EXECUTE_TOKEN:
        raise RuntimeError(f"execute requires exact confirmation {EXECUTE_TOKEN}")
    current = now().astimezone(timezone.utc)
    if not (validated["window_start_utc"] <= current < validated["window_end_utc"]):
        raise RuntimeError("canary_current_time_outside_approval_window")
    if latest_due_scheduled_slot(current).slot_start_utc != validated["slot_start_utc"]:
        raise RuntimeError("canary_requested_slot_is_not_current_scheduled_slot")
    result = dict(coordinator(slot_start_utc=validated["slot_start_utc"], domain_dns=validated["domain_dns"]) or {})
    if result.get("status") not in {"published", "replayed_existing"}:
        raise RuntimeError("canary_coordinator_result_status_invalid")
    if result["status"] == "published":
        acquisition = dict(result.get("acquisition") or {})
        if acquisition != {"base_invocations": 1, "privileged_invocations": 1,
                            "vpn_invocations": 1, "posture_invocations": 1,
                            "health_invocations": 1, "gpo_invocations": 1,
                            "user_full_queries": 1, "computer_full_queries": 1,
                            "gpo_v2_queries": 1}:
            raise RuntimeError("canary_acquisition_metadata_failed")
    elif (result.get("source_contacted") is not False
          or result.get("database_modified") is not False
          or result.get("single_query_proof") is not False):
        raise RuntimeError("canary_replay_contact_flags_invalid")
    if result.get("base_complete") is not True:
        raise RuntimeError("canary_complete_base_required")
    if result.get("slot_start_utc") != validated["slot_start_utc"] or str(result.get("domain_dns") or "").casefold() != validated["domain_dns"]:
        raise RuntimeError("canary_slot_or_domain_readback_mismatch")
    expected_families = set(AD_FAMILIES) | {"users_v2", "computers_v6", "gpo_v2"}
    source_hashes = result.get("source_hashes")
    source_ids = result.get("source_ids")
    source_states = result.get("source_states")
    if (not isinstance(source_hashes, dict)
            or set(source_hashes) != expected_families
            or any(len(str(value)) != 64 for value in source_hashes.values())):
        raise RuntimeError("canary_exact_source_hash_readback_missing")
    if (not isinstance(source_ids, dict) or set(source_ids) != expected_families
            or any(not str(value).strip() for value in source_ids.values())):
        raise RuntimeError("canary_exact_source_id_readback_missing")
    if (not isinstance(source_states, dict) or set(source_states) != expected_families
            or any(value not in {"complete", "partial", "failed"} for value in source_states.values())):
        raise RuntimeError("canary_exact_source_state_readback_missing")
    if source_states.get("ad_context_base") == "failed" or source_states.get("computers_v6") == "failed":
        raise RuntimeError("canary_usable_required_base_families_missing")
    surfaced = sorted(family for family, state in source_states.items() if state != "complete")
    if result.get("partial_families") != surfaced:
        raise RuntimeError("canary_optional_noncomplete_families_not_surfaced")
    if len(str(result.get("manifest_sha256") or "")) != 64:
        raise RuntimeError("canary_manifest_hash_readback_missing")
    return {**base, **result, "scheduler_changed": False, "processes_changed": False}


def _account() -> str:
    if os.name == "nt":
        completed = subprocess.run(["whoami"], capture_output=True, text=True, timeout=5, check=True)
        return completed.stdout.strip()
    return getpass.getuser()


def _coordinator(*, slot_start_utc: str, domain_dns: str) -> dict[str, Any]:
    requested = _utc(slot_start_utc, "slot_start_utc")
    scheduled_slot = scheduled_slot_from_utc(requested)
    current = datetime.now(timezone.utc)
    if scheduled_slot != latest_due_scheduled_slot(current):
        raise RuntimeError("canary_requested_slot_is_not_current_scheduled_slot")
    result = _default_cycle(current, domain_dns=domain_dns, scheduled_slot=scheduled_slot)
    if result.get("slot_start_utc") != requested.isoformat().replace("+00:00", "Z"):
        raise RuntimeError("coordinator_returned_unrequested_slot")
    if str(result.get("domain_dns") or "").casefold() != domain_dns.casefold():
        raise RuntimeError("coordinator_returned_unrequested_domain")
    return result


def main(argv: list[str] | None = None) -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-json", required=True)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm")
    args = parser.parse_args(argv)
    try:
        request = json.loads(args.request_json)
        result = run(request=request, request_hash=args.request_sha256, execute=args.execute,
                     confirmation=args.confirm, current_account=_account(), coordinator=_coordinator)
    except Exception as exc:
        result = {"status": "error", "error_type": type(exc).__name__, "error": str(exc),
                  "source_contacted": None if args.execute else False,
                  "database_modified": None if args.execute else False,
                  "scheduler_changed": False, "processes_changed": False}
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0 if result["status"] in {"validated", "published", "replayed_existing"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
