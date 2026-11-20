"""Snapshot qualification and one-shot assembly without acquisition workers."""
from __future__ import annotations

import math
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid5
from zoneinfo import ZoneInfo

from server.sli.plugins.ad.snapshots.manifest import (
    V1_CONTRACT_VERSION, V2_CONTRACT_VERSION, SCHEDULE_TIMEZONE, SCHEDULE_LOCAL_HOURS,
    canonical_manifest_sha256, snapshot_composition, validate_snapshot_manifest,
    V3_CONTRACT_VERSION, agent_schedule_header,
)

INTERVAL_SECONDS = 43200
BASE_PROFILE = "ad_snapshot_base_v1"
BASE_SECTIONS = ("directory_accounts", "directory_group_graph", "directory_exact_logon")
AD_FAMILY_SPECS = {
    "ad_context_base": (BASE_PROFILE, BASE_SECTIONS),
    "ad_privileged_membership": (None, ("privileged_membership",)),
    "ad_vpn_membership": (None, ("vpn_membership",)),
    "ad_domain_posture": (None, ("domain_posture",)),
    "ad_domain_health": (None, ("domain_health",)),
    "ad_gpo_governance": (None, ("gpo_governance",)),
}
AD_FAMILIES = tuple(AD_FAMILY_SPECS)
MAX_RECORDS = 50_000
MAX_BUNDLE_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_DIRECTORY_USERS = 40_000
DEFAULT_MAX_DIRECTORY_COMPUTERS = 10_000
BASE_BLOCKING_QUALITY_CODES = frozenset({
    "directory_accounts_truncated", "directory_accounts_failed",
    "directory_group_graph_truncated", "directory_group_memberships_truncated",
    "directory_group_links_unresolved", "directory_group_graph_failed",
    "exact_last_logon_users_truncated", "exact_last_logon_dc_coverage_partial",
    "directory_exact_logon_failed",
})
TECHNICAL_INVENTORY_QUALITY_CODE = re.compile(
    r"^technical_inventory_[a-z0-9][a-z0-9.-]{0,252}_(?:timeout|failed)$"
)


def _qualify_base_bundle(bundle: Mapping[str, Any]) -> dict[str, Any]:
    section_states = {
        str(item.get("name") or ""): str(item.get("status") or "")
        for item in bundle.get("sections") or []
    }
    section_errors = {
        str(item.get("name") or ""): item.get("error_code")
        for item in bundle.get("sections") or []
    }
    quality_codes = {section: set() for section in BASE_SECTIONS}
    for record in bundle.get("records") or []:
        if record.get("record_type") != "data_quality":
            continue
        section = str(record.get("section") or "")
        if section in quality_codes:
            quality_codes[section].add(str(record.get("code") or ""))

    all_quality_codes = set().union(*quality_codes.values())
    unknown_codes = sorted(
        code for code in all_quality_codes
        if code != "password_expiry_partial"
        and code not in BASE_BLOCKING_QUALITY_CODES
        and not TECHNICAL_INVENTORY_QUALITY_CODE.fullmatch(code)
    )
    blocking_codes = sorted(all_quality_codes & BASE_BLOCKING_QUALITY_CODES)
    blocking_reasons: list[str] = []
    if set(section_states) != set(BASE_SECTIONS):
        blocking_reasons.append("base_section_set_mismatch")
    for section in BASE_SECTIONS:
        state = section_states.get(section)
        error_code = section_errors.get(section)
        if section == "directory_accounts" and state == "partial":
            if error_code != "collection_incomplete" or "password_expiry_partial" not in quality_codes[section]:
                blocking_reasons.append("directory_accounts_unapproved_partial_reason")
        elif state != "complete" or error_code is not None:
            blocking_reasons.append(f"{section}_state_or_error_inconsistent")
        elif section == "directory_accounts" and "password_expiry_partial" in quality_codes[section]:
            blocking_reasons.append("directory_accounts_state_or_error_inconsistent")
    if blocking_codes:
        blocking_reasons.append("blocking_data_quality_code")
    if unknown_codes:
        blocking_reasons.append("unknown_data_quality_code")
    return {
        "usable": not blocking_reasons,
        "coverage_state": "complete" if set(section_states.values()) == {"complete"} else "partial",
        "section_states": section_states,
        "section_error_codes": section_errors,
        "data_quality_codes": {section: sorted(codes) for section, codes in quality_codes.items()},
        "accepted_partial_reasons": {"directory_accounts": ["password_expiry_partial"]},
        "blocking_codes": blocking_codes,
        "unknown_codes": unknown_codes,
        "blocking_reasons": blocking_reasons,
    }


@dataclass(frozen=True)
class ScheduledSlot:
    schedule_timezone: str
    scheduled_local_at: str
    slot_start_utc: str


def slot_start_utc(value: datetime) -> str:
    """Legacy v1 UTC-half-day boundary retained for compatibility callers."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("slot_timestamp_must_be_timezone_aware")
    stamp = value.astimezone(timezone.utc)
    return stamp.replace(hour=12 if stamp.hour >= 12 else 0, minute=0, second=0, microsecond=0).isoformat().replace("+00:00", "Z")


def scheduled_slot_from_local(value: datetime) -> ScheduledSlot:
    """Resolve one 06:00/18:00 Novosibirsk civil boundary through ZoneInfo."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("scheduled_slot_timestamp_must_be_timezone_aware")
    local = value.astimezone(ZoneInfo(SCHEDULE_TIMEZONE))
    if (
        local.hour not in SCHEDULE_LOCAL_HOURS
        or local.minute != 0
        or local.second != 0
        or local.microsecond != 0
    ):
        raise ValueError("scheduled_slot_must_be_06_or_18_asia_novosibirsk")
    return ScheduledSlot(
        schedule_timezone=SCHEDULE_TIMEZONE,
        scheduled_local_at=local.replace(tzinfo=None).isoformat(timespec="seconds"),
        slot_start_utc=local.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


def scheduled_slot_from_utc(value: datetime) -> ScheduledSlot:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("scheduled_slot_timestamp_must_be_timezone_aware")
    return scheduled_slot_from_local(value.astimezone(ZoneInfo(SCHEDULE_TIMEZONE)))


def latest_due_scheduled_slot(now: datetime) -> ScheduledSlot:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("scheduled_slot_timestamp_must_be_timezone_aware")
    stamp = now.astimezone(timezone.utc)
    local_now = stamp.astimezone(ZoneInfo(SCHEDULE_TIMEZONE))
    for hour in (18, 6):
        candidate = local_now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if candidate.astimezone(timezone.utc) <= stamp:
            return scheduled_slot_from_local(candidate)
    yesterday_evening = (local_now - timedelta(days=1)).replace(
        hour=18, minute=0, second=0, microsecond=0
    )
    return scheduled_slot_from_local(yesterday_evening)


def next_scheduled_slot(now: datetime) -> ScheduledSlot:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("scheduled_slot_timestamp_must_be_timezone_aware")
    stamp = now.astimezone(timezone.utc)
    local_now = stamp.astimezone(ZoneInfo(SCHEDULE_TIMEZONE))
    for hour in (6, 18):
        candidate = local_now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if candidate.astimezone(timezone.utc) > stamp:
            return scheduled_slot_from_local(candidate)
    tomorrow_morning = (local_now + timedelta(days=1)).replace(
        hour=6, minute=0, second=0, microsecond=0
    )
    return scheduled_slot_from_local(tomorrow_morning)


def seconds_until_next_scheduled_slot(now: datetime) -> int:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("scheduled_slot_timestamp_must_be_timezone_aware")
    next_slot = next_scheduled_slot(now)
    target = datetime.fromisoformat(next_slot.slot_start_utc.replace("Z", "+00:00"))
    return max(0, math.ceil((target - now.astimezone(timezone.utc)).total_seconds()))


def _resolve_manifest_slot(
    requested_slot_start_utc: str,
    *,
    contract_version: str | None,
    schedule_timezone: str | None,
    scheduled_local_at: str | None,
) -> tuple[str, str, ScheduledSlot | None]:
    parsed_slot = datetime.fromisoformat(str(requested_slot_start_utc).replace("Z", "+00:00"))
    if parsed_slot.tzinfo is None or parsed_slot.utcoffset() is None:
        raise ValueError("slot_start_utc_must_be_timezone_aware")
    canonical_slot = parsed_slot.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if contract_version is None:
        contract_version = (
            V1_CONTRACT_VERSION
            if slot_start_utc(parsed_slot) == canonical_slot
            else V2_CONTRACT_VERSION
        )
    if contract_version not in {V1_CONTRACT_VERSION, V2_CONTRACT_VERSION, V3_CONTRACT_VERSION}:
        raise ValueError("unsupported_manifest_contract_version")
    if contract_version == V1_CONTRACT_VERSION:
        if canonical_slot != slot_start_utc(parsed_slot):
            raise ValueError("slot_start_utc_must_be_exact_00_or_12_utc")
        if schedule_timezone is not None or scheduled_local_at is not None:
            raise ValueError("v1_manifest_cannot_declare_schedule_header")
        return canonical_slot, contract_version, None

    if contract_version == V3_CONTRACT_VERSION:
        header = agent_schedule_header(parsed_slot)
        scheduled_slot = ScheduledSlot(**header, slot_start_utc=canonical_slot)
    else:
        scheduled_slot = scheduled_slot_from_utc(parsed_slot)
    if canonical_slot != scheduled_slot.slot_start_utc:
        raise ValueError("slot_start_utc_must_be_exact_06_or_18_asia_novosibirsk")
    if (
        schedule_timezone is not None
        and schedule_timezone != scheduled_slot.schedule_timezone
    ):
        raise ValueError("schedule_timezone_does_not_match_slot")
    if (
        scheduled_local_at is not None
        and scheduled_local_at != scheduled_slot.scheduled_local_at
    ):
        raise ValueError("scheduled_local_at_does_not_match_slot")
    return canonical_slot, contract_version, scheduled_slot


def _exact_manifest(
    *,
    slot: str,
    domain: Mapping[str, Any],
    members: list[dict[str, Any]],
    assembled_at: str,
    contract_version: str,
    scheduled_slot: ScheduledSlot | None,
) -> dict[str, Any]:
    ordered = sorted((dict(member) for member in members), key=lambda item: str(item["family"]))
    identity = json.dumps(
        {"contract": contract_version, "domain_id": int(domain["id"]), "slot": slot,
         "schedule": (
             {"timezone": scheduled_slot.schedule_timezone, "local_at": scheduled_slot.scheduled_local_at}
             if scheduled_slot is not None else None
         ),
         "members": [{"family": item["family"], "source_id": item["source_id"], "sha256": item["payload_sha256"]} for item in ordered]},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    manifest: dict[str, Any] = {
        "contract_version": contract_version,
        "manifest_id": str(uuid5(NAMESPACE_URL, identity)),
        "domain_id": int(domain["id"]),
        "domain_sid": str(domain["sid"]),
        "domain_dns": str(domain["dns"]).lower(),
        "slot_start_utc": slot,
        "assembled_at_utc": assembled_at,
        "coverage_state": "complete" if all(item["source_state"] == "complete" for item in ordered) else "partial",
        "members": ordered,
        **(
            {
                "schedule_timezone": scheduled_slot.schedule_timezone,
                "scheduled_local_at": scheduled_slot.scheduled_local_at,
            }
            if scheduled_slot is not None else {}
        ),
    }
    manifest["manifest_sha256"] = canonical_manifest_sha256(manifest)
    return manifest


def _require_descriptor(value: Any, family: str) -> dict[str, Any]:
    descriptor = dict(value or {})
    if descriptor.get("family") != family:
        raise RuntimeError(f"{family}_exact_source_descriptor_missing")
    required = {"contract_id", "source_id", "observed_at_utc", "source_state", "payload_sha256", "reason_code"}
    if not required.issubset(descriptor):
        raise RuntimeError(f"{family}_exact_source_descriptor_incomplete")
    return descriptor


def run_one_shot(
    *,
    slot_start_utc: str,
    domain: Mapping[str, Any],
    execute: bool,
    acquire_ad_family: Callable[[str], Any],
    import_ad_family: Callable[[Any, str], Any],
    persist_users: Callable[[Any], Any],
    persist_computers: Callable[[list[Mapping[str, Any]]], Any],
    publish: Callable[[dict[str, Any]], Any],
    import_gpo: Callable[[Any], Any],
    assembled_at_utc: str | None = None,
    lookup_existing: Callable[..., Any] | None = None,
    resolve_existing_source: Callable[[dict[str, Any]], Any] | None = None,
    verify_existing_base: Callable[[list[dict[str, Any]]], Any] | None = None,
    contract_version: str | None = None,
    schedule_timezone: str | None = None,
    scheduled_local_at: str | None = None,
    gpo_enabled: bool = True,
) -> dict[str, Any]:
    """Execute every active AD source family once without report cutover."""
    active_families = tuple(
        family for family in AD_FAMILIES
        if gpo_enabled or family != "ad_gpo_governance"
    )
    slot_start_utc, active_contract_version, scheduled_slot = _resolve_manifest_slot(
        slot_start_utc,
        contract_version=contract_version,
        schedule_timezone=schedule_timezone,
        scheduled_local_at=scheduled_local_at,
    )
    for key in ("id", "sid", "dns"):
        if not domain.get(key):
            raise ValueError(f"domain_{key}_required")
    if not execute:
        return {
            "status": "validated", "slot_start_utc": slot_start_utc,
            "domain_dns": str(domain["dns"]).lower(), "source_contacted": False,
            "database_modified": False, "expected_interval_seconds": INTERVAL_SECONDS,
            "families": list(active_families), "contract_version": active_contract_version,
            **(
                {
                    "schedule_timezone": scheduled_slot.schedule_timezone,
                    "scheduled_local_at": scheduled_slot.scheduled_local_at,
                }
                if scheduled_slot is not None else {}
            ),
        }

    existing = lookup_existing(
        domain_id=int(domain["id"]), slot_start_utc=slot_start_utc,
        contract_version=active_contract_version,
    ) if lookup_existing is not None else None
    if existing is not None:
        if resolve_existing_source is None:
            raise RuntimeError("existing_manifest_source_resolver_required")
        candidate = dict(existing)
        if (candidate.get("contract_version") != active_contract_version
                or int(candidate.get("domain_id") or 0) != int(domain["id"])
                or str(candidate.get("domain_sid") or "").casefold() != str(domain["sid"]).casefold()
                or str(candidate.get("domain_dns") or "").casefold() != str(domain["dns"]).casefold()
                or candidate.get("slot_start_utc") != slot_start_utc):
            raise RuntimeError("existing_manifest_header_mismatch")
        if scheduled_slot is not None and (
            candidate.get("schedule_timezone") != scheduled_slot.schedule_timezone
            or candidate.get("scheduled_local_at") != scheduled_slot.scheduled_local_at
        ):
            raise RuntimeError("existing_manifest_schedule_header_mismatch")
        base_families = (set(AD_FAMILIES) - {"ad_gpo_governance"}) | {"users_v2", "computers_v6"}
        full_families = base_families | {"ad_gpo_governance", "gpo_v2"}
        if {str(item.get("family") or "") for item in candidate.get("members") or []} not in (
            base_families, full_families,
        ):
            raise RuntimeError("existing_manifest_family_set_mismatch")
        verified = validate_snapshot_manifest(candidate, resolve_source=resolve_existing_source)
        members = list(verified["members"])
        if verify_existing_base is None:
            raise RuntimeError("existing_manifest_base_verifier_required")
        base_proof = dict(verify_existing_base(members) or {})
        if base_proof.get("usable") is not True:
            raise RuntimeError(
                f"existing_manifest_required_base_not_usable:{json.dumps(base_proof, sort_keys=True)}"
            )
        partial = sorted(item["family"] for item in members if item["source_state"] != "complete")
        return {
            "status": "replayed_existing", "slot_start_utc": slot_start_utc,
            "domain_dns": str(domain["dns"]).lower(), "source_contacted": False,
            "database_contacted": True, "database_modified": False,
            "contract_version": active_contract_version,
            "base_complete": True, "manifest_id": verified["manifest_id"],
            "manifest_sha256": verified["manifest_sha256"],
            "coverage_state": verified["coverage_state"], "partial_families": partial,
            "composition": snapshot_composition(verified),
            "source_hashes": {item["family"]: item["payload_sha256"] for item in members},
            "source_ids": {item["family"]: item["source_id"] for item in members},
            "source_states": {item["family"]: item["source_state"] for item in members},
            "replayed": 1, "single_query_proof": False,
            **(
                {
                    "schedule_timezone": scheduled_slot.schedule_timezone,
                    "scheduled_local_at": scheduled_slot.scheduled_local_at,
                }
                if scheduled_slot is not None else {}
            ),
        }

    base = dict(acquire_ad_family("ad_context_base") or {})
    acquisition = dict(base.get("acquisition") or {})
    if acquisition.get("profile") != BASE_PROFILE:
        raise RuntimeError("base_profile_mismatch")
    if int(acquisition.get("user_full_queries") or 0) != 1 or int(acquisition.get("computer_full_queries") or 0) != 1:
        raise RuntimeError("base_single_query_contract_failed")
    if base.get("base_complete") is not True:
        raise RuntimeError(f"base_source_not_complete:{json.dumps(base.get('base_qualification') or {}, sort_keys=True)}")
    base_bundle = base.get("bundle")
    if not isinstance(base_bundle, Mapping):
        raise RuntimeError("base_bundle_missing")

    members = [
        _require_descriptor(import_ad_family(base_bundle, "ad_context_base"), "ad_context_base"),
        _require_descriptor(persist_users(base_bundle), "users_v2"),
        _require_descriptor(persist_computers(list(base.get("computer_rows") or [])), "computers_v6"),
    ]
    if any(item["family"] in {"ad_context_base", "computers_v6"} and item["source_state"] == "failed" for item in members):
        raise RuntimeError("required_base_family_failed")

    gpo_bundle: Mapping[str, Any] | None = None
    for family in active_families[1:]:
        acquired = dict(acquire_ad_family(family) or {})
        bundle = acquired.get("bundle")
        if not isinstance(bundle, Mapping):
            raise RuntimeError(f"{family}_bundle_missing")
        members.append(_require_descriptor(import_ad_family(bundle, family), family))
        if family == "ad_gpo_governance":
            gpo_bundle = bundle
    if gpo_enabled:
        if gpo_bundle is None:
            raise RuntimeError("gpo_v2_import_not_configured")
        members.append(_require_descriptor(import_gpo(gpo_bundle), "gpo_v2"))

    assembled = assembled_at_utc or max(str(item["observed_at_utc"]) for item in members)
    manifest = _exact_manifest(
        slot=slot_start_utc,
        domain=domain,
        members=members,
        assembled_at=assembled,
        contract_version=active_contract_version,
        scheduled_slot=scheduled_slot,
    )
    publication = dict(publish(manifest) or {})
    if (str(publication.get("manifest_id") or "") != manifest["manifest_id"]
            or publication.get("readback_verified") is not True):
        raise RuntimeError("manifest_publication_exact_readback_failed")
    partial = sorted(item["family"] for item in members if item["source_state"] != "complete")
    invocation_counts = {
        "base_invocations": 1, "privileged_invocations": 1,
        "vpn_invocations": 1, "posture_invocations": 1,
        "health_invocations": 1, "gpo_invocations": int(gpo_enabled),
        "user_full_queries": 1, "computer_full_queries": 1, "gpo_v2_queries": int(gpo_enabled),
    }
    return {
        "status": "published", "slot_start_utc": slot_start_utc,
        "domain_dns": str(domain["dns"]).lower(), "source_contacted": True,
        "database_modified": True, "base_complete": True,
        "contract_version": active_contract_version,
        "manifest_id": manifest["manifest_id"],
        "manifest_sha256": manifest["manifest_sha256"],
        "coverage_state": manifest["coverage_state"], "partial_families": partial,
        "composition": snapshot_composition(manifest),
        "source_hashes": {item["family"]: item["payload_sha256"] for item in members},
        "source_ids": {item["family"]: item["source_id"] for item in members},
        "source_states": {item["family"]: item["source_state"] for item in members},
        "acquisition": invocation_counts,
        "replayed": int(publication.get("replayed") or 0),
        "database_contacted": True, "single_query_proof": True,
        **(
            {
                "schedule_timezone": scheduled_slot.schedule_timezone,
                "scheduled_local_at": scheduled_slot.scheduled_local_at,
            }
            if scheduled_slot is not None else {}
        ),
    }


def _iso_utc_to_windows_filetime(value: Any) -> int | None:
    if value is None:
        return None
    match = re.fullmatch(
        r"(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
        r"(?:\.(?P<fraction>\d{1,7}))?(?P<zone>Z|[+-]\d{2}:\d{2})",
        str(value),
    )
    if match is None:
        raise ValueError("computer_last_logon_timestamp_must_be_iso_utc")
    zone = "+00:00" if match.group("zone") == "Z" else match.group("zone")
    stamp = datetime.fromisoformat(f"{match.group('base')}{zone}").astimezone(timezone.utc)
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = stamp - epoch
    fraction_ticks = int((match.group("fraction") or "0").ljust(7, "0"))
    return ((delta.days * 86400 + delta.seconds) * 10_000_000) + fraction_ticks


def _computer_rows(bundle: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in bundle.get("records") or []:
        if record.get("section") != "directory_accounts":
            continue
        identity = dict(record.get("identity") or {})
        if identity.get("kind") != "ad_computer":
            continue
        attributes = dict(record.get("attributes") or {})
        rows.append({
            "Name": attributes.get("display_name"),
            "OperatingSystem": attributes.get("operating_system"),
            "ServicePrincipalName": attributes.get("service_principal_names"),
            "DNSHostName": attributes.get("dns_host_name"),
            "ObjectGUID": identity.get("object_guid"),
            "lastLogonTimestamp": _iso_utc_to_windows_filetime(attributes.get("last_logon_utc")),
            "OperatingSystemVersion": attributes.get("operating_system_version"),
            "OperatingSystemServicePack": attributes.get("operating_system_service_pack"),
            "Enabled": attributes.get("enabled"),
            "CanonicalName": attributes.get("canonical_name"),
            "DistinguishedName": attributes.get("distinguished_name"),
            "PasswordLastSet": attributes.get("password_last_set_utc"),
            "whenCreated": attributes.get("created_utc"),
            "whenChanged": attributes.get("when_changed_utc"),
            "Description": attributes.get("description"),
            "Location": attributes.get("location"),
            "ManagedBy": attributes.get("managed_by"),
            "SID": identity.get("object_sid"),
            "userAccountControl": attributes.get("user_account_control"),
            "TrustedForDelegation": attributes.get("trusted_for_delegation"),
            "TrustedToAuthForDelegation": attributes.get("trusted_to_auth_for_delegation"),
        })
    return rows


def _source_descriptor(connection: Any, family: str, source_id: str) -> dict[str, Any]:
    from server.sli.plugins.ad.context.repository import _resolve_manifest_source
    with connection.cursor() as cursor:
        row = _resolve_manifest_source(cursor, {"family": family, "source_id": str(source_id)})
    if row is None:
        raise RuntimeError(f"{family}_exact_source_readback_missing")
    return {key: row[key] for key in ("family", "contract_id", "source_id", "observed_at_utc", "source_state", "payload_sha256")} | {"reason_code": None if row["source_state"] == "complete" else f"{family}_source_partial"}
