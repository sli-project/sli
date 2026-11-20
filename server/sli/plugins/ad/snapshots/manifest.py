from __future__ import annotations

"""Immutable metadata receipt for one exact AD source collection cycle."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Callable
from uuid import UUID
from zoneinfo import ZoneInfo

from server.sli.plugins.ad.context.contracts import (
    AD_SNAPSHOT_MANIFEST_CONTRACT_VERSION,
    AD_SNAPSHOT_MANIFEST_V1_CONTRACT_VERSION,
    AD_SNAPSHOT_MANIFEST_V2_CONTRACT_VERSION,
    AD_SNAPSHOT_MANIFEST_V3_CONTRACT_VERSION,
)


V1_CONTRACT_VERSION = AD_SNAPSHOT_MANIFEST_V1_CONTRACT_VERSION
V2_CONTRACT_VERSION = AD_SNAPSHOT_MANIFEST_V2_CONTRACT_VERSION
V3_CONTRACT_VERSION = AD_SNAPSHOT_MANIFEST_V3_CONTRACT_VERSION
CONTRACT_VERSION = AD_SNAPSHOT_MANIFEST_CONTRACT_VERSION
SUPPORTED_CONTRACT_VERSIONS = frozenset({V1_CONTRACT_VERSION, V2_CONTRACT_VERSION, V3_CONTRACT_VERSION})
SCHEDULE_TIMEZONE = "Asia/Novosibirsk"
SCHEDULE_LOCAL_HOURS = frozenset({6, 18})
SLOT_SECONDS = 43200
ALLOWED_FAMILY_CONTRACTS = {
    "ad_context_base": "sli.windows.ad-context",
    "ad_privileged_membership": "sli.windows.ad-context",
    "ad_vpn_membership": "sli.windows.ad-context",
    "ad_domain_posture": "sli.windows.ad-context",
    "ad_domain_health": "sli.windows.ad-context",
    "ad_gpo_governance": "sli.windows.ad-context",
    "users_v2": "sli.users-report.v2",
    "computers_v6": "sli.ad-computers.snapshot/2.0",
    "gpo_v2": "sli.ad-gpo.snapshot/1.0",
}
BASE_FAMILIES = frozenset({"ad_context_base", "computers_v6"})
SOURCE_STATES = frozenset({"complete", "partial", "failed"})
TOP_LEVEL_KEYS = frozenset({
    "contract_version", "manifest_id", "domain_id", "domain_sid", "domain_dns",
    "slot_start_utc", "assembled_at_utc", "coverage_state", "members",
    "manifest_sha256", "schedule_timezone", "scheduled_local_at",
})
MEMBER_KEYS = frozenset({
    "family", "contract_id", "source_id", "observed_at_utc", "source_state",
    "payload_sha256", "reason_code",
})
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SourceResolver = Callable[[dict[str, Any]], dict[str, Any] | None]


class SnapshotManifestError(ValueError):
    pass


def snapshot_composition(manifest: dict[str, Any]) -> dict[str, Any]:
    """Version the composition derived from the immutable source references."""
    members = manifest.get("members") or []
    families = set(members) if isinstance(members, dict) else {
        member["family"] for member in members
    }
    parts = ["base_ad"] if BASE_FAMILIES & families else []
    if {"gpo_v2", "ad_gpo_governance"} & families:
        parts.append("gpo")
    return {"version": 1, "parts": parts}


def v2_schedule_header(slot_start_utc: Any) -> dict[str, str]:
    """Return the canonical Novosibirsk header for an exact v2 slot."""
    slot = _parse_utc(slot_start_utc, "slot_start_utc")
    local = slot.astimezone(ZoneInfo(SCHEDULE_TIMEZONE))
    if (
        local.hour not in SCHEDULE_LOCAL_HOURS
        or local.minute != 0
        or local.second != 0
        or local.microsecond != 0
    ):
        raise SnapshotManifestError(
            "v2 slot_start_utc must map to 06:00 or 18:00 Asia/Novosibirsk"
        )
    return {
        "schedule_timezone": SCHEDULE_TIMEZONE,
        "scheduled_local_at": local.replace(tzinfo=None).isoformat(timespec="seconds"),
    }


def canonical_manifest_sha256(value: dict[str, Any]) -> str:
    normalized = _normalize_shape(value, enforce_semantics=False)
    normalized.pop("manifest_sha256", None)
    payload = json.dumps(
        normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def agent_schedule_header(slot_start_utc: Any) -> dict[str, str]:
    """The agent policy validates local hours; v3 preserves the exact UTC slot."""
    slot = _parse_utc(slot_start_utc, "slot_start_utc")
    if slot.second or slot.microsecond:
        raise SnapshotManifestError("v3 slot_start_utc must be an exact minute")
    return {"schedule_timezone": "UTC",
            "scheduled_local_at": slot.replace(tzinfo=None).isoformat(timespec="seconds")}


def validate_snapshot_manifest(
    value: dict[str, Any], *, resolve_source: SourceResolver
) -> dict[str, Any]:
    normalized = _normalize_shape(value)
    supplied_hash = str(value.get("manifest_sha256") or "").strip().lower()
    calculated_hash = canonical_manifest_sha256(normalized)
    if supplied_hash != calculated_hash:
        raise SnapshotManifestError("manifest hash does not match canonical metadata")
    normalized["manifest_sha256"] = calculated_hash

    slot = _parse_utc(normalized["slot_start_utc"], "slot_start_utc")
    slot_end = slot + timedelta(seconds=SLOT_SECONDS)
    for member in normalized["members"]:
        readback = resolve_source(dict(member))
        if readback is None:
            raise SnapshotManifestError("manifest source member does not exist as completed/imported")
        _validate_readback(normalized, member, readback, slot, slot_end)
    return normalized


def _normalize_shape(
    value: dict[str, Any], *, enforce_semantics: bool = True
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SnapshotManifestError("manifest must be an object")
    unknown = sorted(set(value) - TOP_LEVEL_KEYS)
    if unknown:
        raise SnapshotManifestError(f"manifest has unsupported fields: {', '.join(unknown)}")
    contract_version = str(value.get("contract_version") or "")
    if contract_version not in SUPPORTED_CONTRACT_VERSIONS:
        raise SnapshotManifestError("unsupported manifest contract_version")
    manifest_id = _uuid(value.get("manifest_id"), "manifest_id")
    try:
        domain_id = int(value.get("domain_id"))
    except (TypeError, ValueError) as exc:
        raise SnapshotManifestError("domain_id must be a positive integer") from exc
    if domain_id <= 0:
        raise SnapshotManifestError("domain_id must be a positive integer")
    domain_sid = _text(value.get("domain_sid"), "domain_sid", 256)
    domain_dns = _text(value.get("domain_dns"), "domain_dns", 253).lower()
    slot_start = _canonical_utc(value.get("slot_start_utc"), "slot_start_utc")
    slot = _parse_utc(slot_start, "slot_start_utc")
    schedule_header: dict[str, str] = {}
    if contract_version == V1_CONTRACT_VERSION:
        if any(value.get(key) not in (None, "") for key in ("schedule_timezone", "scheduled_local_at")):
            raise SnapshotManifestError("v1 manifest cannot declare a schedule header")
        if (
            slot.minute != 0
            or slot.second != 0
            or slot.microsecond != 0
            or slot.hour not in {0, 12}
        ):
            raise SnapshotManifestError("v1 slot_start_utc must be 00:00 or 12:00 UTC")
    else:
        expected_header = (agent_schedule_header(slot) if contract_version == V3_CONTRACT_VERSION
                           else v2_schedule_header(slot))
        schedule_timezone = _text(value.get("schedule_timezone"), "schedule_timezone", 64)
        scheduled_local_at = _canonical_scheduled_local_at(value.get("scheduled_local_at"))
        if (
            schedule_timezone != expected_header["schedule_timezone"]
            or scheduled_local_at != expected_header["scheduled_local_at"]
        ):
            raise SnapshotManifestError(
                f"{'v3' if contract_version == V3_CONTRACT_VERSION else 'v2'} schedule header does not match slot_start_utc"
            )
        schedule_header = expected_header
    assembled = _canonical_utc(value.get("assembled_at_utc"), "assembled_at_utc")
    if _parse_utc(assembled, "assembled_at_utc") < slot:
        raise SnapshotManifestError("assembled_at_utc cannot precede slot_start_utc")
    coverage = str(value.get("coverage_state") or "")
    if coverage not in {"complete", "partial"}:
        raise SnapshotManifestError("coverage_state must be complete or partial")
    raw_members = value.get("members")
    if not isinstance(raw_members, list) or not raw_members:
        raise SnapshotManifestError("members must be a non-empty array")
    members = [_normalize_member(item) for item in raw_members]
    families = [member["family"] for member in members]
    if len(families) != len(set(families)):
        raise SnapshotManifestError("manifest member families must be unique")
    if enforce_semantics:
        missing_base = sorted(BASE_FAMILIES - set(families))
        if missing_base:
            raise SnapshotManifestError("manifest is missing required base families")
        if any(
            member["family"] in BASE_FAMILIES
            and member["source_state"] == "failed"
            for member in members
        ):
            raise SnapshotManifestError(
                "hard-failed base source prevents manifest publication"
            )
        expected_coverage = (
            "complete"
            if all(member["source_state"] == "complete" for member in members)
            else "partial"
        )
        if coverage != expected_coverage:
            raise SnapshotManifestError(
                "coverage_state is inconsistent with source members"
            )
    return {
        "contract_version": contract_version,
        "manifest_id": manifest_id,
        "domain_id": domain_id,
        "domain_sid": domain_sid,
        "domain_dns": domain_dns,
        "slot_start_utc": slot_start,
        "assembled_at_utc": assembled,
        "coverage_state": coverage,
        "members": sorted(members, key=lambda member: member["family"]),
        **schedule_header,
        **({"manifest_sha256": str(value["manifest_sha256"]).strip().lower()}
           if value.get("manifest_sha256") is not None else {}),
    }


def _normalize_member(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SnapshotManifestError("manifest member must be an object")
    unknown = sorted(set(value) - MEMBER_KEYS)
    if unknown:
        raise SnapshotManifestError(f"manifest member has unsupported fields: {', '.join(unknown)}")
    family = str(value.get("family") or "")
    if family not in ALLOWED_FAMILY_CONTRACTS:
        raise SnapshotManifestError("manifest member family is unsupported")
    contract_id = _text(value.get("contract_id"), "member.contract_id", 128)
    if contract_id != ALLOWED_FAMILY_CONTRACTS[family]:
        raise SnapshotManifestError("manifest member contract_id does not match family")
    source_id = _text(value.get("source_id"), "member.source_id", 128)
    if family != "users_v2":
        source_id = _uuid(source_id, "member.source_id")
    elif not source_id.isdigit() or int(source_id) <= 0:
        raise SnapshotManifestError("users_v2 member.source_id must be a positive snapshot ID")
    source_state = str(value.get("source_state") or "")
    if source_state not in SOURCE_STATES:
        raise SnapshotManifestError("manifest member source_state is unsupported")
    digest = str(value.get("payload_sha256") or "").strip().lower()
    if not SHA256_RE.fullmatch(digest):
        raise SnapshotManifestError("manifest member payload_sha256 is invalid")
    reason = value.get("reason_code")
    if reason in (None, ""):
        reason = None
    else:
        reason = _text(reason, "member.reason_code", 128)
    if source_state == "complete" and reason is not None:
        raise SnapshotManifestError("complete source member cannot have reason_code")
    if source_state != "complete" and reason is None:
        raise SnapshotManifestError("non-complete source member requires reason_code")
    return {
        "family": family,
        "contract_id": contract_id,
        "source_id": source_id,
        "observed_at_utc": _canonical_utc(value.get("observed_at_utc"), "member.observed_at_utc"),
        "source_state": source_state,
        "payload_sha256": digest,
        "reason_code": reason,
    }


def _validate_readback(
    manifest: dict[str, Any], member: dict[str, Any], readback: dict[str, Any],
    slot: datetime, slot_end: datetime,
) -> None:
    if str(readback.get("import_state") or "") != "completed":
        raise SnapshotManifestError("manifest source must exist in completed/imported state")
    if int(readback.get("domain_id") or 0) != manifest["domain_id"]:
        raise SnapshotManifestError("manifest source domain_id differs from manifest domain")
    if str(readback.get("domain_sid") or "").casefold() != manifest["domain_sid"].casefold():
        raise SnapshotManifestError("manifest source domain SID differs from manifest domain")
    if str(readback.get("domain_dns") or "").casefold() != manifest["domain_dns"].casefold():
        raise SnapshotManifestError("manifest source DNS domain differs from manifest domain")
    observed = _parse_utc(readback.get("observed_at_utc"), "source observed_at_utc")
    if manifest["contract_version"] == V3_CONTRACT_VERSION:
        if observed < slot or observed > _parse_utc(manifest["assembled_at_utc"], "assembled_at_utc"):
            raise SnapshotManifestError("manifest source observation is outside the agent cycle")
    elif observed < slot or observed >= slot_end:
        raise SnapshotManifestError("manifest source observation is outside the half-day slot")
    exact_fields = (
        "family", "contract_id", "source_id", "source_state", "payload_sha256"
    )
    if any(str(readback.get(field)) != str(member[field]) for field in exact_fields):
        raise SnapshotManifestError("manifest source readback does not match declared metadata")
    declared_observed = _parse_utc(member["observed_at_utc"], "member observed_at_utc")
    if observed != declared_observed:
        raise SnapshotManifestError("manifest source readback does not match declared metadata")


def _uuid(value: Any, label: str) -> str:
    try:
        return str(UUID(str(value or "")))
    except ValueError as exc:
        raise SnapshotManifestError(f"{label} must be a UUID") from exc


def _text(value: Any, label: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise SnapshotManifestError(f"{label} is required and bounded")
    return text


def _parse_utc(value: Any, label: str) -> datetime:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SnapshotManifestError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise SnapshotManifestError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _canonical_utc(value: Any, label: str) -> str:
    return _parse_utc(value, label).isoformat().replace("+00:00", "Z")


def _canonical_scheduled_local_at(value: Any) -> str:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SnapshotManifestError("scheduled_local_at must be ISO-8601 local civil time") from exc
    if parsed.tzinfo is not None:
        raise SnapshotManifestError("scheduled_local_at must not include a timezone")
    return parsed.isoformat(timespec="seconds")
