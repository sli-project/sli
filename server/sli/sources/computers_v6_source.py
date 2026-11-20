"""Validated source boundary for the V6 Computers reference collector.

This module is intentionally V6-only.  It validates snapshots produced by the
pinned reference collector before any row can become report authority.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Mapping
from uuid import UUID


SCHEMA_VERSION = "2.0"
MAX_OBJECTS = 250_000
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
SOURCE_STATE_FIELDS = (
    "status",
    "source",
    "value",
    "observed_at",
    "error",
    "details",
)
SOURCE_STATUS_MEANINGS = {
    "observed": "source successfully produced an observation",
    "not_collected": "source was explicitly not queried",
    "not_evaluated": "a missing prerequisite prevented evaluation",
    "missing_in_source": "source read succeeded but the field was absent",
    "no_record": "the query ran but found no matching record",
    "partial": "only part of the required result was obtained",
    "failed": "source operation failed",
    "access_denied": "source access was denied",
    "parse_error": "a returned value could not be converted",
    "not_applicable": "source or condition is inapplicable",
}
NON_HEALTHY_SOURCE_STATUSES = frozenset(SOURCE_STATUS_MEANINGS) - {"observed"}
QUALITY_CATEGORIES = (
    "source_error",
    "not_collected",
    "not_evaluated",
    "no_record_or_missing_source",
    "partial",
    "missing_field",
)
REQUIRED_METADATA_FIELDS = frozenset(
    {
        "snapshot_id",
        "label",
        "started_at",
        "completed_at",
        "query_dc",
        "domain",
        "search_base",
        "collection_status",
        "object_count",
        "collector_version",
        "sources",
        "errors",
    }
)
REQUIRED_OBJECT_FIELDS = frozenset(
    {
        "id",
        "objectGuid",
        "name",
        "dnsHostName",
        "enabled",
        "deviceType",
        "classification",
        "ipv4s",
        "ipv6s",
        "osName",
        "osVersion",
        "osBuild",
        "osFamily",
        "servicePack",
        "ou",
        "distinguishedName",
        "canonicalName",
        "domain",
        "adSite",
        "lastLogonTimestamp",
        "exactLastLogon",
        "eventLastSeen",
        "passwordLastSet",
        "whenCreated",
        "whenChanged",
        "description",
        "location",
        "managedBy",
        "sid",
        "userAccountControl",
        "spns",
        "trustedForDelegation",
        "trustedToAuthForDelegation",
        "roleHint",
        "roleEvidence",
        "collectedAt",
        "queryDc",
        "collectorVersion",
        "sources",
        "collectionErrors",
    }
)
REQUIRED_SOURCE_NAMES = frozenset(
    {
        "ad",
        "dns",
        "os",
        "site",
        "last_logon_timestamp",
        "exact_last_logon",
        "dc_events",
    }
)


class ComputersV6SourceContractError(ValueError):
    """The candidate document is not an authoritative V6 source snapshot."""


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ComputersV6SourceContractError(f"{field}_must_be_object")
    return dict(value)


def _bounded_limit(
    value: Any,
    *,
    hard_maximum: int,
    error_prefix: str,
    allow_zero: bool,
) -> int:
    if isinstance(value, bool):
        raise ComputersV6SourceContractError(f"{error_prefix}_limit_out_of_bounds")
    try:
        limit = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ComputersV6SourceContractError(
            f"{error_prefix}_limit_out_of_bounds"
        ) from exc
    minimum = 0 if allow_zero else 1
    if limit < minimum or limit > hard_maximum:
        raise ComputersV6SourceContractError(f"{error_prefix}_limit_out_of_bounds")
    return limit


def _utc_timestamp(value: Any, *, path: str) -> datetime:
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ComputersV6SourceContractError(f"timestamp_invalid:{path}") from exc
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ComputersV6SourceContractError(f"timestamp_timezone_required:{path}")
    return stamp.astimezone(timezone.utc)


def _validate_source_state(state: Mapping[str, Any], *, path: str) -> None:
    status = str(state.get("status") or "")
    if status not in SOURCE_STATUS_MEANINGS:
        raise ComputersV6SourceContractError(f"source_state_status_invalid:{path}")
    observed_at = state.get("observed_at")
    if status in {
        "observed",
        "missing_in_source",
        "no_record",
        "partial",
        "failed",
        "access_denied",
        "parse_error",
    } and not observed_at:
        raise ComputersV6SourceContractError(
            f"source_state_observed_at_required:{path}:{status}"
        )
    if observed_at is not None:
        _utc_timestamp(observed_at, path=f"{path}.observed_at")
    if status == "not_collected" and (
        state.get("value") is not None or observed_at is not None
    ):
        raise ComputersV6SourceContractError(
            f"source_state_not_collected_must_not_observe:{path}"
        )
    if status in {"not_evaluated", "partial"} and state.get("details") is None:
        raise ComputersV6SourceContractError(
            f"source_state_details_required:{path}:{status}"
        )
    if status in {"failed", "access_denied", "parse_error"} and not state.get(
        "error"
    ):
        raise ComputersV6SourceContractError(
            f"source_state_error_required:{path}:{status}"
        )


def source_is_healthy(status: str) -> bool:
    """Only a successful observation is affirmative; all other states are unknown/error."""
    return str(status or "").strip().lower() == "observed"


def quality_category_for_source_state(
    status: str, *, requested: bool
) -> str | None:
    normalized = str(status or "").strip().lower()
    if normalized in {"failed", "access_denied", "parse_error"}:
        return "source_error"
    if normalized == "not_collected":
        return "not_collected" if requested else None
    if normalized == "not_evaluated":
        return "not_evaluated"
    if normalized in {"no_record", "missing_in_source"}:
        return "no_record_or_missing_source"
    if normalized == "partial":
        return "partial"
    return None


def is_source_quality_issue(state: Mapping[str, Any], *, requested: bool) -> bool:
    return (
        quality_category_for_source_state(
            str(state.get("status") or ""), requested=requested
        )
        is not None
    )


def derive_last_observed(item: Mapping[str, Any]) -> Any:
    for field in ("eventLastSeen", "exactLastLogon", "lastLogonTimestamp"):
        value = item.get(field)
        if value not in (None, ""):
            return value
    return None


def base_inventory_status(snapshot: Mapping[str, Any]) -> str:
    metadata = snapshot.get("metadata")
    if not isinstance(metadata, Mapping):
        return "failed"
    for raw_stage in metadata.get("sources") or []:
        if isinstance(raw_stage, Mapping) and raw_stage.get("name") == "ad":
            status = str(raw_stage.get("status") or "failed")
            return "observed" if status == "observed" else status
    return "failed"


def missing_required_object_fields(item: Mapping[str, Any]) -> list[str]:
    checks = (
        ("osName", item.get("osName")),
        ("dnsHostName", item.get("dnsHostName")),
        ("lastObserved", derive_last_observed(item)),
        ("distinguishedName", item.get("distinguishedName")),
    )
    return [name for name, value in checks if value in (None, "")]


def parse_computers_v6_snapshot(
    payload: bytes | bytearray | str | Mapping[str, Any],
    *,
    max_bytes: int = MAX_SNAPSHOT_BYTES,
    max_objects: int = MAX_OBJECTS,
) -> dict[str, Any]:
    byte_limit = _bounded_limit(
        max_bytes,
        hard_maximum=MAX_SNAPSHOT_BYTES,
        error_prefix="byte",
        allow_zero=False,
    )
    object_limit = _bounded_limit(
        max_objects,
        hard_maximum=MAX_OBJECTS,
        error_prefix="object",
        allow_zero=True,
    )
    if isinstance(payload, Mapping):
        return validate_computers_v6_snapshot(payload, max_objects=object_limit)
    if isinstance(payload, str):
        encoded = payload.encode("utf-8")
    elif isinstance(payload, (bytes, bytearray)):
        encoded = bytes(payload)
    else:
        raise ComputersV6SourceContractError("snapshot_payload_type_invalid")
    if len(encoded) > byte_limit:
        raise ComputersV6SourceContractError("snapshot_size_out_of_bounds")
    try:
        decoded = encoded.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ComputersV6SourceContractError("snapshot_utf8_invalid") from exc
    try:
        document = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ComputersV6SourceContractError("snapshot_json_invalid") from exc
    return validate_computers_v6_snapshot(document, max_objects=object_limit)


def validate_computers_v6_snapshot(
    candidate: Mapping[str, Any], *, max_objects: int = MAX_OBJECTS
) -> dict[str, Any]:
    object_limit = _bounded_limit(
        max_objects,
        hard_maximum=MAX_OBJECTS,
        error_prefix="object",
        allow_zero=True,
    )
    snapshot = _mapping(candidate, "snapshot")
    if str(snapshot.get("schema_version") or "") != SCHEMA_VERSION:
        raise ComputersV6SourceContractError("unsupported_schema_version")
    metadata = _mapping(snapshot.get("metadata"), "metadata")
    missing_metadata = REQUIRED_METADATA_FIELDS - set(metadata)
    if missing_metadata:
        raise ComputersV6SourceContractError(
            "metadata_fields_missing:" + ",".join(sorted(missing_metadata))
        )
    started_at = _utc_timestamp(
        metadata.get("started_at"), path="metadata.started_at"
    )
    completed_at = _utc_timestamp(
        metadata.get("completed_at"), path="metadata.completed_at"
    )
    if completed_at < started_at:
        raise ComputersV6SourceContractError("snapshot_time_window_invalid")
    objects = snapshot.get("objects")
    if not isinstance(objects, list):
        raise ComputersV6SourceContractError("objects_must_be_array")

    provenance_text = " ".join(
        str(metadata.get(field) or "")
        for field in ("snapshot_id", "label", "collector_version")
    ).casefold()
    if "demo" in provenance_text or "пример" in provenance_text:
        raise ComputersV6SourceContractError("demo_source_snapshot_forbidden")
    try:
        UUID(str(metadata.get("snapshot_id") or ""))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ComputersV6SourceContractError("snapshot_id_invalid") from exc
    if metadata.get("collection_status") not in {"complete", "partial", "failed"}:
        raise ComputersV6SourceContractError("collection_status_invalid")
    for field in ("query_dc", "domain", "collector_version"):
        if not str(metadata.get(field) or "").strip():
            raise ComputersV6SourceContractError(f"metadata_{field}_required")
    raw_stage_states = metadata.get("sources")
    if not isinstance(raw_stage_states, list):
        raise ComputersV6SourceContractError("metadata_sources_must_be_array")
    stage_names: set[str] = set()
    stage_statuses: dict[str, str] = {}
    stage_requested: dict[str, bool] = {}
    for index, raw_stage in enumerate(raw_stage_states):
        stage = _mapping(raw_stage, f"metadata.sources[{index}]")
        if not {"name", "status", "requested"}.issubset(stage):
            raise ComputersV6SourceContractError("metadata_source_fields_missing")
        name = str(stage.get("name") or "")
        if not name or name in stage_names:
            raise ComputersV6SourceContractError("metadata_source_name_duplicate")
        if str(stage.get("status") or "") not in SOURCE_STATUS_MEANINGS:
            raise ComputersV6SourceContractError("metadata_source_status_invalid")
        if not isinstance(stage.get("requested"), bool):
            raise ComputersV6SourceContractError("metadata_source_requested_invalid")
        stage_names.add(name)
        stage_statuses[name] = str(stage["status"])
        stage_requested[name] = bool(stage["requested"])

    object_count = metadata.get("object_count")
    if isinstance(object_count, bool) or not isinstance(object_count, int):
        raise ComputersV6SourceContractError("object_count_must_be_integer")
    if object_count != len(objects):
        raise ComputersV6SourceContractError("object_count_mismatch")
    if object_count < 0 or object_count > object_limit:
        raise ComputersV6SourceContractError("object_count_out_of_bounds")
    if object_count and not REQUIRED_SOURCE_NAMES.issubset(stage_names):
        raise ComputersV6SourceContractError("metadata_required_sources_missing")
    collection_status = str(metadata["collection_status"])
    ad_stage_status = stage_statuses.get("ad")
    if collection_status == "failed":
        if object_count != 0 or ad_stage_status == "observed":
            raise ComputersV6SourceContractError("failed_base_ad_snapshot_invalid")
    elif ad_stage_status != "observed":
        raise ComputersV6SourceContractError("base_ad_stage_not_observed")
    if object_count and (
        stage_statuses.get("dc_events") != "not_collected"
        or stage_requested.get("dc_events") is not False
    ):
        raise ComputersV6SourceContractError("dc_events_stage_must_remain_not_collected")

    seen_object_ids: set[UUID] = set()
    for index, raw_object in enumerate(objects):
        item = _mapping(raw_object, f"objects[{index}]")
        missing_object_fields = REQUIRED_OBJECT_FIELDS - set(item)
        if missing_object_fields:
            raise ComputersV6SourceContractError(
                f"object_fields_missing:{index}:"
                + ",".join(sorted(missing_object_fields))
            )
        try:
            object_id = UUID(str(item.get("id") or ""))
            object_guid = UUID(str(item.get("objectGuid") or ""))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ComputersV6SourceContractError(
                f"object_stable_identity_invalid:{index}"
            ) from exc
        if object_id != object_guid:
            raise ComputersV6SourceContractError(
                f"object_stable_identity_mismatch:{index}"
            )
        if object_id in seen_object_ids:
            raise ComputersV6SourceContractError(
                f"object_stable_identity_duplicate:{object_id}"
            )
        seen_object_ids.add(object_id)
        source_states = _mapping(item.get("sources"), f"objects[{index}].sources")
        if not REQUIRED_SOURCE_NAMES.issubset(source_states):
            raise ComputersV6SourceContractError(
                f"object_required_sources_missing:{index}"
            )
        ad_state = _mapping(
            source_states["ad"], f"objects[{index}].sources.ad"
        )
        if str(ad_state.get("status") or "") != "observed":
            raise ComputersV6SourceContractError(
                f"object_base_ad_not_observed:{index}"
            )
        dc_event_state = _mapping(
            source_states["dc_events"],
            f"objects[{index}].sources.dc_events",
        )
        if str(dc_event_state.get("status") or "") != "not_collected":
            raise ComputersV6SourceContractError(
                f"object_dc_events_must_remain_not_collected:{index}"
            )
        for source_name, raw_state in source_states.items():
            state = _mapping(
                raw_state, f"objects[{index}].sources.{source_name}"
            )
            if not set(SOURCE_STATE_FIELDS).issubset(state):
                raise ComputersV6SourceContractError(
                    f"source_state_fields_missing:{index}:{source_name}"
                )
            if str(state.get("source") or "") != str(source_name):
                raise ComputersV6SourceContractError(
                    f"source_state_name_mismatch:{index}:{source_name}"
                )
            _validate_source_state(
                state, path=f"objects[{index}].sources.{source_name}"
            )

    return deepcopy(snapshot)


def canonical_computers_v6_snapshot(
    snapshot: Mapping[str, Any],
) -> tuple[str, bytes]:
    validated = validate_computers_v6_snapshot(snapshot)
    text = json.dumps(
        validated,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return text, hashlib.sha256(text.encode("utf-8")).digest()


def load_latest_computers_v6_source_snapshot(
    connection: Any,
    *,
    domain_fqdn: str,
    max_bytes: int = MAX_SNAPSHOT_BYTES,
    max_objects: int = MAX_OBJECTS,
) -> dict[str, Any] | None:
    byte_limit = _bounded_limit(
        max_bytes,
        hard_maximum=MAX_SNAPSHOT_BYTES,
        error_prefix="byte",
        allow_zero=False,
    )
    object_limit = _bounded_limit(
        max_objects,
        hard_maximum=MAX_OBJECTS,
        error_prefix="object",
        allow_zero=True,
    )
    domain = str(domain_fqdn or "").strip().lower()
    if not domain:
        raise ComputersV6SourceContractError("source_domain_required")
    with connection.cursor() as cursor:
        cursor.execute(
            """
            select source.source_snapshot_id,source.domain_id,source.snapshot_uuid,
                   source.source_completed_at_utc,source.captured_at_utc,
                   source.collection_status,source.base_inventory_status,
                   source.object_count,source.payload_json,source.payload_sha256
            from computers_v6_source_snapshots source
            join domains domain on domain.id=source.domain_id
            where lower(domain.fqdn)=lower(%s)
            order by source.source_completed_at_utc desc,
                     source.source_snapshot_id desc
            limit 1
            """,
            (domain,),
        )
        raw_row = cursor.fetchone()
    if not raw_row:
        return None
    row = dict(raw_row)
    raw_payload = row.get("payload_json")
    if isinstance(raw_payload, Mapping):
        snapshot = validate_computers_v6_snapshot(
            raw_payload, max_objects=object_limit
        )
    else:
        snapshot = parse_computers_v6_snapshot(
            str(raw_payload or ""),
            max_bytes=byte_limit,
            max_objects=object_limit,
        )
    payload_text, expected_hash = canonical_computers_v6_snapshot(snapshot)
    del payload_text
    stored_hash = row.get("payload_sha256")
    if isinstance(stored_hash, memoryview):
        stored_hash = stored_hash.tobytes()
    if bytes(stored_hash or b"") != expected_hash:
        raise ComputersV6SourceContractError("stored_snapshot_hash_mismatch")
    if int(row.get("object_count") or 0) != len(snapshot["objects"]):
        raise ComputersV6SourceContractError("stored_snapshot_object_count_mismatch")
    if str(row.get("snapshot_uuid") or "") != str(
        snapshot["metadata"]["snapshot_id"]
    ):
        raise ComputersV6SourceContractError("stored_snapshot_identity_mismatch")
    if str(row.get("collection_status") or "") != str(
        snapshot["metadata"]["collection_status"]
    ):
        raise ComputersV6SourceContractError("stored_snapshot_status_mismatch")
    if str(row.get("base_inventory_status") or "") != base_inventory_status(
        snapshot
    ):
        raise ComputersV6SourceContractError("stored_base_inventory_status_mismatch")
    return {
        "source_snapshot_id": int(row["source_snapshot_id"]),
        "domain_id": int(row["domain_id"]),
        "snapshot_uuid": str(row["snapshot_uuid"]),
        "source_completed_at_utc": row.get("source_completed_at_utc"),
        "captured_at_utc": row.get("captured_at_utc"),
        "collection_status": str(row["collection_status"]),
        "base_inventory_status": str(row["base_inventory_status"]),
        "object_count": int(row["object_count"]),
        "payload_sha256": expected_hash,
        "snapshot": snapshot,
    }
