"""Canonical Storage V2 row transforms and semantic hashes."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_EVEN
from typing import Any, Iterable, Mapping, Sequence

from server.sli.events.event_catalog import event_noise_classification
from server.sli.storage.storage_v2_compact_archive import INT32_MAX, INT64_MAX
from server.source_packs.registry import resolve_source_normalizer

PROCESS_ACTIVITY_FACT_COLUMNS = frozenset({
    "process_parent_id", "process_command_line", "process_user_sid",
    "process_user_name", "process_user_domain", "process_logon_id",
    "service_file", "service_account", "service_start_type", "task_content",
    "task_change", "native_process_id",
})

EVENT_ARCHIVE_COLUMNS: tuple[str, ...] = (
    "id", "raw_log_file_id", "server_id", "domain_id", "site_id", "log_source_id",
    "event_record_id", "event_id", "version", "level", "task", "opcode", "keywords",
    "provider_name", "provider_guid", "channel", "computer", "time_created_utc",
    "time_created_local", "record_xml", "message_text", "event_data_json",
    "subject_user_sid", "subject_user_name", "subject_domain_name", "target_user_sid",
    "target_user_name", "target_domain_name", "ip_address", "workstation_name",
    "logon_id", "correlation_id", "normalized_at", "normalized_hash",
)

LINK_DETAIL_COLUMNS: tuple[str, ...] = (
    "event_id", "entity_id", "link_role", "role_id", "confidence", "extracted_from",
    "extracted_from_id", "created_at", "evidence_json", "attributes_json",
)


class StorageV2DataError(ValueError):
    """Raised when a source row cannot be represented without data loss."""


def _positive_int32(value: Any, *, field: str) -> int:
    number = int(value)
    if not 0 < number <= INT32_MAX:
        raise StorageV2DataError(f"{field} exceeds positive int32 capacity")
    return number


def _positive_int64(value: Any, *, field: str) -> int:
    number = int(value)
    if not 0 < number <= INT64_MAX:
        raise StorageV2DataError(f"{field} exceeds positive int64 capacity")
    return number


@dataclass(frozen=True)
class EventCoreV2:
    values: Mapping[str, Any]
    source_core_sha256: bytes


@dataclass(frozen=True)
class EventFactsV2:
    """Small, queryable facts that replace report reads from large payload text."""

    values: Mapping[str, Any]
    source_facts_sha256: bytes


@dataclass(frozen=True)
class EntityCoreV2:
    values: Mapping[str, Any]
    source_core_sha256: bytes
    details_json: Mapping[str, Any] | None
    source_details_sha256: bytes | None


@dataclass(frozen=True)
class LinkCoreV2:
    values: Mapping[str, Any]
    source_core_sha256: bytes
    details: Mapping[str, Any] | None


@dataclass(frozen=True)
class IdentityCapacityStatus:
    max_event_id: int
    max_entity_id: int
    max_retained_reference_id: int
    int32_max: int = INT32_MAX
    warning_threshold_ratio: float = 0.80
    int64_max: int = INT64_MAX

    @property
    def max_observed_id(self) -> int:
        return max(self.max_event_id, self.max_entity_id, self.max_retained_reference_id)

    @property
    def remaining_ids(self) -> int:
        return min(
            self.int64_max - max(self.max_event_id, self.max_retained_reference_id),
            self.int32_max - self.max_entity_id,
        )

    @property
    def usage_ratio(self) -> float:
        return max(
            max(self.max_event_id, self.max_retained_reference_id) / self.int64_max,
            self.max_entity_id / self.int32_max,
        )

    @property
    def status(self) -> str:
        if self.remaining_ids <= 0:
            return "blocked"
        if self.usage_ratio >= self.warning_threshold_ratio:
            return "warning"
        return "ok"

    def public_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "max_event_id": self.max_event_id,
            "max_entity_id": self.max_entity_id,
            "max_retained_reference_id": self.max_retained_reference_id,
            "max_observed_id": self.max_observed_id,
            "int32_max": self.int32_max,
            "int64_max": self.int64_max,
            "remaining_ids": self.remaining_ids,
            "usage_ratio": round(self.usage_ratio, 9),
            "warning_threshold_ratio": self.warning_threshold_ratio,
        }


def identity_capacity_status(
    *,
    max_event_id: int,
    max_entity_id: int,
    max_retained_reference_id: int = 0,
    warning_threshold_ratio: float = 0.80,
) -> IdentityCapacityStatus:
    return IdentityCapacityStatus(
        max_event_id=max(0, int(max_event_id)),
        max_entity_id=max(0, int(max_entity_id)),
        max_retained_reference_id=max(0, int(max_retained_reference_id)),
        warning_threshold_ratio=float(warning_threshold_ratio),
    )


def json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, bytes):
        return value.hex().upper()
    if isinstance(value, Mapping):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        json_safe(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def canonical_archive_line(kind: str, row: Mapping[str, Any], columns: Sequence[str]) -> bytes:
    payload = {"kind": kind, "row": {column: json_safe(row.get(column)) for column in columns}}
    return canonical_json_bytes(payload) + b"\n"


def parse_utc_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        result = value
    else:
        text = str(value or "").strip()
        if not text:
            raise StorageV2DataError("timestamp is empty")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        match = re.match(r"^(?P<prefix>.*\.)(?P<fraction>\d{7,})(?P<tz>[+-]\d\d:\d\d)$", text)
        if match:
            micros = int(
                (Decimal("0." + match.group("fraction")) * Decimal(1_000_000)).to_integral_value(
                    rounding=ROUND_HALF_EVEN
                )
            )
            base = datetime.fromisoformat(match.group("prefix")[:-1] + match.group("tz"))
            result = base.replace(microsecond=0) + timedelta(microseconds=micros)
        else:
            result = datetime.fromisoformat(text)
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def parse_json_object(value: Any, *, field: str) -> Mapping[str, Any] | None:
    if value in (None, "", "{}"):
        return None
    if isinstance(value, Mapping):
        return dict(value)
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError as exc:
        raise StorageV2DataError(f"{field} contains invalid JSON") from exc
    if parsed in (None, {}):
        return None
    if not isinstance(parsed, Mapping):
        raise StorageV2DataError(f"{field} must contain a JSON object")
    return dict(parsed)


def normalized_hash_bytes(value: Any, *, fallback_row: Mapping[str, Any]) -> bytes:
    text = str(value or "").strip()
    if text:
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raw = b""
        if len(raw) == 32:
            return raw
    return sha256_bytes(canonical_json_bytes(fallback_row))


def semantic_sequence_sha256(rows: Iterable[Mapping[str, Any]], columns: Sequence[str]) -> bytes:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(canonical_archive_line("semantic", row, columns))
    return digest.digest()


def event_source_core_sha256(row: Mapping[str, Any]) -> bytes:
    """Hash the canonical source fields stored in an event core identity."""
    source_core = {
        name: row.get(name)
        for name in EVENT_ARCHIVE_COLUMNS
        if name not in {"record_xml", "message_text", "event_data_json", "time_created_local", "provider_guid"}
    }
    return sha256_bytes(canonical_json_bytes(source_core))


def event_core_from_v1(row: Mapping[str, Any], dictionary_ids: Mapping[str, Mapping[str, int]]) -> EventCoreV2:
    required = ("id", "server_id", "domain_id", "log_source_id", "event_id", "channel", "time_created_utc")
    missing = [name for name in required if row.get(name) in (None, "")]
    if missing:
        raise StorageV2DataError(f"event row is missing required fields: {missing}")

    def dict_id(kind: str, value: Any, *, required_value: bool = False) -> int | None:
        if value in (None, ""):
            if required_value:
                raise StorageV2DataError(f"dictionary value {kind} is required")
            return None
        mapping = dictionary_ids.get(kind) or {}
        try:
            return int(mapping[str(value)])
        except KeyError as exc:
            raise StorageV2DataError(f"dictionary {kind} has no value {value!r}") from exc

    noise_class, noise_catalog_version = event_noise_classification(
        int(row["event_id"]),
        str(row.get("channel") or ""),
        str(row.get("provider_name") or ""),
    )
    values = {
        "id": _positive_int64(row["id"], field="event id"),
        "raw_log_file_id": row.get("raw_log_file_id"),
        "server_id": int(row["server_id"]),
        "domain_id": int(row["domain_id"]),
        "site_id": row.get("site_id"),
        "log_source_id": int(row["log_source_id"]),
        "event_record_id": row.get("event_record_id"),
        "event_id": int(row["event_id"]),
        "version": row.get("version"),
        "level": row.get("level"),
        "task": row.get("task"),
        "opcode": row.get("opcode"),
        "keywords_id": dict_id("keywords", row.get("keywords")),
        "provider_id": dict_id("provider", row.get("provider_name")),
        "channel_id": dict_id("channel", row.get("channel"), required_value=True),
        "computer_id": dict_id("computer", row.get("computer")),
        "time_created_utc": parse_utc_timestamp(row.get("time_created_utc")),
        "subject_user_sid": row.get("subject_user_sid"),
        "subject_user_name": row.get("subject_user_name"),
        "subject_domain_id": dict_id("domain", row.get("subject_domain_name")),
        "target_user_sid": row.get("target_user_sid"),
        "target_user_name": row.get("target_user_name"),
        "target_domain_id": dict_id("domain", row.get("target_domain_name")),
        "ip_address": row.get("ip_address"),
        "workstation_name": row.get("workstation_name"),
        "logon_id": row.get("logon_id"),
        "correlation_id": row.get("correlation_id"),
        "normalized_at": parse_utc_timestamp(row.get("normalized_at")),
        "normalized_hash": normalized_hash_bytes(row.get("normalized_hash"), fallback_row=row),
        "noise_class": noise_class,
        "noise_catalog_version": noise_catalog_version,
    }
    return EventCoreV2(values=values, source_core_sha256=event_source_core_sha256(row))


def event_facts_from_v1(
    row: Mapping[str, Any], *, include_process_activity: bool = True,
) -> EventFactsV2 | None:
    """Extract bounded report/search facts while the full source stays in the archive.

    Invalid or non-object ``event_data_json`` never causes payload loss: the
    canonical archive remains authoritative and only the optional derived facts
    are omitted.  Text fields are deliberately bounded so this table cannot
    become a second payload store.
    """

    raw_data = row.get("event_data_json")
    if isinstance(raw_data, Mapping):
        event_data: Mapping[str, Any] = raw_data
    else:
        try:
            candidate = json.loads(str(raw_data)) if raw_data not in (None, "") else {}
        except (json.JSONDecodeError, TypeError, ValueError):
            candidate = {}
        event_data = candidate if isinstance(candidate, Mapping) else {}

    source_normalizer = resolve_source_normalizer(
        row.get("channel"),
        row.get("provider_name"),
        str(row.get("event_id") or ""),
    )
    source_values = (
        source_normalizer.event_facts(row=row, event_data=event_data)
        if source_normalizer
        else {}
    )
    values = {"event_id": int(row["id"]), **source_values}
    # Migration 089 is admitted separately from collection. Select the supported
    # projection before hashing; never strip populated values from a hashed row
    # at the SQL boundary. The complete source still goes to the archive.
    if not include_process_activity:
        for column in PROCESS_ACTIVITY_FACT_COLUMNS.intersection(values):
            values[column] = None
    # The table has a fixed write shape.  These keys were introduced after
    # earlier rows existed, so default them only at the persistence boundary.
    for column in (
        "account_target_sid",
        "account_target_name",
        "account_name_before",
        "account_name_after",
        "membership_member_sid",
        "membership_member_name",
    ):
        values.setdefault(column, None)
    if not any(value is not None for key, value in values.items() if key != "event_id"):
        return None
    # Migrations 086 and 087 introduce nullable columns into the fixed V2 facts row.
    # Keep hashes for every already-existing source-fact projection byte-for-
    # byte stable when these new fields are absent; otherwise at-least-once
    # replay would reject historic rows solely because the schema grew.
    hash_values = {
        key: value
        for key, value in values.items()
        if (
            key
            not in {
                "account_target_sid",
                "account_target_name",
                "account_name_before",
                "account_name_after",
                "membership_member_sid",
                "membership_member_name",
            }
            or value is not None
        )
    }
    return EventFactsV2(
        values=values,
        source_facts_sha256=sha256_bytes(canonical_json_bytes(hash_values)),
    )


def entity_core_from_v1(row: Mapping[str, Any], entity_type_id: int) -> EntityCoreV2:
    required = ("id", "entity_type", "natural_key", "display_name")
    missing = [name for name in required if row.get(name) in (None, "")]
    if missing:
        raise StorageV2DataError(f"entity row is missing required fields: {missing}")
    values = {
        "id": _positive_int32(row["id"], field="entity id"),
        "entity_type_id": int(entity_type_id),
        "natural_key": str(row["natural_key"]),
        "display_name": str(row["display_name"]),
        "domain_id": row.get("domain_id"),
        "server_id": row.get("server_id"),
        "first_seen_utc": parse_utc_timestamp(row["first_seen_utc"]) if row.get("first_seen_utc") else None,
        "last_seen_utc": parse_utc_timestamp(row["last_seen_utc"]) if row.get("last_seen_utc") else None,
    }
    details = parse_json_object(row.get("attributes_json"), field="attributes_json")
    return EntityCoreV2(
        values=values,
        source_core_sha256=sha256_bytes(canonical_json_bytes(values)),
        details_json=details,
        source_details_sha256=sha256_bytes(canonical_json_bytes(details)) if details is not None else None,
    )


def link_core_from_v1(row: Mapping[str, Any], role_id: int, extracted_from_id: int | None) -> LinkCoreV2:
    required = ("event_id", "entity_id", "link_role", "created_at")
    missing = [name for name in required if row.get(name) in (None, "")]
    if missing:
        raise StorageV2DataError(f"link row is missing required fields: {missing}")
    values = {
        "event_id": _positive_int64(row["event_id"], field="link event_id"),
        "entity_id": _positive_int32(row["entity_id"], field="link entity_id"),
        "role_id": int(role_id),
        "confidence": float(row.get("confidence") if row.get("confidence") is not None else 1.0),
        "extracted_from_id": int(extracted_from_id) if extracted_from_id is not None else None,
        "created_at": parse_utc_timestamp(row.get("created_at")),
    }
    if not 0 <= values["confidence"] <= 1:
        raise StorageV2DataError("link confidence must be between 0 and 1")
    if not 0 <= values["role_id"] <= 32_767:
        raise StorageV2DataError("link role_id exceeds PostgreSQL smallint capacity")
    evidence = parse_json_object(row.get("evidence_json"), field="evidence_json")
    attributes = parse_json_object(row.get("attributes_json"), field="attributes_json")
    details = {
        "event_id": values["event_id"],
        "entity_id": values["entity_id"],
        "link_role": str(row["link_role"]),
        "role_id": values["role_id"],
        "confidence": values["confidence"],
        "extracted_from": str(row.get("extracted_from") or ""),
        "extracted_from_id": values["extracted_from_id"],
        "created_at": values["created_at"],
        "evidence_json": evidence,
        "attributes_json": attributes,
    }
    return LinkCoreV2(
        values=values,
        source_core_sha256=sha256_bytes(canonical_json_bytes(values)),
        details=details,
    )


def link_core_from_archive(row: Mapping[str, Any]) -> LinkCoreV2:
    """Rebuild the semantic link core from bytes read from a published archive."""
    required = ("event_id", "entity_id", "role_id", "confidence", "created_at")
    missing = [name for name in required if row.get(name) is None]
    if missing:
        raise StorageV2DataError(f"link archive row is missing required fields: {missing}")
    values = {
        "event_id": _positive_int64(row["event_id"], field="link event_id"),
        "entity_id": _positive_int32(row["entity_id"], field="link entity_id"),
        "role_id": int(row["role_id"]),
        "confidence": float(row["confidence"]),
        "extracted_from_id": (
            int(row["extracted_from_id"])
            if row.get("extracted_from_id") is not None else None
        ),
        "created_at": parse_utc_timestamp(row["created_at"]),
    }
    if not 0 <= values["role_id"] <= 32_767:
        raise StorageV2DataError("link role_id exceeds PostgreSQL smallint capacity")
    if not 0 <= values["confidence"] <= 1:
        raise StorageV2DataError("link confidence must be between 0 and 1")
    return LinkCoreV2(
        values=values,
        source_core_sha256=sha256_bytes(canonical_json_bytes(values)),
        details=dict(row),
    )
