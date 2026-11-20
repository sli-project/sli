from __future__ import annotations

"""Fixture-only RADIUS Accounting runtime state machine.

The module receives already-read lines and never opens a source, writes a
database, activates a worker, or persists a cursor.  It makes the future
read-only tail worker's cursor/cache/commit rules falsifiable before runtime.
"""

import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

from sli_collect.radius_accounting import (
    ACCESS_ACCEPT_PACKET_TYPE,
    RadiusSessionObservation,
    build_class_identity_binding,
    build_session_observation,
    parse_database_compatible_record,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config" / "stage9_radius_runtime_contract_v1.json"
CONTRACT_ID = "sli.radius-accounting-runtime.v1"
_IDENTITY_KEY = re.compile(r"^[a-z][a-z0-9_.-]*:.{1,500}$", re.IGNORECASE)
IdentityResolver = Callable[[str], str | None]


class RadiusRuntimeContractError(ValueError):
    """Closed-code fixture/runtime contract failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RadiusFileCursor:
    source_instance_id: str
    stream_id: str
    transport_binding: str
    file_generation: str
    byte_offset: int
    last_record_sha256: str | None = None


@dataclass(frozen=True)
class RadiusClassCacheEntry:
    class_scope_sha256: str
    exact_principal_key: str = field(repr=False)
    expires_at_utc: str


@dataclass(frozen=True)
class RadiusBatchPlan:
    contract_id: str
    current_cursor: RadiusFileCursor
    next_cursor: RadiusFileCursor
    rotation_from_eof: bool
    evidence_sha256: tuple[str, ...]
    session_observations: tuple[RadiusSessionObservation, ...]
    proposed_class_cache: Mapping[str, RadiusClassCacheEntry] = field(
        repr=False
    )
    counters: Mapping[str, int]


@dataclass
class RadiusFixtureLedger:
    cursor: RadiusFileCursor
    class_cache: dict[str, RadiusClassCacheEntry] = field(default_factory=dict)
    evidence: set[str] = field(default_factory=set)
    session_outbox: set[tuple[str, str]] = field(default_factory=set)

    def commit(
        self,
        plan: RadiusBatchPlan,
        *,
        fail_after: str | None = None,
    ) -> None:
        """Apply an all-or-nothing fixture transaction."""

        if self.cursor != plan.current_cursor:
            raise RadiusRuntimeContractError("stale_batch_cursor")
        evidence = set(self.evidence)
        outbox = set(self.session_outbox)
        cache = dict(self.class_cache)
        evidence.update(plan.evidence_sha256)
        if fail_after == "evidence":
            raise RuntimeError("injected_after_evidence")
        for observation in plan.session_observations:
            outbox.add(
                (
                    observation.canonical_record_sha256,
                    observation.session_identity_key or "identity_unresolved",
                )
            )
        if fail_after == "outbox":
            raise RuntimeError("injected_after_outbox")
        cache = dict(plan.proposed_class_cache)
        if fail_after == "cache":
            raise RuntimeError("injected_after_cache")
        self.evidence = evidence
        self.session_outbox = outbox
        self.class_cache = cache
        self.cursor = plan.next_cursor


def load_contract(path: Path = CONTRACT_PATH) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusRuntimeContractError("contract_invalid") from exc
    if not isinstance(value, dict):
        raise RadiusRuntimeContractError("contract_object_required")
    return value


def validate_contract(contract: Mapping) -> dict:
    if contract.get("schema_version") != 1:
        raise RadiusRuntimeContractError("unsupported_contract_schema")
    if contract.get("contract_id") != CONTRACT_ID:
        raise RadiusRuntimeContractError("unexpected_contract_id")
    if contract.get("status") != "accepted_for_fixture_only":
        raise RadiusRuntimeContractError("fixture_only_status_required")
    if contract.get("runtime_enabled") is not False:
        raise RadiusRuntimeContractError("runtime_must_remain_disabled")
    if contract.get("transport") != "read_only_tail":
        raise RadiusRuntimeContractError("read_only_tail_required")
    if set(contract.get("cursor_owner_fields") or []) != {
        "source_instance_id",
        "stream_id",
        "transport_binding",
    }:
        raise RadiusRuntimeContractError("cursor_owner_contract_mismatch")
    cache = dict(contract.get("class_cache") or {})
    if cache != {
        "key": "sha256(source_instance_id + exact_class_octets)",
        "value": "exact_principal_key_only",
        "ttl_seconds": 604_800,
        "maximum_entries": 10_000,
        "raw_class_persisted": False,
        "distinguished_name_persisted": False,
    }:
        raise RadiusRuntimeContractError("class_cache_contract_mismatch")
    if contract.get("cursor_commit_protocol") != (
        "evidence_then_outbox_cache_cursor_atomic"
    ):
        raise RadiusRuntimeContractError("cursor_commit_contract_mismatch")
    if contract.get("rotation_protocol") != (
        "previous_generation_eof_then_new_generation_offset_zero"
    ):
        raise RadiusRuntimeContractError("rotation_contract_mismatch")
    required = {
        "source_contact",
        "postgresql_migration",
        "clickhouse_migration",
        "worker_activation",
        "autostart",
        "cursor_persistence",
        "production_outbox_write",
    }
    if not required.issubset(set(contract.get("prohibited_actions") or [])):
        raise RadiusRuntimeContractError("fixture_prohibition_missing")
    return {
        "contract_id": CONTRACT_ID,
        "stream_id": str(contract["stream_id"]),
        "cache_ttl_seconds": int(cache["ttl_seconds"]),
        "cache_maximum_entries": int(cache["maximum_entries"]),
        "runtime_enabled": False,
    }


def initial_cursor(
    *,
    source_instance_id: str,
    transport_binding: str,
    file_generation: str,
    contract: Mapping | None = None,
) -> RadiusFileCursor:
    validated = validate_contract(contract or load_contract())
    source = _token(source_instance_id, "source_instance_id")
    binding = _token(transport_binding, "transport_binding")
    generation = _token(file_generation, "file_generation")
    return RadiusFileCursor(
        source_instance_id=source,
        stream_id=validated["stream_id"],
        transport_binding=binding,
        file_generation=generation,
        byte_offset=0,
    )


def plan_batch(
    *,
    cursor: RadiusFileCursor,
    class_cache: Mapping[str, RadiusClassCacheEntry],
    file_generation: str,
    start_offset: int,
    end_offset: int,
    lines: Iterable[str],
    identity_resolver: IdentityResolver,
    batch_observed_at_utc: datetime,
    source_timezone_id: str,
    source_utc_offset_minutes: int,
    previous_generation_eof: bool = False,
    contract: Mapping | None = None,
) -> RadiusBatchPlan:
    validated = validate_contract(contract or load_contract())
    if cursor.stream_id != validated["stream_id"]:
        raise RadiusRuntimeContractError("cursor_stream_mismatch")
    generation = _token(file_generation, "file_generation")
    start = int(start_offset)
    end = int(end_offset)
    if start < 0 or end < start:
        raise RadiusRuntimeContractError("byte_range_invalid")
    if generation == cursor.file_generation:
        if start != cursor.byte_offset:
            raise RadiusRuntimeContractError("cursor_offset_mismatch")
    else:
        if not previous_generation_eof or start != 0:
            raise RadiusRuntimeContractError(
                "rotation_requires_previous_eof_and_zero_offset"
            )
    now = _utc(batch_observed_at_utc)
    cache = {
        key: entry
        for key, entry in class_cache.items()
        if _parse_utc(entry.expires_at_utc) > now
    }
    evidence: list[str] = []
    sessions: list[RadiusSessionObservation] = []
    counters = {
        "records": 0,
        "access_accept": 0,
        "class_binding_resolved": 0,
        "class_binding_unresolved": 0,
        "accounting_control": 0,
        "accounting_lifecycle": 0,
        "session_identity_ready": 0,
        "session_identity_unresolved": 0,
        "expired_class_cache_entries": len(class_cache) - len(cache),
    }
    last_hash = cursor.last_record_sha256
    for line in lines:
        record = parse_database_compatible_record(line)
        counters["records"] += 1
        evidence.append(record.canonical_record_sha256)
        last_hash = record.canonical_record_sha256
        if record.packet_type == ACCESS_ACCEPT_PACKET_TYPE:
            counters["access_accept"] += 1
            principal = None
            if record.distinguished_name:
                principal = identity_resolver(record.distinguished_name)
                if principal is not None and _IDENTITY_KEY.fullmatch(
                    str(principal)
                ) is None:
                    raise RadiusRuntimeContractError(
                        "identity_resolver_returned_invalid_key"
                    )
            binding = build_class_identity_binding(
                record,
                source_instance_id=cursor.source_instance_id,
                exact_principal_key=principal,
            )
            if binding is not None and binding.exact_principal_key:
                scope = _class_scope(
                    cursor.source_instance_id,
                    binding.class_attribute,
                )
                cache[scope] = RadiusClassCacheEntry(
                    class_scope_sha256=scope,
                    exact_principal_key=binding.exact_principal_key,
                    expires_at_utc=(
                        now
                        + timedelta(
                            seconds=validated["cache_ttl_seconds"]
                        )
                    ).isoformat(),
                )
                counters["class_binding_resolved"] += 1
            else:
                counters["class_binding_unresolved"] += 1
            continue
        if not record.is_accounting_request:
            continue
        if record.is_accounting_control_event:
            counters["accounting_control"] += 1
            continue
        counters["accounting_lifecycle"] += 1
        cache_entry = None
        if record.class_attribute:
            cache_entry = cache.get(
                _class_scope(
                    cursor.source_instance_id,
                    record.class_attribute,
                )
            )
        observation = build_session_observation(
            record,
            source_instance_id=cursor.source_instance_id,
            exact_principal_key=(
                cache_entry.exact_principal_key
                if cache_entry is not None
                else None
            ),
            source_timezone_id=source_timezone_id,
            source_utc_offset_minutes=source_utc_offset_minutes,
        )
        if observation is None:
            raise RadiusRuntimeContractError(
                "accounting_observation_required"
            )
        sessions.append(observation)
        if observation.session_identity_ready:
            counters["session_identity_ready"] += 1
        else:
            counters["session_identity_unresolved"] += 1
    if len(cache) > validated["cache_maximum_entries"]:
        raise RadiusRuntimeContractError("class_cache_capacity_exceeded")
    next_cursor = RadiusFileCursor(
        source_instance_id=cursor.source_instance_id,
        stream_id=cursor.stream_id,
        transport_binding=cursor.transport_binding,
        file_generation=generation,
        byte_offset=end,
        last_record_sha256=last_hash,
    )
    return RadiusBatchPlan(
        contract_id=CONTRACT_ID,
        current_cursor=cursor,
        next_cursor=next_cursor,
        rotation_from_eof=generation != cursor.file_generation,
        evidence_sha256=tuple(evidence),
        session_observations=tuple(sessions),
        proposed_class_cache=dict(cache),
        counters=counters,
    )


def _class_scope(source_instance_id: str, class_attribute: str) -> str:
    material = (
        f"{source_instance_id.casefold()}\0{class_attribute}"
    ).encode()
    return sha256(material).hexdigest()


def _token(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", text) is None:
        raise RadiusRuntimeContractError(f"{field_name}_invalid")
    return text


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise RadiusRuntimeContractError("batch_time_must_be_aware")
    return value.astimezone(timezone.utc)


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise RadiusRuntimeContractError(
            "class_cache_expiry_invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise RadiusRuntimeContractError("class_cache_expiry_must_be_aware")
    return parsed.astimezone(timezone.utc)
