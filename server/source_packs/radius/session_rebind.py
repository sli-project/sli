from __future__ import annotations

"""Pure post-reset rebind of RADIUS session projection inputs.

The builder accepts hash-verified local evidence and immutable stored observation
metadata, resolves principals against the current identity spine, and returns the
existing radius-session read model fold. It performs no I/O and mutates no state.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable

from server.source_packs.radius.accounting import (
    ACCESS_ACCEPT_PACKET_TYPE,
    RadiusClassIdentityBinding,
    build_class_identity_binding,
    build_session_observation,
    parse_database_compatible_record,
)
from server.source_packs.radius.accounting_identity import resolve_radius_principal
from server.source_packs.radius.session_read_model import (
    RadiusLifecycleInput,
    RadiusSessionFoldResult,
    fold_radius_sessions,
)

MAXIMUM_EVIDENCE_RECORDS = 10_000
MAXIMUM_STORED_OBSERVATIONS = 10_000


class RadiusSessionRebindError(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedRadiusEvidence:
    evidence_uid: str
    canonical_record: str = field(repr=False)
    canonical_record_sha256: str


@dataclass(frozen=True)
class ImmutableStoredRadiusObservation:
    observation_id: str
    evidence_uid: str
    lifecycle_event: str
    timestamp_state: str
    observed_at_utc: datetime | str | None
    canonical_record_sha256: str


def build_rebound_radius_projection(
    *,
    evidence_records: Iterable[VerifiedRadiusEvidence],
    stored_observations: Iterable[ImmutableStoredRadiusObservation],
    source_instance_id: str,
    organization_fqdn: str,
    source_timezone_id: str,
    source_utc_offset_minutes: int,
    exact_lookup: Callable[[str, str], str | None],
) -> RadiusSessionFoldResult:
    """Re-resolve stored lifecycle evidence against the current entity spine."""

    records = tuple(evidence_records)
    observations = tuple(stored_observations)
    if not 1 <= len(records) <= MAXIMUM_EVIDENCE_RECORDS:
        raise RadiusSessionRebindError("rebind_evidence_count_invalid")
    if not 1 <= len(observations) <= MAXIMUM_STORED_OBSERVATIONS:
        raise RadiusSessionRebindError("rebind_observation_count_invalid")

    parsed_by_uid: dict[str, object] = {}
    for item in records:
        uid = str(item.evidence_uid).strip().lower()
        if not uid or uid in parsed_by_uid:
            raise RadiusSessionRebindError("rebind_evidence_identity_invalid")
        parsed = parse_database_compatible_record(item.canonical_record)
        if parsed.canonical_record_sha256 != str(item.canonical_record_sha256).lower():
            raise RadiusSessionRebindError("rebind_evidence_hash_mismatch")
        parsed_by_uid[uid] = parsed

    organization = str(organization_fqdn or "").strip().casefold()
    bindings: dict[str, RadiusClassIdentityBinding] = {}
    for parsed in parsed_by_uid.values():
        if parsed.packet_type != ACCESS_ACCEPT_PACKET_TYPE:
            continue
        principal = resolve_radius_principal(
            str(parsed.distinguished_name or ""),
            expected_organization_fqdn=organization,
            exact_lookup=exact_lookup,
        )
        binding = build_class_identity_binding(
            parsed,
            source_instance_id=source_instance_id,
            exact_principal_key=principal,
        )
        if binding is None or not binding.exact_principal_key:
            continue
        existing = bindings.get(binding.class_attribute)
        if existing is not None and existing.exact_principal_key != binding.exact_principal_key:
            raise RadiusSessionRebindError("rebind_class_identity_conflict")
        bindings[binding.class_attribute] = binding

    rebound: list[RadiusLifecycleInput] = []
    seen_observations: set[str] = set()
    for stored in observations:
        observation_id = str(stored.observation_id).strip()
        if not observation_id or observation_id in seen_observations:
            raise RadiusSessionRebindError("rebind_observation_identity_invalid")
        seen_observations.add(observation_id)
        parsed = parsed_by_uid.get(str(stored.evidence_uid).strip().lower())
        if parsed is None:
            raise RadiusSessionRebindError("rebind_observation_evidence_missing")
        if parsed.canonical_record_sha256 != str(stored.canonical_record_sha256).lower():
            raise RadiusSessionRebindError("rebind_evidence_hash_mismatch")
        binding = bindings.get(str(parsed.class_attribute or ""))
        rebuilt = build_session_observation(
            parsed,
            source_instance_id=source_instance_id,
            class_identity_binding=binding,
            source_timezone_id=source_timezone_id,
            source_utc_offset_minutes=source_utc_offset_minutes,
        )
        if rebuilt is None:
            raise RadiusSessionRebindError("rebind_session_observation_required")
        if rebuilt.lifecycle_event != str(stored.lifecycle_event):
            raise RadiusSessionRebindError("rebind_lifecycle_mismatch")
        timestamp_state = str(stored.timestamp_state)
        rebuilt_timestamp_state = "ready" if rebuilt.timestamp_ready else "unresolved"
        if rebuilt_timestamp_state != timestamp_state:
            raise RadiusSessionRebindError("rebind_timestamp_state_mismatch")
        if timestamp_state == "ready" and _utc(rebuilt.observed_at_utc) != _utc(stored.observed_at_utc):
            raise RadiusSessionRebindError("rebind_timestamp_mismatch")
        if timestamp_state == "unresolved" and stored.observed_at_utc is not None:
            raise RadiusSessionRebindError("rebind_timestamp_mismatch")
        identity_ready = bool(
            rebuilt.session_identity_ready
            and rebuilt.session_identity_key
            and rebuilt.exact_principal_key
        )
        rebound.append(
            RadiusLifecycleInput(
                observation_id=observation_id,
                lifecycle_event=rebuilt.lifecycle_event,
                identity_state="exact" if identity_ready else "unresolved",
                timestamp_state=timestamp_state,
                session_identity_key=(rebuilt.session_identity_key if identity_ready else None),
                exact_principal_key=(rebuilt.exact_principal_key if identity_ready else None),
                observed_at_utc=rebuilt.observed_at_utc,
                evidence_sha256=parsed.canonical_record_sha256,
            )
        )
    return fold_radius_sessions(rebound)


def _utc(value: datetime | str | None) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RadiusSessionRebindError("rebind_timestamp_invalid") from exc
    else:
        raise RadiusSessionRebindError("rebind_timestamp_invalid")
    if parsed.tzinfo is None:
        raise RadiusSessionRebindError("rebind_timestamp_timezone_required")
    return parsed.astimezone(timezone.utc)
