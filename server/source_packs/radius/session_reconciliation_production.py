from __future__ import annotations

"""Pure, evidence-verified plan for bounded RADIUS reconciliation.

This module keeps raw Accounting values in memory only.  Its output contains
only existing evidence IDs, hashes, canonical entity keys and derived session
keys; writing those outputs is an explicit maintenance-control responsibility.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from types import MappingProxyType
from typing import Callable, Iterable, Mapping
from uuid import UUID

from server.source_packs.radius.accounting import (
    ACCESS_ACCEPT_PACKET_TYPE,
    RadiusClassIdentityBinding,
    build_class_identity_binding,
    build_session_observation,
    parse_database_compatible_record,
)
from server.source_packs.radius.accounting_identity import (
    ExactLookup,
    resolve_radius_principal,
)
from server.source_packs.radius.session_reconciliation import (
    ExactResolutionProposal,
    RadiusSessionReconciliationError,
    UnresolvedCandidate,
)


MAXIMUM_EVIDENCE_RECORDS = 1_000
MAXIMUM_TERMINAL_OBSERVATIONS = 50


class RadiusSessionReconciliationProductionError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class VerifiedEvidenceRecord:
    evidence_uid: str
    canonical_record: str = field(repr=False)


@dataclass(frozen=True)
class ImmutableTerminalObservation:
    observation_id: str
    evidence_uid: str
    lifecycle_event: str
    timestamp_state: str
    observed_at_utc: datetime | str | None


@dataclass(frozen=True)
class ExactReconciliationBatch:
    evidence_corpus_sha256: str
    candidates: tuple[UnresolvedCandidate, ...]
    proposals: Mapping[str, ExactResolutionProposal]
    evidence_record_count: int
    access_accept_count: int
    unresolved_access_accept_count: int
    reconciled_count: int


def build_exact_reconciliation_batch(
    *,
    evidence_records: Iterable[VerifiedEvidenceRecord],
    terminal_observations: Iterable[ImmutableTerminalObservation],
    source_instance_id: str,
    organization_fqdn: str,
    source_timezone_id: str,
    source_utc_offset_minutes: int,
    exact_lookup: ExactLookup,
) -> ExactReconciliationBatch:
    """Prove only exact Access-Accept Class -> Accounting observations.

    Any duplicate, ambiguous bridge, timestamp mismatch or identity conflict
    stops the batch before it can reach a PostgreSQL writer. A terminal fact
    without an exact Class bridge stays a reconciliation candidate, but cannot
    receive a proposal or overlay.
    """

    records = tuple(evidence_records)
    observations = tuple(terminal_observations)
    if not 1 <= len(records) <= MAXIMUM_EVIDENCE_RECORDS:
        raise RadiusSessionReconciliationProductionError(
            "production_reconciliation_evidence_count_invalid"
        )
    if not 1 <= len(observations) <= MAXIMUM_TERMINAL_OBSERVATIONS:
        raise RadiusSessionReconciliationProductionError(
            "production_reconciliation_observation_count_invalid"
        )
    source = str(source_instance_id or "").strip()
    organization = str(organization_fqdn or "").strip().casefold()
    if not source or not organization:
        raise RadiusSessionReconciliationProductionError(
            "production_reconciliation_source_scope_invalid"
        )

    parsed_by_evidence: dict[str, tuple[str, object]] = {}
    for item in records:
        evidence_uid = _uuid(item.evidence_uid, "evidence_uid")
        if evidence_uid in parsed_by_evidence:
            raise RadiusSessionReconciliationProductionError(
                "production_reconciliation_evidence_duplicate"
            )
        parsed = parse_database_compatible_record(item.canonical_record)
        parsed_by_evidence[evidence_uid] = (
            parsed.canonical_record_sha256,
            parsed,
        )

    bindings: dict[str, tuple[RadiusClassIdentityBinding, str]] = {}
    access_accept_count = 0
    unresolved_access_accept_count = 0
    for evidence_uid, (canonical_sha, parsed) in parsed_by_evidence.items():
        if parsed.packet_type != ACCESS_ACCEPT_PACKET_TYPE:
            continue
        access_accept_count += 1
        principal = resolve_radius_principal(
            str(parsed.distinguished_name or ""),
            expected_organization_fqdn=organization,
            exact_lookup=exact_lookup,
        )
        binding = build_class_identity_binding(
            parsed,
            source_instance_id=source,
            exact_principal_key=principal,
        )
        if binding is None:
            raise RadiusSessionReconciliationProductionError(
                "production_reconciliation_access_accept_missing"
            )
        if not binding.exact_identity_ready or not binding.exact_principal_key:
            unresolved_access_accept_count += 1
            continue
        existing = bindings.get(binding.class_attribute)
        if existing is not None and (
            existing[0].exact_principal_key != binding.exact_principal_key
        ):
            raise RadiusSessionReconciliationProductionError(
                "production_reconciliation_class_identity_conflict"
            )
        if existing is None or canonical_sha < existing[1]:
            bindings[binding.class_attribute] = (binding, canonical_sha)

    candidates: list[UnresolvedCandidate] = []
    proposals: dict[str, ExactResolutionProposal] = {}
    seen_observations: set[str] = set()
    for observation in sorted(observations, key=lambda value: value.observation_id):
        observation_id = _uuid(observation.observation_id, "observation_id")
        evidence_uid = _uuid(observation.evidence_uid, "observation_evidence_uid")
        if observation_id in seen_observations:
            raise RadiusSessionReconciliationProductionError(
                "production_reconciliation_observation_duplicate"
            )
        seen_observations.add(observation_id)
        stored = parsed_by_evidence.get(evidence_uid)
        if stored is None:
            raise RadiusSessionReconciliationProductionError(
                "production_reconciliation_observation_evidence_missing"
            )
        accounting_sha, parsed = stored
        candidates.append(
            UnresolvedCandidate(
                observation_id=observation_id,
                evidence_uid=evidence_uid,
                original_outcome="identity_unresolved",
            )
        )
        class_binding = bindings.get(str(parsed.class_attribute or ""))
        if class_binding is None:
            continue
        rebuilt = build_session_observation(
            parsed,
            source_instance_id=source,
            class_identity_binding=class_binding[0],
            source_timezone_id=source_timezone_id,
            source_utc_offset_minutes=source_utc_offset_minutes,
        )
        if rebuilt is None or not rebuilt.session_identity_ready:
            raise RadiusSessionReconciliationProductionError(
                "production_reconciliation_session_identity_required"
            )
        if rebuilt.lifecycle_event != observation.lifecycle_event:
            raise RadiusSessionReconciliationProductionError(
                "production_reconciliation_lifecycle_mismatch"
            )
        if observation.timestamp_state != "ready" or not rebuilt.timestamp_ready:
            raise RadiusSessionReconciliationProductionError(
                "production_reconciliation_timestamp_ready_required"
            )
        if _utc(rebuilt.observed_at_utc) != _utc(observation.observed_at_utc):
            raise RadiusSessionReconciliationProductionError(
                "production_reconciliation_timestamp_mismatch"
            )
        if not rebuilt.exact_principal_key or not rebuilt.session_identity_key:
            raise RadiusSessionReconciliationProductionError(
                "production_reconciliation_exact_keys_required"
            )
        resolution_hash = sha256(
            json.dumps(
                {
                    "access_accept_record_sha256": class_binding[1],
                    "accounting_record_sha256": accounting_sha,
                    "evidence_uid": evidence_uid,
                    "exact_principal_key": rebuilt.exact_principal_key,
                    "observation_id": observation_id,
                    "session_identity_key": rebuilt.session_identity_key,
                    "source_instance_id": source,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        proposals[observation_id] = ExactResolutionProposal(
            observation_id=observation_id,
            session_identity_key=rebuilt.session_identity_key,
            exact_principal_key=rebuilt.exact_principal_key,
            resolution_input_sha256=resolution_hash,
        )

    corpus = sha256(
        "\n".join(
            f"{evidence_uid}\0{canonical_sha}"
            for evidence_uid, (canonical_sha, _)
            in sorted(parsed_by_evidence.items())
        ).encode("utf-8")
    ).hexdigest()
    return ExactReconciliationBatch(
        evidence_corpus_sha256=corpus,
        candidates=tuple(candidates),
        proposals=MappingProxyType(dict(proposals)),
        evidence_record_count=len(records),
        access_accept_count=access_accept_count,
        unresolved_access_accept_count=unresolved_access_accept_count,
        reconciled_count=len(proposals),
    )


def _uuid(value: str, label: str) -> str:
    try:
        return str(UUID(str(value)))
    except ValueError as exc:
        raise RadiusSessionReconciliationProductionError(
            f"production_reconciliation_{label}_invalid"
        ) from exc


def _utc(value: datetime | str | None) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise RadiusSessionReconciliationProductionError(
                "production_reconciliation_timestamp_invalid"
            ) from exc
    else:
        raise RadiusSessionReconciliationProductionError(
            "production_reconciliation_timestamp_invalid"
        )
    if parsed.tzinfo is None:
        raise RadiusSessionReconciliationProductionError(
            "production_reconciliation_timestamp_timezone_required"
        )
    return parsed.astimezone(timezone.utc)
