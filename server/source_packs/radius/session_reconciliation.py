from __future__ import annotations

"""Pure plan for immutable RADIUS session identity reconciliation."""

from dataclasses import dataclass, field
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from server.source_packs.radius.session_read_model import RadiusLifecycleInput


ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = ROOT / "config/stage10_radius_session_reconciliation_v1.json"
CONTRACT_ID = "sli.radius-session-reconciliation.v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SESSION_KEY = re.compile(r"^radius-session:[0-9a-f]{64}$")
_PRINCIPAL_KEY = re.compile(r"^entity:[1-9][0-9]*$")


class RadiusSessionReconciliationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class UnresolvedCandidate:
    observation_id: str
    evidence_uid: str
    original_outcome: str


@dataclass(frozen=True)
class ExactResolutionProposal:
    observation_id: str
    session_identity_key: str = field(repr=False)
    exact_principal_key: str = field(repr=False)
    resolution_input_sha256: str


@dataclass(frozen=True)
class ReconciliationAttempt:
    attempt_key: str
    observation_id: str
    evidence_uid: str
    outcome: str
    evidence_corpus_sha256: str
    resolver_contract_id: str
    resolution_input_sha256: str | None


def load_reconciliation_contract(
    path: Path = CONTRACT_PATH,
) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusSessionReconciliationError(
            "reconciliation_contract_invalid"
        ) from exc
    expected = {
        "schema_version": 1,
        "contract_id": CONTRACT_ID,
        "status": "prepared_source_only",
        "candidate_outcome": "identity_unresolved",
        "maximum_candidates_per_run": 50,
        "maximum_evidence_records_per_run": 1000,
        "maximum_evidence_bytes_per_run": 67_108_864,
        "source_contact_allowed": False,
        "verified_local_evidence_read_allowed": True,
        "production_migration_applied": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
    }
    if not isinstance(value, dict):
        raise RadiusSessionReconciliationError(
            "reconciliation_contract_object_required"
        )
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise RadiusSessionReconciliationError(
                f"reconciliation_contract_{key}_invalid"
            )
    if set(value.get("retry_boundary") or []) != {
        "new_evidence_corpus_sha256",
        "new_resolver_contract_id",
    }:
        raise RadiusSessionReconciliationError(
            "reconciliation_contract_retry_boundary_invalid"
        )
    if value.get("identity_evidence_discovery") != {
        "maximum_manifests_per_run": 2_000,
        "maximum_bytes_per_run": 67_108_864,
        "manifest_page_size": 250,
    }:
        raise RadiusSessionReconciliationError(
            "reconciliation_contract_identity_evidence_discovery_invalid"
        )
    return value


def build_reconciliation_attempts(
    candidates: Iterable[UnresolvedCandidate],
    proposals: Mapping[str, ExactResolutionProposal],
    *,
    evidence_corpus_sha256: str,
    resolver_contract_id: str,
    prior_attempt_keys: Iterable[str] = (),
    limit: int = 50,
    contract: Mapping[str, Any] | None = None,
) -> tuple[ReconciliationAttempt, ...]:
    validated = dict(contract or load_reconciliation_contract())
    maximum = int(validated["maximum_candidates_per_run"])
    if not 1 <= int(limit) <= maximum:
        raise RadiusSessionReconciliationError(
            "reconciliation_limit_invalid"
        )
    corpus_hash = _required_hex(evidence_corpus_sha256, "corpus_hash")
    resolver_id = str(resolver_contract_id or "").strip()
    if not resolver_id or len(resolver_id) > 160:
        raise RadiusSessionReconciliationError(
            "reconciliation_resolver_contract_invalid"
        )
    prior = {
        _required_hex(value, "attempt_key") for value in prior_attempt_keys
    }
    seen: set[str] = set()
    attempts: list[ReconciliationAttempt] = []
    values = sorted(tuple(candidates), key=lambda item: item.observation_id)
    for candidate in values:
        observation_id = str(candidate.observation_id or "").strip()
        evidence_uid = str(candidate.evidence_uid or "").strip()
        if not observation_id or not evidence_uid:
            raise RadiusSessionReconciliationError(
                "reconciliation_candidate_identity_invalid"
            )
        if observation_id in seen:
            raise RadiusSessionReconciliationError(
                "reconciliation_candidate_duplicate"
            )
        seen.add(observation_id)
        if candidate.original_outcome != validated["candidate_outcome"]:
            raise RadiusSessionReconciliationError(
                "reconciliation_candidate_outcome_invalid"
            )
        attempt_key = sha256(
            (observation_id + "\0" + corpus_hash + "\0" + resolver_id).encode()
        ).hexdigest()
        if attempt_key in prior:
            continue
        proposal = proposals.get(observation_id)
        resolution_hash: str | None = None
        outcome = "still_unresolved"
        if proposal is not None:
            _validate_proposal(proposal, observation_id)
            resolution_hash = proposal.resolution_input_sha256
            outcome = "projected"
        attempts.append(
            ReconciliationAttempt(
                attempt_key=attempt_key,
                observation_id=observation_id,
                evidence_uid=evidence_uid,
                outcome=outcome,
                evidence_corpus_sha256=corpus_hash,
                resolver_contract_id=resolver_id,
                resolution_input_sha256=resolution_hash,
            )
        )
        if len(attempts) >= int(limit):
            break
    if set(proposals) - seen:
        raise RadiusSessionReconciliationError(
            "reconciliation_proposal_without_candidate"
        )
    return tuple(attempts)


def apply_exact_resolution(
    original: RadiusLifecycleInput,
    proposal: ExactResolutionProposal,
) -> RadiusLifecycleInput:
    if original.identity_state != "unresolved":
        raise RadiusSessionReconciliationError(
            "reconciliation_exact_observation_override_forbidden"
        )
    _validate_proposal(proposal, original.observation_id)
    return RadiusLifecycleInput(
        observation_id=original.observation_id,
        lifecycle_event=original.lifecycle_event,
        identity_state="exact",
        timestamp_state=original.timestamp_state,
        session_identity_key=proposal.session_identity_key,
        exact_principal_key=proposal.exact_principal_key,
        observed_at_utc=original.observed_at_utc,
        evidence_sha256=original.evidence_sha256,
    )


def _validate_proposal(
    proposal: ExactResolutionProposal,
    observation_id: str,
) -> None:
    if proposal.observation_id != observation_id:
        raise RadiusSessionReconciliationError(
            "reconciliation_proposal_observation_mismatch"
        )
    if _SESSION_KEY.fullmatch(proposal.session_identity_key) is None:
        raise RadiusSessionReconciliationError(
            "reconciliation_session_key_invalid"
        )
    if _PRINCIPAL_KEY.fullmatch(proposal.exact_principal_key) is None:
        raise RadiusSessionReconciliationError(
            "reconciliation_principal_key_invalid"
        )
    _required_hex(proposal.resolution_input_sha256, "resolution_input_hash")


def _required_hex(value: str, label: str) -> str:
    clean = str(value or "").strip().lower()
    if _HEX64.fullmatch(clean) is None:
        raise RadiusSessionReconciliationError(
            f"reconciliation_{label}_invalid"
        )
    return clean
