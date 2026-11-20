from __future__ import annotations

"""Append-only PostgreSQL writer for RADIUS identity reconciliation.

The writer never contacts the source and never updates the original typed
observation, terminal delivery receipt, or evidence manifest.
"""

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
from uuid import UUID

from server.source_packs.radius.session_reconciliation import (
    ExactResolutionProposal,
    ReconciliationAttempt,
)


ROOT = Path(__file__).resolve().parents[3]
CONTRACT_PATH = (
    ROOT / "config/stage10_radius_session_reconciliation_writer_v1.json"
)
CONTRACT_ID = "sli.radius-session-reconciliation-writer.v1"
WRITER_ROLE = "adlog_radius_session_reconciliation_writer"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SESSION_KEY = re.compile(r"^radius-session:[0-9a-f]{64}$")
_PRINCIPAL_KEY = re.compile(r"^entity:[1-9][0-9]*$")


class RadiusSessionReconciliationWriterError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ReconciliationWriteReceipt:
    attempt_key: str
    observation_id: str
    outcome: str
    persistence_state: str
    overlay_created: bool


def load_writer_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RadiusSessionReconciliationWriterError(
            "writer_contract_invalid"
        ) from exc
    expected = {
        "schema_version": 1,
        "contract_id": CONTRACT_ID,
        "status": "prepared_disabled_only",
        "required_migration": 65,
        "writer_role": WRITER_ROLE,
        "maximum_attempts_per_transaction": 50,
        "source_contact_allowed": False,
        "production_migration_applied": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
    }
    if not isinstance(value, dict):
        raise RadiusSessionReconciliationWriterError(
            "writer_contract_object_required"
        )
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise RadiusSessionReconciliationWriterError(
                f"writer_contract_{key}_invalid"
            )
    if set(value.get("immutable_inputs") or []) != {
        "radius_accounting_session_observations",
        "radius_session_projection_receipts",
        "core_evidence_manifests",
    }:
        raise RadiusSessionReconciliationWriterError(
            "writer_contract_immutable_inputs_invalid"
        )
    if set(value.get("append_only_outputs") or []) != {
        "radius_session_reconciliation_attempts",
        "radius_session_identity_overlays",
    }:
        raise RadiusSessionReconciliationWriterError(
            "writer_contract_append_only_outputs_invalid"
        )
    return value


def write_reconciliation_attempts(
    conn: Any,
    attempts: Sequence[ReconciliationAttempt],
    proposals: Mapping[str, ExactResolutionProposal],
    *,
    contract: Mapping[str, Any] | None = None,
) -> tuple[ReconciliationWriteReceipt, ...]:
    """Persist one bounded batch atomically under the dedicated DB role."""

    validated = dict(contract or load_writer_contract())
    _validate_contract(validated)
    values = tuple(attempts)
    maximum = int(validated["maximum_attempts_per_transaction"])
    if not 1 <= len(values) <= maximum:
        raise RadiusSessionReconciliationWriterError(
            "writer_attempt_count_invalid"
        )
    normalized = [
        _normalize_attempt(attempt, proposals.get(attempt.observation_id))
        for attempt in values
    ]
    observation_ids = [item[1] for item in normalized]
    if len(set(observation_ids)) != len(observation_ids):
        raise RadiusSessionReconciliationWriterError(
            "writer_duplicate_observation_in_batch"
        )
    if set(proposals) != {
        item[1] for item in normalized if item[2] == "projected"
    }:
        raise RadiusSessionReconciliationWriterError(
            "writer_proposal_set_mismatch"
        )

    receipts: list[ReconciliationWriteReceipt] = []
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(f"set local role {WRITER_ROLE}")
            for item in normalized:
                receipts.append(_write_one(cur, item))
    return tuple(receipts)


def _write_one(
    cur: Any,
    item: tuple[
        ReconciliationAttempt,
        str,
        str,
        str,
        str,
        str,
        str | None,
        ExactResolutionProposal | None,
    ],
) -> ReconciliationWriteReceipt:
    (
        attempt,
        observation_id,
        outcome,
        evidence_uid,
        corpus_hash,
        resolver_id,
        resolution_hash,
        proposal,
    ) = item
    cur.execute(
        """
        select observation.evidence_uid::text,observation.identity_state,
               exists(
                 select 1 from radius_session_projection_receipts receipt
                 where receipt.observation_id=observation.observation_id
                   and receipt.outcome='identity_unresolved'
               )
        from radius_accounting_session_observations observation
        where observation.observation_id=%s
        """,
        (observation_id,),
    )
    original = cur.fetchone()
    if original is None:
        raise RadiusSessionReconciliationWriterError(
            "writer_observation_not_found"
        )
    if str(original[0]).lower() != evidence_uid:
        raise RadiusSessionReconciliationWriterError(
            "writer_evidence_uid_mismatch"
        )
    if str(original[1]) != "unresolved" or not bool(original[2]):
        raise RadiusSessionReconciliationWriterError(
            "writer_terminal_unresolved_receipt_required"
        )

    cur.execute(
        """
        select observation_id::text,evidence_uid::text,outcome,
               evidence_corpus_sha256,resolver_contract_id,
               resolution_input_sha256,writer_contract_id
        from radius_session_reconciliation_attempts
        where attempt_key=%s
        """,
        (attempt.attempt_key,),
    )
    existing = cur.fetchone()
    expected = (
        observation_id,
        evidence_uid,
        outcome,
        corpus_hash,
        resolver_id,
        resolution_hash,
        CONTRACT_ID,
    )
    if existing is not None:
        actual = tuple(None if value is None else str(value) for value in existing)
        if actual != expected:
            raise RadiusSessionReconciliationWriterError(
                "writer_attempt_replay_conflict"
            )
        _verify_existing_overlay(cur, item)
        return ReconciliationWriteReceipt(
            attempt.attempt_key,
            observation_id,
            outcome,
            "already_persisted",
            False,
        )

    cur.execute(
        "select attempt_key from radius_session_identity_overlays "
        "where observation_id=%s",
        (observation_id,),
    )
    if cur.fetchone() is not None:
        raise RadiusSessionReconciliationWriterError(
            "writer_observation_already_resolved"
        )
    if proposal is not None:
        entity_id = int(proposal.exact_principal_key.split(":", 1)[1])
        cur.execute("select exists(select 1 from entities_v2 where id=%s)", (entity_id,))
        if not bool(cur.fetchone()[0]):
            raise RadiusSessionReconciliationWriterError(
                "writer_exact_entity_not_found"
            )

    cur.execute(
        """
        insert into radius_session_reconciliation_attempts(
          attempt_key,observation_id,evidence_uid,outcome,
          evidence_corpus_sha256,resolver_contract_id,
          resolution_input_sha256,writer_contract_id
        ) values(%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            attempt.attempt_key,
            observation_id,
            evidence_uid,
            outcome,
            corpus_hash,
            resolver_id,
            resolution_hash,
            CONTRACT_ID,
        ),
    )
    overlay_created = proposal is not None
    if proposal is not None:
        cur.execute(
            """
            insert into radius_session_identity_overlays(
              observation_id,attempt_key,evidence_uid,
              session_identity_key,exact_principal_key,
              resolution_input_sha256,resolver_contract_id
            ) values(%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                observation_id,
                attempt.attempt_key,
                evidence_uid,
                proposal.session_identity_key,
                proposal.exact_principal_key,
                resolution_hash,
                resolver_id,
            ),
        )
    return ReconciliationWriteReceipt(
        attempt.attempt_key,
        observation_id,
        outcome,
        "created",
        overlay_created,
    )


def _verify_existing_overlay(
    cur: Any,
    item: tuple[
        ReconciliationAttempt,
        str,
        str,
        str,
        str,
        str,
        str | None,
        ExactResolutionProposal | None,
    ],
) -> None:
    attempt, observation_id, outcome, evidence_uid, _, resolver_id, resolution_hash, proposal = item
    cur.execute(
        """
        select attempt_key,evidence_uid::text,session_identity_key,
               exact_principal_key,resolution_input_sha256,
               resolver_contract_id
        from radius_session_identity_overlays
        where observation_id=%s
        """,
        (observation_id,),
    )
    overlay = cur.fetchone()
    if outcome == "still_unresolved":
        if overlay is not None:
            raise RadiusSessionReconciliationWriterError(
                "writer_unresolved_replay_has_overlay"
            )
        return
    if proposal is None or overlay is None:
        raise RadiusSessionReconciliationWriterError(
            "writer_projected_replay_overlay_missing"
        )
    expected = (
        attempt.attempt_key,
        evidence_uid,
        proposal.session_identity_key,
        proposal.exact_principal_key,
        resolution_hash,
        resolver_id,
    )
    if tuple(str(value) for value in overlay) != expected:
        raise RadiusSessionReconciliationWriterError(
            "writer_overlay_replay_conflict"
        )


def _normalize_attempt(
    attempt: ReconciliationAttempt,
    proposal: ExactResolutionProposal | None,
) -> tuple[
    ReconciliationAttempt,
    str,
    str,
    str,
    str,
    str,
    str | None,
    ExactResolutionProposal | None,
]:
    try:
        observation_id = str(UUID(str(attempt.observation_id)))
        evidence_uid = str(UUID(str(attempt.evidence_uid)))
    except ValueError as exc:
        raise RadiusSessionReconciliationWriterError(
            "writer_uuid_invalid"
        ) from exc
    corpus_hash = _required_hex(attempt.evidence_corpus_sha256, "corpus_hash")
    resolver_id = str(attempt.resolver_contract_id or "").strip()
    if not resolver_id or len(resolver_id) > 160:
        raise RadiusSessionReconciliationWriterError(
            "writer_resolver_contract_invalid"
        )
    expected_attempt_key = sha256(
        (observation_id + "\0" + corpus_hash + "\0" + resolver_id).encode()
    ).hexdigest()
    if attempt.attempt_key != expected_attempt_key:
        raise RadiusSessionReconciliationWriterError(
            "writer_attempt_key_invalid"
        )
    outcome = str(attempt.outcome)
    if outcome not in {"projected", "still_unresolved"}:
        raise RadiusSessionReconciliationWriterError(
            "writer_outcome_invalid"
        )
    resolution_hash = attempt.resolution_input_sha256
    if outcome == "projected":
        if proposal is None or proposal.observation_id != observation_id:
            raise RadiusSessionReconciliationWriterError(
                "writer_projected_proposal_required"
            )
        if _SESSION_KEY.fullmatch(proposal.session_identity_key) is None:
            raise RadiusSessionReconciliationWriterError(
                "writer_session_key_invalid"
            )
        if _PRINCIPAL_KEY.fullmatch(proposal.exact_principal_key) is None:
            raise RadiusSessionReconciliationWriterError(
                "writer_principal_key_invalid"
            )
        resolution_hash = _required_hex(resolution_hash, "resolution_hash")
        if proposal.resolution_input_sha256 != resolution_hash:
            raise RadiusSessionReconciliationWriterError(
                "writer_resolution_hash_mismatch"
            )
    elif proposal is not None or resolution_hash is not None:
        raise RadiusSessionReconciliationWriterError(
            "writer_unresolved_proposal_forbidden"
        )
    return (
        attempt,
        observation_id,
        outcome,
        evidence_uid,
        corpus_hash,
        resolver_id,
        resolution_hash,
        proposal,
    )


def _required_hex(value: str | None, label: str) -> str:
    clean = str(value or "").strip().lower()
    if _HEX64.fullmatch(clean) is None:
        raise RadiusSessionReconciliationWriterError(
            f"writer_{label}_invalid"
        )
    return clean


def _validate_contract(contract: Mapping[str, Any]) -> None:
    expected = {
        "schema_version": 1,
        "contract_id": CONTRACT_ID,
        "status": "prepared_disabled_only",
        "required_migration": 65,
        "writer_role": WRITER_ROLE,
        "maximum_attempts_per_transaction": 50,
        "source_contact_allowed": False,
        "production_migration_applied": False,
        "runtime_enabled": False,
        "autostart_enabled": False,
    }
    for key, expected_value in expected.items():
        if contract.get(key) != expected_value:
            raise RadiusSessionReconciliationWriterError(
                f"writer_contract_{key}_invalid"
            )
