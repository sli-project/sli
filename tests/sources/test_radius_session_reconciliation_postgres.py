from pathlib import Path

import pytest

from server.source_packs.radius.session_reconciliation import (
    ExactResolutionProposal,
    ReconciliationAttempt,
)
from server.source_packs.radius.session_reconciliation_postgres import (
    CONTRACT_ID,
    RadiusSessionReconciliationWriterError,
    load_writer_contract,
    write_reconciliation_attempts,
)


ROOT = Path(__file__).resolve().parents[2]
FORWARD = (
    ROOT
    / "config/postgres_migrations/"
    "065_radius_session_reconciliation_overlay.sql"
).read_text(encoding="utf-8").lower()
ROLLBACK = (
    ROOT
    / "config/postgres_migrations/"
    "065_radius_session_reconciliation_overlay.rollback.sql"
).read_text(encoding="utf-8").lower()
OBSERVATION = "11111111-1111-1111-1111-111111111111"
EVIDENCE = "22222222-2222-2222-2222-222222222222"


def test_writer_contract_is_disabled_source_free_and_bounded() -> None:
    contract = load_writer_contract()
    assert contract["contract_id"] == CONTRACT_ID
    assert contract["required_migration"] == 65
    assert contract["maximum_attempts_per_transaction"] == 50
    assert contract["source_contact_allowed"] is False
    assert contract["production_migration_applied"] is False
    assert contract["runtime_enabled"] is False


def test_migration_is_append_only_and_least_privilege() -> None:
    assert "values (65,'radius_session_reconciliation_overlay')" in FORWARD
    assert "create role adlog_radius_session_reconciliation_writer" in FORWARD
    assert "nologin nosuperuser" in FORWARD
    assert "create table radius_session_reconciliation_attempts" in FORWARD
    assert "create table radius_session_identity_overlays" in FORWARD
    assert "grant insert(" in FORWARD
    assert "grant update" not in FORWARD
    assert "grant delete" not in FORWARD
    assert "rollback 065 forbidden after reconciliation evidence" in ROLLBACK


def test_invalid_attempt_is_rejected_before_database_contact() -> None:
    attempt = ReconciliationAttempt(
        attempt_key="0" * 64,
        observation_id=OBSERVATION,
        evidence_uid=EVIDENCE,
        outcome="projected",
        evidence_corpus_sha256="b" * 64,
        resolver_contract_id="resolver-v1",
        resolution_input_sha256="c" * 64,
    )
    proposal = ExactResolutionProposal(
        OBSERVATION,
        "radius-session:" + "a" * 64,
        "entity:101",
        "c" * 64,
    )
    with pytest.raises(
        RadiusSessionReconciliationWriterError,
        match="writer_attempt_key_invalid",
    ):
        write_reconciliation_attempts(
            object(), [attempt], {OBSERVATION: proposal}
        )


def test_empty_batch_is_rejected_before_database_contact() -> None:
    with pytest.raises(
        RadiusSessionReconciliationWriterError,
        match="writer_attempt_count_invalid",
    ):
        write_reconciliation_attempts(object(), [], {})
