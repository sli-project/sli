from datetime import datetime, timezone

import pytest

from server.source_packs.radius.session_read_model import RadiusLifecycleInput
from server.source_packs.radius.session_reconciliation import (
    ExactResolutionProposal,
    RadiusSessionReconciliationError,
    UnresolvedCandidate,
    apply_exact_resolution,
    build_reconciliation_attempts,
)


OBSERVATION = "11111111-1111-1111-1111-111111111111"
EVIDENCE = "22222222-2222-2222-2222-222222222222"
SESSION = "radius-session:" + "a" * 64
CORPUS = "b" * 64
INPUT = "c" * 64


def candidate() -> UnresolvedCandidate:
    return UnresolvedCandidate(OBSERVATION, EVIDENCE, "identity_unresolved")


def proposal() -> ExactResolutionProposal:
    return ExactResolutionProposal(OBSERVATION, SESSION, "entity:101", INPUT)




def test_attempt_is_stable_and_retries_only_on_new_boundary() -> None:
    first = build_reconciliation_attempts(
        [candidate()],
        {OBSERVATION: proposal()},
        evidence_corpus_sha256=CORPUS,
        resolver_contract_id="resolver-v1",
    )
    assert first[0].outcome == "projected"
    assert build_reconciliation_attempts(
        [candidate()],
        {OBSERVATION: proposal()},
        evidence_corpus_sha256=CORPUS,
        resolver_contract_id="resolver-v1",
        prior_attempt_keys=[first[0].attempt_key],
    ) == ()
    changed = build_reconciliation_attempts(
        [candidate()],
        {},
        evidence_corpus_sha256="d" * 64,
        resolver_contract_id="resolver-v1",
        prior_attempt_keys=[first[0].attempt_key],
    )
    assert changed[0].attempt_key != first[0].attempt_key
    assert changed[0].outcome == "still_unresolved"


def test_overlay_preserves_fact_and_does_not_mutate_original() -> None:
    original = RadiusLifecycleInput(
        observation_id=OBSERVATION,
        lifecycle_event="start",
        identity_state="unresolved",
        timestamp_state="ready",
        session_identity_key=None,
        exact_principal_key=None,
        observed_at_utc=datetime(2026, 8, 2, tzinfo=timezone.utc),
        evidence_sha256="e" * 64,
    )
    resolved = apply_exact_resolution(original, proposal())
    assert original.identity_state == "unresolved"
    assert resolved.identity_state == "exact"
    assert resolved.session_identity_key == SESSION
    assert resolved.observed_at_utc == original.observed_at_utc
    assert resolved.evidence_sha256 == original.evidence_sha256


def test_exact_observation_and_unrelated_proposal_fail_closed() -> None:
    exact = RadiusLifecycleInput(
        OBSERVATION,
        "start",
        "exact",
        "ready",
        SESSION,
        "entity:101",
        datetime(2026, 8, 2, tzinfo=timezone.utc),
    )
    with pytest.raises(
        RadiusSessionReconciliationError,
        match="reconciliation_exact_observation_override_forbidden",
    ):
        apply_exact_resolution(exact, proposal())
    with pytest.raises(
        RadiusSessionReconciliationError,
        match="reconciliation_proposal_without_candidate",
    ):
        build_reconciliation_attempts(
            [],
            {OBSERVATION: proposal()},
            evidence_corpus_sha256=CORPUS,
            resolver_contract_id="resolver-v1",
        )
