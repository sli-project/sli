from __future__ import annotations

from datetime import datetime, timezone

import pytest

from server.source_packs.radius.session_read_model import (
    CONTRACT_ID,
    RadiusLifecycleInput,
    RadiusSessionReadModelError,
    fold_radius_sessions,
)


SESSION = "radius-session:" + "a" * 64
PRINCIPAL = "entity:11111111-1111-1111-1111-111111111111"


def _input(
    observation_id: str,
    event: str,
    minute: int,
    *,
    session: str | None = SESSION,
    principal: str | None = PRINCIPAL,
    identity_state: str = "exact",
    timestamp_state: str = "ready",
    evidence_sha256: str | None = "e" * 64,
):
    observed = (
        datetime(2026, 7, 30, 4, minute, tzinfo=timezone.utc)
        if timestamp_state == "ready"
        else None
    )
    return RadiusLifecycleInput(
        observation_id=observation_id,
        lifecycle_event=event,
        identity_state=identity_state,
        timestamp_state=timestamp_state,
        session_identity_key=session,
        exact_principal_key=principal,
        observed_at_utc=observed,
        evidence_sha256=evidence_sha256,
    )


def test_complete_session_is_folded_without_active_claim() -> None:
    result = fold_radius_sessions([
        _input("three", "stop", 30),
        _input("one", "start", 10),
        _input("two", "interim_update", 20),
    ])

    assert result.contract_id == CONTRACT_ID
    assert result.input_observations == 3
    assert result.exact_ready_observations == 3
    assert result.complete_sessions == 1
    assert result.open_observed_sessions == 0
    row = result.sessions[0]
    assert row.lifecycle_state == "closed"
    assert row.completeness == "complete"
    assert row.duration_seconds == 1200
    assert row.observation_count == 3
    assert row.anomalies == ()


def test_unresolved_facts_are_counted_but_never_merged() -> None:
    result = fold_radius_sessions([
        _input(
            "identity",
            "start",
            1,
            session=None,
            principal=None,
            identity_state="unresolved",
        ),
        _input(
            "timestamp",
            "start",
            2,
            timestamp_state="unresolved",
        ),
    ])

    assert result.sessions == ()
    assert result.unresolved_identity_observations == 1
    assert result.unresolved_timestamp_observations == 1


def test_missing_boundaries_remain_partial() -> None:
    middle = fold_radius_sessions([
        _input("interim", "interim_update", 1),
    ]).sessions[0]
    assert middle.lifecycle_state == "partial_open"
    assert middle.completeness == "middle_only"
    assert middle.duration_seconds is None

    stopped = fold_radius_sessions([
        _input("stop", "stop", 2),
    ]).sessions[0]
    assert stopped.lifecycle_state == "partial_closed"
    assert stopped.completeness == "missing_start"


def test_session_key_reuse_after_stop_creates_new_generation() -> None:
    result = fold_radius_sessions([
        _input("start-1", "start", 1),
        _input("stop-1", "stop", 2),
        _input("start-2", "start", 3),
    ])

    assert len(result.sessions) == 2
    generations = sorted(
        (row.generation, row.lifecycle_state)
        for row in result.sessions
    )
    assert generations == [(1, "closed"), (2, "open_observed")]


def test_second_start_does_not_invent_a_stop() -> None:
    result = fold_radius_sessions([
        _input("start-1", "start", 1),
        _input("start-2", "start", 2),
    ])

    assert len(result.sessions) == 2
    first = next(row for row in result.sessions if row.generation == 1)
    assert first.lifecycle_state == "open_observed"
    assert first.duration_seconds is None
    assert first.anomalies == ("start_before_stop",)


def test_duplicate_and_principal_conflict_fail_closed() -> None:
    with pytest.raises(
        RadiusSessionReadModelError,
        match="duplicate_observation_id",
    ):
        fold_radius_sessions([
            _input("same", "start", 1),
            _input("same", "stop", 2),
        ])

    with pytest.raises(
        RadiusSessionReadModelError,
        match="session_key_principal_conflict",
    ):
        fold_radius_sessions([
            _input("one", "start", 1),
            _input(
                "two",
                "stop",
                2,
                principal="entity:22222222-2222-2222-2222-222222222222",
            ),
        ])


def test_naive_ready_timestamp_is_rejected() -> None:
    item = RadiusLifecycleInput(
        observation_id="naive",
        lifecycle_event="start",
        identity_state="exact",
        timestamp_state="ready",
        session_identity_key=SESSION,
        exact_principal_key=PRINCIPAL,
        observed_at_utc=datetime(2026, 7, 30, 4, 0),
        evidence_sha256="e" * 64,
    )
    with pytest.raises(
        RadiusSessionReadModelError,
        match="observed_at_utc_timezone_required",
    ):
        fold_radius_sessions([item])


@pytest.mark.parametrize("digest", [None, "", "not-a-sha256"])
def test_exact_ready_lifecycle_requires_valid_evidence_sha256(
    digest: str | None,
) -> None:
    with pytest.raises(
        RadiusSessionReadModelError,
        match="evidence_sha256_(required|invalid)",
    ):
        fold_radius_sessions([_input("exact", "start", 1, evidence_sha256=digest)])
