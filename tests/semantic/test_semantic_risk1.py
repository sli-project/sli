from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from server.sli.semantic.event_semantic_contract import Confidence, MachineRisk
from server.sli.semantic.semantic_risk import (
    CompletenessSnapshot,
    ConfidenceFactors,
    ConclusionState,
    ControlCoverage,
    CoverageStatus,
    EvidenceQuality,
    IdentityResolution,
    RiskContribution,
    ScenarioProposal,
    ScenarioResultClass,
    ScenarioSourceKind,
    ScenarioStep,
    aggregate_risk,
    assess_confidence,
    merge_scenario_proposals,
    resolve_conclusion_state,
    summarize_coverage,
)


NOW = datetime(2026, 7, 19, 5, tzinfo=timezone.utc)
POLICY_SHA = bytes.fromhex("11" * 32)


def _snapshot(*, complete: bool) -> CompletenessSnapshot:
    required = ("dc-1|Security",)
    timeout = 900 if complete else None
    deadline = NOW + timedelta(seconds=900 + 60) if complete else None
    return CompletenessSnapshot(
        captured_at_utc=NOW + timedelta(hours=1),
        catalog_entry_count=10,
        catalog_fully_classified=10 if complete else 9,
        catalog_schema_v2_ready=10,
        freshness_max_age_seconds=60 if complete else None,
        freshness_budget_seconds=1800,
        required_channels=required,
        available_channels=required if complete else (),
        window_end_utc=NOW,
        descriptor_close_timeout_seconds=timeout,
        allowed_lateness_seconds=60,
        close_deadline_utc=deadline,
        window_closed=complete,
    )


def _coverage(status: CoverageStatus, *, minute: int = 0) -> ControlCoverage:
    return ControlCoverage(
        control_id="security-audit-logon",
        status=status,
        reason=f"control is {status.value}",
        observed_at_utc=NOW + timedelta(minutes=minute),
    )


def _proposal(
    source_id: str,
    *,
    minute: int = 0,
    risk_class: MachineRisk = MachineRisk.HIGH,
    hard_critical: bool = False,
    contribution_key: str | None = None,
    partition: str = "dc-1",
    session: str = "dc-1:0xabc",
    coverage: tuple[ControlCoverage, ...] = (),
    factors: ConfidenceFactors | None = None,
) -> ScenarioProposal:
    source_kind = ScenarioSourceKind.CORRELATION_CANDIDATE
    return ScenarioProposal(
        scenario_kind="authentication.privileged_session",
        result_class=ScenarioResultClass.SECURITY_INCIDENT,
        partition_key=partition,
        strict_keys={"session_principal": session},
        merge_window=timedelta(minutes=30),
        title="Privileged session requires review",
        explanation="Strict host and session identity matched",
        step=ScenarioStep(
            step_key=f"candidate:{source_id}",
            source_kind=source_kind,
            source_id=source_id,
            occurred_at_utc=NOW + timedelta(minutes=minute),
            title="Privileged session",
            explanation="Correlation candidate is exact",
            normalized_event_ids=(f"00000000-0000-0000-0000-{int(source_id):012d}",),
            confidence_factors=factors
            or ConfidenceFactors(
                identity_resolution=IdentityResolution.EXACT,
                multi_source_confirmed=True,
                sequence_completeness=100,
                time_quality=EvidenceQuality.GOOD,
                parser_quality=EvidenceQuality.GOOD,
            ),
        ),
        contribution=RiskContribution(
            contribution_key=contribution_key or f"privileged-session:{source_id}",
            source_kind=source_kind,
            source_id=source_id,
            policy_id="privileged-session-policy",
            policy_version=1,
            policy_sha256=POLICY_SHA,
            risk_class=risk_class,
            raw_score=Decimal("50"),
            display_points=50,
            hard_critical=hard_critical,
            rationale="Exact privileged session correlation",
        ),
        coverage=coverage,
    )


def test_coverage_is_explicit_and_latest_observation_wins() -> None:
    assert summarize_coverage(()) is CoverageStatus.UNKNOWN
    assert summarize_coverage((_coverage(CoverageStatus.UNAVAILABLE),)) is CoverageStatus.UNAVAILABLE
    assert summarize_coverage(
        (
            _coverage(CoverageStatus.UNAVAILABLE),
            _coverage(CoverageStatus.COMPLETE, minute=1),
        )
    ) is CoverageStatus.COMPLETE
    second = ControlCoverage(
        control_id="directory-audit",
        status=CoverageStatus.UNAVAILABLE,
        reason="SACL is not confirmed",
        observed_at_utc=NOW,
    )
    assert summarize_coverage((_coverage(CoverageStatus.COMPLETE), second)) is CoverageStatus.PARTIAL


def test_confidence_uses_evidence_quality_but_does_not_own_risk() -> None:
    low = assess_confidence(
        ConfidenceFactors(
            identity_resolution=IdentityResolution.UNRESOLVED,
            sequence_completeness=10,
            time_quality=EvidenceQuality.POOR,
            parser_quality=EvidenceQuality.POOR,
        ),
        coverage_status=CoverageStatus.UNAVAILABLE,
    )
    assert low.level is Confidence.LOW
    critical = aggregate_risk(
        (
            _proposal(
                "1", risk_class=MachineRisk.CRITICAL, hard_critical=True
            ).contribution,
        )
    )
    assert critical.risk_class is MachineRisk.CRITICAL
    assert critical.hard_critical is True


def test_repeated_contribution_is_idempotent_and_conflict_is_rejected() -> None:
    contribution = _proposal("1").contribution
    risk = aggregate_risk((contribution, contribution))
    assert risk.raw_score == Decimal("50")
    assert risk.display_score == 50
    conflicting = _proposal(
        "2", contribution_key=contribution.contribution_key
    ).contribution
    with pytest.raises(ValueError, match="replay conflict"):
        aggregate_risk((contribution, conflicting))


def test_different_policies_do_not_double_count_the_same_evidence() -> None:
    first = _proposal("1").contribution
    second = RiskContribution(
        contribution_key="second-policy:same-source",
        source_kind=first.source_kind,
        source_id=first.source_id,
        policy_id="second-policy",
        policy_version=1,
        policy_sha256=bytes.fromhex("33" * 32),
        risk_class=MachineRisk.CRITICAL,
        raw_score=Decimal("60"),
        display_points=60,
        hard_critical=True,
        rationale="A second policy evaluates the same exact source evidence",
    )
    risk = aggregate_risk((first, second))
    assert risk.raw_score == Decimal("60")
    assert risk.display_score == 60
    assert risk.risk_class is MachineRisk.CRITICAL
    assert risk.hard_critical is True


def test_scenario_merge_requires_strict_identity_and_bounded_window() -> None:
    merged = merge_scenario_proposals((_proposal("1"), _proposal("2", minute=10)))
    assert merged.first_seen_utc == NOW
    assert merged.last_seen_utc == NOW + timedelta(minutes=10)
    assert merged.risk.display_score == 100
    assert merged.confidence.level is Confidence.HIGH
    with pytest.raises(ValueError, match="strict identity"):
        merge_scenario_proposals((_proposal("1"), _proposal("2", partition="dc-2")))
    with pytest.raises(ValueError, match="merge window"):
        merge_scenario_proposals((_proposal("1"), _proposal("2", minute=31)))


def test_scenario_confidence_is_limited_by_weakest_mandatory_step() -> None:
    weak = ConfidenceFactors(
        identity_resolution=IdentityResolution.UNRESOLVED,
        sequence_completeness=10,
        time_quality=EvidenceQuality.POOR,
        parser_quality=EvidenceQuality.POOR,
    )
    merged = merge_scenario_proposals(
        (_proposal("1"), _proposal("2", minute=10, factors=weak))
    )
    assert merged.confidence.level is Confidence.LOW
    assert merged.confidence.score == 2


def test_hard_critical_contract_rejects_inconsistent_class() -> None:
    with pytest.raises(ValueError, match="must be critical"):
        _proposal("1", risk_class=MachineRisk.HIGH, hard_critical=True)


def test_negative_conclusion_requires_all_four_captured_values() -> None:
    complete = _snapshot(complete=True)
    assert complete.supports_negative_conclusion is True
    assert resolve_conclusion_state(
        ConclusionState.NOT_FOUND,
        snapshot=complete,
    ) is ConclusionState.NOT_FOUND
    payload = complete.as_dict()
    assert set(payload) >= {
        "catalog_completeness",
        "collection_freshness",
        "channel_availability",
        "window_closure",
    }

    incomplete = _snapshot(complete=False)
    assert incomplete.supports_negative_conclusion is False
    assert resolve_conclusion_state(
        ConclusionState.NOT_FOUND,
        snapshot=incomplete,
    ) is ConclusionState.NOT_CHECKED
    assert resolve_conclusion_state(
        ConclusionState.OBSERVED,
        snapshot=incomplete,
    ) is ConclusionState.OBSERVED
