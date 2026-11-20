from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from server.sli.semantic.event_semantic_contract import MachineRisk
from server.sli.semantic.semantic_risk import (
    ConfidenceFactors,
    CoverageStatus,
    EvidenceQuality,
    IdentityResolution,
    RiskContribution,
    ScenarioProposal,
    ScenarioResultClass,
    ScenarioSourceKind,
    ScenarioStep,
)
import server.sli.semantic.semantic_risk_repository as repository


NOW = datetime(2026, 7, 19, 6, tzinfo=timezone.utc)
NORMALIZED_ID = "00000000-0000-0000-0000-000000000001"


def _proposal(*, partition: str = "dc-1") -> ScenarioProposal:
    source_kind = ScenarioSourceKind.CORRELATION_CANDIDATE
    return ScenarioProposal(
        scenario_kind="authentication.privileged_session",
        result_class=ScenarioResultClass.SECURITY_INCIDENT,
        partition_key=partition,
        strict_keys={"session_principal": "dc-1:0xabc"},
        merge_window=timedelta(minutes=30),
        title="Privileged session",
        explanation="Exact session correlation",
        step=ScenarioStep(
            step_key="candidate:00000000-0000-0000-0000-000000000010",
            source_kind=source_kind,
            source_id="00000000-0000-0000-0000-000000000010",
            occurred_at_utc=NOW,
            title="Candidate",
            explanation="Exact evidence",
            normalized_event_ids=(NORMALIZED_ID,),
            confidence_factors=ConfidenceFactors(sequence_completeness=100),
        ),
        contribution=RiskContribution(
            contribution_key="candidate-risk:10",
            source_kind=source_kind,
            source_id="00000000-0000-0000-0000-000000000010",
            policy_id="policy",
            policy_version=1,
            policy_sha256=bytes.fromhex("22" * 32),
            risk_class=MachineRisk.HIGH,
            raw_score=Decimal("50"),
            display_points=50,
            hard_critical=False,
            rationale="Exact candidate",
        ),
    )


class CandidateCursor:
    def __init__(self, *, linked: bool = True) -> None:
        self.sql = ""
        self.linked = linked

    def execute(self, sql, params=()):
        self.sql = " ".join(sql.split()).lower()

    def fetchone(self):
        if "from semantic_correlation_candidates" in self.sql:
            return {
                "candidate_status": "matched",
                "partition_key": "dc-1",
                "window_start_utc": NOW,
                "window_end_utc": NOW,
            }
        return None

    def fetchall(self):
        if "from semantic_correlation_candidate_evidence" in self.sql and self.linked:
            return [{"normalized_event_id": NORMALIZED_ID}]
        return []


def test_candidate_source_requires_exact_partition_and_linked_evidence() -> None:
    repository._verify_source_evidence(CandidateCursor(), proposal=_proposal())
    with pytest.raises(RuntimeError, match="partition"):
        repository._verify_source_evidence(
            CandidateCursor(), proposal=_proposal(partition="dc-2")
        )
    with pytest.raises(RuntimeError, match="not linked"):
        repository._verify_source_evidence(
            CandidateCursor(linked=False), proposal=_proposal()
        )


def test_contribution_replay_conflict_is_fail_closed() -> None:
    proposal = _proposal()
    contribution = proposal.contribution
    row = {
        "source_kind": contribution.source_kind.value,
        "correlation_candidate_id": contribution.source_id,
        "policy_id": contribution.policy_id,
        "policy_version": contribution.policy_version,
        "policy_sha256": contribution.policy_sha256,
        "risk_class": contribution.risk_class.value,
        "raw_score": contribution.raw_score,
        "display_points": contribution.display_points + 1,
        "hard_critical": contribution.hard_critical,
        "rationale": contribution.rationale,
    }
    with pytest.raises(RuntimeError, match="replay conflict"):
        repository._verify_contribution_replay(row, proposal=proposal)


def test_durable_refresh_keeps_the_weakest_step_confidence() -> None:
    strong = ConfidenceFactors(
        identity_resolution=IdentityResolution.EXACT,
        state_confirmed=True,
        multi_source_confirmed=True,
        sequence_completeness=100,
        time_quality=EvidenceQuality.GOOD,
        parser_quality=EvidenceQuality.GOOD,
    )
    weak = ConfidenceFactors(
        identity_resolution=IdentityResolution.UNRESOLVED,
        sequence_completeness=10,
        time_quality=EvidenceQuality.POOR,
        parser_quality=EvidenceQuality.POOR,
    )

    assessment = repository._weakest_confidence_assessment(
        [strong.as_dict(), weak.as_dict()],
        coverage_status=CoverageStatus.COMPLETE,
    )

    assert assessment.factors == weak
    assert assessment.score < 20


def test_durable_refresh_rejects_a_scenario_without_steps() -> None:
    with pytest.raises(RuntimeError, match="no durable step"):
        repository._weakest_confidence_assessment(
            [],
            coverage_status=CoverageStatus.UNKNOWN,
        )
