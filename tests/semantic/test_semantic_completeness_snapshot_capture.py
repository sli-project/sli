from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace

from server.sli.semantic.event_semantic_contract import MachineRisk
from server.sli.semantic.semantic_risk import (
    ConfidenceFactors,
    EvidenceQuality,
    IdentityResolution,
    RiskContribution,
    ScenarioProposal,
    ScenarioResultClass,
    ScenarioSourceKind,
    ScenarioStep,
)
from server.sli.semantic.semantic_risk_policy import (
    RiskPolicyDefinition,
    compile_risk_policy,
)
from server.sli.semantic import semantic_risk_runtime_repository as repository


NOW = datetime(2026, 7, 29, tzinfo=timezone.utc)


class _Cursor:
    def __init__(self, *, backfill_completed: bool = True) -> None:
        self.backfill_completed = backfill_completed
        self.rows = []

    def execute(self, sql: str, params=()) -> None:
        if "semantic_correlation_candidate_evidence evidence" in sql:
            self.rows = [
                {
                    "server_name": "dc-1",
                    "channel_name": "Security",
                    "event_id": 4624,
                    "provider_name": "Microsoft-Windows-Security-Auditing",
                }
            ]
        elif "from collection_channel_state" in sql:
            self.rows = [
                {
                    "last_successful_collection_utc": NOW
                    + timedelta(seconds=3940),
                    "backfill_completed": self.backfill_completed,
                }
            ]
        else:
            raise AssertionError(sql)

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None


def _policy():
    return compile_risk_policy(
        RiskPolicyDefinition(
            policy_id="snapshot-test",
            policy_version=1,
            source_kind=ScenarioSourceKind.CORRELATION_CANDIDATE,
            definition={
                "type": "scenario_policy",
                "source_selector": {"relation_kind": "session"},
                "scenario_kind": "authentication.session",
                "result_class": "security_incident",
                "strict_roles": ["session_principal"],
                "merge_window_seconds": 1800,
                "allowed_lateness_seconds": 1800,
                "title": "Session",
                "explanation": "Session evidence",
                "risk": {
                    "class": "high",
                    "raw_score": "10",
                    "display_points": 10,
                    "rationale": "Observed session",
                },
            },
        )
    )


def _proposal() -> ScenarioProposal:
    source_kind = ScenarioSourceKind.CORRELATION_CANDIDATE
    return ScenarioProposal(
        scenario_kind="authentication.session",
        result_class=ScenarioResultClass.SECURITY_INCIDENT,
        partition_key="dc-1",
        strict_keys={"session_principal": "dc-1:0x1"},
        merge_window=timedelta(seconds=1800),
        title="Session",
        explanation="Session evidence",
        step=ScenarioStep(
            step_key="snapshot-test-step",
            source_kind=source_kind,
            source_id="00000000-0000-0000-0000-000000000001",
            occurred_at_utc=NOW,
            title="Session",
            explanation="Session evidence",
            normalized_event_ids=(
                "00000000-0000-0000-0000-000000000002",
            ),
            confidence_factors=ConfidenceFactors(
                identity_resolution=IdentityResolution.EXACT,
                sequence_completeness=100,
                time_quality=EvidenceQuality.GOOD,
                parser_quality=EvidenceQuality.GOOD,
            ),
        ),
        contribution=RiskContribution(
            contribution_key="snapshot-test-contribution",
            source_kind=source_kind,
            source_id="00000000-0000-0000-0000-000000000001",
            policy_id="snapshot-test",
            policy_version=1,
            policy_sha256=bytes.fromhex("11" * 32),
            risk_class=MachineRisk.HIGH,
            raw_score=Decimal("10"),
            display_points=10,
            hard_critical=False,
            rationale="Observed session",
        ),
    )


def _catalogue_entry() -> dict[str, object]:
    return {
        "base_risk": "low",
        "purpose_tier": "technical",
        "noise_class": "context",
        "category": "authentication",
        "lifecycle": {},
        "correlation": {},
        "required_fields": ["event_id"],
    }


def test_capture_uses_exact_values_and_can_support_negative(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        repository,
        "all_event_catalog_entries",
        lambda: [_catalogue_entry()],
    )
    monkeypatch.setattr(
        repository,
        "lookup_event_catalog",
        lambda *_args: {"correlation": {"close_timeout_seconds": 900}},
    )
    snapshot = repository._capture_completeness_snapshot(
        _Cursor(),
        policy=_policy(),
        proposal=_proposal(),
        source_id="00000000-0000-0000-0000-000000000001",
        captured_at_utc=NOW + timedelta(seconds=4000),
    )
    assert snapshot.required_channels == ("dc-1|Security",)
    assert snapshot.available_channels == ("dc-1|Security",)
    assert snapshot.freshness_max_age_seconds == 60
    assert snapshot.descriptor_close_timeout_seconds == 900
    assert snapshot.window_closed is True
    assert snapshot.supports_negative_conclusion is True


def test_capture_marks_unavailable_channel_as_incomplete(monkeypatch) -> None:
    monkeypatch.setattr(
        repository,
        "all_event_catalog_entries",
        lambda: [_catalogue_entry()],
    )
    monkeypatch.setattr(
        repository,
        "lookup_event_catalog",
        lambda *_args: {"correlation": {"close_timeout_seconds": 900}},
    )
    snapshot = repository._capture_completeness_snapshot(
        _Cursor(backfill_completed=False),
        policy=_policy(),
        proposal=_proposal(),
        source_id="00000000-0000-0000-0000-000000000001",
        captured_at_utc=NOW + timedelta(seconds=4000),
    )
    assert snapshot.freshness_max_age_seconds == 60
    assert snapshot.available_channels == ()
    assert snapshot.supports_negative_conclusion is False


def test_control_health_is_selected_as_of_the_event_time() -> None:
    class Cursor:
        def __init__(self) -> None:
            self.sql = ""
            self.params = ()

        def execute(self, sql: str, params=()) -> None:
            self.sql = " ".join(sql.split()).lower()
            self.params = params

        def fetchone(self):
            return {
                "control_id": "collection.security",
                "coverage_status": "complete",
                "reason": "Known at event time",
                "observed_at_utc": NOW - timedelta(minutes=1),
            }

    cursor = Cursor()
    coverage = repository._coverage_for_policy(
        cursor,
        policy=SimpleNamespace(required_controls=("collection.security",)),
        partition_key="dc-1",
        observed_at=NOW,
    )

    assert "observed_at_utc <= %s" in cursor.sql
    assert cursor.params == ("dc-1", "collection.security", NOW)
    assert coverage[0].observed_at_utc < NOW
