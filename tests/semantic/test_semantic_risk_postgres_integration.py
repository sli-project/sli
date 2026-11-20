from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from server.sli.semantic.event_semantic_contract import Confidence, MachineRisk
from server.sli.semantic.semantic_correlation import (
    correlate_session_privilege_observation,
)
from server.sli.semantic.semantic_correlation_repository import (
    CorrelationRuleDefinition,
    persist_correlation_candidate,
    register_correlation_rule,
    transition_correlation_rule,
)
from server.sli.semantic.semantic_processing import StoredEvent, normalize_windows_event
from server.sli.semantic.semantic_processing_repository import persist_normalized_event
from server.sli.semantic.semantic_risk import (
    ConfidenceFactors,
    ControlCoverage,
    CoverageStatus,
    EvidenceQuality,
    IdentityResolution,
    RiskContribution,
    ScenarioProposal,
    ScenarioResultClass,
    ScenarioSourceKind,
    ScenarioStep,
)
from server.sli.semantic.semantic_risk_repository import persist_scenario_proposal
from tests.postgres_integration_guard import assert_disposable_database


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_scenario_risk_confidence_and_coverage_are_durable_and_independent() -> None:
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL tests")

    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    rule_ids = ("risk-session-rule-low", "risk-session-rule-high")
    source_ids = (940001, 940002)
    with connect() as conn, conn.cursor() as cur:
        assert_disposable_database(conn)
        cur.execute(
            "select 1 from schema_migrations "
            "where version=28 and name='semantic_risk_scenarios'"
        )
        assert cur.fetchone() is not None
        cur.execute("select count(*) as value from findings")
        findings_before = int(cur.fetchone()["value"])
        cur.execute(
            "delete from semantic_scenario_coverage_history where scenario_id in "
            "(select scenario_id from semantic_security_scenarios "
            "where partition_key='1' and scenario_kind='authentication.privileged_session')"
        )
        cur.execute(
            "delete from semantic_risk_contributions where scenario_id in "
            "(select scenario_id from semantic_security_scenarios "
            "where partition_key='1' and scenario_kind='authentication.privileged_session')"
        )
        cur.execute(
            "delete from semantic_scenario_evidence where scenario_id in "
            "(select scenario_id from semantic_security_scenarios "
            "where partition_key='1' and scenario_kind='authentication.privileged_session')"
        )
        cur.execute(
            "delete from semantic_scenario_steps where scenario_id in "
            "(select scenario_id from semantic_security_scenarios "
            "where partition_key='1' and scenario_kind='authentication.privileged_session')"
        )
        cur.execute(
            "delete from semantic_security_scenarios "
            "where partition_key='1' and scenario_kind='authentication.privileged_session'"
        )
        cur.execute(
            "update semantic_correlation_rules set lifecycle_status='draft' "
            "where rule_id=any(%s)",
            (list(rule_ids),),
        )
        cur.execute(
            "delete from semantic_correlation_candidate_evidence where candidate_id in "
            "(select candidate_id from semantic_correlation_candidates where rule_id=any(%s))",
            (list(rule_ids),),
        )
        cur.execute(
            "delete from semantic_correlation_candidates where rule_id=any(%s)",
            (list(rule_ids),),
        )
        cur.execute(
            "delete from semantic_correlation_replays where rule_id=any(%s)",
            (list(rule_ids),),
        )
        cur.execute(
            "delete from semantic_correlation_subscriptions where rule_id=any(%s)",
            (list(rule_ids),),
        )
        cur.execute(
            "delete from semantic_correlation_rules where rule_id=any(%s)",
            (list(rule_ids),),
        )
        cur.execute(
            "delete from normalized_events where source_event_id=any(%s)",
            (list(source_ids),),
        )
        cur.execute(
            "delete from semantic_processing_outbox where source_event_id=any(%s)",
            (list(source_ids),),
        )
        cur.execute("delete from events_v2_core where id=any(%s)", (list(source_ids),))

    occurred = datetime(2026, 7, 19, 7, tzinfo=timezone.utc)
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "insert into storage_v2_provider(value) values ('Microsoft-Windows-Security-Auditing') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        provider_id = cur.fetchone()["id"]
        cur.execute(
            "insert into storage_v2_channel(value) values ('Security') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        channel_id = cur.fetchone()["id"]
        cur.execute(
            "insert into storage_v2_computer(value) values ('risk-dc') "
            "on conflict(value) do update set value=excluded.value returning id"
        )
        computer_id = cur.fetchone()["id"]
        for index, (source_id, event_id) in enumerate(zip(source_ids, (4624, 4672))):
            event_time = occurred + timedelta(seconds=index)
            cur.execute(
                """
                insert into events_v2_core(
                    id,server_id,domain_id,log_source_id,event_record_id,event_id,
                    provider_id,channel_id,computer_id,time_created_utc,
                    normalized_at,normalized_hash,source_core_sha256
                ) values (%s,1,1,1,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    source_id,
                    source_id,
                    event_id,
                    provider_id,
                    channel_id,
                    computer_id,
                    event_time,
                    event_time,
                    bytes([event_id % 251]) * 32,
                    bytes([(event_id + 1) % 251]) * 32,
                ),
            )
        normalized = (
            normalize_windows_event(
                StoredEvent(
                    940001,
                    4624,
                    "Security",
                    "DC1",
                    occurred,
                    {"TargetUserSid": "S-1-5-21-300", "TargetLogonId": "0xabc"},
                    provider="Microsoft-Windows-Security-Auditing",
                    source_host_id=1,
                )
            ),
            normalize_windows_event(
                StoredEvent(
                    940002,
                    4672,
                    "Security",
                    "DC1",
                    occurred + timedelta(seconds=1),
                    {"SubjectUserSid": "S-1-5-21-300", "SubjectLogonId": "0xabc"},
                    provider="Microsoft-Windows-Security-Auditing",
                    source_host_id=1,
                )
            ),
        )
        normalized_ids = tuple(persist_normalized_event(cur, event=item) for item in normalized)
        relation = correlate_session_privilege_observation(normalized)[0]
        candidate_ids: list[str] = []
        for rule_id in rule_ids:
            rule = CorrelationRuleDefinition(
                rule_id=rule_id,
                rule_version=1,
                rule_kind="all_of",
                definition={
                    "type": "all_of",
                    "inputs": [
                        "authentication.session.created",
                        "authentication.privileged_session.created",
                    ],
                    "window_seconds": 900,
                },
            )
            register_correlation_rule(cur, rule=rule)
            transition_correlation_rule(
                cur, rule_id=rule_id, rule_version=1, target_status="validated"
            )
            transition_correlation_rule(
                cur, rule_id=rule_id, rule_version=1, target_status="test"
            )
            candidate_ids.append(
                persist_correlation_candidate(
                    cur, rule_id=rule_id, rule_version=1, relation=relation
                )
            )
        cur.execute(
            "select distinct partition_key from semantic_correlation_candidates "
            "where candidate_id=any(%s)",
            (candidate_ids,),
        )
        partition_key = str(cur.fetchone()["partition_key"])

        def proposal(
            *,
            candidate_id: str,
            suffix: str,
            factors: ConfidenceFactors,
            coverage: ControlCoverage,
            raw_score: str,
            display_points: int,
            hard_critical: bool,
        ) -> ScenarioProposal:
            source_kind = ScenarioSourceKind.CORRELATION_CANDIDATE
            return ScenarioProposal(
                scenario_kind="authentication.privileged_session",
                result_class=ScenarioResultClass.SECURITY_INCIDENT,
                partition_key=partition_key,
                strict_keys={"session_principal": "1:0xabc"},
                merge_window=timedelta(minutes=30),
                title="Privileged session requires review",
                explanation="Strict session identity joined two correlation sources",
                step=ScenarioStep(
                    step_key=f"risk-step:{suffix}:{candidate_id}",
                    source_kind=source_kind,
                    source_id=candidate_id,
                    occurred_at_utc=occurred + timedelta(seconds=1),
                    title=f"Risk source {suffix}",
                    explanation="Exact normalized evidence from a matched candidate",
                    normalized_event_ids=normalized_ids,
                    confidence_factors=factors,
                ),
                contribution=RiskContribution(
                    contribution_key=f"risk-contribution:{suffix}:{candidate_id}",
                    source_kind=source_kind,
                    source_id=candidate_id,
                    policy_id="privileged-session-risk",
                    policy_version=1,
                    policy_sha256=bytes.fromhex("33" * 32),
                    risk_class=(
                        MachineRisk.CRITICAL if hard_critical else MachineRisk.HIGH
                    ),
                    raw_score=Decimal(raw_score),
                    display_points=display_points,
                    hard_critical=hard_critical,
                    rationale=f"Risk contribution {suffix}",
                ),
                coverage=(coverage,),
            )

        unavailable = ControlCoverage(
            control_id="security-audit-logon",
            status=CoverageStatus.UNAVAILABLE,
            reason="Audit coverage is not confirmed",
            observed_at_utc=occurred,
        )
        low_proposal = proposal(
            candidate_id=candidate_ids[0],
            suffix="low",
            factors=ConfidenceFactors(
                identity_resolution=IdentityResolution.UNRESOLVED,
                sequence_completeness=10,
                time_quality=EvidenceQuality.POOR,
                parser_quality=EvidenceQuality.POOR,
            ),
            coverage=unavailable,
            raw_score="80",
            display_points=90,
            hard_critical=True,
        )
        first = persist_scenario_proposal(cur, proposal=low_proposal)
        replay = persist_scenario_proposal(cur, proposal=low_proposal)
        assert replay == first
        assert first.risk_class is MachineRisk.CRITICAL
        assert first.hard_critical is True
        assert first.confidence is Confidence.LOW
        assert first.coverage_status is CoverageStatus.UNAVAILABLE
        assert (first.step_count, first.evidence_count, first.contribution_count) == (1, 2, 1)

        complete = ControlCoverage(
            control_id="security-audit-logon",
            status=CoverageStatus.COMPLETE,
            reason="Audit coverage is confirmed",
            observed_at_utc=occurred + timedelta(minutes=1),
        )
        second = persist_scenario_proposal(
            cur,
            proposal=proposal(
                candidate_id=candidate_ids[1],
                suffix="high",
                factors=ConfidenceFactors(
                    identity_resolution=IdentityResolution.EXACT,
                    state_confirmed=True,
                    multi_source_confirmed=True,
                    sequence_completeness=100,
                    time_quality=EvidenceQuality.GOOD,
                    parser_quality=EvidenceQuality.GOOD,
                ),
                coverage=complete,
                raw_score="30",
                display_points=20,
                hard_critical=False,
            ),
        )
        assert second.scenario_id == first.scenario_id
        assert second.risk_class is MachineRisk.CRITICAL
        assert second.raw_score == Decimal(110)
        assert second.display_score == 100
        assert second.hard_critical is True
        # Adding a stronger step cannot erase the earlier unresolved evidence.
        assert second.confidence is Confidence.LOW
        assert second.coverage_status is CoverageStatus.COMPLETE
        assert (second.step_count, second.evidence_count, second.contribution_count) == (2, 2, 2)

    with connect() as conn, conn.cursor() as cur:
        cur.execute("select count(*) as value from findings")
        assert int(cur.fetchone()["value"]) == findings_before
        cur.execute(
            "select count(*) as value from semantic_security_scenarios "
            "where scenario_kind='authentication.privileged_session' and partition_key='1'"
        )
        assert int(cur.fetchone()["value"]) == 1

    with pytest.raises(psycopg.Error, match="immutable"), connect() as conn, conn.cursor() as cur:
        cur.execute(
            "update semantic_risk_contributions set display_points=1 "
            "where policy_id='privileged-session-risk'"
        )
