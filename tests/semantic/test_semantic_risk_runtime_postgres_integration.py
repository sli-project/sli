from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

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
    ControlCoverage,
    CoverageStatus,
    ScenarioSourceKind,
)
from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition
from server.sli.semantic.semantic_risk_runtime_repository import (
    claim_risk_evaluation_jobs,
    enqueue_candidate_risk_jobs,
    enqueue_control_health_risk_jobs,
    execute_risk_evaluation,
    load_risk_evaluation_work_item,
    record_control_health,
    register_risk_policy,
    transition_risk_policy,
)
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "maintenance" / "run_semantic_risk_shadow_once.py"


def _policy_definition(*, control_gap: bool = False) -> dict[str, object]:
    return {
        "type": "scenario_policy",
        "source_selector": (
            {"control_id": "security-audit-logon"}
            if control_gap
            else {"relation_kind": "authentication.session.has_special_privileges"}
        ),
        "scenario_kind": (
            "control.audit.unavailable"
            if control_gap
            else "authentication.privileged_session"
        ),
        "result_class": "control_gap" if control_gap else "security_incident",
        "strict_roles": [] if control_gap else ["session_principal"],
        "merge_window_seconds": 1800,
        "title": "Audit control gap" if control_gap else "Privileged session",
        "explanation": (
            "Required audit coverage is unavailable"
            if control_gap
            else "Exact host and session identity matched"
        ),
        "expected_evidence_count": 1 if control_gap else 2,
        "required_controls": ["security-audit-logon"],
        "risk": {
            "class": "critical",
            "raw_score": "70" if control_gap else "80",
            "display_points": 70 if control_gap else 90,
            "hard_critical": True,
            "rationale": "Critical control gap" if control_gap else "Privileged session",
        },
    }


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_test_and_shadow_risk_runtime_are_leased_idempotent_and_findings_free(postgres_semantic_worker_dsn) -> None:
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL tests")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    rule_id = "runtime-risk-source-rule"
    policy_ids = ("runtime-privileged-risk", "runtime-audit-gap")
    source_ids = (950001, 950002)
    with connect() as conn, conn.cursor() as cur:
        assert_disposable_database(conn)
        cur.execute(
            "select 1 from schema_migrations "
            "where version=29 and name='semantic_risk_runtime'"
        )
        assert cur.fetchone() is not None
        cur.execute("select count(*) as value from findings")
        findings_before = int(cur.fetchone()["value"])
        cur.execute("delete from semantic_risk_evaluation_results")
        cur.execute("delete from semantic_risk_evaluation_jobs")
        cur.execute(
            "update semantic_risk_policies set lifecycle_status='draft' "
            "where policy_id=any(%s)",
            (list(policy_ids),),
        )
        cur.execute(
            "delete from semantic_risk_policy_subscriptions where policy_id=any(%s)",
            (list(policy_ids),),
        )
        cur.execute(
            "delete from semantic_risk_policies where policy_id=any(%s)",
            (list(policy_ids),),
        )
        cur.execute("delete from semantic_scenario_coverage_history")
        cur.execute("delete from semantic_risk_contributions")
        cur.execute("delete from semantic_scenario_evidence")
        cur.execute("delete from semantic_scenario_steps")
        cur.execute("delete from semantic_security_scenarios")
        cur.execute("delete from semantic_control_health_observations")
        cur.execute(
            "update semantic_correlation_rules set lifecycle_status='draft' where rule_id=%s",
            (rule_id,),
        )
        cur.execute(
            "delete from semantic_correlation_candidate_evidence where candidate_id in "
            "(select candidate_id from semantic_correlation_candidates where rule_id=%s)",
            (rule_id,),
        )
        cur.execute("delete from semantic_correlation_candidates where rule_id=%s", (rule_id,))
        cur.execute("delete from semantic_correlation_replays where rule_id=%s", (rule_id,))
        cur.execute("delete from semantic_correlation_subscriptions where rule_id=%s", (rule_id,))
        cur.execute("delete from semantic_correlation_rules where rule_id=%s", (rule_id,))
        cur.execute("delete from normalized_events where source_event_id=any(%s)", (list(source_ids),))
        cur.execute("delete from semantic_processing_outbox where source_event_id=any(%s)", (list(source_ids),))
        cur.execute("delete from events_v2_core where id=any(%s)", (list(source_ids),))

    occurred = datetime(2026, 7, 19, 9, tzinfo=timezone.utc)
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
            "insert into storage_v2_computer(value) values ('risk-runtime-dc') "
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
                    950001,
                    4624,
                    "Security",
                    "DC1",
                    occurred,
                    {"TargetUserSid": "S-1-5-21-400", "TargetLogonId": "0xabc"},
                    provider="Microsoft-Windows-Security-Auditing",
                    source_host_id=1,
                )
            ),
            normalize_windows_event(
                StoredEvent(
                    950002,
                    4672,
                    "Security",
                    "DC1",
                    occurred + timedelta(seconds=1),
                    {"SubjectUserSid": "S-1-5-21-400", "SubjectLogonId": "0xabc"},
                    provider="Microsoft-Windows-Security-Auditing",
                    source_host_id=1,
                )
            ),
        )
        for item in normalized:
            persist_normalized_event(cur, event=item)
        correlation_rule = CorrelationRuleDefinition(
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
        register_correlation_rule(cur, rule=correlation_rule)
        transition_correlation_rule(
            cur, rule_id=rule_id, rule_version=1, target_status="validated"
        )
        transition_correlation_rule(cur, rule_id=rule_id, rule_version=1, target_status="test")
        candidate_id = persist_correlation_candidate(
            cur,
            rule_id=rule_id,
            rule_version=1,
            relation=correlate_session_privilege_observation(normalized)[0],
        )
        candidate_policy = RiskPolicyDefinition(
            policy_id=policy_ids[0],
            policy_version=1,
            source_kind=ScenarioSourceKind.CORRELATION_CANDIDATE,
            definition=_policy_definition(),
        )
        register_risk_policy(cur, policy=candidate_policy)
        transition_risk_policy(
            cur, policy_id=policy_ids[0], policy_version=1, target_status="validated"
        )
        transition_risk_policy(
            cur, policy_id=policy_ids[0], policy_version=1, target_status="test"
        )
        test_job = enqueue_candidate_risk_jobs(cur, candidate_id=candidate_id)[0]
        assert enqueue_candidate_risk_jobs(cur, candidate_id=candidate_id) == (test_job,)

    with connect() as conn, conn.cursor() as cur:
        claimed = claim_risk_evaluation_jobs(cur, limit=1)[0]
        work = load_risk_evaluation_work_item(
            cur,
            job_id=str(claimed["job_id"]),
            lease_token=str(claimed["lease_token"]),
        )
        test_result = execute_risk_evaluation(cur, work=work, evaluation_ms=1)
        assert test_result.evaluation_mode == "test"
        assert test_result.scenario_id is None
        cur.execute("select count(*) as value from semantic_security_scenarios")
        assert int(cur.fetchone()["value"]) == 0

    with connect() as conn, conn.cursor() as cur:
        transition_risk_policy(
            cur, policy_id=policy_ids[0], policy_version=1, target_status="shadow"
        )
        enqueue_candidate_risk_jobs(cur, candidate_id=candidate_id)
        observation_id = record_control_health(
            cur,
            partition_key="1",
            coverage=ControlCoverage(
                control_id="security-audit-logon",
                status=CoverageStatus.UNAVAILABLE,
                reason="Audit policy confirmation is unavailable",
                observed_at_utc=occurred,
            ),
            source_reference="integration:audit-policy",
        )
        gap_policy = RiskPolicyDefinition(
            policy_id=policy_ids[1],
            policy_version=1,
            source_kind=ScenarioSourceKind.CONTROL_HEALTH,
            definition=_policy_definition(control_gap=True),
        )
        register_risk_policy(cur, policy=gap_policy)
        for status in ("validated", "test", "shadow"):
            transition_risk_policy(
                cur, policy_id=policy_ids[1], policy_version=1, target_status=status
            )
        enqueue_control_health_risk_jobs(cur, observation_id=observation_id)

    env = dict(os.environ)
    env.update(
        {
            "ADLOG_SEMANTIC_WORKER_DSN": postgres_semantic_worker_dsn,
            "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "true",
            "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "true",
            "ADLOG_SEMANTIC_CORRELATION_ENABLED": "true",
            "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "true",
        }
    )
    run = subprocess.run(
        [sys.executable, str(RUNNER), "--execute", "--limit", "4"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "select last_error_code,last_error_detail from semantic_risk_evaluation_jobs "
            "where last_error_code is not null"
        )
        failures = cur.fetchall()
    assert run.returncode == 0, (run.stderr, failures)
    payload = json.loads(run.stdout)
    assert payload["failed"] == 0
    assert payload["modes"]["shadow"] == 2
    assert payload["findings_created"] == 0

    with connect() as conn, conn.cursor() as cur:
        cur.execute("select count(*) as value from findings")
        assert int(cur.fetchone()["value"]) == findings_before
        cur.execute(
            "select result_class,risk_class,hard_critical,coverage_status "
            "from semantic_security_scenarios order by result_class"
        )
        scenarios = cur.fetchall()
        assert len(scenarios) == 2
        assert {row["result_class"] for row in scenarios} == {
            "security_incident",
            "control_gap",
        }
        assert all(row["risk_class"] == "critical" for row in scenarios)
        assert all(row["hard_critical"] for row in scenarios)
        assert all(row["coverage_status"] == "unavailable" for row in scenarios)
        cur.execute(
            "select count(*) as value from semantic_risk_evaluation_results"
        )
        assert int(cur.fetchone()["value"]) == 3

    with connect() as conn, conn.cursor() as cur:
        record_control_health(
            cur,
            partition_key="1",
            coverage=ControlCoverage(
                control_id="security-audit-logon",
                status=CoverageStatus.UNAVAILABLE,
                reason="A later audit policy confirmation is still unavailable",
                observed_at_utc=occurred + timedelta(minutes=2),
            ),
            source_reference="integration:audit-policy:later",
        )

    later = subprocess.run(
        [sys.executable, str(RUNNER), "--execute", "--limit", "1"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert later.returncode == 0, later.stderr
    assert json.loads(later.stdout)["completed"] == 1
    with connect() as conn, conn.cursor() as cur:
        cur.execute("select count(*) as value from semantic_risk_evaluation_results")
        assert int(cur.fetchone()["value"]) == 4
        cur.execute("select count(*) as value from semantic_security_scenarios")
        assert int(cur.fetchone()["value"]) == 2

    with pytest.raises(psycopg.Error, match="immutable"), connect() as conn, conn.cursor() as cur:
        cur.execute(
            "update semantic_risk_policies set definition_json='{}'::jsonb "
            "where policy_id=%s",
            (policy_ids[0],),
        )
