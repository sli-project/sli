# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``semantic_risk_runtime_repository`` at call time.
"""Versioned policy, control-health and leased risk evaluation runtime."""
from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
from typing import Any

from server.sli.entities.entity_identity_merge import (
    record_finding_identity_supersessions,
    record_scenario_identity_supersessions,
)
from server.sli.events.event_catalog import (
    all_event_catalog_entries,
    lookup_event_catalog,
)
from server.sli.events.event_catalog_quality import catalog_completeness
from server.sli.semantic.event_semantic_contract import Confidence, MachineRisk
from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
from server.sli.semantic.semantic_risk import (
    CompletenessSnapshot,
    ConclusionState,
    ConfidenceFactors,
    ControlCoverage,
    CoverageStatus,
    EvidenceQuality,
    IdentityResolution,
    RiskContribution,
    ScenarioProposal,
    ScenarioSourceKind,
    ScenarioStep,
    merge_scenario_proposals,
    resolve_conclusion_state,
)
from server.sli.semantic.semantic_risk_policy import (
    EXECUTABLE_POLICY_STATES,
    POLICY_LIFECYCLE,
    POLICY_TRANSITIONS,
    CompiledRiskPolicy,
    RiskPolicyDefinition,
    compile_risk_policy,
)
from server.sli.semantic.semantic_risk_repository import _existing_scenario, persist_scenario_proposal

MAX_RISK_CLAIM = 16
COMPLETENESS_FRESHNESS_BUDGET_SECONDS = 30 * 60
_INTRINSIC_EXACT_ROLES = frozenset(
    {"source_host", "source_ip", "session_principal"}
)
_IDENTITY_RESOLUTION_ORDER = {
    IdentityResolution.UNRESOLVED: 0,
    IdentityResolution.UNKNOWN: 1,
    IdentityResolution.PARTIAL: 2,
    IdentityResolution.EXACT: 3,
}


@dataclass(frozen=True, kw_only=True)
class RiskEvaluationWorkItem:
    job_id: str
    lease_token: str
    attempt_count: int
    max_attempts: int
    evaluation_mode: str
    proposal: ScenarioProposal
    completeness_snapshot: CompletenessSnapshot
    conclusion_state: ConclusionState


@dataclass(frozen=True, kw_only=True)
class RiskEvaluationResult:
    job_id: str
    scenario_id: str | None
    evaluation_mode: str
    risk_class: MachineRisk
    raw_score: Decimal
    display_score: int
    hard_critical: bool
    confidence: Confidence
    confidence_score: int
    coverage_status: CoverageStatus
    completeness_snapshot: CompletenessSnapshot
    conclusion_state: ConclusionState
    finding_id: int | None = None
    finding_created: bool = False
    publication_state: str | None = None


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    parsed = json.loads(str(value or "{}"))
    if not isinstance(parsed, Mapping):
        raise RuntimeError("semantic risk runtime JSON must contain an object")
    return dict(parsed)










def _enqueue_source(cur: Any, *, source_kind: ScenarioSourceKind, source_id: str) -> tuple[str, ...]:
    if source_kind is ScenarioSourceKind.CANONICAL_ACTION:
        cur.execute(
            """
            select canonical_action_id::text as source_id,
                   action_kind as selector_value
            from canonical_actions
            where canonical_action_id=%s
              and action_status not in ('contradicted','superseded','quarantined')
            """,
            (source_id,),
        )
    elif source_kind is ScenarioSourceKind.CORRELATION_CANDIDATE:
        cur.execute(
            """
            select candidate_id::text as source_id,relation_kind as selector_value
            from semantic_correlation_candidates
            where candidate_id=%s and candidate_status='matched'
            """,
            (source_id,),
        )
    elif source_kind is ScenarioSourceKind.CONTROL_HEALTH:
        cur.execute(
            """
            select observation_id::text as source_id,control_id as selector_value
            from semantic_control_health_observations where observation_id=%s
            """,
            (source_id,),
        )
    elif source_kind is ScenarioSourceKind.DETECTION_MATCH:
        cur.execute(
            "select match_id as source_id,rule_id as selector_value,evaluation_mode "
            "from semantic_detection_matches where match_id=%s", (source_id,),
        )
    elif source_kind is ScenarioSourceKind.QW_SIGNAL:
        cur.execute(
            "select signal_id as source_id,document_json->>'rule_id' as selector_value,evaluation_mode "
            "from semantic_qw_signals where signal_id=%s", (source_id,),
        )
    else:
        raise ValueError("risk runtime source kind is not supported")
    source = dict(cur.fetchone() or {})
    if not source:
        raise LookupError("risk evaluation source not found or not eligible")
    execution = None
    if source_kind is ScenarioSourceKind.DETECTION_MATCH:
        from server.sli.sigma.detection_input import load_detection_match

        execution = load_detection_match(cur, match_id=source_id).execution
    signal = None
    if source_kind is ScenarioSourceKind.QW_SIGNAL:
        from server.sli.semantic.qw_input import load_qw_signal

        signal = load_qw_signal(cur, signal_id=source_id)
        execution = signal.execution
    cur.execute(
        """
        select policy.policy_id,policy.policy_version,
               semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status) as lifecycle_status,
               policy.definition_sha256,
               policy.definition_json#>'{source_selector,execution}' as detection_execution
        from semantic_risk_policy_subscriptions subscription
        join semantic_risk_policies policy
          on policy.policy_id=subscription.policy_id
         and policy.policy_version=subscription.policy_version
         and policy.definition_sha256=subscription.definition_sha256
        where subscription.source_kind=%s and subscription.selector_value=%s
          and semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)=any(%s)
          and (semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)<>'enabled'
               or exists(select 1 from semantic_policy_admission admission
                   where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                     and admission.enabled is true))
          and (policy.source_kind not in ('detection_match','qw_signal') or (
              policy.definition_json#>'{source_selector,execution}'=%s::jsonb))
        order by policy.policy_id,policy.policy_version
        """,
        (
            source_kind.value,
            source["selector_value"],
            sorted(EXECUTABLE_POLICY_STATES),
            json.dumps(execution, sort_keys=True) if execution is not None else None,
        ),
    )
    jobs: list[str] = []
    for policy in (dict(item) for item in (cur.fetchall() or [])):
        mode = str(policy["lifecycle_status"])
        if source_kind is ScenarioSourceKind.DETECTION_MATCH:
            if (mode != source["evaluation_mode"]
                    or _json_object(policy.get("detection_execution")) != execution):
                continue
        if source_kind is ScenarioSourceKind.QW_SIGNAL:
            if (mode != signal.evaluation_mode or int(policy["policy_version"]) != signal.policy_revision
                    or _json_object(policy.get("detection_execution")) != execution):
                continue
        payload = json.dumps(
            {
                "policy_id": policy["policy_id"],
                "policy_version": int(policy["policy_version"]),
                "policy_sha256": bytes(policy["definition_sha256"]).hex(),
                "source_kind": source_kind.value,
                "source_id": source_id,
                "evaluation_mode": mode,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        identity = sha256(payload.encode("utf-8")).digest()
        job_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:risk-evaluation:{identity.hex()}"))
        action_id = source_id if source_kind is ScenarioSourceKind.CANONICAL_ACTION else None
        candidate_id = source_id if source_kind is ScenarioSourceKind.CORRELATION_CANDIDATE else None
        health_id = source_id if source_kind is ScenarioSourceKind.CONTROL_HEALTH else None
        detection_id = source_id if source_kind is ScenarioSourceKind.DETECTION_MATCH else None
        cur.execute(
            """
            insert into semantic_risk_evaluation_jobs(
                job_id,policy_id,policy_version,source_kind,
                canonical_action_id,correlation_candidate_id,control_health_id,
                source_reference,
                evaluation_mode,idempotency_key,detection_match_id,qw_signal_id
            ) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            on conflict(idempotency_key) do nothing
            """,
            (
                job_id,
                policy["policy_id"],
                int(policy["policy_version"]),
                source_kind.value,
                action_id,
                candidate_id,
                health_id,
                source_id,
                mode,
                identity,
                detection_id,
                source_id if source_kind is ScenarioSourceKind.QW_SIGNAL else None,
            ),
        )
        cur.execute(
            "select job_id from semantic_risk_evaluation_jobs where idempotency_key=%s",
            (identity,),
        )
        if str(dict(cur.fetchone() or {}).get("job_id")) != job_id:
            raise RuntimeError("risk evaluation job identity replay conflict")
        jobs.append(job_id)
    return tuple(jobs)


def enqueue_canonical_action_risk_jobs(
    cur: Any, *, canonical_action_id: str
) -> tuple[str, ...]:
    return _enqueue_source(
        cur,
        source_kind=ScenarioSourceKind.CANONICAL_ACTION,
        source_id=canonical_action_id,
    )


def enqueue_candidate_risk_jobs(cur: Any, *, candidate_id: str) -> tuple[str, ...]:
    return _enqueue_source(
        cur,
        source_kind=ScenarioSourceKind.CORRELATION_CANDIDATE,
        source_id=candidate_id,
    )


def enqueue_control_health_risk_jobs(cur: Any, *, observation_id: str) -> tuple[str, ...]:
    return _enqueue_source(
        cur,
        source_kind=ScenarioSourceKind.CONTROL_HEALTH,
        source_id=observation_id,
    )


def enqueue_risk_backlog(cur: Any, *, limit: int = 100) -> tuple[str, ...]:
    requested = max(1, min(int(limit), 1000))
    # Start with executable subscriptions, then use the action-kind index.
    # A correlated EXISTS over every historical action made even an empty poll
    # scan and sort the full history. Each policy needs at most the global limit
    # of its earliest unevaluated sources to preserve the final FIFO selection.
    # Evaluate the STABLE admission mode once per matching policy in this
    # statement snapshot, rather than for each historical source/job probe.
    cur.execute(
        """
        with effective_policy as materialized (
            select policy.policy_id,policy.policy_version,policy.definition_sha256,
                   policy.lifecycle_status,policy.definition_json,
                   semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status) as effective_mode
            from semantic_risk_policies policy
            where exists (
                select 1 from semantic_risk_policy_subscriptions subscription
                where subscription.policy_id=policy.policy_id
                  and subscription.policy_version=policy.policy_version
                  and subscription.definition_sha256=policy.definition_sha256
            )
        )
        select source_kind,source_id from (
            select distinct 'canonical_action' as source_kind,
                   canonical_action_id::text as source_id,
                   occurred_at_utc as source_time
            from semantic_risk_policy_subscriptions subscription
            join effective_policy policy
              on policy.policy_id=subscription.policy_id
             and policy.policy_version=subscription.policy_version
             and policy.definition_sha256=subscription.definition_sha256
            cross join lateral (
                select action.canonical_action_id,action.occurred_at_utc
                from canonical_actions action
                where subscription.selector_value=action.action_kind
                  and action_status not in ('contradicted','superseded','quarantined')
                  and not exists (
                      select 1 from semantic_risk_evaluation_jobs job
                      where job.policy_id=policy.policy_id
                        and job.policy_version=policy.policy_version
                        and job.source_kind='canonical_action'
                        and job.source_reference=action.canonical_action_id::text
                        and job.evaluation_mode=policy.effective_mode
                  )
                order by action.occurred_at_utc,action.canonical_action_id
                limit %s
            ) action
            where subscription.source_kind='canonical_action'
              and policy.effective_mode=any(%s)
              and (policy.effective_mode<>'enabled'
                   or exists(select 1 from semantic_policy_admission admission
                       where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                         and admission.enabled is true))
            union all
            select 'correlation_candidate' as source_kind,candidate_id::text as source_id,
                   first_matched_at as source_time
            from semantic_correlation_candidates candidate
            where candidate_status='matched' and exists (
                select 1 from semantic_risk_policy_subscriptions subscription
                join effective_policy policy
                  on policy.policy_id=subscription.policy_id
                 and policy.policy_version=subscription.policy_version
                 and policy.definition_sha256=subscription.definition_sha256
                where subscription.source_kind='correlation_candidate'
                  and subscription.selector_value=candidate.relation_kind
                  and policy.effective_mode=any(%s)
                  and (policy.effective_mode<>'enabled'
                       or exists(select 1 from semantic_policy_admission admission
                           where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                             and admission.enabled is true))
                  and not exists (
                      select 1 from semantic_risk_evaluation_jobs job
                      where job.policy_id=policy.policy_id
                        and job.policy_version=policy.policy_version
                        and job.source_kind='correlation_candidate'
                        and job.source_reference=candidate.candidate_id::text
                        and job.evaluation_mode=policy.effective_mode
                  )
            )
            union all
            select 'control_health',observation_id::text,observed_at_utc
            from semantic_control_health_observations health
            where exists (
                select 1 from semantic_risk_policy_subscriptions subscription
                join effective_policy policy
                  on policy.policy_id=subscription.policy_id
                 and policy.policy_version=subscription.policy_version
                 and policy.definition_sha256=subscription.definition_sha256
                where subscription.source_kind='control_health'
                  and subscription.selector_value=health.control_id
                  and policy.effective_mode=any(%s)
                  and (policy.effective_mode<>'enabled'
                       or exists(select 1 from semantic_policy_admission admission
                           where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                             and admission.enabled is true))
                  and not exists (
                      select 1 from semantic_risk_evaluation_jobs job
                      where job.policy_id=policy.policy_id
                        and job.policy_version=policy.policy_version
                        and job.source_kind='control_health'
                        and job.source_reference=health.observation_id::text
                        and job.evaluation_mode=policy.effective_mode
                  )
            )
            union all
            select 'detection_match',detection.match_id,detection.occurred_at_utc
            from semantic_detection_matches detection
            where exists (
                select 1 from semantic_risk_policy_subscriptions subscription
                join effective_policy policy
                  on policy.policy_id=subscription.policy_id
                 and policy.policy_version=subscription.policy_version
                 and policy.definition_sha256=subscription.definition_sha256
                where subscription.source_kind='detection_match'
                  and subscription.selector_value=detection.rule_id
                  and policy.effective_mode=detection.evaluation_mode
                  and policy.definition_json#>'{source_selector,execution}'=jsonb_build_object(
                      'version','sli.sigma.execution.v1','rule_id',detection.rule_id,
                      'rule_sha256',detection.document_json->'rule_sha256',
                      'manifest_sha256',detection.document_json->'manifest_sha256',
                      'compiler_version',detection.document_json->'compiler_version',
                      'mapping_version',detection.document_json->'mapping_version',
                      'overlay_sha256',detection.document_json->'overlay_sha256',
                      'scope',detection.document_json#>'{evidence,scope}')
                  and (detection.evaluation_mode<>'enabled' or exists(
                      select 1 from semantic_policy_admission admission
                      where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                        and admission.enabled is true))
                  and not exists (
                      select 1 from semantic_risk_evaluation_jobs job
                      where job.policy_id=policy.policy_id and job.policy_version=policy.policy_version
                        and job.source_kind='detection_match' and job.source_reference=detection.match_id
                        and job.evaluation_mode=detection.evaluation_mode
                  )
            )
            union all
            select 'qw_signal',signal.signal_id,signal.created_at
            from semantic_qw_signals signal
            where exists (
                select 1 from semantic_risk_policy_subscriptions subscription
                join effective_policy policy
                  on policy.policy_id=subscription.policy_id
                 and policy.policy_version=subscription.policy_version
                 and policy.definition_sha256=subscription.definition_sha256
                where subscription.source_kind='qw_signal'
                  and subscription.selector_value=signal.document_json->>'rule_id'
                  and to_jsonb(policy.policy_version)=signal.document_json->'policy_revision'
                  and policy.effective_mode=signal.evaluation_mode
                  and policy.definition_json#>'{source_selector,execution}'=case when signal.document_json->>'kind'='acl'
                    then jsonb_build_object('version','sli.qw.file-acl-execution.v1','kind','acl',
                      'rule_id',signal.document_json->'rule_id','rule_version',signal.document_json->'rule_version',
                      'rule_sha256',signal.document_json->'rule_sha256','resource',signal.document_json#>'{acl_context,resource}')
                    else jsonb_build_object(
                      'version','sli.qw.execution.v1','kind',signal.document_json->'kind',
                      'rule_id',signal.document_json->'rule_id','rule_version',signal.document_json->'rule_version',
                      'rule_sha256',signal.document_json->'rule_sha256',
                      'scope',signal.document_json#>'{evidence_refs,0,scope}') end
                  and (signal.evaluation_mode<>'enabled' or exists(
                      select 1 from semantic_policy_admission admission
                      where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                        and admission.enabled is true))
                  and not exists (
                      select 1 from semantic_risk_evaluation_jobs job
                      where job.policy_id=policy.policy_id and job.policy_version=policy.policy_version
                        and job.source_kind='qw_signal' and job.source_reference=signal.signal_id
                        and job.evaluation_mode=signal.evaluation_mode
                  )
            )
        ) source
        order by source_time,source_kind,source_id limit %s
        """,
        (
            requested,
            sorted(EXECUTABLE_POLICY_STATES),
            sorted(EXECUTABLE_POLICY_STATES),
            sorted(EXECUTABLE_POLICY_STATES),
            requested,
        ),
    )
    jobs: list[str] = []
    for row in (dict(item) for item in (cur.fetchall() or [])):
        jobs.extend(
            _enqueue_source(
                cur,
                source_kind=ScenarioSourceKind(str(row["source_kind"])),
                source_id=str(row["source_id"]),
            )
        )
    return tuple(dict.fromkeys(jobs))


def claim_risk_evaluation_jobs(
    cur: Any, *, limit: int = 1, lease_seconds: int = 300
) -> list[dict[str, Any]]:
    requested = max(1, min(int(limit), MAX_RISK_CLAIM))
    lease = max(60, min(int(lease_seconds), 3600))
    token = str(uuid.uuid4())
    cur.execute(
        """
        with candidates as (
            select job_id from semantic_risk_evaluation_jobs job
            where attempt_count < max_attempts and available_at <= now()
              and exists(select 1 from semantic_risk_policies policy
                  where policy.policy_id=job.policy_id and policy.policy_version=job.policy_version
                  and semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)=job.evaluation_mode
                  and (job.evaluation_mode<>'enabled' or exists(
                      select 1 from semantic_policy_admission admission
                      where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                        and admission.enabled is true)))
              and (evaluation_status in ('queued','failed')
                   or (evaluation_status='leased' and lease_until < now()))
            order by available_at,created_at,job_id
            for update skip locked limit %s
        )
        update semantic_risk_evaluation_jobs job
        set evaluation_status='leased',attempt_count=attempt_count+1,
            lease_token=%s,lease_until=now()+(%s * interval '1 second'),
            heartbeat_at=now(),updated_at=now(),
            last_error_code=null,last_error_detail=null
        from candidates where job.job_id=candidates.job_id
        returning job.*
        """,
        (requested, token, lease),
    )
    return [dict(item) for item in (cur.fetchall() or [])]


















def load_risk_evaluation_work_item(
    cur: Any, *, job_id: str, lease_token: str
) -> RiskEvaluationWorkItem:
    cur.execute(
        "select 1 from schema_migrations "
        "where version=52 and name='semantic_conclusion_completeness'"
    )
    if cur.fetchone() is None:
        raise RuntimeError("semantic conclusion completeness schema is required")
    cur.execute(
        """
        select job.*,policy.source_kind as policy_source_kind,
               semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status) as lifecycle_status,
               policy.definition_json,
               policy.definition_sha256
        from semantic_risk_evaluation_jobs job
        join semantic_risk_policies policy
          on policy.policy_id=job.policy_id and policy.policy_version=job.policy_version
        where job.job_id=%s and job.evaluation_status='leased' and job.lease_token=%s
        for share of policy
        """,
        (job_id, lease_token),
    )
    row = dict(cur.fetchone() or {})
    if not row:
        raise RuntimeError("risk evaluation lease is not available")
    if row.get("lifecycle_status") not in EXECUTABLE_POLICY_STATES:
        raise RuntimeError("risk evaluation policy is no longer executable")
    if row.get("lifecycle_status") != row.get("evaluation_mode"):
        raise RuntimeError("risk evaluation policy admission changed")
    source_kind = ScenarioSourceKind(str(row["policy_source_kind"]))
    if row["evaluation_mode"] == "enabled":
        # Admission writers lock the policy FOR UPDATE. Read in a fresh statement
        # after acquiring FOR SHARE, including when we waited for such a writer.
        cur.execute("select enabled from semantic_policy_admission where policy_id=%s and policy_version=%s",
                    (row["policy_id"], row["policy_version"]))
        if dict(cur.fetchone() or {}).get("enabled") is not True:
            raise RuntimeError("qw_policy_admission_required" if source_kind is ScenarioSourceKind.QW_SIGNAL
                               else "sigma_detection_admission_required" if source_kind is ScenarioSourceKind.DETECTION_MATCH
                               else "semantic_policy_admission_required")
    policy_source = RiskPolicyDefinition(
        policy_id=str(row["policy_id"]),
        policy_version=int(row["policy_version"]),
        source_kind=source_kind,
        definition=_json_object(row["definition_json"]),
    )
    policy = compile_risk_policy(policy_source)
    if policy.definition_sha256 != bytes(row["definition_sha256"]):
        raise RuntimeError("risk evaluation policy definition hash mismatch")
    source_id = str(row["source_reference"])
    if source_kind is ScenarioSourceKind.CANONICAL_ACTION:
        proposal = _canonical_action_proposal(
            cur, policy=policy, source_id=source_id
        )
    elif source_kind is ScenarioSourceKind.CORRELATION_CANDIDATE:
        proposal = _candidate_proposal(cur, policy=policy, source_id=source_id)
    elif source_kind is ScenarioSourceKind.DETECTION_MATCH:
        from server.sli.sigma.detection_input import detection_match_proposal, load_detection_match

        match = load_detection_match(cur, match_id=source_id)
        if match.evaluation_mode != row["evaluation_mode"]:
            raise RuntimeError("sigma_detection_mode_mismatch")
        proposal = detection_match_proposal(cur, policy=policy, source_id=source_id)
    elif source_kind is ScenarioSourceKind.QW_SIGNAL:
        from server.sli.semantic.qw_input import load_qw_signal, qw_signal_proposal

        signal = load_qw_signal(cur, signal_id=source_id)
        if signal.evaluation_mode != row["evaluation_mode"] or row["source_kind"] != "qw_signal":
            raise RuntimeError("qw_signal_policy_mismatch")
        proposal = qw_signal_proposal(cur, policy=policy, source_id=source_id)
    else:
        proposal = _control_health_proposal(
            cur, policy=policy, source_id=source_id
        )
    snapshot = _capture_completeness_snapshot(
        cur,
        policy=policy,
        proposal=proposal,
        source_id=source_id,
    )
    return RiskEvaluationWorkItem(
        job_id=str(row["job_id"]),
        lease_token=str(row["lease_token"]),
        attempt_count=int(row["attempt_count"]),
        max_attempts=int(row["max_attempts"]),
        evaluation_mode=str(row["evaluation_mode"]),
        proposal=proposal,
        completeness_snapshot=snapshot,
        conclusion_state=(ConclusionState(signal.conclusion_state) if source_kind is ScenarioSourceKind.QW_SIGNAL
                          else ConclusionState.OBSERVED),
    )


def _complete_password_frozen(cur, *, work, assessment):
    cur.execute("""update semantic_risk_evaluation_jobs
        set evaluation_status='completed',completed_at=now(),heartbeat_at=now(),
            lease_token=null,lease_until=null,updated_at=now(),
            last_error_code='episode_frozen',last_error_detail='episode_frozen'
        where job_id=%s and evaluation_status='leased' and lease_token=%s returning job_id""",
        (work.job_id, work.lease_token))
    if cur.fetchone() is None:
        raise RuntimeError("risk evaluation lease was lost")
    return RiskEvaluationResult(job_id=work.job_id, scenario_id=None, evaluation_mode=work.evaluation_mode,
        risk_class=assessment.risk.risk_class, raw_score=assessment.risk.raw_score,
        display_score=assessment.risk.display_score, hard_critical=assessment.risk.hard_critical,
        confidence=assessment.confidence.level, confidence_score=assessment.confidence.score,
        coverage_status=assessment.coverage_status, completeness_snapshot=work.completeness_snapshot,
        conclusion_state=work.conclusion_state, publication_state="episode_frozen")


def execute_risk_evaluation(
    cur: Any,
    *,
    work: RiskEvaluationWorkItem,
    evaluation_ms: int,
    create_finding: bool = False,
) -> RiskEvaluationResult:
    if evaluation_ms < 0:
        raise ValueError("evaluation_ms must not be negative")
    assessment = merge_scenario_proposals((work.proposal,))
    scenario = None
    password_signal = None
    password_pending = False
    qw_source = work.proposal.step.source_kind is ScenarioSourceKind.QW_SIGNAL
    if qw_source and work.evaluation_mode == "enabled" and not create_finding:
        raise RuntimeError("enabled semantic evaluation requires finding publication")
    persist_scenario = work.evaluation_mode != "test" and (
        work.proposal.step.source_kind not in {ScenarioSourceKind.DETECTION_MATCH, ScenarioSourceKind.QW_SIGNAL}
        or work.evaluation_mode == "enabled"
    ) and (not qw_source or work.conclusion_state is ConclusionState.OBSERVED)
    if persist_scenario:
        from server.sli.semantic.password_attack_runtime import (
            _scenario_signals, is_password_signal, scenario_password_signal,
        )

        # The generic identity deliberately excludes source kind. Serialize the
        # exact merge/replay lookup with every ordinary scenario writer before any
        # scenario/evidence/context mutation, including for non-QW work.
        cur.execute("select pg_advisory_xact_lock(hashtextextended(%s,0))",
                    (work.proposal.identity_sha256.hex(),))
        target = _existing_scenario(cur, proposal=work.proposal)
        if target:
            from server.sli.semantic.qw_input import load_qw_signal

            incoming = load_qw_signal(cur, signal_id=work.proposal.step.source_id) if qw_source else None
            target_password = scenario_password_signal(cur, str(target["scenario_id"]))
            if incoming is not None and is_password_signal(incoming):
                steps = _scenario_signals(cur, str(target["scenario_id"]))
                if any(not is_password_signal(item) or item.execution != incoming.execution
                       or item.episode_key != incoming.episode_key for item in steps):
                    raise RuntimeError("password_v2_scenario_invalid")
            elif target_password is not None:
                raise RuntimeError("password_v2_scenario_invalid")
    if qw_source and work.evaluation_mode == "enabled":
        from server.sli.semantic.qw_input import load_qw_signal
        from server.sli.semantic.password_attack_runtime import (
            PasswordEpisodeFrozen, is_password_signal, lock_publication,
        )

        signal = load_qw_signal(cur, signal_id=work.proposal.step.source_id)
        if is_password_signal(signal):
            password_signal = signal
            # Same key as persist_scenario_proposal; reentrant acquisition there
            # preserves generic identity logic and keeps ledger SHARE second.
            cur.execute("select pg_advisory_xact_lock(hashtextextended(%s,0))",
                        (work.proposal.identity_sha256.hex(),))
            try:
                lock_publication(cur, signal)
            except PasswordEpisodeFrozen:
                return _complete_password_frozen(cur, work=work, assessment=assessment)
    if persist_scenario:
        scenario = persist_scenario_proposal(cur, proposal=work.proposal)
        if password_signal is not None:
            from server.sli.semantic.password_attack_runtime import scenario_complete

            password_pending = not scenario_complete(cur, scenario.scenario_id, password_signal)
            if password_pending:
                cur.execute("update semantic_security_scenarios set evidence_state='evidence_pending' where scenario_id=%s",
                            (scenario.scenario_id,))
    scenario_id = scenario.scenario_id if scenario else None
    if scenario_id is not None:
        record_scenario_identity_supersessions(cur, new_scenario_id=scenario_id)
    confidence = scenario.confidence if scenario else assessment.confidence.level
    confidence_score = (
        scenario.confidence_score if scenario else assessment.confidence.score
    )
    coverage = scenario.coverage_status if scenario else assessment.coverage_status
    raw_score = scenario.raw_score if scenario else assessment.risk.raw_score
    display_score = scenario.display_score if scenario else assessment.risk.display_score
    hard_critical = scenario.hard_critical if scenario else assessment.risk.hard_critical
    risk_class = scenario.risk_class if scenario else assessment.risk.risk_class
    conclusion_state = resolve_conclusion_state(
        work.conclusion_state,
        snapshot=work.completeness_snapshot,
    )
    snapshot_json = json.dumps(
        work.completeness_snapshot.as_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    cur.execute(
        """
        insert into semantic_risk_evaluation_results(
            job_id,scenario_id,evaluation_mode,risk_class,raw_score,display_score,
            hard_critical,confidence,confidence_score,coverage_status,evaluation_ms,
            conclusion_state,completeness_snapshot_json
        ) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
        on conflict(job_id) do nothing
        """,
        (
            work.job_id,
            scenario_id,
            work.evaluation_mode,
            risk_class.value,
            raw_score,
            display_score,
            hard_critical,
            confidence.value,
            confidence_score,
            coverage.value,
            min(int(evaluation_ms), 2147483647),
            conclusion_state.value,
            snapshot_json,
        ),
    )
    finding: dict[str, object] | None = None
    pending_evidence = password_pending or (scenario is not None and scenario.evidence_state == "evidence_pending")
    if (work.evaluation_mode == "enabled" and not pending_evidence
            and (not qw_source or conclusion_state is ConclusionState.OBSERVED)):
        if not create_finding:
            raise RuntimeError(
                "enabled semantic evaluation requires finding publication"
            )
        if scenario_id is None:
            raise RuntimeError(
                "enabled semantic evaluation requires a persisted scenario"
            )
        finding = publish_enabled_scenario_finding(
            cur,
            job_id=work.job_id,
            scenario_id=scenario_id,
        )
        record_finding_identity_supersessions(
            cur,
            new_scenario_id=scenario_id,
            new_finding_id=int(finding["finding_id"]),
        )
    cur.execute(
        """
        update semantic_risk_evaluation_jobs
        set evaluation_status='completed',completed_at=now(),heartbeat_at=now(),
            lease_token=null,lease_until=null,updated_at=now()
        where job_id=%s and evaluation_status='leased' and lease_token=%s
        returning job_id
        """,
        (work.job_id, work.lease_token),
    )
    if cur.fetchone() is None:
        raise RuntimeError("risk evaluation lease was lost")
    return RiskEvaluationResult(
        job_id=work.job_id,
        scenario_id=scenario_id,
        evaluation_mode=work.evaluation_mode,
        risk_class=risk_class,
        raw_score=raw_score,
        display_score=display_score,
        hard_critical=hard_critical,
        confidence=confidence,
        confidence_score=confidence_score,
        coverage_status=coverage,
        completeness_snapshot=work.completeness_snapshot,
        conclusion_state=conclusion_state,
        finding_id=(
            int(finding["finding_id"])
            if finding is not None
            else None
        ),
        finding_created=bool(
            finding is not None and finding.get("created")
        ),
        publication_state=("evidence_pending" if password_pending else
                           scenario.evidence_state if qw_source and scenario is not None else None),
    )


def fail_risk_evaluation_job(
    cur: Any,
    *,
    job_id: str,
    lease_token: str,
    attempt_count: int,
    max_attempts: int,
    error_code: str,
    error_detail: str,
) -> str:
    terminal = int(attempt_count) >= int(max_attempts)
    status = "quarantined" if terminal else "failed"
    retry_seconds = min(3600, 30 * (2 ** min(max(0, int(attempt_count) - 1), 7)))
    cur.execute(
        """
        update semantic_risk_evaluation_jobs
        set evaluation_status=%s,available_at=now()+(%s * interval '1 second'),
            lease_token=null,lease_until=null,last_error_code=%s,
            last_error_detail=%s,updated_at=now()
        where job_id=%s and evaluation_status='leased' and lease_token=%s
        returning evaluation_status
        """,
        (
            status,
            retry_seconds,
            error_code[:160],
            error_detail[:1000],
            job_id,
            lease_token,
        ),
    )
    if cur.fetchone() is None:
        raise RuntimeError("risk evaluation lease was lost while recording failure")
    return status


from server.sli.semantic.semantic_risk_runtime_repository_completeness import (
    _capture_completeness_snapshot,
    _source_channel_measurements,
)
from server.sli.semantic.semantic_risk_runtime_repository_policy import (
    record_control_health,
    register_risk_policy,
    replace_risk_policy_subscription,
    transition_risk_policy,
)
from server.sli.semantic.semantic_risk_runtime_repository_proposals import (
    _candidate_identity_resolution,
    _candidate_proposal,
    _canonical_action_proposal,
    _control_health_proposal,
    _coverage_for_policy,
    _proposal,
)
