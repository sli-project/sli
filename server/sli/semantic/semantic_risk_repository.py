"""Durable scenario and risk primitives for migration 028.

Callers own transactions and feature gates. This module does not register a
worker and never creates legacy findings.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
from typing import Any

from server.sli.semantic.event_semantic_contract import Confidence, MachineRisk
from server.sli.semantic.semantic_risk import (
    ConfidenceFactors,
    ControlCoverage,
    CoverageStatus,
    EvidenceQuality,
    IdentityResolution,
    RiskContribution,
    ScenarioProposal,
    ScenarioSourceKind,
    aggregate_risk,
    assess_confidence,
    merge_scenario_proposals,
    summarize_coverage,
)


@dataclass(frozen=True, kw_only=True)
class ScenarioPersistenceResult:
    scenario_id: str
    scenario_status: str
    risk_class: MachineRisk
    raw_score: Decimal
    display_score: int
    hard_critical: bool
    confidence: Confidence
    confidence_score: int
    coverage_status: CoverageStatus
    step_count: int
    evidence_count: int
    contribution_count: int
    evidence_state: str = "ready"


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    parsed = json.loads(str(value or "{}"))
    if not isinstance(parsed, Mapping):
        raise RuntimeError("semantic scenario JSON must contain an object")  # noqa: TRY004 - repository error contract
    return dict(parsed)


def _json_text(value: Mapping[str, object]) -> str:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _source_values(kind: ScenarioSourceKind, source_id: str) -> tuple[str | None, ...]:
    if kind is ScenarioSourceKind.CANONICAL_ACTION:
        return source_id, None, None, None
    if kind is ScenarioSourceKind.CORRELATION_CANDIDATE:
        return None, source_id, None, None
    if kind is ScenarioSourceKind.DETECTION_MATCH:
        return None, None, None, source_id
    if kind is ScenarioSourceKind.QW_SIGNAL:
        return None, None, None, None
    return None, None, source_id, None


def _row_source_id(row: Mapping[str, Any]) -> str:
    return str(
        row.get("canonical_action_id")
        or row.get("qw_signal_id")
        or row.get("detection_match_id")
        or row.get("correlation_candidate_id")
        or row.get("control_reference")
        or ""
    )


def _verify_source_evidence(cur: Any, *, proposal: ScenarioProposal) -> None:
    if proposal.step.source_kind is ScenarioSourceKind.QW_SIGNAL:
        from server.sli.semantic.qw_input import verify_qw_proposal

        verify_qw_proposal(cur, proposal=proposal)
        return
    if proposal.step.source_kind is ScenarioSourceKind.DETECTION_MATCH:
        from server.sli.sigma.detection_input import verify_detection_proposal

        verify_detection_proposal(cur, proposal=proposal)
        return
    source_id = proposal.step.source_id
    expected = set(proposal.step.normalized_event_ids)
    if proposal.step.source_kind is ScenarioSourceKind.CONTROL_HEALTH:
        if expected:
            raise ValueError("control-health scenario step cannot copy event evidence")
        # Observations are immutable; the worker has SELECT/INSERT, not UPDATE
        # required by PostgreSQL row locks. The step FK protects source lineage.
        cur.execute(
            """
            select observation_id,control_id,partition_key,coverage_status,
                   reason,observed_at_utc
            from semantic_control_health_observations
            where observation_id=%s
            """,
            (source_id,),
        )
        source = dict(cur.fetchone() or {})
        if not source:
            raise LookupError("control-health source not found")
        if source.get("partition_key") != proposal.partition_key:
            raise RuntimeError("scenario partition does not match control health")
        if source.get("observed_at_utc") != proposal.step.occurred_at_utc:
            raise RuntimeError("scenario step time does not match control health")
        exact = any(
            item.control_id == source.get("control_id")
            and item.status.value == source.get("coverage_status")
            and item.reason == source.get("reason")
            and item.observed_at_utc == source.get("observed_at_utc")
            for item in proposal.coverage
        )
        if not exact:
            raise RuntimeError("scenario coverage does not match control health source")
        return
    if proposal.step.source_kind is ScenarioSourceKind.CORRELATION_CANDIDATE:
        cur.execute(
            """
            select candidate_status,partition_key,window_start_utc,window_end_utc
            from semantic_correlation_candidates where candidate_id=%s
            for share
            """,
            (source_id,),
        )
        source = dict(cur.fetchone() or {})
        if not source:
            raise LookupError("correlation candidate source not found")
        if source.get("candidate_status") != "matched":
            raise RuntimeError("only matched correlation candidates can create scenarios")
        if source.get("partition_key") != proposal.partition_key:
            raise RuntimeError("scenario partition does not match correlation candidate")
        if not (
            source["window_start_utc"]
            <= proposal.step.occurred_at_utc
            <= source["window_end_utc"]
        ):
            raise RuntimeError("scenario step time is outside correlation candidate")
        cur.execute(
            """
            select normalized_event_id
            from semantic_correlation_candidate_evidence
            where candidate_id=%s
            """,
            (source_id,),
        )
    else:
        cur.execute(
            """
            select action_status,occurred_at_utc from canonical_actions
            where canonical_action_id=%s for share
            """,
            (source_id,),
        )
        source = dict(cur.fetchone() or {})
        if not source:
            raise LookupError("canonical action source not found")
        if source.get("action_status") == "contradicted":
            raise RuntimeError("contradicted canonical action cannot create risk")
        if source.get("occurred_at_utc") != proposal.step.occurred_at_utc:
            raise RuntimeError("scenario step time does not match canonical action")
        cur.execute(
            """
            select normalized_event_id from canonical_action_evidence
            where canonical_action_id=%s
            """,
            (source_id,),
        )
    available = {str(item["normalized_event_id"]) for item in (cur.fetchall() or [])}
    if not expected or not expected.issubset(available):
        raise RuntimeError("scenario evidence is not linked to its exact source")


def _verify_contribution_replay(
    row: Mapping[str, Any], *, proposal: ScenarioProposal
) -> None:
    incoming = proposal.contribution
    actual = {
        "source_kind": row.get("source_kind"),
        "source_id": _row_source_id(row),
        "policy_id": row.get("policy_id"),
        "policy_version": int(row.get("policy_version") or 0),
        "policy_sha256": bytes(row.get("policy_sha256") or b""),
        "risk_class": row.get("risk_class"),
        "raw_score": Decimal(str(row.get("raw_score") or 0)),
        "display_points": int(row.get("display_points") or 0),
        "hard_critical": bool(row.get("hard_critical")),
        "rationale": row.get("rationale"),
    }
    expected = {
        "source_kind": incoming.source_kind.value,
        "source_id": incoming.source_id,
        "policy_id": incoming.policy_id,
        "policy_version": incoming.policy_version,
        "policy_sha256": bytes(incoming.policy_sha256),
        "risk_class": incoming.risk_class.value,
        "raw_score": incoming.raw_score,
        "display_points": incoming.display_points,
        "hard_critical": incoming.hard_critical,
        "rationale": incoming.rationale,
    }
    if actual != expected:
        raise RuntimeError("risk contribution identity replay conflict")


def _verify_scenario_identity(row: Mapping[str, Any], *, proposal: ScenarioProposal) -> None:
    if (
        bytes(row.get("identity_key") or b"") != proposal.identity_sha256
        or row.get("scenario_kind") != proposal.scenario_kind
        or row.get("result_class") != proposal.result_class.value
        or row.get("partition_key") != proposal.partition_key
        or _json_object(row.get("strict_keys_json")) != dict(proposal.strict_keys)
        or int(row.get("merge_window_seconds") or 0)
        != int(proposal.merge_window.total_seconds())
    ):
        raise RuntimeError("semantic scenario identity replay conflict")


def _existing_scenario(
    cur: Any, *, proposal: ScenarioProposal, for_update: bool = False,
) -> dict[str, Any] | None:
    """Exact merge/replay target; read-only unless the existing writer requests locks."""
    contribution_key = proposal.contribution.contribution_sha256
    cur.execute(
        """
        select contribution.*,scenario.identity_key,scenario.scenario_kind,
               scenario.result_class,scenario.partition_key,
               scenario.strict_keys_json,scenario.merge_window_seconds
        from semantic_risk_contributions contribution
        join semantic_security_scenarios scenario
          on scenario.scenario_id=contribution.scenario_id
        where contribution.contribution_key=%s
        """ + (" for update of scenario" if for_update else ""),
        (contribution_key,),
    )
    replay = dict(cur.fetchone() or {})
    if replay:
        _verify_contribution_replay(replay, proposal=proposal)
        _verify_scenario_identity(replay, proposal=proposal)
        return replay
    occurred = proposal.step.occurred_at_utc
    window_seconds = int(proposal.merge_window.total_seconds())
    qw_episode = proposal.step.source_kind is ScenarioSourceKind.QW_SIGNAL
    cur.execute(
        """
        select * from semantic_security_scenarios
        where identity_key=%s and (scenario_status in ('open','under_review') or %s)
          and (%s or (first_seen_utc >= %s-(%s * interval '1 second')
          and last_seen_utc <= %s+(%s * interval '1 second')))
        order by last_seen_utc desc,scenario_id
        """ + (" for update" if for_update else "") + " limit 1",
        (
            proposal.identity_sha256,
            qw_episode or proposal.step.source_kind is ScenarioSourceKind.DETECTION_MATCH,
            qw_episode,
            occurred,
            window_seconds,
            occurred,
            window_seconds,
        ),
    )
    existing = dict(cur.fetchone() or {})
    if existing:
        _verify_scenario_identity(existing, proposal=proposal)
        return existing
    return None


def _select_scenario(cur: Any, *, proposal: ScenarioProposal) -> dict[str, Any]:
    existing = _existing_scenario(cur, proposal=proposal, for_update=True)
    if existing:
        return existing
    window_seconds = int(proposal.merge_window.total_seconds())
    qw_episode = proposal.step.source_kind is ScenarioSourceKind.QW_SIGNAL
    scenario_key = proposal.identity_sha256 if qw_episode else sha256(
        proposal.identity_sha256 + proposal.contribution.contribution_sha256
    ).digest()
    scenario_id = str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:semantic-scenario:{scenario_key.hex()}")
    )
    single = merge_scenario_proposals((proposal,))
    cur.execute(
        """
        insert into semantic_security_scenarios(
            scenario_id,scenario_kind,result_class,identity_key,scenario_key,
            partition_key,strict_keys_json,merge_window_seconds,title,explanation,
            first_seen_utc,last_seen_utc,risk_class,raw_score,display_score,
            hard_critical,confidence,confidence_score,confidence_factors_json,
            coverage_status
        ) values (%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
        on conflict(scenario_key) do nothing
        """,
        (
            scenario_id,
            proposal.scenario_kind,
            proposal.result_class.value,
            proposal.identity_sha256,
            scenario_key,
            proposal.partition_key,
            _json_text(dict(proposal.strict_keys)),
            window_seconds,
            proposal.title,
            proposal.explanation,
            single.first_seen_utc,
            single.last_seen_utc,
            single.risk.risk_class.value,
            single.risk.raw_score,
            single.risk.display_score,
            single.risk.hard_critical,
            single.confidence.level.value,
            single.confidence.score,
            _json_text(single.confidence.factors.as_dict()),
            single.coverage_status.value,
        ),
    )
    cur.execute(
        "select * from semantic_security_scenarios where scenario_key=%s for update",
        (scenario_key,),
    )
    created = dict(cur.fetchone() or {})
    if str(created.get("scenario_id")) != scenario_id:
        raise RuntimeError("semantic scenario deterministic identity conflict")
    _verify_scenario_identity(created, proposal=proposal)
    return created


def _persist_step(cur: Any, *, scenario_id: str, proposal: ScenarioProposal) -> None:
    step = proposal.step
    # A step stores intrinsic evidence quality. Current control coverage is
    # applied separately when the scenario aggregate is refreshed.
    confidence = assess_confidence(
        step.confidence_factors, coverage_status=CoverageStatus.UNKNOWN
    )
    action_id, candidate_id, control_reference, detection_id = _source_values(step.source_kind, step.source_id)
    step_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:scenario-step:{step.step_sha256.hex()}"))
    factors_json = _json_text(step.confidence_factors.as_dict())
    cur.execute(
        """
        insert into semantic_scenario_steps(
            step_id,scenario_id,step_key,source_kind,canonical_action_id,
            correlation_candidate_id,control_reference,occurred_at_utc,title,
            explanation,confidence,confidence_score,confidence_factors_json,detection_match_id,qw_signal_id
        ) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
        on conflict(step_key) do nothing
        """,
        (
            step_id,
            scenario_id,
            step.step_sha256,
            step.source_kind.value,
            action_id,
            candidate_id,
            control_reference,
            step.occurred_at_utc,
            step.title,
            step.explanation,
            confidence.level.value,
            confidence.score,
            factors_json,
            detection_id,
            step.source_id if step.source_kind is ScenarioSourceKind.QW_SIGNAL else None,
        ),
    )
    cur.execute("select * from semantic_scenario_steps where step_key=%s", (step.step_sha256,))
    row = dict(cur.fetchone() or {})
    if (
        str(row.get("step_id")) != step_id
        or str(row.get("scenario_id")) != scenario_id
        or row.get("source_kind") != step.source_kind.value
        or _row_source_id(row) != step.source_id
        or row.get("occurred_at_utc") != step.occurred_at_utc
        or row.get("title") != step.title
        or row.get("explanation") != step.explanation
        or row.get("confidence") != confidence.level.value
        or int(row.get("confidence_score") or 0) != confidence.score
        or _json_object(row.get("confidence_factors_json"))
        != step.confidence_factors.as_dict()
    ):
        raise RuntimeError("semantic scenario step identity replay conflict")


def _persist_evidence(cur: Any, *, scenario_id: str, proposal: ScenarioProposal) -> None:
    for normalized_id in proposal.step.normalized_event_ids:
        cur.execute(
            """
            select evidence_order from semantic_scenario_evidence
            where scenario_id=%s and normalized_event_id=%s
            """,
            (scenario_id, normalized_id),
        )
        if cur.fetchone() is not None:
            continue
        cur.execute(
            """
            select coalesce(max(evidence_order),-1) as last_order
            from semantic_scenario_evidence where scenario_id=%s
            """,
            (scenario_id,),
        )
        last_order = int(dict(cur.fetchone() or {"last_order": -1})["last_order"])
        cur.execute(
            """
            insert into semantic_scenario_evidence(
                scenario_id,normalized_event_id,evidence_order
            ) values (%s,%s,%s)
            """,
            (scenario_id, normalized_id, last_order + 1),
        )


def _persist_contribution(cur: Any, *, scenario_id: str, proposal: ScenarioProposal) -> None:
    contribution = proposal.contribution
    action_id, candidate_id, control_reference, detection_id = _source_values(
        contribution.source_kind, contribution.source_id
    )
    contribution_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"adlog:risk-contribution:{contribution.contribution_sha256.hex()}",
        )
    )
    cur.execute(
        """
        insert into semantic_risk_contributions(
            contribution_id,scenario_id,contribution_key,source_kind,
            canonical_action_id,correlation_candidate_id,control_reference,
            policy_id,policy_version,policy_sha256,risk_class,raw_score,
            display_points,hard_critical,rationale,detection_match_id,qw_signal_id
        ) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        on conflict(contribution_key) do nothing
        """,
        (
            contribution_id,
            scenario_id,
            contribution.contribution_sha256,
            contribution.source_kind.value,
            action_id,
            candidate_id,
            control_reference,
            contribution.policy_id,
            contribution.policy_version,
            contribution.policy_sha256,
            contribution.risk_class.value,
            contribution.raw_score,
            contribution.display_points,
            contribution.hard_critical,
            contribution.rationale,
            detection_id,
            contribution.source_id if contribution.source_kind is ScenarioSourceKind.QW_SIGNAL else None,
        ),
    )
    cur.execute(
        "select * from semantic_risk_contributions where contribution_key=%s",
        (contribution.contribution_sha256,),
    )
    row = dict(cur.fetchone() or {})
    if str(row.get("contribution_id")) != contribution_id or str(
        row.get("scenario_id")
    ) != scenario_id:
        raise RuntimeError("risk contribution was already assigned to another scenario")
    _verify_contribution_replay(row, proposal=proposal)


def _persist_coverage(cur: Any, *, scenario_id: str, proposal: ScenarioProposal) -> None:
    for item in proposal.coverage:
        assessment_key = sha256(
            scenario_id.encode("utf-8") + item.assessment_sha256
        ).digest()
        coverage_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:scenario-coverage:{assessment_key.hex()}")
        )
        cur.execute(
            """
            insert into semantic_scenario_coverage_history(
                coverage_id,scenario_id,assessment_key,control_id,
                coverage_status,reason,observed_at_utc
            ) values (%s,%s,%s,%s,%s,%s,%s)
            on conflict(scenario_id,assessment_key) do nothing
            """,
            (
                coverage_id,
                scenario_id,
                assessment_key,
                item.control_id,
                item.status.value,
                item.reason,
                item.observed_at_utc,
            ),
        )


def _confidence_factors(value: Any) -> ConfidenceFactors:
    parsed = _json_object(value)
    return ConfidenceFactors(
        identity_resolution=IdentityResolution(
            str(parsed.get("identity_resolution") or "unknown")
        ),
        state_confirmed=bool(parsed.get("state_confirmed")),
        multi_source_confirmed=bool(parsed.get("multi_source_confirmed")),
        sequence_completeness=int(parsed.get("sequence_completeness") or 0),
        time_quality=EvidenceQuality(str(parsed.get("time_quality") or "unknown")),
        parser_quality=EvidenceQuality(str(parsed.get("parser_quality") or "unknown")),
    )


def _weakest_confidence_assessment(
    values: list[Any], *, coverage_status: CoverageStatus
):
    assessments = [
        assess_confidence(
            _confidence_factors(value),
            coverage_status=coverage_status,
        )
        for value in values
    ]
    if not assessments:
        raise RuntimeError("semantic scenario has no durable step")
    return min(assessments, key=lambda item: item.score)


def _refresh_scenario(
    cur: Any, *, scenario_id: str
) -> ScenarioPersistenceResult:
    cur.execute(
        """
        select contribution.source_kind,canonical_action_id,correlation_candidate_id,
               contribution.detection_match_id,contribution.qw_signal_id,
               coalesce(detection.evidence_key,
                   encode(sha256(convert_to((signal.document_json->'evidence_refs')::text,'UTF8')),'hex'),'') as evidence_key,
               control_reference,policy_id,policy_version,policy_sha256,
               risk_class,raw_score,display_points,hard_critical,rationale,
               encode(contribution_key,'hex') as contribution_key_hex
        from semantic_risk_contributions contribution
        left join semantic_detection_matches detection on detection.match_id=contribution.detection_match_id
        left join semantic_qw_signals signal on signal.signal_id=contribution.qw_signal_id
        where scenario_id=%s order by contribution_id
        """,
        (scenario_id,),
    )
    contribution_rows = [dict(item) for item in (cur.fetchall() or [])]
    contributions = tuple(
        RiskContribution(
            contribution_key=str(item["contribution_key_hex"]),
            source_kind=ScenarioSourceKind(str(item["source_kind"])),
            source_id=_row_source_id(item),
            policy_id=str(item["policy_id"]),
            policy_version=int(item["policy_version"]),
            policy_sha256=bytes(item["policy_sha256"]),
            risk_class=MachineRisk(str(item["risk_class"])),
            raw_score=Decimal(str(item["raw_score"])),
            display_points=int(item["display_points"]),
            hard_critical=bool(item["hard_critical"]),
            rationale=str(item["rationale"]),
            evidence_key=str(item.get("evidence_key") or ""),
        )
        for item in contribution_rows
    )
    risk = aggregate_risk(contributions)
    cur.execute(
        """
        select confidence_factors_json from semantic_scenario_steps
        where scenario_id=%s
        order by occurred_at_utc,step_id
        """,
        (scenario_id,),
    )
    factor_values = [
        item["confidence_factors_json"]
        for item in (dict(row) for row in (cur.fetchall() or []))
    ]
    cur.execute(
        """
        select distinct on(control_id)
               control_id,coverage_status,reason,observed_at_utc
        from semantic_scenario_coverage_history
        where scenario_id=%s
        order by control_id,observed_at_utc desc,coverage_id desc
        """,
        (scenario_id,),
    )
    coverage_rows = [dict(item) for item in (cur.fetchall() or [])]
    coverage = summarize_coverage(
        tuple(
            ControlCoverage(
                control_id=str(item["control_id"]),
                status=CoverageStatus(str(item["coverage_status"])),
                reason=str(item["reason"]),
                observed_at_utc=item["observed_at_utc"],
            )
            for item in coverage_rows
        )
    )
    confidence = _weakest_confidence_assessment(
        factor_values,
        coverage_status=coverage,
    )
    factors = confidence.factors
    cur.execute(
        """
        select min(occurred_at_utc) as first_seen_utc,
               max(occurred_at_utc) as last_seen_utc,
               count(*) as step_count,
               (select count(*) from semantic_scenario_evidence
                where scenario_id=%s) +
               (select count(distinct detection.evidence_key)
                from semantic_scenario_steps step join semantic_detection_matches detection
                  on detection.match_id=step.detection_match_id
                where step.scenario_id=%s) +
               (select count(distinct ref) from semantic_scenario_steps step
                join semantic_qw_signals signal on signal.signal_id=step.qw_signal_id,
                lateral jsonb_array_elements(signal.document_json->'evidence_refs') ref
                where step.scenario_id=%s) as evidence_count,
               (select count(*) from semantic_risk_contributions
                where scenario_id=%s) as contribution_count,
               (select coalesce(max((signal.document_json->>'evidence_total')::integer),0)
                from semantic_scenario_steps step join semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
                where step.scenario_id=%s) as expected_evidence_count
        from semantic_scenario_steps where scenario_id=%s
        """,
        (scenario_id, scenario_id, scenario_id, scenario_id, scenario_id, scenario_id),
    )
    counts = dict(cur.fetchone() or {})
    cur.execute(
        """
        update semantic_security_scenarios
        set first_seen_utc=%s,last_seen_utc=%s,risk_class=%s,raw_score=%s,
            display_score=%s,hard_critical=%s,confidence=%s,
            confidence_score=%s,confidence_factors_json=%s::jsonb,
            coverage_status=%s,step_count=%s,evidence_count=%s,
            contribution_count=%s,evidence_state=%s,updated_at=now()
        where scenario_id=%s
        returning scenario_id,scenario_status,risk_class,raw_score,display_score,
                  hard_critical,confidence,confidence_score,coverage_status,
                  step_count,evidence_count,contribution_count,evidence_state
        """,
        (
            counts["first_seen_utc"],
            counts["last_seen_utc"],
            risk.risk_class.value,
            risk.raw_score,
            risk.display_score,
            risk.hard_critical,
            confidence.level.value,
            confidence.score,
            _json_text(factors.as_dict()),
            coverage.value,
            int(counts["step_count"]),
            int(counts["evidence_count"]),
            int(counts["contribution_count"]),
            "evidence_pending" if int(counts["evidence_count"]) < int(counts.get("expected_evidence_count") or 0) else "ready",
            scenario_id,
        ),
    )
    row = dict(cur.fetchone() or {})
    if not row:
        raise RuntimeError("semantic scenario aggregate was not persisted")
    return ScenarioPersistenceResult(
        scenario_id=str(row["scenario_id"]),
        scenario_status=str(row["scenario_status"]),
        risk_class=MachineRisk(str(row["risk_class"])),
        raw_score=Decimal(str(row["raw_score"])),
        display_score=int(row["display_score"]),
        hard_critical=bool(row["hard_critical"]),
        confidence=Confidence(str(row["confidence"])),
        confidence_score=int(row["confidence_score"]),
        coverage_status=CoverageStatus(str(row["coverage_status"])),
        step_count=int(row["step_count"]),
        evidence_count=int(row["evidence_count"]),
        contribution_count=int(row["contribution_count"]),
        evidence_state=str(row.get("evidence_state") or "ready"),
    )


def persist_scenario_proposal(
    cur: Any, *, proposal: ScenarioProposal
) -> ScenarioPersistenceResult:
    """Persist one proposal and merge it only through strict bounded identity."""
    merge_scenario_proposals((proposal,))
    # Validate native authorization before creating even an internal episode.
    _verify_source_evidence(cur, proposal=proposal)
    cur.execute(
        "select pg_advisory_xact_lock(hashtextextended(%s,0))",
        (proposal.identity_sha256.hex(),),
    )
    scenario = _select_scenario(cur, proposal=proposal)
    scenario_id = str(scenario["scenario_id"])
    _persist_step(cur, scenario_id=scenario_id, proposal=proposal)
    _persist_evidence(cur, scenario_id=scenario_id, proposal=proposal)
    _persist_contribution(cur, scenario_id=scenario_id, proposal=proposal)
    _persist_coverage(cur, scenario_id=scenario_id, proposal=proposal)
    if proposal.step.source_kind is ScenarioSourceKind.QW_SIGNAL and proposal.scenario_kind == "qw.nps-denials":
        cur.execute("""update semantic_security_scenarios set explanation=%s
            where scenario_id=%s and last_seen_utc<=%s""",
            (proposal.explanation, scenario_id, proposal.step.occurred_at_utc))
    return _refresh_scenario(cur, scenario_id=scenario_id)
