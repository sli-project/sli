"""Split out of ``server.sli.semantic.semantic_risk_runtime_repository`` (plan 7.2b).

Module-level names of ``semantic_risk_runtime_repository`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.semantic.semantic_risk_runtime_repository as _src


def _candidate_identity_resolution(
    evidence: list[dict[str, _src.Any]],
    *,
    strict_roles: tuple[str, ...],
) -> _src.IdentityResolution:
    """Return the weakest proved identity used by the strict scenario key."""

    resolutions: list[_src.IdentityResolution] = []
    for item in evidence:
        roles = _src._json_object(item["roles_json"])
        quality = _src._json_object(item["quality_json"])
        identity_roles = _src._json_object(quality.get("identity_roles"))
        for role in strict_roles:
            role_value = str(roles.get(role) or "").strip()
            if not role_value:
                return _src.IdentityResolution.UNRESOLVED
            if role in _src._INTRINSIC_EXACT_ROLES:
                resolutions.append(_src.IdentityResolution.EXACT)
                continue
            metadata = _src._json_object(identity_roles.get(role))
            metadata_key = str(metadata.get("key") or "").strip()
            if metadata_key and metadata_key != role_value:
                raise RuntimeError(
                    f"risk policy identity metadata differs from strict role: {role}"
                )
            state = str(metadata.get("state") or "").strip()
            resolutions.append(
                {
                    "resolved": _src.IdentityResolution.EXACT,
                    "external": _src.IdentityResolution.EXACT,
                    "provisional": _src.IdentityResolution.PARTIAL,
                    "unresolved": _src.IdentityResolution.UNRESOLVED,
                }.get(state, _src.IdentityResolution.UNKNOWN)
            )
    if not resolutions:
        return _src.IdentityResolution.UNKNOWN
    return min(resolutions, key=_src._IDENTITY_RESOLUTION_ORDER.__getitem__)


def _canonical_action_proposal(
    cur: _src.Any, *, policy: _src.CompiledRiskPolicy, source_id: str
) -> _src.ScenarioProposal:
    cur.execute(
        """
        select canonical_action_id,action_kind,action_status,occurred_at_utc,
               attributes_json
        from canonical_actions where canonical_action_id=%s for share
        """,
        (source_id,),
    )
    source = dict(cur.fetchone() or {})
    if not source:
        raise RuntimeError("risk policy canonical action is unavailable")
    if source.get("action_status") in {
        "contradicted",
        "superseded",
        "quarantined",
    }:
        raise RuntimeError("risk policy canonical action is not eligible")
    if source.get("action_kind") != policy.selector_value:
        raise RuntimeError("risk policy selector no longer matches canonical action")
    cur.execute(
        """
        select evidence.normalized_event_id,normalized.roles_json,
               normalized.quality_json,normalized.semantic_type
        from canonical_action_evidence evidence
        join normalized_events normalized
          on normalized.normalized_event_id=evidence.normalized_event_id
        where evidence.canonical_action_id=%s order by evidence.evidence_order
        """,
        (source_id,),
    )
    evidence = [dict(item) for item in (cur.fetchall() or [])]
    if not evidence:
        raise RuntimeError("risk policy canonical action has no normalized evidence")
    attributes = _src._json_object(source.get("attributes_json"))
    material = _src._json_object(attributes.get("material_identity", {}))
    source_hosts = {
        str(_src._json_object(item["roles_json"]).get("source_host") or "").strip()
        for item in evidence
    } - {""}
    material_host = str(material.get("source_host") or "").strip()
    if material_host:
        source_hosts.add(material_host)
    if len(source_hosts) != 1:
        raise RuntimeError("canonical action source_host is not exact")
    partition_key = next(iter(source_hosts))
    # The action identity belongs to the immutable step/contribution evidence.
    # Putting it into scenario strict keys would make every action its own
    # scenario and silently defeat the policy merge window.
    strict: dict[str, str] = {}
    for role in policy.strict_roles:
        values = {
            str(_src._json_object(item["roles_json"]).get(role) or "").strip()
            for item in evidence
        } - {""}
        if len(values) != 1:
            raise RuntimeError(f"risk policy strict role is not exact: {role}")
        strict[role] = next(iter(values))
    qualities = tuple(_src._json_object(item["quality_json"]) for item in evidence)
    parser_good = all(
        not item.get("unknown_event_mapping")
        and item.get("event_data_encoding") == "named"
        for item in qualities
    )
    completeness = min(
        100,
        int(100 * len(evidence) / policy.expected_evidence_count),
    )
    factors = _src.ConfidenceFactors(
        identity_resolution=(
            _src._candidate_identity_resolution(
                evidence,
                strict_roles=policy.strict_roles,
            )
            if policy.strict_roles
            else _src.IdentityResolution.EXACT
        ),
        state_confirmed=source.get("action_status")
        in {"state_confirmed", "multi_source_confirmed"},
        sequence_completeness=completeness,
        time_quality=_src.EvidenceQuality.GOOD,
        parser_quality=(
            _src.EvidenceQuality.GOOD if parser_good else _src.EvidenceQuality.DEGRADED
        ),
    )
    occurred = source["occurred_at_utc"]
    coverage = _src._coverage_for_policy(
        cur,
        policy=policy,
        partition_key=partition_key,
        observed_at=occurred,
    )
    return _src._proposal(
        policy=policy,
        source_id=source_id,
        partition_key=partition_key,
        strict_keys=strict,
        occurred_at=occurred,
        normalized_ids=tuple(
            str(item["normalized_event_id"]) for item in evidence
        ),
        factors=factors,
        coverage=coverage,
    )


def _candidate_proposal(
    cur: _src.Any, *, policy: _src.CompiledRiskPolicy, source_id: str
) -> _src.ScenarioProposal:
    cur.execute(
        """
        select candidate_id,relation_kind,candidate_status,partition_key,
               window_end_utc,confidence,evidence_count
        from semantic_correlation_candidates where candidate_id=%s for share
        """,
        (source_id,),
    )
    source = dict(cur.fetchone() or {})
    if not source or source.get("candidate_status") != "matched":
        raise RuntimeError("risk policy requires a matched correlation candidate")
    if source.get("relation_kind") != policy.selector_value:
        raise RuntimeError("risk policy selector no longer matches candidate")
    cur.execute(
        """
        select evidence.normalized_event_id,normalized.roles_json,
               normalized.quality_json,normalized.semantic_type
        from semantic_correlation_candidate_evidence evidence
        join normalized_events normalized
          on normalized.normalized_event_id=evidence.normalized_event_id
        where evidence.candidate_id=%s order by evidence.evidence_order
        """,
        (source_id,),
    )
    evidence = [dict(item) for item in (cur.fetchall() or [])]
    if not evidence:
        raise RuntimeError("risk policy candidate has no normalized evidence")
    strict: dict[str, str] = {}
    for role in policy.strict_roles:
        values = {
            str(_src._json_object(item["roles_json"]).get(role) or "").strip()
            for item in evidence
        } - {""}
        if len(values) != 1:
            raise RuntimeError(f"risk policy strict role is not exact: {role}")
        strict[role] = next(iter(values))
    qualities = tuple(_src._json_object(item["quality_json"]) for item in evidence)
    parser_good = all(
        not item.get("unknown_event_mapping")
        and item.get("event_data_encoding") == "named"
        for item in qualities
    )
    cap = {"low": 40, "medium": 70, "high": 100}[str(source["confidence"])]
    completeness = min(
        cap,
        int(100 * len(evidence) / policy.expected_evidence_count),
    )
    factors = _src.ConfidenceFactors(
        identity_resolution=_src._candidate_identity_resolution(
            evidence,
            strict_roles=policy.strict_roles,
        ),
        sequence_completeness=completeness,
        time_quality=_src.EvidenceQuality.GOOD,
        parser_quality=_src.EvidenceQuality.GOOD if parser_good else _src.EvidenceQuality.DEGRADED,
    )
    occurred = source["window_end_utc"]
    coverage = _src._coverage_for_policy(
        cur,
        policy=policy,
        partition_key=str(source["partition_key"]),
        observed_at=occurred,
    )
    return _src._proposal(
        policy=policy,
        source_id=source_id,
        partition_key=str(source["partition_key"]),
        strict_keys=strict,
        occurred_at=occurred,
        normalized_ids=tuple(str(item["normalized_event_id"]) for item in evidence),
        factors=factors,
        coverage=coverage,
    )


def _control_health_proposal(
    cur: _src.Any, *, policy: _src.CompiledRiskPolicy, source_id: str
) -> _src.ScenarioProposal:
    # Immutable observations need no row locks requiring UPDATE privileges.
    cur.execute(
        "select * from semantic_control_health_observations "
        "where observation_id=%s",
        (source_id,),
    )
    source = dict(cur.fetchone() or {})
    if not source or source.get("control_id") != policy.selector_value:
        raise RuntimeError("risk policy selector no longer matches control health")
    coverage = _src.ControlCoverage(
        control_id=str(source["control_id"]),
        status=_src.CoverageStatus(str(source["coverage_status"])),
        reason=str(source["reason"]),
        observed_at_utc=source["observed_at_utc"],
    )
    return _src._proposal(
        policy=policy,
        source_id=source_id,
        partition_key=str(source["partition_key"]),
        strict_keys={"control_id": str(source["control_id"])},
        occurred_at=source["observed_at_utc"],
        normalized_ids=(),
        factors=_src.ConfidenceFactors(
            identity_resolution=_src.IdentityResolution.EXACT,
            state_confirmed=True,
            sequence_completeness=100,
            time_quality=_src.EvidenceQuality.GOOD,
            parser_quality=_src.EvidenceQuality.GOOD,
        ),
        coverage=(coverage,),
    )


def _proposal(
    *,
    policy: _src.CompiledRiskPolicy,
    source_id: str,
    partition_key: str,
    strict_keys: _src.Mapping[str, str],
    occurred_at: _src.datetime,
    normalized_ids: tuple[str, ...],
    factors: _src.ConfidenceFactors,
    coverage: tuple[_src.ControlCoverage, ...],
    evidence_refs: tuple = (),
    evidence_key: str = "",
) -> _src.ScenarioProposal:
    contribution_key = (
        f"risk-policy:{policy.policy_id}:{policy.policy_version}:"
        f"{policy.source_kind.value}:{source_id}"
    )
    return _src.ScenarioProposal(
        scenario_kind=policy.scenario_kind,
        result_class=policy.result_class,
        partition_key=partition_key,
        strict_keys=strict_keys,
        merge_window=policy.merge_window,
        title=policy.title,
        explanation=policy.explanation,
        step=_src.ScenarioStep(
            step_key=f"policy-step:{contribution_key}",
            source_kind=policy.source_kind,
            source_id=source_id,
            occurred_at_utc=occurred_at,
            title=policy.title,
            explanation=policy.explanation,
            normalized_event_ids=normalized_ids,
            confidence_factors=factors,
            evidence_refs=evidence_refs,
        ),
        contribution=_src.RiskContribution(
            contribution_key=contribution_key,
            source_kind=policy.source_kind,
            source_id=source_id,
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_sha256=policy.definition_sha256,
            risk_class=policy.risk_class,
            raw_score=policy.raw_score,
            display_points=policy.display_points,
            hard_critical=policy.hard_critical,
            rationale=policy.rationale,
            evidence_key=evidence_key,
        ),
        coverage=coverage,
    )


def _coverage_for_policy(
    cur: _src.Any, *, policy: _src.CompiledRiskPolicy, partition_key: str, observed_at: _src.datetime
) -> tuple[_src.ControlCoverage, ...]:
    result: list[_src.ControlCoverage] = []
    for control_id in policy.required_controls:
        cur.execute(
            """
            select control_id,coverage_status,reason,observed_at_utc
            from semantic_control_health_observations
            where partition_key=%s and control_id=%s
              and observed_at_utc <= %s
            order by observed_at_utc desc,observation_id desc limit 1
            """,
            (partition_key, control_id, observed_at),
        )
        row = dict(cur.fetchone() or {})
        result.append(
            _src.ControlCoverage(
                control_id=control_id,
                status=_src.CoverageStatus(str(row.get("coverage_status") or "unknown")),
                reason=str(row.get("reason") or "No control health observation is available"),
                observed_at_utc=row.get("observed_at_utc") or observed_at,
            )
        )
    return tuple(result)
