"""Bounded, read-only semantic scenario workspace for the React UI.

The scenario runtime is deliberately activation-gated.  This module only reads
already persisted migration-028 data and reports the feature/worker state; a
page refresh can never enqueue semantic work or create a legacy finding.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from server.sli.core.database import is_postgres_runtime_db, query_rows_bounded
from server.sli.core.keyset_cursor import decode_cursor, encode_cursor
from server.sli.core.time_contract import normalize_utc_range
from server.sli.ops.runtime_workers import get_runtime_workers_overview
from server.sli.semantic.semantic_processing import SemanticFeatureSettings
from server.sli.semantic.semantic_production_runtime import (
    FINDINGS_MODE,
    semantic_runtime_mode_from_env,
    validate_semantic_runtime_settings,
)
from server.sli.semantic.semantic_reviews import summarize_review_labels
from server.sli.sources.source_coverage_integrity import get_source_coverage_integrity

SCENARIO_LIST_LIMIT = 30
SCENARIO_LIST_MAX = 100
SCENARIO_EVIDENCE_LIMIT = 5
SCENARIO_STATUSES = frozenset({"open", "under_review", "resolved", "dismissed"})
SCENARIO_RESULT_CLASSES = frozenset({"security_incident", "security_exposure", "control_gap"})
SCENARIO_RISK_CLASSES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})
ACTION_LIST_LIMIT = 30
ACTION_LIST_MAX = 100
ACTION_EVIDENCE_LIMIT = 5
ACTION_STATUSES = frozenset({
    "observed", "partially_confirmed", "state_confirmed", "multi_source_confirmed",
    "contradicted", "superseded", "quarantined",
})
EVENT_LOOKUP_MAX = 100
EVENT_LOOKUP_EVIDENCE_MAX = 64
EVENT_LOOKUP_TOTAL_EVIDENCE_MAX = 128


def _clean_filter(value: str | None, allowed: frozenset[str], name: str) -> str | None:
    clean = str(value or "").strip().lower()
    if not clean:
        return None
    if clean not in allowed:
        raise ValueError(f"invalid_{name}")
    return clean


def _semantic_event_preflight(
    *, table: str, evidence_table: str, item_column: str, event_db_id: int,
    time_from: str | None, time_to: str | None, timezone_name: str | None,
) -> dict[str, Any]:
    """Find exact proof candidates and every protected evidence ID, never payload."""
    event_id = int(event_db_id)
    if event_id <= 0:
        raise ValueError("invalid_event_db_id")
    start, end = normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
    if not is_postgres_runtime_db():
        raise RuntimeError("semantic_event_lookup_requires_postgres")
    _execution, marker = _execution_contract()
    if marker != 29:
        return {"state": "unavailable", "reason": "schema_unavailable", "resource_event_ids": [], "execution": _execution, "time_from_utc": start, "time_to_utc_exclusive": end}
    bounds: list[str] = []
    params: list[Any] = [event_id]
    if start:
        bounds.append("anchor.occurred_at_utc >= ?")
        params.append(start)
    if end:
        bounds.append("anchor.occurred_at_utc < ?")
        params.append(end)
    where = " and ".join(["anchor.source_event_id = ?", *bounds])
    rows = query_rows_bounded(
        f"""
        with candidates as (
            select distinct item.{item_column} as item_id
            from {table} item
            join {evidence_table} anchor_link on anchor_link.{item_column}=item.{item_column}
            join normalized_events anchor on anchor.normalized_event_id=anchor_link.normalized_event_id
            where {where}
            order by item_id limit ?
        )
        select candidate.item_id, array(
            select proof.source_event_id
            from {evidence_table} proof_link
            left join normalized_events proof on proof.normalized_event_id=proof_link.normalized_event_id
            where proof_link.{item_column}=candidate.item_id
            order by proof_link.normalized_event_id
            limit {EVENT_LOOKUP_EVIDENCE_MAX + 1}
        ) as evidence_event_ids
        from candidates candidate
        order by candidate.item_id
        """,
        tuple(params + [EVENT_LOOKUP_MAX + 1]), statement_timeout_ms=5000,
    )
    if len(rows) > EVENT_LOOKUP_MAX:
        return {"state": "unavailable", "reason": "candidate_limit_exceeded", "resource_event_ids": [], "execution": _execution, "time_from_utc": start, "time_to_utc_exclusive": end}
    evidence_ids: set[int] = set()
    for row in rows:
        raw_ids = row.get("evidence_event_ids") or []
        if len(raw_ids) > EVENT_LOOKUP_EVIDENCE_MAX:
            return {"state": "unavailable", "reason": "evidence_limit_exceeded", "resource_event_ids": [], "execution": _execution, "time_from_utc": start, "time_to_utc_exclusive": end}
        if not raw_ids:
            return {"state": "unavailable", "reason": "evidence_unavailable", "resource_event_ids": [], "execution": _execution, "time_from_utc": start, "time_to_utc_exclusive": end}
        try:
            if any(value is None or int(value) <= 0 for value in raw_ids):
                raise ValueError("invalid_evidence_identity")
            evidence_ids.update(int(value) for value in raw_ids)
        except (TypeError, ValueError):
            return {"state": "unavailable", "reason": "evidence_unavailable", "resource_event_ids": [], "execution": _execution, "time_from_utc": start, "time_to_utc_exclusive": end}
    evidence_ids.add(event_id)
    if len(evidence_ids) > EVENT_LOOKUP_TOTAL_EVIDENCE_MAX:
        return {"state": "unavailable", "reason": "evidence_limit_exceeded", "resource_event_ids": [], "execution": _execution, "time_from_utc": start, "time_to_utc_exclusive": end}
    return {"state": "ready", "item_ids": [str(row["item_id"]) for row in rows], "resource_event_ids": sorted(evidence_ids), "execution": _execution, "time_from_utc": start, "time_to_utc_exclusive": end}


def get_semantic_actions_event_preflight(*, event_db_id: int, time_from: str | None = None, time_to: str | None = None, timezone_name: str | None = "UTC") -> dict[str, Any]:
    return _semantic_event_preflight(table="canonical_actions", evidence_table="canonical_action_evidence", item_column="canonical_action_id", event_db_id=event_db_id, time_from=time_from, time_to=time_to, timezone_name=timezone_name)


def get_semantic_scenarios_event_preflight(*, event_db_id: int, time_from: str | None = None, time_to: str | None = None, timezone_name: str | None = "UTC") -> dict[str, Any]:
    return _semantic_event_preflight(table="semantic_security_scenarios", evidence_table="semantic_scenario_evidence", item_column="scenario_id", event_db_id=event_db_id, time_from=time_from, time_to=time_to, timezone_name=timezone_name)


def metadata_only_action_item(row: dict[str, Any]) -> dict[str, Any]:
    fields = ("canonical_action_id", "action_kind", "status", "semantic_contract_version", "assembler_id", "assembler_version", "occurred_at_utc", "created_at", "updated_at", "evidence")
    return {**{key: row[key] for key in fields if key in row}, "attributes": {}, "payload_state": "metadata_only"}


def metadata_only_scenario_item(row: dict[str, Any]) -> dict[str, Any]:
    fields = ("scenario_id", "scenario_kind", "result_class", "status", "first_seen_utc", "last_seen_utc", "risk_class", "raw_score", "display_score", "hard_critical", "confidence", "confidence_score", "coverage_status", "conclusion_state", "step_count", "evidence_count", "contribution_count", "updated_at", "evidence", "evidence_has_more", "evidence_next_cursor")
    return {**{key: row[key] for key in fields if key in row}, "partition_key": "", "strict_keys": {}, "confidence_factors": {}, "title": "Сохранённый сценарий", "explanation": "Текстовые подробности скрыты в этом представлении.", "completeness_snapshot": {"payload_state": "metadata_only"}, "latest_review": None, "review_count": 0, "payload_state": "metadata_only"}


def _execution_state(settings: SemanticFeatureSettings, worker: dict[str, Any] | None) -> str:
    try:
        mode = semantic_runtime_mode_from_env()
    except RuntimeError as exc:
        return "disabled" if str(exc) == "semantic production admission is required" else "partially_enabled"
    try:
        validate_semantic_runtime_settings(mode, settings)
    except RuntimeError:
        return "partially_enabled"
    if worker and worker.get("state") == "active":
        observed_mode = worker.get("runtime_mode") or FINDINGS_MODE
        if observed_mode != mode:
            return "enabled_without_worker"
        return "active"
    return "enabled_without_worker"


def _public_worker_state() -> dict[str, Any]:
    overview = get_runtime_workers_overview()
    worker = next(
        (item for item in overview.get("items") or [] if item.get("worker_name") == "semantic"),
        None,
    )
    return {
        "state": str((worker or {}).get("state") or "not_registered"),
        "status": str((worker or {}).get("status") or "not_observed"),
        "heartbeat_at": (worker or {}).get("heartbeat_at"),
        "runtime_mode": ((worker or {}).get("details") or {}).get("runtime_mode"),
    }


def _schema_markers() -> tuple[int | None, int | None, bool]:
    rows = query_rows_bounded(
        """
        select max(version) as runtime_marker,
               max(version) filter (where version between 22 and 29) as semantic_marker,
               bool_or(
                   version=68 and name='entity_identity_merge_r7'
               ) as identity_merge_schema_ready
        from schema_migrations
        """,
        statement_timeout_ms=2000,
    )
    row = rows[0] if rows else {}
    return (
        int(row["runtime_marker"]) if row.get("runtime_marker") is not None else None,
        int(row["semantic_marker"]) if row.get("semantic_marker") is not None else None,
        bool(row.get("identity_merge_schema_ready")),
    )


def _execution_contract() -> tuple[dict[str, Any], int | None]:
    settings = SemanticFeatureSettings.from_env()
    worker = _public_worker_state()
    runtime_marker, semantic_marker, identity_merge_schema_ready = (
        _schema_markers()
    )
    state = _execution_state(settings, worker)
    try:
        mode = semantic_runtime_mode_from_env()
    except RuntimeError:
        mode = None
    return ({
        "state": state,
        "runtime_mode": mode,
        "schema_state": "ready" if semantic_marker == 29 else "unavailable",
        "runtime_marker": runtime_marker,
        "semantic_schema_marker": semantic_marker,
        "feature_chain": {
            "normalization": settings.normalization_enabled,
            "assembly": settings.assembly_enabled,
            "directory_state": settings.directory_state_enabled,
            "correlation": settings.correlation_enabled,
            "risk_engine": settings.risk_engine_enabled,
            "finding_creation": settings.finding_creation_enabled,
        },
        "worker": worker,
        "finding_path_live": state == "active" and mode == FINDINGS_MODE and settings.finding_creation_enabled,
        "analyst_review_schema_ready": bool(runtime_marker is not None and runtime_marker >= 33),
        "conclusion_completeness_schema_ready": bool(
            runtime_marker is not None and runtime_marker >= 52
        ),
        "identity_merge_schema_ready": identity_merge_schema_ready,
    }, semantic_marker)


def get_semantic_scenarios_workspace_data(
    *,
    status: str | None = None,
    result_class: str | None = None,
    risk_class: str | None = None,
    limit: int = SCENARIO_LIST_LIMIT,
    cursor: str | None = None,
    scenario_id: str | None = None,
    evidence_cursor: str | None = None,
    event_item_ids: list[str] | None = None,
    metadata_only: bool = False,
    authorized_evidence_ids: list[int] | None = None,
) -> dict[str, Any]:
    """Return a bounded scenario list without COUNT, payload or runtime writes."""
    if not is_postgres_runtime_db():
        raise RuntimeError("semantic_scenarios_require_postgres")

    clean_status = _clean_filter(status, SCENARIO_STATUSES, "scenario_status")
    clean_result = _clean_filter(result_class, SCENARIO_RESULT_CLASSES, "result_class")
    clean_risk = _clean_filter(risk_class, SCENARIO_RISK_CLASSES, "risk_class")
    clean_limit = max(1, min(int(limit or SCENARIO_LIST_LIMIT), SCENARIO_LIST_MAX))
    clean_scenario_id = str(UUID(scenario_id)) if scenario_id is not None else None
    cursor_context = ["scenarios", clean_status, clean_result, clean_risk, clean_scenario_id, event_item_ids]
    after = decode_cursor(cursor, cursor_context) if cursor is not None else None
    evidence_after = None
    if evidence_cursor is not None:
        if clean_scenario_id is None or cursor is not None:
            raise ValueError("invalid_cursor")
        evidence_after = decode_cursor(evidence_cursor, ["scenario-evidence", clean_scenario_id])
        try:
            order = evidence_after["order"]
            if type(order) is not int or not 0 <= order < 2**31:
                raise ValueError("invalid_cursor")
            evidence_after = (order, str(UUID(evidence_after["id"])))
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ValueError("invalid_cursor") from exc
    if after is not None:
        try:
            timestamp = datetime.fromisoformat(after["time"].replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                raise ValueError("invalid_cursor")
            after = (timestamp.isoformat(), str(UUID(after["id"])))
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ValueError("invalid_cursor") from exc
    execution, semantic_marker = _execution_contract()
    if semantic_marker != 29:
        return {
            "generated_at_utc": datetime.now(timezone.utc),
            "read_only": True,
            "execution": execution,
            "state": "schema_unavailable",
            "items": [],
            "has_more": False,
            "filters": {"status": clean_status, "result_class": clean_result, "risk_class": clean_risk},
            "limits": {"items": clean_limit, "evidence_per_scenario": SCENARIO_EVIDENCE_LIMIT, "total_count": "not_calculated"},
        }

    clauses: list[str] = []
    params: list[Any] = []
    if clean_scenario_id is not None:
        clauses.append("scenario.scenario_id = ?::uuid")
        params.append(clean_scenario_id)
        clean_limit = 1
    if after is not None:
        clauses.append("(scenario.updated_at, scenario.scenario_id) < (?::timestamptz, ?::uuid)")
        params.extend(after)
    if clean_status:
        clauses.append("scenario.scenario_status = ?")
        params.append(clean_status)
    if clean_result:
        clauses.append("scenario.result_class = ?")
        params.append(clean_result)
    if clean_risk:
        clauses.append("scenario.risk_class = ?")
        params.append(clean_risk)
    if event_item_ids is not None:
        if not event_item_ids:
            return {
                "generated_at_utc": datetime.now(timezone.utc), "read_only": True,
                "execution": execution, "state": "empty", "items": [], "has_more": False,
                "filters": {"status": clean_status, "result_class": clean_result, "risk_class": clean_risk},
                "limits": {"items": clean_limit, "evidence_per_scenario": 0, "total_count": "not_calculated", "payload_state": "metadata_only"},
            }
        clauses.append("scenario.scenario_id = any(?::uuid[])")
        params.append(event_item_ids)
        if not authorized_evidence_ids or len(authorized_evidence_ids) > EVENT_LOOKUP_TOTAL_EVIDENCE_MAX:
            raise ValueError("authorized_evidence_required")
        clauses.append("""not exists (
            select 1 from semantic_scenario_evidence guard_link
            left join normalized_events guard_event on guard_event.normalized_event_id=guard_link.normalized_event_id
            where guard_link.scenario_id=scenario.scenario_id
              and (guard_event.source_event_id is null or not (guard_event.source_event_id = any(?::bigint[])))
        )""")
        params.append(authorized_evidence_ids)
    if execution.get("identity_merge_schema_ready"):
        clauses.append(
            "not exists (select 1 from entity_identity_scenario_supersessions_v2 "
            "where old_scenario_id=scenario.scenario_id)"
        )
    where = f"where {' and '.join(clauses)}" if clauses else ""
    review_ready = not metadata_only and bool(execution.get("analyst_review_schema_ready"))
    review_columns = (
        "review.review_id as latest_review_id,review.review_request_id,"
        "review.verdict as review_verdict,review.review_confidence,review.rationale as review_rationale,"
        "encode(review.scenario_snapshot_sha256,'hex') as review_snapshot_sha256,"
        "review.reviewed_by,review.reviewer_role,review.reviewed_at,"
        "coalesce(review.review_count,0)::integer as review_count"
        if review_ready else
        "null::uuid as latest_review_id,null::uuid as review_request_id,"
        "null::text as review_verdict,null::text as review_confidence,null::text as review_rationale,"
        "null::text as review_snapshot_sha256,null::text as reviewed_by,null::text as reviewer_role,"
        "null::timestamptz as reviewed_at,0::integer as review_count"
    )
    review_join = (
        """
        left join lateral (
            select latest.review_id,latest.review_request_id,latest.verdict,
                   latest.review_confidence,latest.rationale,
                   latest.scenario_snapshot_sha256,latest.reviewed_by,
                   latest.reviewer_role,latest.reviewed_at,
                   (select count(*) from semantic_scenario_reviews counted
                    where counted.scenario_id=scenario.scenario_id) as review_count
            from semantic_scenario_reviews latest
            where latest.scenario_id=scenario.scenario_id
            order by latest.reviewed_at desc,latest.review_id desc
            limit 1
        ) review on true
        """ if review_ready else ""
    )
    conclusion_ready = bool(
        execution.get("conclusion_completeness_schema_ready")
    )
    conclusion_columns = (
        "conclusion.conclusion_state,"
        "conclusion.completeness_snapshot_json"
        if conclusion_ready
        else
        "'not_checked'::text as conclusion_state,"
        """'{"legacy_missing":true,"supports_negative_conclusion":false}'"""
        "::jsonb as completeness_snapshot_json"
    )
    completeness_column = "'{}'::jsonb as completeness_snapshot_json" if metadata_only else "result.completeness_snapshot_json"
    conclusion_join = (
        f"""
        left join lateral (
            select result.conclusion_state,{completeness_column}
            from semantic_risk_evaluation_results result
            where result.scenario_id=scenario.scenario_id
            order by result.created_at desc,result.job_id desc
            limit 1
        ) conclusion on true
        """
        if conclusion_ready
        else ""
    )
    identity_columns = ("''::text as partition_key,'{}'::jsonb as strict_keys_json,"
                        "''::text as title,''::text as explanation" if metadata_only else
                        "scenario.partition_key,scenario.strict_keys_json,scenario.title,scenario.explanation")
    confidence_column = "'{}'::jsonb as confidence_factors_json" if metadata_only else "scenario.confidence_factors_json"
    evidence_sql = "" if evidence_after is None else "and (item.evidence_order, item.normalized_event_id) > (?::integer, ?::uuid)"
    rows = query_rows_bounded(
        f"""
        select scenario.scenario_id,scenario.scenario_kind,scenario.result_class,
               scenario.scenario_status,{identity_columns},scenario.first_seen_utc,
               scenario.last_seen_utc,scenario.risk_class,scenario.raw_score,
               scenario.display_score,scenario.hard_critical,scenario.confidence,
               scenario.confidence_score,{confidence_column},
               scenario.coverage_status,scenario.step_count,scenario.evidence_count,
               scenario.contribution_count,scenario.updated_at,
               {conclusion_columns},
               {review_columns},
               coalesce(evidence.items,'[]'::jsonb) as evidence
        from semantic_security_scenarios scenario
        {review_join}
        {conclusion_join}
        left join lateral (
            select jsonb_agg(jsonb_build_object(
                       'normalized_event_id',bounded.normalized_event_id,
                       'event_db_id',bounded.source_event_id,
                       'evidence_order',bounded.evidence_order
                   ) order by bounded.evidence_order,bounded.normalized_event_id) as items
            from (
                select item.normalized_event_id,normalized.source_event_id,item.evidence_order
                from semantic_scenario_evidence item
                join normalized_events normalized
                  on normalized.normalized_event_id=item.normalized_event_id
                where item.scenario_id=scenario.scenario_id
                {evidence_sql}
                order by item.evidence_order,item.normalized_event_id
                limit {SCENARIO_EVIDENCE_LIMIT + 1}
            ) bounded
        ) evidence on true
        {where}
        order by scenario.updated_at desc,scenario.scenario_id desc
        limit ?
        """,
        tuple(list(evidence_after or ()) + params + [clean_limit + 1]),
        statement_timeout_ms=5000,
    )
    has_more = len(rows) > clean_limit
    items = [_scenario_item(row) for row in rows[:clean_limit]]
    next_cursor = encode_cursor(cursor_context, {"time": str(rows[clean_limit - 1]["updated_at"]), "id": str(rows[clean_limit - 1]["scenario_id"])}) if has_more and items else None
    if metadata_only:
        items = [metadata_only_scenario_item(item) for item in items]
    return {
        "generated_at_utc": datetime.now(timezone.utc),
        "read_only": True,
        "execution": execution,
        "state": "available" if items else "empty",
        "items": items,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "filters": {"status": clean_status, "result_class": clean_result, "risk_class": clean_risk},
        "limits": {"items": clean_limit, "evidence_per_scenario": SCENARIO_EVIDENCE_LIMIT, "total_count": "not_calculated"},
    }


def _scenario_item(row: dict[str, Any]) -> dict[str, Any]:
    evidence = list(row.get("evidence") or [])
    has_more = len(evidence) > SCENARIO_EVIDENCE_LIMIT
    evidence = evidence[:SCENARIO_EVIDENCE_LIMIT]
    next_cursor = encode_cursor(["scenario-evidence", str(row["scenario_id"])], {
        "order": evidence[-1]["evidence_order"], "id": str(evidence[-1]["normalized_event_id"]),
    }) if has_more and evidence else None
    return {
        "scenario_id": str(row["scenario_id"]),
        "scenario_kind": str(row["scenario_kind"]),
        "result_class": str(row["result_class"]),
        "status": str(row["scenario_status"]),
        "partition_key": str(row["partition_key"]),
        "strict_keys": row.get("strict_keys_json") or {},
        "title": str(row["title"]),
        "explanation": str(row["explanation"]),
        "first_seen_utc": row.get("first_seen_utc"),
        "last_seen_utc": row.get("last_seen_utc"),
        "risk_class": str(row["risk_class"]),
        "raw_score": float(row.get("raw_score") or 0),
        "display_score": int(row.get("display_score") or 0),
        "hard_critical": bool(row.get("hard_critical")),
        "confidence": str(row.get("confidence") or "unknown"),
        "confidence_score": int(row.get("confidence_score") or 0),
        "confidence_factors": row.get("confidence_factors_json") or {},
        "coverage_status": str(row.get("coverage_status") or "unknown"),
        "conclusion_state": str(row.get("conclusion_state") or "not_checked"),
        "completeness_snapshot": row.get("completeness_snapshot_json") or {
            "legacy_missing": True,
            "supports_negative_conclusion": False,
        },
        "step_count": int(row.get("step_count") or 0),
        "evidence_count": int(row.get("evidence_count") or 0),
        "contribution_count": int(row.get("contribution_count") or 0),
        "updated_at": row.get("updated_at"),
        "evidence": evidence,
        "evidence_has_more": has_more,
        "evidence_next_cursor": next_cursor,
        "review_count": int(row.get("review_count") or 0),
        "latest_review": ({
            "review_id": str(row["latest_review_id"]),
            "review_request_id": str(row["review_request_id"]),
            "scenario_id": str(row["scenario_id"]),
            "verdict": str(row["review_verdict"]),
            "review_confidence": str(row["review_confidence"]),
            "rationale": str(row["review_rationale"]),
            "scenario_snapshot_sha256": str(row["review_snapshot_sha256"]),
            "reviewed_by": str(row["reviewed_by"]),
            "reviewer_role": str(row["reviewer_role"]),
            "reviewed_at": row.get("reviewed_at"),
        } if row.get("latest_review_id") else None),
    }


def get_semantic_actions_workspace_data(
    *,
    status: str | None = None,
    action_kind: str | None = None,
    limit: int = ACTION_LIST_LIMIT,
    event_item_ids: list[str] | None = None,
    metadata_only: bool = False,
    authorized_evidence_ids: list[int] | None = None,
) -> dict[str, Any]:
    """Return canonical actions and exact evidence without deriving a verdict."""
    if not is_postgres_runtime_db():
        raise RuntimeError("semantic_actions_require_postgres")
    clean_status = _clean_filter(status, ACTION_STATUSES, "action_status")
    clean_kind = str(action_kind or "").strip()
    if len(clean_kind) > 160:
        raise ValueError("invalid_action_kind")
    clean_limit = max(1, min(int(limit or ACTION_LIST_LIMIT), ACTION_LIST_MAX))
    execution, semantic_marker = _execution_contract()
    if semantic_marker != 29:
        return {
            "generated_at_utc": datetime.now(timezone.utc), "read_only": True,
            "execution": execution, "state": "schema_unavailable", "items": [],
            "has_more": False, "filters": {"status": clean_status, "action_kind": clean_kind or None},
            "limits": {"items": clean_limit, "evidence_per_action": ACTION_EVIDENCE_LIMIT, "total_count": "not_calculated"},
        }

    clauses: list[str] = []
    params: list[Any] = []
    if clean_status:
        clauses.append("action.action_status = ?")
        params.append(clean_status)
    if clean_kind:
        clauses.append("action.action_kind = ?")
        params.append(clean_kind)
    if event_item_ids is not None:
        if not event_item_ids:
            return {
                "generated_at_utc": datetime.now(timezone.utc), "read_only": True,
                "execution": execution, "state": "empty", "items": [], "has_more": False,
                "filters": {"status": clean_status, "action_kind": clean_kind or None},
                "limits": {"items": clean_limit, "evidence_per_action": 0, "total_count": "not_calculated", "payload_state": "metadata_only"},
            }
        clauses.append("action.canonical_action_id = any(?::uuid[])")
        params.append(event_item_ids)
        if not authorized_evidence_ids or len(authorized_evidence_ids) > EVENT_LOOKUP_TOTAL_EVIDENCE_MAX:
            raise ValueError("authorized_evidence_required")
        clauses.append("""not exists (
            select 1 from canonical_action_evidence guard_link
            left join normalized_events guard_event on guard_event.normalized_event_id=guard_link.normalized_event_id
            where guard_link.canonical_action_id=action.canonical_action_id
              and (guard_event.source_event_id is null or not (guard_event.source_event_id = any(?::bigint[])))
        )""")
        params.append(authorized_evidence_ids)
    where = f"where {' and '.join(clauses)}" if clauses else ""
    attributes_column = "'{}'::jsonb as attributes_json" if metadata_only else "action.attributes_json"
    rows = query_rows_bounded(
        f"""
        select action.canonical_action_id,action.action_kind,action.action_status,
               action.semantic_contract_version,action.assembler_id,
               action.assembler_version,action.occurred_at_utc,{attributes_column},
               action.created_at,action.updated_at,
               coalesce(evidence.items,'[]'::jsonb) as evidence
        from canonical_actions action
        left join lateral (
            select jsonb_agg(jsonb_build_object(
                       'normalized_event_id',bounded.normalized_event_id,
                       'event_db_id',bounded.source_event_id,
                       'evidence_role',bounded.evidence_role,
                       'entity_role',bounded.entity_role,
                       'evidence_order',bounded.evidence_order,
                       'relation_confidence',bounded.relation_confidence
                   ) order by bounded.evidence_order) as items
            from (
                select item.normalized_event_id,normalized.source_event_id,
                       item.evidence_role,item.entity_role,item.evidence_order,
                       item.relation_confidence
                from canonical_action_evidence item
                join normalized_events normalized
                  on normalized.normalized_event_id=item.normalized_event_id
                where item.canonical_action_id=action.canonical_action_id
                order by item.evidence_order
                limit {ACTION_EVIDENCE_LIMIT}
            ) bounded
        ) evidence on true
        {where}
        order by action.occurred_at_utc desc,action.canonical_action_id desc
        limit ?
        """,
        tuple(params + [clean_limit + 1]),
        statement_timeout_ms=5000,
    )
    has_more = len(rows) > clean_limit
    items = [{
        "canonical_action_id": str(row["canonical_action_id"]),
        "action_kind": str(row["action_kind"]),
        "status": str(row["action_status"]),
        "semantic_contract_version": int(row["semantic_contract_version"]),
        "assembler_id": str(row["assembler_id"]),
        "assembler_version": str(row["assembler_version"]),
        "occurred_at_utc": row.get("occurred_at_utc"),
        "attributes": row.get("attributes_json") or {},
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "evidence": row.get("evidence") or [],
    } for row in rows[:clean_limit]]
    if metadata_only:
        items = [metadata_only_action_item(item) for item in items]
    return {
        "generated_at_utc": datetime.now(timezone.utc), "read_only": True,
        "execution": execution, "state": "available" if items else "empty",
        "items": items, "has_more": has_more,
        "filters": {"status": clean_status, "action_kind": clean_kind or None},
        "limits": {"items": clean_limit, "evidence_per_action": ACTION_EVIDENCE_LIMIT, "total_count": "not_calculated"},
    }


def get_semantic_calibration_workspace_data(
    *, window_hours: int = 24,
) -> dict[str, Any]:
    """Read bounded TEST/SHADOW calibration aggregates without enabling work."""
    if not is_postgres_runtime_db():
        raise RuntimeError("semantic_calibration_requires_postgres")
    clean_window = max(1, min(int(window_hours or 24), 168))
    execution, semantic_marker = _execution_contract()
    base = {
        "generated_at_utc": datetime.now(timezone.utc), "read_only": True,
        "execution": execution, "window_hours": clean_window,
        "jobs": [], "results": [], "policies": [],
        "calibration_readiness": {
            "control_health": {"total": 0, "by_status": {}},
            "coverage": {"total": 0, "by_status": {}},
            "execution_reliability": {
                "jobs": 0, "completed": 0, "failed": 0,
                "quarantined": 0, "retries": 0,
            },
            "source_quality": {"normalized": 0, "flags": {}},
            "time_provenance": {
                "observed": 0, "future_clock_skew": 0, "delayed_ingest": 0,
                "average_ingest_delay_seconds": 0, "max_ingest_delay_seconds": 0,
            },
            "source_coverage_integrity": {
                "state": "schema_unavailable",
                "channels": {"total": 0, "by_status": {}, "items": []},
                "cursor_integrity": {}, "run_integrity": {}, "gap_detection": {},
                "surveyed_servers_contacted": False, "payload_read": False,
            },
            "false_positive_rate": {
                "state": "not_measurable",
                "reason": "analyst_review_schema_unavailable",
                "reviewed_scenarios": 0,
                "decisive_labels": 0, "false_positive_labels": 0,
                "rate_percent": None, "minimum_decisive_sample": 10,
                "by_verdict": {},
            },
        },
        "limits": {"window_hours_max": 168, "payload": False, "legacy_findings": False},
    }
    if semantic_marker != 29:
        return {**base, "state": "schema_unavailable"}
    job_rows = query_rows_bounded(
        """
        select evaluation_mode,evaluation_status,count(*) as job_count,
               coalesce(sum(attempt_count),0) as attempts,
               count(*) filter (where last_error_code is not null) as errors,
               min(created_at) as first_created_at,max(updated_at) as last_updated_at
        from semantic_risk_evaluation_jobs
        where created_at >= now() - (? * interval '1 hour')
        group by evaluation_mode,evaluation_status
        order by evaluation_mode,evaluation_status
        """, (clean_window,), statement_timeout_ms=4000,
    )
    result_rows = query_rows_bounded(
        """
        select evaluation_mode,risk_class,confidence,coverage_status,
               count(*) as result_count,count(scenario_id) as scenario_count,
               round(avg(display_score),2) as average_risk_score,
               round(avg(confidence_score),2) as average_confidence_score,
               round(avg(evaluation_ms),2) as average_evaluation_ms,
               max(evaluation_ms) as max_evaluation_ms
        from semantic_risk_evaluation_results
        where created_at >= now() - (? * interval '1 hour')
        group by evaluation_mode,risk_class,confidence,coverage_status
        order by evaluation_mode,risk_class,confidence,coverage_status
        """, (clean_window,), statement_timeout_ms=4000,
    )
    policy_rows = query_rows_bounded(
        """
        select lifecycle_status,source_kind,count(*) as policy_count
        from semantic_risk_policies
        group by lifecycle_status,source_kind
        order by lifecycle_status,source_kind
        """, statement_timeout_ms=3000,
    )
    control_rows = query_rows_bounded(
        """
        select coverage_status,count(*) as item_count
        from semantic_control_health_observations
        where created_at >= now() - (? * interval '1 hour')
        group by coverage_status order by coverage_status
        """, (clean_window,), statement_timeout_ms=3000,
    )
    coverage_rows = query_rows_bounded(
        """
        select coverage_status,count(*) as item_count
        from semantic_risk_evaluation_results
        where created_at >= now() - (? * interval '1 hour')
        group by coverage_status order by coverage_status
        """, (clean_window,), statement_timeout_ms=3000,
    )
    quality_rows = query_rows_bounded(
        """
        select count(*) as normalized,
               count(*) filter (where coalesce((quality_json->>'missing_actor_sid')::boolean,false)) as missing_actor_sid,
               count(*) filter (where coalesce((quality_json->>'unresolved_actor')::boolean,false)) as unresolved_actor,
               count(*) filter (where coalesce((quality_json->>'unresolved_target')::boolean,false)) as unresolved_target,
               count(*) filter (where coalesce((quality_json->>'missing_source_ip')::boolean,false)) as missing_source_ip,
               count(*) filter (where coalesce((quality_json->>'unknown_event_mapping')::boolean,false)) as unknown_event_mapping,
               count(*) filter (where occurred_at_utc > source_ingested_at + interval '5 minutes') as future_clock_skew,
               count(*) filter (where source_ingested_at > occurred_at_utc + interval '15 minutes') as delayed_ingest,
               round(avg(greatest(0,extract(epoch from (source_ingested_at-occurred_at_utc)))),2) as average_ingest_delay_seconds,
               round(max(greatest(0,extract(epoch from (source_ingested_at-occurred_at_utc)))),2) as max_ingest_delay_seconds
        from normalized_events
        where normalized_at >= now() - (? * interval '1 hour')
        """, (clean_window,), statement_timeout_ms=3000,
    )
    review_schema_ready = bool(execution.get("analyst_review_schema_ready"))
    review_rows = query_rows_bounded(
        """
        with latest as (
            select distinct on (scenario_id) scenario_id,verdict,reviewed_at
            from semantic_scenario_reviews
            order by scenario_id,reviewed_at desc,review_id desc
        )
        select verdict,count(*) as item_count
        from latest
        where reviewed_at >= now() - (? * interval '1 hour')
        group by verdict order by verdict
        """, (clean_window,), statement_timeout_ms=3000,
    ) if review_schema_ready else []
    jobs = [{**row, "job_count": int(row.get("job_count") or 0),
             "attempts": int(row.get("attempts") or 0), "errors": int(row.get("errors") or 0)}
            for row in job_rows]
    results = [{
        **row,
        "result_count": int(row.get("result_count") or 0),
        "scenario_count": int(row.get("scenario_count") or 0),
        "average_risk_score": float(row.get("average_risk_score") or 0),
        "average_confidence_score": float(row.get("average_confidence_score") or 0),
        "average_evaluation_ms": float(row.get("average_evaluation_ms") or 0),
        "max_evaluation_ms": int(row.get("max_evaluation_ms") or 0),
    } for row in result_rows]
    policies = [{**row, "policy_count": int(row.get("policy_count") or 0)} for row in policy_rows]
    control_by_status = {
        str(row["coverage_status"]): int(row.get("item_count") or 0)
        for row in control_rows
    }
    coverage_by_status = {
        str(row["coverage_status"]): int(row.get("item_count") or 0)
        for row in coverage_rows
    }
    quality = dict(quality_rows[0]) if quality_rows else {}
    all_jobs = sum(item["job_count"] for item in jobs)
    completed = sum(item["job_count"] for item in jobs if item["evaluation_status"] == "completed")
    failed = sum(item["job_count"] for item in jobs if item["evaluation_status"] == "failed")
    quarantined = sum(item["job_count"] for item in jobs if item["evaluation_status"] == "quarantined")
    attempts = sum(item["attempts"] for item in jobs)
    readiness = {
        "control_health": {"total": sum(control_by_status.values()), "by_status": control_by_status},
        "coverage": {"total": sum(coverage_by_status.values()), "by_status": coverage_by_status},
        "execution_reliability": {
            "jobs": all_jobs, "completed": completed, "failed": failed,
            "quarantined": quarantined, "retries": max(0, attempts - all_jobs),
        },
        "source_quality": {
            "normalized": int(quality.get("normalized") or 0),
            "flags": {
                name: int(quality.get(name) or 0)
                for name in (
                    "missing_actor_sid", "unresolved_actor", "unresolved_target",
                    "missing_source_ip", "unknown_event_mapping",
                )
            },
        },
        "time_provenance": {
            "observed": int(quality.get("normalized") or 0),
            "future_clock_skew": int(quality.get("future_clock_skew") or 0),
            "delayed_ingest": int(quality.get("delayed_ingest") or 0),
            "average_ingest_delay_seconds": float(quality.get("average_ingest_delay_seconds") or 0),
            "max_ingest_delay_seconds": float(quality.get("max_ingest_delay_seconds") or 0),
        },
        "source_coverage_integrity": get_source_coverage_integrity(
            window_hours=clean_window,
        ),
        "false_positive_rate": summarize_review_labels(
            review_rows, schema_ready=review_schema_ready,
        ),
    }
    return {**base, "state": "available" if jobs or results or policies else "empty",
            "jobs": jobs, "results": results, "policies": policies,
            "calibration_readiness": readiness}
