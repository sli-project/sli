"""Optional AD Context source-pack bridge into core entity evidence/state DTOs."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from server.sli.core.database import query_rows_bounded

MAX_CONTEXT_EVIDENCE = 100


def get_runtime_entity_context_evidence(
    entity_id: int, *, limit: int = 50
) -> dict[str, Any]:
    """Return context for the shared entity ID, with exact-alias fallback."""
    exact_id = int(entity_id)
    direct = get_entity_context_evidence(exact_id, limit=limit)
    if direct["items"]:
        return {
            **direct,
            "ad_context_entity_id": exact_id,
            "resolution": "shared_entity_id",
        }
    rows = query_rows_bounded(
        """
        select entity.id,entity.domain_id,entity.natural_key,entity.display_name,
               details.attributes_json
        from entities_v2 entity
        left join entity_details_v2 details on details.entity_id=entity.id
        where entity.id=? limit 1
        """,
        (exact_id,),
        statement_timeout_ms=3000,
    )
    if not rows:
        return {"entity_id": exact_id, "resolution": "not_found", "items": [], "returned_count": 0, "bounded": True}
    runtime = dict(rows[0])
    attributes = runtime.get("attributes_json") if isinstance(runtime.get("attributes_json"), dict) else {}
    aliases: list[tuple[str, str]] = []
    sid = str(attributes.get("sid") or "").strip()
    if sid:
        aliases.append(("object_sid", sid))
    for candidate in (
        str(runtime.get("display_name") or "").rsplit("\\", 1)[-1],
        str(runtime.get("natural_key") or "").rsplit(":", 1)[-1],
    ):
        value = candidate.strip()
        if value and ("sam_account_name", value.casefold()) not in {(kind, item.casefold()) for kind, item in aliases}:
            aliases.append(("sam_account_name", value))
    domain_id = runtime.get("domain_id")
    if domain_id is None or not aliases:
        return {"entity_id": exact_id, "resolution": "no_exact_alias", "items": [], "returned_count": 0, "bounded": True}
    conditions = " or ".join("(alias_type=? and normalized_value=lower(?))" for _ in aliases)
    params: list[Any] = [int(domain_id)]
    for alias_type, alias_value in aliases:
        params.extend((alias_type, alias_value))
    resolved = query_rows_bounded(
        f"select distinct entity_id from ad_context_entity_aliases where domain_id=? and ({conditions}) order by entity_id limit 2",
        tuple(params),
        statement_timeout_ms=3000,
    )
    if len(resolved) != 1:
        return {
            "entity_id": exact_id,
            "resolution": "ambiguous" if resolved else "not_observed",
            "items": [],
            "returned_count": 0,
            "bounded": True,
        }
    context = get_entity_context_evidence(int(resolved[0]["entity_id"]), limit=limit)
    return {**context, "entity_id": exact_id, "ad_context_entity_id": int(resolved[0]["entity_id"]), "resolution": "exact_alias"}


def get_entity_context_evidence(
    entity_id: int,
    *,
    limit: int = 50,
) -> dict[str, Any]:
    """Return bounded supplemental evidence; no state or relation is inferred."""
    exact_id = int(entity_id)
    if exact_id <= 0:
        raise ValueError("entity_id_must_be_positive")
    clean_limit = max(1, min(int(limit), MAX_CONTEXT_EVIDENCE))
    # Expose the version ordering as columns so PostgreSQL can incrementally
    # sort and stop each UNION branch before probing all historical evidence.
    # Each local cap is the largest supported request, preserving the global
    # top N even with missing evidence, duplicate observations and timestamp ties.
    rows = query_rows_bounded(
        """
        (
        select evidence.id as context_evidence_id, evidence.evidence_type,
               evidence.source_pack_id, evidence.source_run_id,
               evidence.observed_at_utc, encode(evidence.integrity_sha256,'hex') as integrity_sha256,
               'entity' as context_kind, version.entity_id as subject_entity_id,
               current_entity.display_name as subject_display_name,
               null::bigint as related_entity_id, null::text as related_display_name,
               version.valid_from_utc, version.valid_to_utc,
               version.last_observed_at_utc, version.current,
               version.source_section, version.attributes_json
        from (
            select *, (valid_to_utc is null) as current
            from ad_context_entity_versions where entity_id=?
            order by (valid_to_utc is null) desc, last_observed_at_utc desc offset 0
        ) version
        join lateral (
            select display_name from entities_v2_active
            where id=version.entity_id limit 1
        ) current_entity on true
        join lateral (
            select * from ad_context_evidence evidence
            where evidence.source_run_id=version.source_run_id
         and evidence.evidence_type='entity_observation'
         and evidence.locator_json->>'record_key'=version.attributes_json->>'record_key'
            order by evidence.observed_at_utc desc, evidence.id desc limit 100
        ) evidence on true
        order by current desc, last_observed_at_utc desc, observed_at_utc desc, context_evidence_id desc
        limit 100
        )
        union all
        (
        select evidence.id as context_evidence_id, evidence.evidence_type,
               evidence.source_pack_id, evidence.source_run_id,
               evidence.observed_at_utc, encode(evidence.integrity_sha256,'hex') as integrity_sha256,
               'relation' as context_kind,
               case when relation.source_entity_id=? then relation.source_entity_id else relation.target_entity_id end as subject_entity_id,
               case when relation.source_entity_id=? then source_entity.display_name else target_entity.display_name end as subject_display_name,
               case when relation.source_entity_id=? then relation.target_entity_id else relation.source_entity_id end as related_entity_id,
               case when relation.source_entity_id=? then target_entity.display_name else source_entity.display_name end as related_display_name,
               relation.valid_from_utc, relation.valid_to_utc,
               relation.last_observed_at_utc, relation.current,
               relation.source_section, relation.attributes_json
        from (
            select *, (valid_to_utc is null) as current
            from ad_context_relation_versions where source_entity_id=? or target_entity_id=?
            order by (valid_to_utc is null) desc, last_observed_at_utc desc offset 0
        ) relation
        join lateral (
            select display_name from entities_v2_active
            where id=relation.source_entity_id limit 1
        ) source_entity on true
        join lateral (
            select display_name from entities_v2_active
            where id=relation.target_entity_id limit 1
        ) target_entity on true
        join lateral (
            select * from ad_context_evidence evidence
            where evidence.source_run_id=relation.source_run_id
         and evidence.evidence_type='relation_observation'
         and evidence.locator_json->>'record_key'=relation.relation_key
            order by evidence.observed_at_utc desc, evidence.id desc limit 100
        ) evidence on true
        order by current desc, last_observed_at_utc desc, observed_at_utc desc, context_evidence_id desc
        limit 100
        )
        order by current desc, last_observed_at_utc desc, observed_at_utc desc, context_evidence_id desc
        limit ?
        """,
        (exact_id, exact_id, exact_id, exact_id, exact_id, exact_id, exact_id, clean_limit),
        statement_timeout_ms=5000,
        wall_timeout_ms=6500,
    )
    items = []
    for raw in rows:
        row = dict(raw)
        items.append({
            "context_evidence_id": int(row["context_evidence_id"]),
            "evidence_type": str(row["evidence_type"]),
            "source_pack_id": str(row["source_pack_id"]),
            "source_run_id": str(row["source_run_id"]),
            "observed_at_utc": row.get("observed_at_utc"),
            "last_observed_at_utc": row.get("last_observed_at_utc"),
            "integrity_sha256": str(row.get("integrity_sha256") or ""),
            "context_kind": str(row["context_kind"]),
            "subject_entity_id": int(row["subject_entity_id"]),
            "subject_display_name": str(row.get("subject_display_name") or "") or None,
            "related_entity_id": int(row["related_entity_id"]) if row.get("related_entity_id") is not None else None,
            "related_display_name": str(row.get("related_display_name") or "") or None,
            "valid_from_utc": row.get("valid_from_utc"),
            "valid_to_utc": row.get("valid_to_utc"),
            "current": row.get("valid_to_utc") is None,
            "source_section": str(row.get("source_section") or ""),
            "attributes": dict(row.get("attributes_json") or {}) if isinstance(row.get("attributes_json"), dict) else {},
            "supplemental_context_only": True,
            "changes_entity_state": False,
        })
    return {
        "entity_id": exact_id, "items": items, "returned_count": len(items),
        "bounded": True, "limit": clean_limit, "source_pack_optional": True,
        "absence_closes_state": False,
    }


def attach_context_evidence_to_state(
    state_candidate: dict[str, Any], context_items: Iterable[dict[str, Any]]
) -> dict[str, Any]:
    """Attach exact evidence IDs without changing status, order key or provenance."""
    candidate = dict(state_candidate)
    entity_id = int(candidate.get("entity_id") or 0)
    if entity_id <= 0:
        raise ValueError("state_candidate_entity_id_required")
    evidence_ids: list[int] = []
    for item in context_items:
        if int(item.get("subject_entity_id") or 0) != entity_id:
            continue
        if not item.get("supplemental_context_only") or item.get("changes_entity_state"):
            raise ValueError("ad_context_must_remain_supplemental")
        evidence_id = int(item.get("context_evidence_id") or 0)
        if evidence_id > 0 and evidence_id not in evidence_ids:
            evidence_ids.append(evidence_id)
        if len(evidence_ids) >= 20:
            break
    details = dict(candidate.get("details") or {})
    details["ad_context_evidence_ids"] = evidence_ids
    details["ad_context_role"] = "supplemental_incident_context"
    candidate["details"] = details
    return candidate
