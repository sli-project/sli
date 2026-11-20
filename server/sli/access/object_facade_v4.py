"""Policy-filtered registry facade over existing PostgreSQL entity models."""
from __future__ import annotations

from typing import Any, Mapping

from server.sli.access.access_control_v4 import (
    capability_decision_for_resource_groups,
    effective_access,
    ensure_access_schema,
)
from server.sli.core.database import query_rows_bounded
from server.sli.access.entity_access_projection import (
    project_ad_context,
    project_attributes as _project_attributes,
    project_context_record as _project_context_record,
)
from server.sli.reporting.ui_workspace import (
    get_entity_workspace_detail_data,
    get_entity_workspace_resource_preflight,
)

OBJECT_LIMIT_MAX = 100
OBJECT_SCOPE_SCAN_MAX = 500

_OBJECT_TYPE_ALIASES = {
    "account": {"account", "user", "ad_user", "service_account"},
    "user": {"account", "user", "ad_user", "service_account"},
    "computer": {"computer", "ad_computer", "server", "domain_controller", "asset"},
    "server": {"computer", "ad_computer", "server", "domain_controller", "asset"},
    "ip": {"ip", "ip_address"},
    "entity": set(),
}

def _object_type_matches(requested: str, actual: str) -> bool:
    """Accept the exact Storage V2 type and stable UI aliases.

    Search results always emit the physical type, while old links and registered
    reports may still use a product alias.  The entity ID remains authoritative.
    """
    if requested == actual or requested == "entity":
        return True
    return actual in _OBJECT_TYPE_ALIASES.get(requested, set())


def _object_resource_group(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    if row.get("server_id") is not None:
        resources.append({"kind": "server", "id": int(row["server_id"])})
    if row.get("domain_id") is not None:
        resources.append({"kind": "domain", "id": int(row["domain_id"])})
    # Objects without a server/domain are still covered by a global grant, but
    # can never satisfy a resource-bounded server/domain assignment.
    return resources or [{"kind": "unscoped", "value": "global"}]


def _event_resource_group(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    resources = _object_resource_group(row)
    if row.get("channel"):
        resources.append({"kind": "channel", "value": str(row["channel"])})
    return resources


def _has_capability_candidate(access: Mapping[str, Any], capability: str) -> bool:
    key = str(capability)
    return key in set(access.get("capabilities") or []) or key in set(access.get("resource_bound_capabilities") or [])


def _allows_object_capability(
    access: Mapping[str, Any], capability: str, resource_group: list[dict[str, Any]],
) -> bool:
    return bool(capability_decision_for_resource_groups(
        access, capability, resource_groups=[resource_group],
    ).get("allowed"))


def search_objects(
    principal: Mapping[str, Any] | None, *, query: str = "", object_type: str | None = None,
    limit: int = 30, access: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    access = dict(access or effective_access(principal))
    if not _has_capability_candidate(access, "objects.view"):
        raise PermissionError("objects_view_required")
    clean_limit = max(1, min(int(limit), OBJECT_LIMIT_MAX))
    clean_query = str(query or "").strip()
    clean_type = str(object_type or "").strip()
    params: list[Any] = []
    conditions: list[str] = []
    if clean_query:
        conditions.append("(lower(entity.display_name) like lower(?) or lower(entity.natural_key) like lower(?))")
        params.extend((f"%{clean_query}%", f"%{clean_query}%"))
    if clean_type:
        aliases = sorted(_OBJECT_TYPE_ALIASES.get(clean_type, set()) | {clean_type})
        conditions.append("entity_type.value=any(?)")
        params.append(aliases)
    where = "where " + " and ".join(conditions) if conditions else ""
    resource_aware = any(
        str(item.get("capability_key") or "") == "objects.view"
        for item in access.get("capability_policies", [])
    ) or "objects.view" in set(access.get("resource_bound_capabilities") or [])
    scan_limit = OBJECT_SCOPE_SCAN_MAX if resource_aware else clean_limit + 1
    rows = query_rows_bounded(
        f"""select entity.id,entity_type.value as object_type,entity.display_name,entity.natural_key,
                   entity.domain_id,entity.server_id,entity.first_seen_utc,entity.last_seen_utc
            from entities_v2_active entity join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
            {where}
            order by entity.last_seen_utc desc nulls last,entity.id desc limit ?""",
        tuple(params + [scan_limit]), statement_timeout_ms=5000,
    )
    allowed_rows = [
        (row, _object_resource_group(row)) for row in rows
        if _allows_object_capability(access, "objects.view", _object_resource_group(row))
    ]
    visible = allowed_rows[:clean_limit]
    return {
        "api_version": "v4", "query": clean_query, "object_type": clean_type or None,
        "state": "available" if visible else "empty",
        "items": [{
            "object_type": str(row["object_type"]), "object_id": str(row["id"]),
            "display_name": str(row.get("display_name") or row.get("natural_key") or row["id"]),
            "natural_key": str(row.get("natural_key") or "")
            if _allows_object_capability(access, "field.technical", resource_group) else None,
            "first_seen_utc": row.get("first_seen_utc"), "last_seen_utc": row.get("last_seen_utc"),
            "source": "Storage V2", "freshness": "observed" if row.get("last_seen_utc") else "unknown",
        } for row, resource_group in visible],
        "has_more": len(allowed_rows) > clean_limit or (resource_aware and len(rows) == scan_limit),
        "scope_filtered": len(allowed_rows) != len(rows),
        "limits": {
            "items": clean_limit, "scanned": len(rows), "scope_scan_max": scan_limit,
            "scope_truncated": bool(resource_aware and len(rows) == scan_limit),
            "total_count": "not_calculated",
        },
    }


def object_detail(
    principal: Mapping[str, Any] | None, *, object_type: str, object_id: str,
    event_limit: int = 30, access: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    access = dict(access or effective_access(principal))
    if not _has_capability_candidate(access, "objects.view"):
        raise PermissionError("objects_view_required")
    clean_object_type = str(object_type or "").strip().lower()
    if not clean_object_type or len(clean_object_type) > 64 or not all(char.isalnum() or char in {"_", "-"} for char in clean_object_type):
        raise ValueError("unsupported_object_type")
    try:
        entity_id = int(object_id)
    except ValueError as exc:
        raise ValueError("invalid_object_id") from exc
    preflight = get_entity_workspace_resource_preflight(entity_id=entity_id)
    if preflight is None:
        raise ValueError("object_not_found")
    entity_id = int(preflight["id"])
    resource_group = _object_resource_group(preflight)
    if not _allows_object_capability(access, "objects.view", resource_group):
        raise ValueError("object_not_found")
    actual_type = str(preflight.get("type") or preflight.get("entity_type") or "entity")
    if not _object_type_matches(clean_object_type, actual_type):
        raise ValueError("object_type_mismatch")
    can_evidence = _allows_object_capability(access, "evidence.exact", resource_group)

    def event_evidence_allowed(candidate: Mapping[str, Any]) -> bool:
        return can_evidence and _allows_object_capability(
            access, "evidence.exact", _event_resource_group(candidate),
        )

    def event_evidence_projection(candidate: Mapping[str, Any]) -> str | None:
        """Choose a proof-local field projection before its metadata read."""
        resources = _event_resource_group(candidate)
        if not event_evidence_allowed(candidate):
            return None
        technical_allowed = _allows_object_capability(access, "field.technical", resources)
        security_allowed = _allows_object_capability(access, "field.security", resources)
        if technical_allowed and security_allowed:
            return "full"
        if technical_allowed:
            return "technical"
        if security_allowed:
            return "security_metadata"
        return "metadata"

    detail = get_entity_workspace_detail_data(
        entity_id=entity_id,
        limit=max(1, min(int(event_limit), 100)),
        event_evidence_projection=event_evidence_projection,
    )
    if detail is None:
        raise ValueError("object_not_found")
    entity = dict(detail["entity"])
    resource_rows = query_rows_bounded(
        """
        select domain_id,server_id,
               (
                   select event.time_created_utc
                   from event_entity_link_blocks_v2 block
                   join events_v2_core event on event.id=block.last_event_id
                   where block.entity_id=entity.id
                   order by block.block_no desc
                   limit 1
               ) as storage_v2_observed_at_utc
        from entities_v2_active entity
        where entity.id=?
        limit 1
        """,
        (entity_id,), statement_timeout_ms=3000,
    )
    resource_row = resource_rows[0] if resource_rows else {}
    ensure_access_schema()
    links = query_rows_bounded(
        """select source_object_type,source_object_id,target_object_type,target_object_id,relation_type,
                  source_name,match_method,confidence,observed_at,valid_from,valid_until
           from object_identity_links
           where (source_object_type=? and source_object_id=?) or (target_object_type=? and target_object_id=?)
           order by observed_at desc,id desc limit 50""",
        (actual_type,str(entity_id),actual_type,str(entity_id)), statement_timeout_ms=3000,
    )
    can_technical = _allows_object_capability(access, "field.technical", resource_group)
    can_security = _allows_object_capability(access, "field.security", resource_group)
    can_privilege = (
        _allows_object_capability(access, "field.privilege", resource_group)
        and _allows_object_capability(access, "objects.privileges", resource_group)
    )
    can_groups = _allows_object_capability(access, "objects.groups", resource_group)
    projected_capabilities = {
        capability for capability in (
            "field.identity_basic", "field.security", "field.privilege", "field.hr",
            "field.contact", "field.technical",
        ) if _allows_object_capability(access, capability, resource_group)
    }
    # Group membership relations serve the groups tab, privileged ones only the
    # privileges tab: a groups-only reader must not receive privileged paths.
    raw_ad_context = dict(detail.get("ad_context") or {})
    if not can_privilege:
        raw_ad_context["items"] = [
            item for item in raw_ad_context.get("items") or []
            if not (item.get("context_kind") == "relation" and item.get("source_section") == "privileged_membership")
        ]
    ad_context = project_ad_context(
        raw_ad_context,
        capabilities=projected_capabilities,
        include_relations=can_privilege or can_groups,
    )
    context_items = list(ad_context.get("items") or [])
    tabs = [
        {"id": "overview", "label": "Обзор", "available": True},
        {"id": "groups", "label": "Членство в группах", "available": can_groups},
        {"id": "privileges", "label": "Доступ и привилегии", "available": can_privilege},
        {"id": "activity", "label": "Активность", "available": can_security and can_evidence},
        {"id": "states", "label": "Состояние и изменения", "available": can_security},
        {"id": "findings", "label": "Находки", "available": can_security},
        {"id": "evidence", "label": "Доказательства", "available": can_evidence},
        {"id": "technical", "label": "Технические атрибуты", "available": can_technical},
    ]
    safe_entity = {
        "object_type": actual_type, "object_id": str(entity_id),
        "display_name": entity.get("display_name"),
        "natural_key": entity.get("natural_key") if can_technical else None,
        "first_seen_utc": entity.get("first_seen_utc"), "last_seen_utc": entity.get("last_seen_utc"),
        "latest_state": entity.get("latest_state") if can_security else None,
    }
    events_state = str(detail.get("events_state") or "available") if can_evidence else "forbidden"
    events = list(detail.get("events") or []) if can_evidence else []
    findings = []
    if can_security:
        findings = [dict(row) for row in query_rows_bounded(
            """select distinct finding.id,finding.title,finding.severity,finding.status,
                              finding.summary,finding.last_seen_utc,finding.last_evidence_event_id as evidence_event_id
               from findings_active finding
               join finding_entities link on link.finding_id=finding.id
               where link.entity_id=?
               order by finding.last_seen_utc desc nulls last,finding.id desc limit 20""",
            (entity_id,), statement_timeout_ms=3000,
        )]
    limitations = ["Снимок и событие являются разными типами факта", "Отсутствующее значение не интерпретируется как ложь"]
    if events_state == "temporarily_unavailable":
        limitations.append("Лента событий временно недоступна: ограниченный запрос превысил допустимое время выполнения")
    if not can_evidence:
        limitations.append("Точная лента событий скрыта политикой evidence.exact")
    elif detail.get("events_scope_filtered"):
        limitations.append("Часть связанных доказательств скрыта политикой их собственного ресурса")
    if not can_technical and links:
        limitations.append("Связи идентичности и их provenance скрыты политикой технических полей")
    provenance = []
    storage_v2_observed_at = resource_row.get("storage_v2_observed_at_utc")
    if storage_v2_observed_at:
        provenance.append({
            "source": "Storage V2",
            "observed_at_utc": storage_v2_observed_at,
            "freshness": "observed",
        })
    if context_items:
        provenance.append({
            "source": "AD Context",
            "observed_at_utc": context_items[0].get("observed_at_utc"),
            "freshness": "observed",
        })
    if not provenance:
        limitations.append("Для объекта не найдено доказательство наблюдения подключённым источником")
    return {
        "api_version": "v4", "state": "available", "object": safe_entity,
        "identity_links": [dict(row) for row in links] if can_technical else [],
        "identity_contract": "employee_and_account_are_distinct_objects",
        "tabs": tabs, "current_states": detail.get("current_states") if can_security else [],
        "findings": findings,
        "directory_context": {**ad_context, "items": context_items},
        "events": events, "events_state": events_state,
        "has_more_events": bool(detail.get("has_more")) if can_evidence else False,
        # Object-bound task/case mutations do not have a server contract yet.
        # Do not advertise capabilities that the object route cannot execute.
        "actions": ["copy_link"],
        "provenance": provenance,
        "limitations": limitations,
    }
