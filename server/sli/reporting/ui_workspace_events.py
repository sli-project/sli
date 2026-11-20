"""Split out of ``server.sli.reporting.ui_workspace`` (plan 7.2b).

Module-level names of ``ui_workspace`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.reporting.ui_workspace as _src
from server.sli.reporting.ui_labels import event_id_label


def get_event_entities_data(
    *,
    event_db_id: int,
    limit: int = _src.EVENT_ENTITY_LIMIT,
    authorization: _src.CutoverAuthorization | None = None,
    consumer: str = _src.StorageRouteConsumer.EVENT_ENTITIES,
) -> dict[str, _src.Any]:
    """Return direct, bounded entity evidence for one exact persisted event."""
    clean_event_id = int(event_db_id)
    clean_limit = max(1, min(int(limit or _src.EVENT_ENTITY_LIMIT), _src.EVENT_ENTITY_LIMIT))
    _src.resolve_storage_route(authorization=authorization, consumer=consumer)
    if not _src.is_postgres_runtime_db():
        raise RuntimeError("event entity reads require PostgreSQL/Storage V2")
    event_rows = _src.query_rows_bounded(
        "select 1 as present,time_created_utc from events_v2_core where id = ? limit 1",
        (clean_event_id,),
        statement_timeout_ms=3000,
    )
    event_found = bool(event_rows)
    if _src.primary_read_enabled():
        created_at = _src.parse_event_time(event_rows[0]["time_created_utc"]) if event_rows else None
        cutoff = _src.datetime.now(_src.timezone.utc) - _src.timedelta(days=_src.load_storage_policy().db_retention_days)
        if not event_found or (created_at is not None and created_at < cutoff):
            return _src._history_event_entities_data(
                clean_event_id, clean_limit, event_found=event_found,
            )
    if not event_found:
        return {
            "event_db_id": clean_event_id,
            "event_found": False,
            "evidence_status": "event_not_found",
            "items": [],
            "limit": clean_limit,
        }
    rows = _src.query_rows_bounded(
        """
        with exact_blocks as materialized (
            select entity_id,
                   role_ids[array_position(event_ids, ?)] as role_id
            from event_entity_link_blocks_v2
            where first_event_id <= ? and last_event_id >= ?
              and event_ids @> array[?]::bigint[]
        )
        select entity.id, entity_type.value as type, entity.natural_key,
               entity.display_name, role.value as link_role, 1.0 as confidence
        from exact_blocks block
        join entities_v2 entity on entity.id = block.entity_id
        join storage_v2_entity_type entity_type on entity_type.id = entity.entity_type_id
        join storage_v2_role role on role.id = block.role_id
        where entity_v2_is_active(entity.id)
        order by entity.id asc
        limit ?
        """,
        (clean_event_id, clean_event_id, clean_event_id, clean_event_id, clean_limit),
        statement_timeout_ms=3000,
    )
    return {
        "event_db_id": clean_event_id,
        "event_found": True,
        "evidence_status": "present" if rows else "zero_extracted",
        "items": [{
            "id": int(row["id"]), "type": str(row.get("type") or "unknown"),
            "natural_key": str(row.get("natural_key") or ""), "display_name": row.get("display_name"),
            "link_role": str(row.get("link_role") or "context"), "confidence": float(row.get("confidence") or 0),
        } for row in rows],
        "limit": clean_limit,
    }


def _history_event_entities_data(
    event_db_id: int, limit: int, *, event_found: bool,
) -> dict[str, _src.Any]:
    port = _src.configured_read_port()
    if port is None:
        raise RuntimeError("history ClickHouse port missing")
    try:
        event = _src.read_published_event(port, event_db_id)
    except KeyError:
        if event_found:
            raise RuntimeError("published history missing for cold event")
        return {
            "event_db_id": event_db_id, "event_found": False,
            "evidence_status": "history_unavailable", "items": [], "limit": limit,
        }
    created_at = _src.parse_event_time(event["time_created_utc"])
    if created_at is None or created_at >= _src.datetime.now(_src.timezone.utc) - _src.timedelta(days=_src.load_storage_policy().db_retention_days):
        raise RuntimeError("hot history event missing from PostgreSQL")
    links = _src.read_published_links(port, event_db_id)
    entity_ids = sorted({int(link["entity_id"]) for link in links})
    if entity_ids:
        rows = _src.query_rows_bounded(
            "select entity.id,entity_type.value as type,entity.natural_key,"
            "entity.display_name from entities_v2 entity "
            "join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id "
            f"where entity.id in ({','.join('?' for _ in entity_ids)}) "
            "and entity_v2_is_active(entity.id)",
            tuple(entity_ids), statement_timeout_ms=3000,
        )
    else:
        rows = []
    entities = {int(row["id"]): row for row in rows}
    items = [
        {
            "id": entity_id, "type": str(entities[entity_id].get("type") or "unknown"),
            "natural_key": str(entities[entity_id].get("natural_key") or ""),
            "display_name": entities[entity_id].get("display_name"),
            "link_role": str(link.get("link_role") or "context"),
            "confidence": float(link.get("confidence") if link.get("confidence") is not None else 1.0),
        }
        for link in sorted(links, key=lambda item: (int(item["entity_id"]), str(item["link_role"])))
        if (entity_id := int(link["entity_id"])) in entities
    ][:limit]
    return {
        "event_db_id": event_db_id, "event_found": True,
        "evidence_status": "present" if items else "zero_extracted",
        "items": items, "limit": limit,
    }


def _timeline_item(item: dict[str, _src.Any]) -> dict[str, _src.Any]:
    event_db_id = _src._exact_event_db_id(item)
    if event_db_id is None:
        raise ValueError("timeline_item_missing_exact_event_db_id")
    fallback_title = item.get("label") or event_id_label(
        item.get("event_id"), prefix=False, channel=str(item.get("channel") or ""),
        provider_name=item.get("provider_name"),
    )
    if item.get("_metadata_only") is True:
        descriptor = _src._exact_event_catalog_descriptor(item) if not item.get("label") else None
        return {
            "event_db_id": event_db_id,
            "time_utc": item.get("time"), "server": item.get("server"), "channel": item.get("channel"),
            "event_id": int(item.get("event_id") or 0),
            "title": str(fallback_title),
            "title_code": item.get("title_code") or (
                f"{descriptor['channel']}:{descriptor['provider_name']}:{int(item['event_id'])}.title"
                if descriptor else None
            ),
            "category": str(_src.normalize_category(item.get("category"), known=bool(item.get("catalogued")))),
            "severity": "unknown",
            "purpose_tier": "technical",
            "base_risk": "unknown",
            "confidence": "unknown",
            "noise_class": "unknown",
            "actor": item.get("actor"), "target": item.get("target"), "source": item.get("source"),
            "assessment_confidence": "unknown",
            "classification_origin": "unavailable",
            "card_completeness": "not_applicable",
            "inclusion_reason": item.get("inclusion_reason") or "Событие соответствует выбранному контексту расследования.",
            "summary": None,
            "catalogued": bool(item.get("catalogued")),
        }
    card = _src.build_event_card(item)
    catalogued = bool(card.get("known"))
    return {
        "event_db_id": event_db_id,
        "time_utc": item.get("time"), "server": item.get("server"), "channel": item.get("channel"),
        "event_id": int(item.get("event_id") or 0),
        # Prefer the source-pack catalog only when it has an exact rule for
        # this Provider + Channel + Event ID.  Unknown events keep their
        # source label instead of receiving a fabricated description.
        "title": str(card.get("title") if catalogued else fallback_title),
        "title_code": card.get("title_code") if catalogued else None,
        "summary_code": card.get("summary_code") if catalogued else None,
        "category": str(card.get("category") if catalogued else _src.normalize_category(item.get("category"), known=False)),
        "severity": str(card.get("final_risk") if catalogued else _src.normalize_risk(item.get("severity"))),
        "purpose_tier": str(card.get("purpose_tier") if catalogued else "technical"),
        "base_risk": str(card.get("base_risk") if catalogued else "unknown"),
        "confidence": str(card.get("confidence") if catalogued else "unknown"),
        "noise_class": str(card.get("noise_class") if catalogued else "unknown"),
        "actor": item.get("subject"), "target": item.get("target"), "source": item.get("source"),
        "assessment_confidence": (
            card.get("assessment_confidence") or "unknown"
            if catalogued
            else "unknown"
        ),
        "classification_origin": str(card.get("classification_origin") if catalogued else "unavailable"),
        "card_completeness": str(card.get("card_completeness") if catalogued else "not_applicable"),
        "inclusion_reason": item.get("inclusion_reason") or "Событие соответствует выбранному контексту расследования.",
        "summary": card.get("summary") if catalogued else item.get("summary"),
        "catalogued": catalogued,
    }


def get_entities_workspace_data(
    *,
    q: str | None = None,
    entity_types: tuple[str, ...] = (),
    exclude_entity_types: tuple[str, ...] = (),
    limit: int = _src.ENTITY_LIST_LIMIT,
) -> dict[str, _src.Any]:
    """List recent matching entities and exact whole-table counts by type."""
    if not _src.is_postgres_runtime_db():
        raise RuntimeError("entity workspace requires PostgreSQL/Storage V2 runtime")
    clean_query = str(q or "").strip()
    clean_limit = max(1, min(int(limit or _src.ENTITY_LIST_LIMIT), _src.ENTITY_LIST_MAX))
    clean_entity_types = tuple(dict.fromkeys(str(item).strip().lower() for item in entity_types if str(item).strip()))
    clean_excluded_types = tuple(
        dict.fromkeys(str(item).strip().lower() for item in exclude_entity_types if str(item).strip())
    )
    type_count_rows = _src.query_rows(
        """
        select entity_type.value as entity_type, count(*)::bigint as entity_count
        from entities_v2_active entity
        join storage_v2_entity_type entity_type on entity_type.id = entity.entity_type_id
        group by entity_type.value
        order by entity_count desc, entity_type.value
        """,
    )
    known_types = {str(row["entity_type"]).lower() for row in type_count_rows}
    unknown_types = sorted((set(clean_entity_types) | set(clean_excluded_types)) - known_types)
    if unknown_types:
        raise _src.EntityTypeFilterError(unknown_types)

    params: list[_src.Any] = []
    conditions: list[str] = []
    if clean_query:
        like = f"%{clean_query}%"
        conditions.append(
            "(lower(entity.natural_key) = lower(?) or lower(coalesce(entity.display_name,'')) = lower(?) "
            "or lower(entity.natural_key) like lower(?) or lower(coalesce(entity.display_name,'')) like lower(?))"
        )
        params.extend([clean_query, clean_query, like, like])
    if clean_entity_types:
        conditions.append("entity_type.value = any(?)")
        params.append(list(clean_entity_types))
    if clean_excluded_types:
        conditions.append("not (entity_type.value = any(?))")
        params.append(list(clean_excluded_types))
    where = f"where {' and '.join(conditions)}" if conditions else ""
    rows = _src.query_rows(
        f"""
        select entity.id, entity_type.value as entity_type, entity.natural_key, entity.display_name,
               entity.first_seen_utc, entity.last_seen_utc,
               (
                   select state.status from entity_states state
                   where state.entity_id = entity.id
                   order by state.observed_at_utc desc, state.id desc
                   limit 1
               ) as latest_state_status,
               (
                   select state.summary from entity_states state
                   where state.entity_id = entity.id
                   order by state.observed_at_utc desc, state.id desc
                   limit 1
               ) as latest_state_summary,
               (
                   select state.observed_at_utc from entity_states state
                   where state.entity_id = entity.id
                   order by state.observed_at_utc desc, state.id desc
                   limit 1
               ) as latest_state_observed_at_utc,
               (
                   select state.evidence_event_id from entity_states state
                   where state.entity_id = entity.id
                   order by state.observed_at_utc desc, state.id desc
                   limit 1
               ) as latest_state_event_db_id
        from entities_v2_active entity
        join storage_v2_entity_type entity_type on entity_type.id = entity.entity_type_id
        {where}
        order by last_seen_utc desc nulls last, id desc
        limit ?
        """,
        tuple(params + [clean_limit + 1]),
    )
    has_more = len(rows) > clean_limit
    items = rows[:clean_limit]
    type_counts = [
        {"entity_type": str(row["entity_type"]), "count": int(row["entity_count"])}
        for row in type_count_rows
    ]
    return {
        "query": clean_query,
        "state": "empty" if not items else "ok",
        "items": [_src._entity_item(item) for item in items],
        "has_more": has_more,
        "filters": {
            "entity_types": list(clean_entity_types),
            "exclude_entity_types": list(clean_excluded_types),
        },
        "type_counts": type_counts,
        "type_counts_scope": "all_entities",
        "total_entities": sum(item["count"] for item in type_counts),
        "limits": {"items": clean_limit, "full_history": False, "total_count": "not_calculated"},
    }
