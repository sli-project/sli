"""Split out of ``server.sli.reporting.ui_workspace`` (plan 7.2b).

Module-level names of ``ui_workspace`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.reporting.ui_workspace as _src


def get_entity_workspace_detail_data(
    *,
    entity_id: int,
    limit: int = _src.ENTITY_DETAIL_EVENT_LIMIT,
    before_time_utc: str | None = None,
    before_event_db_id: int | None = None,
    time_from_utc: str | None = None,
    time_to_utc_exclusive: str | None = None,
    timezone_name: str = "UTC",
    event_evidence_allowed: _src.Callable[[_src.Mapping[str, _src.Any]], bool] | None = None,
    event_evidence_projection: _src.Callable[[_src.Mapping[str, _src.Any]], str | None] | None = None,
    ad_context_projection: _src.Callable[[_src.Mapping[str, _src.Any]], dict[str, _src.Any]] | None = None,
) -> dict[str, _src.Any] | None:
    """Return one exact entity and a bounded, evidence-only event slice.

    This is deliberately separate from the legacy entity report: it performs
    no COUNT/OFFSET and never returns message/XML/EventData payloads.  The
    cursor is an exclusive descending ``(time_created_utc, event_id)`` pair.
    """
    if not _src.is_postgres_runtime_db():
        raise RuntimeError("entity workspace requires PostgreSQL/Storage V2 runtime")
    clean_limit = max(1, min(int(limit or _src.ENTITY_DETAIL_EVENT_LIMIT), _src.ENTITY_DETAIL_EVENT_MAX))
    entity_rows = _src.query_rows(
        """
        select entity.id, entity_type.value as entity_type, entity.natural_key, entity.display_name,
               entity.first_seen_utc, entity.last_seen_utc,
               (
                   select state.status from entity_states state
                   where state.entity_id = entity.id
                   order by state.observed_at_utc desc, state.id desc limit 1
               ) as latest_state_status,
               (
                   select state.summary from entity_states state
                   where state.entity_id = entity.id
                   order by state.observed_at_utc desc, state.id desc limit 1
               ) as latest_state_summary,
               (
                   select state.observed_at_utc from entity_states state
                   where state.entity_id = entity.id
                   order by state.observed_at_utc desc, state.id desc limit 1
               ) as latest_state_observed_at_utc,
               (
                   select state.evidence_event_id from entity_states state
                   where state.entity_id = entity.id
                   order by state.observed_at_utc desc, state.id desc limit 1
               ) as latest_state_event_db_id
        from entities_v2_active entity
        join storage_v2_entity_type entity_type on entity_type.id = entity.entity_type_id
        where entity.id = resolve_entity_identity_v2(?)
        limit 1
        """,
        (entity_id,),
    )
    if not entity_rows:
        return None
    entity_id = int(entity_rows[0]["id"])

    current_states_state = "available"
    try:
        current_states = _src._get_current_entity_states(entity_id=entity_id)
    except _src.QueryTimeoutError:
        current_states = []
        current_states_state = "temporarily_unavailable"
    from server.sli.plugins.registry import plugin_hook

    ad_context_state = "available"
    try:
        provider = plugin_hook("sli.ad", "get_runtime_entity_context_evidence")
        if provider is None:
            raise RuntimeError("plugin_not_installed")
        ad_context = provider(entity_id, limit=50)
    except (_src.QueryTimeoutError, RuntimeError) as exc:
        if not isinstance(exc, _src.QueryTimeoutError) and str(exc) not in {"plugin_not_installed", "plugin_update_draining"}:
            raise
        ad_context = {
            "entity_id": entity_id,
            "resolution": "temporarily_unavailable",
            "items": [],
            "returned_count": 0,
            "bounded": True,
        }
        ad_context_state = "temporarily_unavailable"
    if ad_context_projection is not None:
        ad_context = ad_context_projection(ad_context)

    events_state = "available"
    events_scope_filtered = False
    events_candidate_window_truncated = False
    try:
        if event_evidence_allowed is None and event_evidence_projection is None:
            rows = _src._get_entity_evidence_event_rows(
                entity_id=entity_id,
                limit=clean_limit + 1,
                before_time_utc=before_time_utc,
                before_event_db_id=before_event_db_id,
                time_from_utc=time_from_utc,
                time_to_utc_exclusive=time_to_utc_exclusive,
            )
        else:
            candidates = _src._get_entity_evidence_event_rows(
                entity_id=entity_id,
                limit=clean_limit + 1,
                before_time_utc=before_time_utc,
                before_event_db_id=before_event_db_id,
                time_from_utc=time_from_utc,
                time_to_utc_exclusive=time_to_utc_exclusive,
                id_only=True,
            )
            events_candidate_window_truncated = len(candidates) > clean_limit
            candidate_by_id = {
                event_db_id: candidate
                for candidate in candidates
                if (event_db_id := _src._exact_event_db_id(candidate)) is not None
            }
            candidate_ids = list(candidate_by_id)
            projections_by_id = {
                event_db_id: (
                    str(event_evidence_projection(candidate) or "")
                    if event_evidence_projection is not None
                    else "full"
                )
                for event_db_id, candidate in candidate_by_id.items()
                if event_evidence_allowed is None or event_evidence_allowed(candidate) is True
            }
            projections_by_id = {
                event_db_id: projection
                for event_db_id, projection in projections_by_id.items()
                if projection in _src._EVENT_EVIDENCE_FIELD_PROJECTIONS
            }
            permitted_ids = list(projections_by_id)
            events_scope_filtered = len(permitted_ids) != len(candidate_ids)
            if permitted_ids:
                rows_by_id: dict[int, dict[str, _src.Any]] = {}
                for field_projection in _src._EVENT_EVIDENCE_FIELD_PROJECTIONS:
                    selected_ids = [
                        event_db_id for event_db_id in candidate_ids
                        if projections_by_id.get(event_db_id) == field_projection
                    ]
                    if not selected_ids:
                        continue
                    selected_rows = _src._get_entity_evidence_event_rows(
                        entity_id=entity_id,
                        limit=clean_limit + 1,
                        before_time_utc=before_time_utc,
                        before_event_db_id=before_event_db_id,
                        time_from_utc=time_from_utc,
                        time_to_utc_exclusive=time_to_utc_exclusive,
                        event_db_ids=selected_ids,
                        field_projection=field_projection,
                    )
                    for row in selected_rows:
                        event_db_id = _src._exact_event_db_id(row)
                        if event_db_id is None or event_db_id not in candidate_by_id:
                            continue
                        rows_by_id[event_db_id] = {
                            **row,
                            "_field_projection": field_projection,
                        }
                rows = [rows_by_id[event_db_id] for event_db_id in candidate_ids if event_db_id in rows_by_id]
            else:
                rows = []
                if candidate_ids:
                    events_state = "forbidden"
    except _src.QueryTimeoutError:
        # The entity, its projected state and directory context are independent
        # facts.  A bounded evidence read must not turn an existing object into
        # an HTTP 500 or masquerade as an honestly empty event history.
        rows = []
        events_state = "temporarily_unavailable"
    has_more = len(rows) > clean_limit or events_candidate_window_truncated
    items = rows[:clean_limit]
    next_cursor = None
    if has_more and items:
        tail = items[-1]
        next_cursor = {
            "time_utc": tail.get("time_created_utc"),
            "event_db_id": int(tail["event_db_id"]),
        }
    return {
        "entity": _src._entity_item(entity_rows[0]),
        "current_states": current_states,
        "current_states_state": current_states_state,
        "ad_context": ad_context,
        "ad_context_state": ad_context_state,
        "events": [_src._entity_detail_event_item(row) for row in items],
        "events_state": events_state,
        "events_scope_filtered": events_scope_filtered,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "context": {
            "time_from_utc": time_from_utc,
            "time_to_utc_exclusive": time_to_utc_exclusive,
            "timezone": timezone_name,
        },
        "limits": {
            "events": clean_limit,
            "current_states": _src.ENTITY_CURRENT_STATE_LIMIT,
            "full_history": False,
            "total_count": "not_calculated",
        },
    }


def get_entity_workspace_resource_preflight(
    *, entity_id: int,
) -> dict[str, _src.Any] | None:
    """Resolve only the exact entity identity and its authorization resources."""
    if not _src.is_postgres_runtime_db():
        raise RuntimeError("entity workspace requires PostgreSQL/Storage V2 runtime")
    rows = _src.query_rows_bounded(
        """
        select entity.id, entity_type.value as entity_type, entity.domain_id, entity.server_id
        from entities_v2_active entity
        join storage_v2_entity_type entity_type on entity_type.id = entity.entity_type_id
        where entity.id = resolve_entity_identity_v2(?)
        limit 1
        """,
        (entity_id,),
        statement_timeout_ms=3000,
    )
    return dict(rows[0]) if rows else None


def _get_entity_evidence_event_rows(
    *,
    entity_id: int,
    limit: int,
    before_time_utc: str | None,
    before_event_db_id: int | None,
    time_from_utc: str | None = None,
    time_to_utc_exclusive: str | None = None,
    event_db_ids: list[int] | None = None,
    id_only: bool = False,
    field_projection: str = "full",
    preauthorized_exact_event_ids: bool = False,
) -> list[dict[str, _src.Any]]:
    """Read bounded evidence from the authoritative runtime representation."""
    cursor_sql = ""
    params: list[_src.Any] = [entity_id]
    if before_time_utc is not None and before_event_db_id is not None:
        cursor_sql = """
          and (event.time_created_utc < ? or (event.time_created_utc = ? and event.id < ?))
        """
        params.extend([before_time_utc, before_time_utc, before_event_db_id])
    time_sql = ""
    if time_from_utc is not None:
        time_sql += " and event.time_created_utc >= ?"
        params.append(time_from_utc)
    if time_to_utc_exclusive is not None:
        time_sql += " and event.time_created_utc < ?"
        params.append(time_to_utc_exclusive)
    event_ids_sql = ""
    if event_db_ids is not None:
        clean_event_ids = [int(item) for item in event_db_ids if int(item) > 0]
        if not clean_event_ids:
            return []
        event_ids_sql = " and event.id = any(?)"
        params.append(clean_event_ids)
    if _src.is_postgres_runtime_db():
        link_expansion = """cross join lateral unnest(block.event_ids, block.role_ids)
                expanded(event_id, role_id)"""
        if id_only:
            joins = """join servers server on server.id = event.server_id
                join storage_v2_channel channel on channel.id = event.channel_id"""
            return _src.query_rows_bounded(
                f"""
                with ordered_candidates as (
                    select distinct event.id as event_db_id, event.server_id,
                           server.domain_id, channel.value as channel,
                           event.time_created_utc as sort_time_utc
                    from event_entity_link_blocks_v2 block
                    {link_expansion}
                    join events_v2_core event on event.id = expanded.event_id
                    {joins}
                    where block.entity_id = resolve_entity_identity_v2(?) and event.id > 0
                    {cursor_sql}
                    {time_sql}
                    {event_ids_sql}
                    order by event.time_created_utc desc, event.id desc
                    limit ?
                )
                select event_db_id, server_id, domain_id, channel
                from ordered_candidates
                order by sort_time_utc desc, event_db_id desc
                """,
                tuple(params + [limit]),
                statement_timeout_ms=3000,
            )
        elif field_projection == "full":
            projection = """role.value as link_role, 1.0 as confidence,
                   event.id as event_db_id, event.event_id, event.time_created_utc,
                   server.hostname as server, channel.value as channel,
                   provider.value as provider_name,
                   event.subject_user_name, event.target_user_name"""
            joins = """join servers server on server.id = event.server_id
                join storage_v2_channel channel on channel.id = event.channel_id
                join storage_v2_provider provider on provider.id = event.provider_id
                join storage_v2_role role on role.id = expanded.role_id"""
        elif field_projection == "technical":
            projection = """role.value as link_role, 1.0 as confidence,
                   event.id as event_db_id, server.hostname as server,
                   channel.value as channel, provider.value as provider_name"""
            joins = """join servers server on server.id = event.server_id
                join storage_v2_channel channel on channel.id = event.channel_id
                join storage_v2_provider provider on provider.id = event.provider_id
                join storage_v2_role role on role.id = expanded.role_id"""
        elif field_projection == "security_metadata":
            projection = """event.id as event_db_id, event.event_id, event.time_created_utc,
                   server.hostname as server, channel.value as channel"""
            joins = """join servers server on server.id = event.server_id
                join storage_v2_channel channel on channel.id = event.channel_id"""
        elif field_projection == "security_history":
            projection = """distinct event.id as event_db_id, event.event_id, event.time_created_utc,
                   server.hostname as server, channel.value as channel,
                   provider.value as provider_name,
                   event.subject_user_name, event.target_user_name"""
            joins = """join servers server on server.id = event.server_id
                join storage_v2_channel channel on channel.id = event.channel_id
                left join storage_v2_provider provider on provider.id = event.provider_id"""
            if preauthorized_exact_event_ids:
                return _src.query_rows_bounded(
                    f"""
                    select {projection}
                    from events_v2_core event
                    {joins}
                    where event.id = any(?)
                    order by event.time_created_utc desc, event.id desc
                    limit ?
                    """,
                    (clean_event_ids, limit),
                    statement_timeout_ms=3000,
                )
            link_expansion = "cross join lateral unnest(block.event_ids) expanded(event_id)"
        elif field_projection == "metadata":
            projection = """event.id as event_db_id, server.hostname as server,
                   channel.value as channel"""
            joins = """join servers server on server.id = event.server_id
                join storage_v2_channel channel on channel.id = event.channel_id"""
        else:
            raise ValueError("invalid_entity_evidence_field_projection")
        return _src.query_rows_bounded(
            f"""
            select {projection}
            from event_entity_link_blocks_v2 block
            {link_expansion}
            join events_v2_core event on event.id = expanded.event_id
            {joins}
            where block.entity_id = resolve_entity_identity_v2(?) and event.id > 0
            {cursor_sql}
            {time_sql}
            {event_ids_sql}
            order by event.time_created_utc desc, event.id desc
            limit ?
            """,
            tuple(params + [limit]),
            statement_timeout_ms=3000,
        )

    raise RuntimeError("entity evidence reads require PostgreSQL/Storage V2")


def _get_current_entity_states(*, entity_id: int) -> list[dict[str, _src.Any]]:
    """Return one bounded PostgreSQL projection row per state type."""
    if not _src.is_postgres_runtime_db():
        raise RuntimeError("entity current-state reads require PostgreSQL runtime")
    rows = _src.query_rows_bounded(
        """
        select current.state_type, current.status, current.projection_status,
               current.observed_at as observed_at_utc,
               current.source_event_db_id as evidence_event_db_id,
               current.rule_id, current.rule_version, history.summary
        from entity_state_current current
        left join entity_states history
          on history.entity_id = current.entity_id
         and history.state_type = current.state_type
         and history.evidence_event_id = current.source_event_db_id
        where current.entity_id = ?
        order by current.observed_at desc, current.state_type asc
        limit ?
        """,
        (entity_id, _src.ENTITY_CURRENT_STATE_LIMIT),
        statement_timeout_ms=3000,
    )
    return [
        {
            "state_type": str(row.get("state_type") or "unknown"),
            "status": str(row.get("status") or "unknown"),
            "projection_status": str(row.get("projection_status") or "unknown"),
            "observed_at_utc": row.get("observed_at_utc"),
            "evidence_event_db_id": int(row["evidence_event_db_id"]),
            "rule_id": row.get("rule_id"),
            "rule_version": row.get("rule_version"),
            "summary": row.get("summary"),
        }
        for row in rows
        if row.get("evidence_event_db_id") is not None
    ]


def _entity_detail_event_item(item: dict[str, _src.Any]) -> dict[str, _src.Any]:
    """Expose only navigation and attribution fields, never raw payload."""
    projection = str(item.get("_field_projection") or "full")
    result = {
        "event_db_id": int(item["event_db_id"]),
        "server": item.get("server"),
        "channel": item.get("channel"),
    }
    if projection in {"full", "security_metadata"}:
        event_id = int(item.get("event_id") or 0)
        result.update({
            "event_id": event_id,
            "label": _src.windows_event_label(event_id, "ru") or f"Event ID {event_id}",
            "time_utc": item.get("time_created_utc"),
        })
    if projection in {"full", "technical"}:
        result.update({
            "provider_name": item.get("provider_name"),
            "link_role": str(item.get("link_role") or "context"),
            "confidence": float(item.get("confidence") or 0.0),
        })
    if projection == "full":
        result.update({
            "actor": item.get("subject_user_name"),
            "target": item.get("target_user_name"),
        })
    return result


def _detail_timeline_source(item: dict[str, _src.Any], inclusion_reason: str) -> dict[str, _src.Any]:
    card = _src.build_event_card(item)
    known = bool(card.get("known"))
    return {
        **item,
        "event_db_id": _src._exact_event_db_id(item),
        "time": item.get("time_created_utc"),
        "label": card.get("title") if known else f"Event ID {item.get('event_id') or '—'}",
        "category": card.get("category") if known else _src.normalize_category(item.get("category"), known=False),
        "severity": card.get("final_risk") if known else _src.normalize_risk(item.get("severity")),
        "summary": card.get("summary") if known else None,
        "inclusion_reason": inclusion_reason,
    }


def _metadata_timeline_source(item: dict[str, _src.Any], inclusion_reason: str) -> dict[str, _src.Any]:
    """Build an entity-history item from retained V2 metadata, never archive payload."""
    event_id = int(item.get("event_id") or 0)
    descriptor = _src._exact_event_catalog_descriptor(item)
    return {
        **item,
        "_metadata_only": True,
        "event_db_id": _src._exact_event_db_id(item),
        "time": item.get("time_created_utc"),
        "label": str(descriptor.get("title") if descriptor else f"Event ID {event_id}"),
        "title_code": (
            f"{descriptor.get('channel') or ''}:{descriptor.get('provider_name') or ''}:{event_id}.title"
            if descriptor else None
        ),
        "category": _src.normalize_category(descriptor.get("category"), known=True) if descriptor else "unknown",
        # Metadata demonstrates the exact observed event and its catalogue
        # descriptor, not a contextual risk assessment from unavailable payload.
        "severity": "unknown",
        "summary": None,
        "actor": item.get("subject_user_name"),
        "target": item.get("target_user_name"),
        "source": None,
        "catalogued": descriptor is not None,
        "inclusion_reason": inclusion_reason,
    }


def _exact_event_catalog_descriptor(item: _src.Mapping[str, _src.Any]) -> dict[str, _src.Any] | None:
    """Return only a descriptor bound to this event's provider/channel identity."""
    try:
        event_id = int(item.get("event_id") or 0)
    except (TypeError, ValueError):
        return None
    channel = str(item.get("channel") or "").strip()
    provider = str(item.get("provider_name") or "").strip()
    if event_id <= 0 or not channel or not provider:
        return None
    descriptor = _src.lookup_event_catalog(event_id, channel, provider)
    if not descriptor:
        return None
    if (
        str(descriptor.get("channel") or "").strip().casefold() != channel.casefold()
        or str(descriptor.get("provider_name") or "").strip().casefold() != provider.casefold()
        or str(descriptor.get("stream") or "").strip().casefold() != channel.casefold()
        or not str(descriptor.get("source") or "").strip()
    ):
        return None
    return descriptor
