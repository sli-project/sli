"""Split out of ``server.sli.reports.security_event_reporting`` (plan 7.2b).

Module-level names of ``security_event_reporting`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.reports.security_event_reporting as _src


def security_event_filter_predicate(
    *, filters: _src.Mapping[str, _src.Any], target_identity_sql: str, target_name_sql: str,
    event_alias: str = "event", facts_alias: str = "facts", server_alias: str = "server",
    keywords_alias: str = "keywords",
) -> tuple[str, list[_src.Any]]:
    """Build only parameterized predicates over persisted core/warm fields."""

    clauses: list[str] = []
    params: list[_src.Any] = []
    category = filters.get("category")
    if category:
        clauses.append(f" and {event_alias}.event_id=any(%s)")
        params.append(sorted(_src.security_event_ids_for_family(category)))
    event_id = filters.get("event_id")
    if event_id is not None:
        clauses.append(f" and {event_alias}.event_id=%s")
        params.append(int(event_id))
    outcome = filters.get("outcome")
    if outcome == "success":
        clauses.append(
            f" and ({event_alias}.event_id=any(%s) or ({event_alias}.event_id=any(%s) "
            f"and (lower(coalesce({keywords_alias}.value,''))=any(%s) "
            f"or replace(lower(coalesce({keywords_alias}.value,'')),' ','') like '%%auditsuccess%%')))"
        )
        params.extend([
            sorted(_src.SECURITY_EVENTS_SUCCESS_EVENT_IDS),
            sorted(_src.SECURITY_EVENTS_MIXED_OUTCOME_EVENT_IDS),
            sorted(_src.SECURITY_AUDIT_SUCCESS_KEYWORDS),
        ])
    elif outcome == "failure":
        clauses.append(
            f" and ({event_alias}.event_id=any(%s) or ({event_alias}.event_id=any(%s) "
            f"and (lower(coalesce({keywords_alias}.value,''))=any(%s) "
            f"or replace(lower(coalesce({keywords_alias}.value,'')),' ','') like '%%auditfailure%%')))"
        )
        params.extend([
            sorted(_src.SECURITY_EVENTS_FAILURE_EVENT_IDS),
            sorted(_src.SECURITY_EVENTS_MIXED_OUTCOME_EVENT_IDS),
            sorted(_src.SECURITY_AUDIT_FAILURE_KEYWORDS),
        ])
    elif outcome == "unknown":
        known = sorted(
            _src.SECURITY_EVENTS_SUCCESS_EVENT_IDS
            | _src.SECURITY_EVENTS_FAILURE_EVENT_IDS
            | _src.SECURITY_EVENTS_MIXED_OUTCOME_EVENT_IDS
        )
        clauses.append(
            f" and (not {event_alias}.event_id=any(%s) or ({event_alias}.event_id=any(%s) "
            f"and lower(coalesce({keywords_alias}.value,''))<>all(%s) "
            f"and replace(lower(coalesce({keywords_alias}.value,'')),' ','') not like '%%auditsuccess%%' "
            f"and replace(lower(coalesce({keywords_alias}.value,'')),' ','') not like '%%auditfailure%%'))"
        )
        params.extend([
            known,
            sorted(_src.SECURITY_EVENTS_MIXED_OUTCOME_EVENT_IDS),
            sorted(_src.SECURITY_AUDIT_SUCCESS_KEYWORDS | _src.SECURITY_AUDIT_FAILURE_KEYWORDS),
        ])

    def identity_match(prefix: str, sid_sql: str, name_sql: str, value: _src.Any) -> None:
        if value is None:
            return
        clauses.append(" and (lower(coalesce(" + sid_sql + ",''))=lower(%s) or lower(coalesce(" + name_sql + ",''))=lower(%s))")
        params.extend([value, value])

    identity_match("actor", f"{event_alias}.subject_user_sid", f"{event_alias}.subject_user_name", filters.get("actor"))
    if filters.get("target_account") is not None:
        clauses.append(f" and not {event_alias}.event_id=any(%s)")
        params.append(sorted(_src.SECURITY_EVENTS_GROUP_EVENT_IDS))
    identity_match("target", target_identity_sql, target_name_sql, filters.get("target_account"))
    if filters.get("group") is not None:
        clauses.append(
            f" and {event_alias}.event_id=any(%s) and (lower(coalesce(" + target_identity_sql
            + ",''))=lower(%s) or lower(coalesce(" + target_name_sql + ",''))=lower(%s))"
        )
        params.extend([sorted(_src.SECURITY_EVENTS_GROUP_EVENT_IDS), filters["group"], filters["group"]])
    if filters.get("source_host") is not None:
        clauses.append(f" and lower({server_alias}.hostname)=lower(%s)")
        params.append(filters["source_host"])
    if filters.get("q") is not None:
        clauses.append(
            f" and concat_ws(' ',{event_alias}.subject_user_sid,{event_alias}.subject_user_name,"
            + target_identity_sql + "," + target_name_sql
            + f",{facts_alias}.membership_member_sid,{facts_alias}.membership_member_name,{server_alias}.hostname) ilike %s"
        )
        params.append("%" + str(filters["q"]).replace("%", "\\%").replace("_", "\\_") + "%")
    if filters.get("entity_id") is not None:
        entity_id = int(filters["entity_id"])

        def active_identity_match(sid_sql: str) -> str:
            return (
                "exists(select 1 from ad_context_entity_aliases alias "
                "join entities_v2 alias_entity on alias_entity.id=alias.entity_id "
                f"where alias.domain_id={event_alias}.domain_id and alias.alias_type='object_sid' "
                "and alias.normalized_value=lower(nullif(btrim(" + sid_sql + "),'')) "
                f"and alias.entity_id=%s and alias_entity.domain_id={event_alias}.domain_id "
                "and entity_v2_is_active(alias_entity.id))"
            )

        def canonical_link_match() -> str:
            return (
                "exists(select 1 from event_entity_link_blocks_v2 block "
                "join entities_v2 linked_entity on linked_entity.id=block.entity_id "
                "cross join lateral unnest(block.event_ids,block.role_ids) "
                "linked(event_id,role_id) "
                f"where linked_entity.domain_id={event_alias}.domain_id "
                "and block.entity_id=resolve_entity_identity_v2(%s) "
                "and entity_v2_is_active(block.entity_id) "
                f"and block.first_event_id<={event_alias}.id and block.last_event_id>={event_alias}.id "
                f"and linked.event_id={event_alias}.id)"
            )
        clauses.append(
            " and (" + " or ".join((
                active_identity_match(f"{event_alias}.subject_user_sid"),
                active_identity_match(target_identity_sql),
                active_identity_match(f"{facts_alias}.membership_member_sid"),
                canonical_link_match(),
            )) + ")"
        )
        params.extend([entity_id, entity_id, entity_id, entity_id])
    if filters.get("event_db_id") is not None:
        clauses.append(f" and {event_alias}.id=%s")
        params.append(int(filters["event_db_id"]))
    return "".join(clauses), params


def _resolve_security_event_entity_ids(
    cur: _src.Any, *, domain_id: int, events: _src.Sequence[dict[str, _src.Any]],
) -> None:
    """Attach only unique active exact-SID aliases for this already bounded page."""

    role_fields = (
        ("subject_user_sid", "actor_entity_id"),
        ("target_user_sid", "target_entity_id"),
        ("membership_member_sid", "member_entity_id"),
    )
    sids = {
        sid
        for event in events
        for sid in (_src._normalized_object_sid(event.get(sid_key)) for sid_key, _ in role_fields)
        if sid is not None
    }
    for event in events:
        for _sid_key, entity_id_key in role_fields:
            event[entity_id_key] = None
    if not sids:
        return
    cur.execute(
        """select alias.normalized_value,alias.entity_id
              from ad_context_entity_aliases alias
              join entities_v2 alias_entity on alias_entity.id=alias.entity_id
             where alias.domain_id=%s and alias.alias_type='object_sid'
               and alias.normalized_value=any(%s)
               and alias_entity.domain_id=alias.domain_id
               and entity_v2_is_active(alias.entity_id)""",
        [domain_id, sorted(sids)],
    )
    candidate_ids: dict[str, set[int]] = {}
    for row in cur.fetchall():
        sid = _src._normalized_object_sid(row.get("normalized_value"))
        entity_id = row.get("entity_id")
        if sid not in sids or entity_id is None:
            continue
        candidate_ids.setdefault(sid, set()).add(int(entity_id))
    resolved_ids = {
        sid: next(iter(entity_ids))
        for sid, entity_ids in candidate_ids.items()
        if len(entity_ids) == 1
    }
    for event in events:
        for sid_key, entity_id_key in role_fields:
            entity_id = resolved_ids.get(_src._normalized_object_sid(event.get(sid_key)))
            if entity_id is not None:
                event[entity_id_key] = entity_id


def security_event_read_contract(
    filters: _src.Mapping[str, _src.Any], *,
    event_alias: str = "event", facts_alias: str = "facts", server_alias: str = "server",
    keywords_alias: str = "keywords", provider_alias: str = "provider",
) -> tuple[list[int], str, list[_src.Any], str, str, str, list[_src.Any]]:
    event_ids = _src._query_event_ids(filters)
    provider_predicate = (
        f"(({event_alias}.event_id=%s and {provider_alias}.value=%s) "
        f"or ({event_alias}.event_id<>%s and {provider_alias}.value=%s))"
    )
    provider_params = [
        _src.SECURITY_EVENTS_EVENTLOG_EVENT_ID,
        _src.EVENTLOG_PROVIDER,
        _src.SECURITY_EVENTS_EVENTLOG_EVENT_ID,
        _src.SECURITY_AUDITING_PROVIDER,
    ]
    target_identity_sql = (
        f"coalesce(nullif(btrim({event_alias}.target_user_sid),''),nullif(btrim({facts_alias}.account_target_sid),''))"
    )
    target_name_sql = (
        f"coalesce(nullif(btrim({event_alias}.target_user_name),''),nullif(btrim({facts_alias}.account_target_name),''))"
    )
    filter_sql, filter_params = _src.security_event_filter_predicate(
        filters=filters,
        target_identity_sql=target_identity_sql,
        target_name_sql=target_name_sql,
        event_alias=event_alias, facts_alias=facts_alias, server_alias=server_alias,
        keywords_alias=keywords_alias,
    )
    return (
        event_ids, provider_predicate, provider_params,
        target_identity_sql, target_name_sql, filter_sql, filter_params,
    )


def _query_event_ids(filters: _src.Mapping[str, _src.Any]) -> list[int]:
    """Return the bounded source IDs for this report request.

    All source-owned categories are included unless the request selects a
    category or exact Event ID. Selectors remain part of the cursor binding.
    """

    event_id = filters.get("event_id")
    if event_id is not None:
        return [int(event_id)]
    category = _src._text(filters.get("category"))
    if category is not None:
        return sorted(_src.security_event_ids_for_family(category))
    return sorted(_src.SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS)
