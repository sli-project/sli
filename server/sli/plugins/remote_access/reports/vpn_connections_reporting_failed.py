"""Split out of ``server.sli.plugins.remote_access.reports.vpn_connections_reporting`` (plan 7.2b).

Module-level names of ``vpn_connections_reporting`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.plugins.remote_access.reports.vpn_connections_reporting as _src


def compose_vpn_failed_authorization_series(
    *,
    source_domain_id: int,
    period_start: _src.datetime,
    period_end: _src.datetime,
    events: _src.Sequence[_src.Mapping[str, _src.Any]],
    identities: _src.Mapping[int, _src.Mapping[str, _src.Any]],
    collection_coverage: _src.Mapping[str, _src.Any],
    event_reference_limit: int = _src.MAX_FAILED_AUTHORIZATION_EVENT_REFERENCES,
) -> dict[str, _src.Any]:
    """Represent bounded, observed NPS denial repetitions without detection.

    A series exists only when one exact observed/canonical identity and one
    nonempty ``events_v2_core.ip_address`` are both present.  Missing source
    or identity evidence remains a one-event item rather than an invented
    common bucket.
    """

    if not period_start.tzinfo or not period_end.tzinfo or period_start >= period_end:
        raise ValueError("vpn_audit_failed_authorization_time_bounds_invalid")
    if len(events) > _src.MAX_FAILED_EVENT_ROWS:
        raise ValueError("vpn_audit_failed_authorization_input_bound_exceeded")
    clean_reference_limit = int(event_reference_limit)
    if not 1 <= clean_reference_limit <= _src.MAX_FAILED_AUTHORIZATION_EVENT_REFERENCES:
        raise ValueError("vpn_audit_failed_authorization_reference_limit_invalid")
    collection_state, public_collection_coverage = _src._failed_authorization_collection_coverage(
        collection_coverage,
        failed_event_count=len(events),
    )

    time_bounds = {
        "from_utc": _src._iso(period_start),
        "to_utc_exclusive": _src._iso(period_end),
    }
    grouped: dict[tuple[str, ...], list[dict[str, _src.Any]]] = {}
    for event in events:
        if int(event.get("event_id") or 0) != 6273:
            raise ValueError("vpn_audit_failed_authorization_event_invalid")
        observed_at = _src._utc(event.get("time_created_utc"))
        if observed_at is None or not period_start <= observed_at < period_end:
            raise ValueError("vpn_audit_failed_authorization_event_outside_bounds")
        identity_key, identity_state, identity = _src._failed_authorization_identity(
            event,
            identities,
        )
        source_ip = str(event.get("source_ip") or "").strip() or None
        source_state = "available" if source_ip else "unavailable"
        event_id = int(event["event_db_id"])
        if identity_key is not None and source_ip is not None:
            group_key = ("series", identity_key, source_ip)
            series_state = "grouped"
        else:
            group_key = ("single_event", str(event_id))
            series_state = "single_event_unattributed"
        grouped.setdefault(group_key, []).append({
            "event_db_id": event_id,
            "event_record_id": event.get("event_record_id"),
            "event_id": 6273,
            "time_created_utc": observed_at,
            "identity_state": identity_state,
            "identity": identity,
            "source_state": source_state,
            "source_ip": source_ip,
            "reason_code": str(event.get("reason_code") or "").strip() or None,
            "source_core_sha256": event.get("source_core_sha256"),
            "series_state": series_state,
        })
    if len(grouped) > _src.MAX_FAILED_AUTHORIZATION_SERIES:
        raise ValueError("vpn_audit_failed_authorization_series_bound_exceeded")

    items: list[dict[str, _src.Any]] = []
    for events_in_series in grouped.values():
        ordered = sorted(
            events_in_series,
            key=lambda item: (
                item["time_created_utc"],
                item["event_db_id"],
            ),
        )
        first = ordered[0]
        reason_codes = sorted({
            str(item["reason_code"])
            for item in ordered
            if item["reason_code"] is not None
        })
        references = [
            {
                "event_db_id": item["event_db_id"],
                "event_record_id": item["event_record_id"],
                "event_id": 6273,
                "time_created_utc": _src._iso(item["time_created_utc"]),
                "source_core_sha256": _src._public(item["source_core_sha256"]),
            }
            for item in ordered[:clean_reference_limit]
        ]
        items.append({
            "series_state": first["series_state"],
            "event_id": 6273,
            "identity_state": first["identity_state"],
            "identity": first["identity"],
            "source_state": first["source_state"],
            "source_ip": first["source_ip"],
            "count": len(ordered),
            "first_failed_at_utc": _src._iso(ordered[0]["time_created_utc"]),
            "last_failed_at_utc": _src._iso(ordered[-1]["time_created_utc"]),
            "time_bounds": time_bounds,
            "reason_codes": reason_codes[:_src.MAX_FAILED_AUTHORIZATION_REASON_CODES],
            "reason_codes_truncated": len(reason_codes) > _src.MAX_FAILED_AUTHORIZATION_REASON_CODES,
            "event_references": references,
            "event_references_truncated": len(ordered) > clean_reference_limit,
        })
    items.sort(key=lambda item: (
        item["last_failed_at_utc"],
        item["first_failed_at_utc"],
        item["source_ip"] or "",
        str(item["identity"]),
    ), reverse=True)
    return {
        "contract_id": _src.FAILED_AUTHORIZATION_SERIES_CONTRACT_ID,
        "report_key": _src.FAILED_AUTHORIZATION_SERIES_REPORT_KEY,
        "source_domain_id": int(source_domain_id),
        "state": collection_state,
        "time_bounds": time_bounds,
        "items": items,
        "collection_coverage": public_collection_coverage,
        "limits": {
            "input_event_limit": _src.MAX_FAILED_EVENT_ROWS,
            "series_limit": _src.MAX_FAILED_AUTHORIZATION_SERIES,
            "event_reference_limit": clean_reference_limit,
            "bounded": True,
        },
    }


def _read_vpn_failed_authorization_series_data(
    *,
    domain_id: int,
    period_start: _src.datetime,
    period_end: _src.datetime,
) -> tuple[list[dict[str, _src.Any]], dict[int, dict[str, _src.Any]], dict[str, _src.Any]]:
    """Read exact NPS 6273 facts, aliases, and bounded collection evidence."""

    with _src._connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read, read only")
        cur.execute(
            """select event.id as event_db_id,event.event_record_id,
                      event.event_id,event.time_created_utc,
                      event.subject_user_sid,
                      nullif(btrim(event.ip_address),'') as source_ip,
                      facts.result_code as reason_code,
                      alias_resolution.alias_match_count,
                      alias_resolution.entity_id,event.source_core_sha256
               from events_v2_core event
               join storage_v2_channel channel on channel.id=event.channel_id
               join storage_v2_provider provider on provider.id=event.provider_id
               left join event_facts_v2 facts on facts.event_id=event.id
               left join lateral (
                   select count(distinct alias.entity_id)::integer as alias_match_count,
                          case when count(distinct alias.entity_id)=1
                               then min(alias.entity_id) end as entity_id
                   from ad_context_entity_aliases alias
                   join entities_v2 alias_entity on alias_entity.id=alias.entity_id
                   where alias.domain_id=event.domain_id
                     and alias.alias_type='object_sid'
                     and alias.normalized_value=lower(event.subject_user_sid)
                     and alias_entity.domain_id=event.domain_id
                     and entity_v2_is_active(alias_entity.id)
               ) alias_resolution on true
               where event.domain_id=%s and event.event_id=6273
                 and channel.value='Security'
                 and provider.value='Microsoft-Windows-Security-Auditing'
                 and event.time_created_utc>=%s and event.time_created_utc<%s
               order by event.time_created_utc,event.id
               limit %s""",
            (domain_id, period_start, period_end, _src.MAX_FAILED_EVENT_ROWS + 1),
        )
        events = [dict(row) for row in cur.fetchall()]
        if len(events) > _src.MAX_FAILED_EVENT_ROWS:
            raise ValueError("vpn_audit_failed_authorization_input_bound_exceeded")
        # Event 6272 is only a durable NPS collection witness for an otherwise
        # empty bounded 6273 result. It is never returned as a series item and
        # is not linked to an Accounting session.
        cur.execute(
            """select count(*) as history_event_count,
                      count(*) filter (
                          where event.event_id=6272
                            and event.time_created_utc>=%s
                            and event.time_created_utc<%s
                      ) as window_success_6272_count,
                      count(*) filter (
                          where event.event_id=6273
                            and event.time_created_utc>=%s
                            and event.time_created_utc<%s
                      ) as window_failed_6273_count
               from events_v2_core event
               join storage_v2_channel channel on channel.id=event.channel_id
               join storage_v2_provider provider on provider.id=event.provider_id
               where event.domain_id=%s and event.event_id in (6272,6273)
                 and channel.value='Security'
                 and provider.value='Microsoft-Windows-Security-Auditing'""",
            (period_start, period_end, period_start, period_end, domain_id),
        )
        collection_coverage = dict(cur.fetchone() or {})
        entity_ids = sorted({
            int(row["entity_id"])
            for row in events
            if row.get("alias_match_count") == 1
            and row.get("entity_id") is not None
        })
        identities: dict[int, dict[str, _src.Any]] = {}
        if entity_ids:
            cur.execute(
                """select entity.id as entity_id,entity.display_name,
                          domain_row.netbios_name,
                          account.attributes_json->'attributes'->>'sam_account_name' as sam_account_name,
                          account.attributes_json->'attributes'->>'department' as department,
                          case when account.attributes_json->'attributes'->>'enabled' in ('true','false')
                               then (account.attributes_json->'attributes'->>'enabled')::boolean end as enabled,
                          account.attributes_json->'attributes'->>'last_logon_utc' as last_logon_utc,
                          exists(select 1 from ad_context_relation_versions privileged
                                 where privileged.source_entity_id=entity.id
                                   and privileged.valid_to_utc is null
                                   and privileged.relation_kind='member_of'
                                   and privileged.source_section='privileged_membership') as privileged
                   from entities_v2 entity
                   join domains domain_row on domain_row.id=entity.domain_id
                   left join lateral (
                       select current.attributes_json
                       from ad_context_entity_versions current
                       where current.entity_id=entity.id
                         and current.source_section in ('directory_accounts','vpn_membership')
                         and current.valid_to_utc is null
                       order by case current.source_section when 'directory_accounts' then 0 else 1 end,
                                current.last_observed_at_utc desc,current.id desc
                       limit 1
                   ) account on true
                   where entity.id=any(%s) and entity.domain_id=%s
                     and entity_v2_is_active(entity.id)""",
                (entity_ids, domain_id),
            )
            identities = {
                int(row["entity_id"]): dict(row)
                for row in cur.fetchall()
            }
    return events, identities, collection_coverage


def get_vpn_failed_authorization_series(
    access: _src.Mapping[str, _src.Any],
    *,
    source_domain_id: int,
    time_from: str | None,
    time_to: str | None,
    timezone_name: str = "UTC",
) -> dict[str, _src.Any]:
    """Read bounded NPS 6273 repetitions within the ``vpn.audit`` boundary."""

    domain_id = int(source_domain_id)
    if domain_id <= 0:
        raise ValueError("vpn_audit_failed_authorization_domain_invalid")
    if not time_from or not time_to:
        raise _src.TimeRangeError("vpn_audit_failed_authorization_requires_time_bounds")
    start_raw, end_raw = _src.normalize_utc_range(
        time_from,
        time_to,
        timezone_name=timezone_name,
    )
    period_start, period_end = _src._utc(start_raw), _src._utc(end_raw)
    if period_start is None or period_end is None or period_start >= period_end:
        raise _src.TimeRangeError("empty_or_reversed_time_range")
    if period_end - period_start > _src.timedelta(days=_src.MAX_PERIOD_DAYS):
        raise _src.TimeRangeError("vpn_audit_failed_authorization_period_too_wide")
    composition = _src.vpn_report_composition_decision(
        access,
        source_domain_id=domain_id,
        action="view",
    )
    if not composition.sessions.allowed:
        return {
            "contract_id": _src.FAILED_AUTHORIZATION_SERIES_CONTRACT_ID,
            "report_key": _src.FAILED_AUTHORIZATION_SERIES_REPORT_KEY,
            "source_domain_id": domain_id,
            "state": "not_authorized",
            "time_bounds": {
                "from_utc": _src._iso(period_start),
                "to_utc_exclusive": _src._iso(period_end),
            },
            "items": [],
            "limits": {
                "input_event_limit": _src.MAX_FAILED_EVENT_ROWS,
                "series_limit": _src.MAX_FAILED_AUTHORIZATION_SERIES,
                "event_reference_limit": _src.MAX_FAILED_AUTHORIZATION_EVENT_REFERENCES,
                "bounded": True,
            },
        }
    events, identities, collection_coverage = _src._read_vpn_failed_authorization_series_data(
        domain_id=domain_id,
        period_start=period_start,
        period_end=period_end,
    )
    return _src.compose_vpn_failed_authorization_series(
        source_domain_id=domain_id,
        period_start=period_start,
        period_end=period_end,
        events=events,
        identities=identities,
        collection_coverage=collection_coverage,
    )


def _failed_authorization_collection_coverage(
    coverage: _src.Mapping[str, _src.Any],
    *,
    failed_event_count: int,
    observed_event_count: int | None = None,
) -> tuple[str, dict[str, _src.Any]]:
    """Describe only durable NPS facts that bound an empty 6273 result.

    A matching 6272 proves an NPS event was durably observed in the requested
    window, but it does not establish collection freshness or uninterrupted
    source coverage. Historical NPS evidence without that window witness is
    deliberately left unverified rather than reported as an empty result.
    """

    history_event_count = int(coverage.get("history_event_count") or 0)
    window_success_6272_count = int(coverage.get("window_success_6272_count") or 0)
    window_failed_6273_count = int(coverage.get("window_failed_6273_count") or 0)
    if min(
        history_event_count,
        window_success_6272_count,
        window_failed_6273_count,
    ) < 0:
        raise ValueError("vpn_audit_failed_authorization_collection_coverage_invalid")
    if window_failed_6273_count != failed_event_count:
        raise ValueError("vpn_audit_failed_authorization_collection_coverage_mismatch")
    if history_event_count < window_success_6272_count + window_failed_6273_count:
        raise ValueError("vpn_audit_failed_authorization_collection_coverage_invalid")

    clean_observed_event_count = failed_event_count if observed_event_count is None else int(observed_event_count)
    if clean_observed_event_count < 0:
        raise ValueError("vpn_audit_failed_authorization_collection_coverage_invalid")
    if clean_observed_event_count:
        state = "available"
        empty_window_basis = None
    elif history_event_count == 0:
        state = "not_collected"
        empty_window_basis = None
    elif window_success_6272_count:
        state = "empty_unverified"
        empty_window_basis = "durable_6272_nps_event"
    else:
        state = "coverage_unverified"
        empty_window_basis = None
    return state, {
        "state": state,
        "history_event_count": history_event_count,
        "window_success_6272_count": window_success_6272_count,
        "window_failed_6273_count": window_failed_6273_count,
        "empty_window_basis": empty_window_basis,
        "source_completeness": "not_proven",
        "freshness": "not_asserted",
    }


def _failed_authorization_identity(
    event: _src.Mapping[str, _src.Any],
    identities: _src.Mapping[int, _src.Mapping[str, _src.Any]],
) -> tuple[str | None, str, dict[str, _src.Any]]:
    alias_match_count = int(event.get("alias_match_count") or 0)
    entity_id = int(event["entity_id"]) if event.get("entity_id") is not None else None
    if alias_match_count == 1 and entity_id is not None:
        identity = _src._identity_for(identities, entity_id)
        return (
            f"canonical_entity:{entity_id}",
            "resolved",
            {
                "entity_id": entity_id,
                "display_name": identity["display_name"],
                "account_name": identity["account_name"],
                "department": identity["department"],
            },
        )
    observed_sid = str(event.get("subject_user_sid") or "").strip() or None
    if observed_sid is not None:
        state = "ambiguous" if alias_match_count > 1 else "unresolved"
        return (
            f"observed_subject_sid:{observed_sid}",
            state,
            {
                "entity_id": None,
                "observed_subject_sid": observed_sid,
            },
        )
    return (
        None,
        "unresolved",
        {
            "entity_id": None,
            "observed_subject_sid": None,
        },
    )


def _failed_rows(
    events: _src.Sequence[_src.Mapping[str, _src.Any]],
    identities: _src.Mapping[int, _src.Mapping[str, _src.Any]],
) -> list[dict[str, _src.Any]]:
    result: list[dict[str, _src.Any]] = []
    for event in events:
        if int(event.get("event_id") or 0) != 6273:
            continue
        entity_id = int(event["entity_id"]) if event.get("entity_id") is not None else None
        identity = _src._identity_for(identities, entity_id)
        domain = str(event.get("subject_domain_name") or "").strip()
        username = str(event.get("subject_user_name") or "").strip()
        observed_account = "\\".join(part for part in (domain, username) if part) or "Не определено"
        result.append({
            "event_db_id": int(event["event_db_id"]),
            "event_record_id": event.get("event_record_id"),
            "event_id": 6273,
            "time_created_utc": _src._public(event.get("time_created_utc")),
            "entity_id": entity_id,
            "display_name": identity["display_name"] if entity_id is not None else "Не определено",
            "account_name": identity["account_name"] if entity_id is not None else observed_account,
            "department": identity["department"] if entity_id is not None else "Не определено",
            "identity_state": "resolved" if entity_id is not None else "unresolved",
            "reason_code": str(event.get("reason_code") or "Не определён"),
            "reason_text": None,
            "source_core_sha256": _src._public(event.get("source_core_sha256")),
        })
    return result
