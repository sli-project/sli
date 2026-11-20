"""Split out of ``server.sli.plugins.remote_access.reports.vpn_connections_reporting`` (plan 7.2b).

Module-level names of ``vpn_connections_reporting`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

from psycopg.errors import QueryCanceled

from server.sli.core.database import QueryTimeoutError
from server.sli.reporting.read_timeout import remaining_read_ms
import server.sli.plugins.remote_access.reports.vpn_connections_reporting as _src


def compose_vpn_authorization_timeline(
    *,
    source_domain_id: int,
    period_start: _src.datetime,
    period_end: _src.datetime,
    events: _src.Sequence[_src.Mapping[str, _src.Any]],
    identities: _src.Mapping[int, _src.Mapping[str, _src.Any]],
    collection_coverage: _src.Mapping[str, _src.Any],
) -> dict[str, _src.Any]:
    """Publish bounded NPS authorization facts without an Accounting bridge."""

    if not period_start.tzinfo or not period_end.tzinfo or period_start >= period_end:
        raise ValueError("vpn_audit_authorization_timeline_time_bounds_invalid")
    if len(events) > _src.MAX_AUTHORIZATION_TIMELINE_ROWS:
        raise ValueError("vpn_audit_authorization_timeline_input_bound_exceeded")
    failed_event_count = sum(int(event.get("event_id") or 0) == 6273 for event in events)
    collection_state, public_collection_coverage = _src._authorization_timeline_collection_coverage(
        collection_coverage,
        failed_event_count=failed_event_count,
        observed_event_count=len(events),
    )
    items: list[dict[str, _src.Any]] = []
    for event in events:
        event_code = int(event.get("event_id") or 0)
        if event_code not in {6272, 6273}:
            raise ValueError("vpn_audit_authorization_timeline_event_invalid")
        observed_at = _src._utc(event.get("time_created_utc"))
        if observed_at is None or not period_start <= observed_at < period_end:
            raise ValueError("vpn_audit_authorization_timeline_event_outside_bounds")
        _, identity_state, identity = _src._failed_authorization_identity(event, identities)
        item = {
            "event_db_id": int(event["event_db_id"]),
            "event_record_id": event.get("event_record_id"),
            "event_id": event_code,
            "time_created_utc": _src._iso(observed_at),
            "authorization_result": "allowed" if event_code == 6272 else "denied",
            "identity_state": identity_state,
            "identity": identity,
            "source_core_sha256": _src._public(event.get("source_core_sha256")),
        }
        source_ip = str(event.get("source_ip") or "").strip()
        if source_ip:
            item["source_ip"] = source_ip
        correlation_id = str(event.get("correlation_id") or "").strip()
        if correlation_id:
            item["correlation_id"] = correlation_id
        if event_code == 6273:
            reason_code = str(event.get("reason_code") or "").strip()
            if reason_code:
                item["reason_code"] = reason_code
        items.append(item)
    items.sort(key=lambda item: (item["time_created_utc"], item["event_db_id"]))
    return {
        "contract_id": _src.AUTHORIZATION_TIMELINE_CONTRACT_ID,
        "report_key": _src.AUTHORIZATION_TIMELINE_REPORT_KEY,
        "source_domain_id": int(source_domain_id),
        "state": collection_state,
        "time_bounds": {
            "from_utc": _src._iso(period_start),
            "to_utc_exclusive": _src._iso(period_end),
        },
        "items": items,
        "collection_coverage": public_collection_coverage,
        "unavailable_reason": collection_coverage.get("unavailable_reason"),
        "result_window": {"truncated": bool(collection_coverage.get("truncated")),
                          "returned_event_count": len(items),
                          "display_limit": _src.MAX_AUTHORIZATION_TIMELINE_ROWS},
        "limits": {
            "input_event_limit": _src.MAX_AUTHORIZATION_TIMELINE_ROWS,
            "bounded": True,
        },
    }


def _read_vpn_authorization_timeline_data(
    *,
    domain_id: int,
    period_start: _src.datetime,
    period_end: _src.datetime,
    failed_only: bool = False,
) -> tuple[list[dict[str, _src.Any]], dict[int, dict[str, _src.Any]], dict[str, _src.Any]]:
    """Read the two NPS authorization facts and their bounded coverage evidence."""

    events = []
    identities = {}
    collection_coverage = {}
    try:
        with _src._connect() as conn, conn.cursor() as cur:
            cur.execute("set transaction isolation level repeatable read, read only")
            remaining_read_ms()
            cur.execute(
                """with selected_events as materialized (
                       select event.* from events_v2_core event
                       join storage_v2_channel channel on channel.id=event.channel_id
                       join storage_v2_provider provider on provider.id=event.provider_id
                       where event.domain_id=%s and event.event_id=any(%s)
                         and channel.value='Security' and provider.value='Microsoft-Windows-Security-Auditing'
                         and event.time_created_utc>=%s and event.time_created_utc<%s
                       order by event.time_created_utc,event.id limit %s
                   )
                   select event.id as event_db_id,event.event_record_id,event.event_id,
                          event.time_created_utc,event.subject_user_sid,
                          nullif(btrim(event.ip_address),'') as source_ip,event.correlation_id,
                          facts.result_code as reason_code,alias_resolution.alias_match_count,
                          alias_resolution.entity_id,event.source_core_sha256
                   from selected_events event
                   left join event_facts_v2 facts on facts.event_id=event.id
                   left join lateral (
                       select count(distinct alias.entity_id)::integer as alias_match_count,
                              case when count(distinct alias.entity_id)=1 then min(alias.entity_id) end as entity_id
                       from ad_context_entity_aliases alias
                       join entities_v2 alias_entity on alias_entity.id=alias.entity_id
                       where alias.domain_id=event.domain_id and alias.alias_type='object_sid'
                         and alias.normalized_value=lower(event.subject_user_sid)
                         and alias_entity.domain_id=event.domain_id and entity_v2_is_active(alias_entity.id)
                   ) alias_resolution on true
                   order by event.time_created_utc,event.id""",
                (domain_id, [6273] if failed_only else [6272, 6273], period_start, period_end,
                 _src.MAX_AUTHORIZATION_TIMELINE_ROWS + 1),
            )
            events = [dict(row) for row in cur.fetchall()]
            truncated = len(events) > _src.MAX_AUTHORIZATION_TIMELINE_ROWS
            collection_coverage["truncated"] = truncated
            events = events[:_src.MAX_AUTHORIZATION_TIMELINE_ROWS]
            remaining_read_ms()
            cur.execute(
                """select exists(
                              select 1 from events_v2_core history_event
                              join storage_v2_channel history_channel on history_channel.id=history_event.channel_id
                              join storage_v2_provider history_provider on history_provider.id=history_event.provider_id
                              where history_event.domain_id=%s and history_event.event_id in (6272,6273)
                                and history_channel.value='Security'
                                and history_provider.value='Microsoft-Windows-Security-Auditing'
                          ) as history_event_present,
                          count(*) filter (where event.event_id=6272) as window_success_6272_count,
                          count(*) filter (where event.event_id=6273) as window_failed_6273_count
                   from events_v2_core event
                   join storage_v2_channel channel on channel.id=event.channel_id
                   join storage_v2_provider provider on provider.id=event.provider_id
                   where event.domain_id=%s and event.event_id in (6272,6273)
                     and channel.value='Security' and provider.value='Microsoft-Windows-Security-Auditing'
                     and event.time_created_utc>=%s and event.time_created_utc<%s""",
                (domain_id, domain_id, period_start, period_end),
            )
            collection_coverage = {**dict(cur.fetchone() or {}), "truncated": truncated}
            entity_ids = sorted({int(row["entity_id"]) for row in events if row.get("alias_match_count") == 1 and row.get("entity_id") is not None})
            identities: dict[int, dict[str, _src.Any]] = {}
            if entity_ids:
                remaining_read_ms()
                cur.execute(
                    """select entity.id as entity_id,entity.display_name,domain_row.netbios_name,
                              account.attributes_json->'attributes'->>'sam_account_name' as sam_account_name,
                              account.attributes_json->'attributes'->>'department' as department
                       from entities_v2 entity join domains domain_row on domain_row.id=entity.domain_id
                       left join lateral (
                           select current.attributes_json from ad_context_entity_versions current
                           where current.entity_id=entity.id and current.source_section in ('directory_accounts','vpn_membership')
                             and current.valid_to_utc is null
                           order by case current.source_section when 'directory_accounts' then 0 else 1 end,
                                    current.last_observed_at_utc desc,current.id desc limit 1
                       ) account on true
                       where entity.id=any(%s) and entity.domain_id=%s and entity_v2_is_active(entity.id)""",
                    (entity_ids, domain_id),
                )
                identities = {int(row["entity_id"]): dict(row) for row in cur.fetchall()}
    except (QueryTimeoutError, QueryCanceled):
        # The connection context rolls back the canceled transaction first.
        # Keep only facts already fetched; missing counts never become zero.
        collection_coverage = {
            "history_event_present": True if events else None,
            "window_success_6272_count": None, "window_failed_6273_count": None,
            **collection_coverage, "read_incomplete": True,
            "unavailable_reason": "source_read_timeout",
        }
    return events, identities, collection_coverage


def get_vpn_authorization_timeline(
    access: _src.Mapping[str, _src.Any],
    *,
    source_domain_id: int,
    time_from: str | None,
    time_to: str | None,
    timezone_name: str = "UTC",
    failed_only: bool = False,
) -> dict[str, _src.Any]:
    """Read bounded, source-native NPS 6272/6273 authorization facts."""

    domain_id = int(source_domain_id)
    if domain_id <= 0:
        raise ValueError("vpn_audit_authorization_timeline_domain_invalid")
    if not time_from or not time_to:
        raise _src.TimeRangeError("vpn_audit_authorization_timeline_requires_time_bounds")
    start_raw, end_raw = _src.normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
    period_start, period_end = _src._utc(start_raw), _src._utc(end_raw)
    if period_start is None or period_end is None or period_start >= period_end:
        raise _src.TimeRangeError("empty_or_reversed_time_range")
    if period_end - period_start > _src.timedelta(days=_src.MAX_PERIOD_DAYS):
        raise _src.TimeRangeError("vpn_audit_authorization_timeline_period_too_wide")
    composition = _src.vpn_report_composition_decision(access, source_domain_id=domain_id, action="view")
    if not composition.sessions.allowed:
        return {
            "contract_id": _src.AUTHORIZATION_TIMELINE_CONTRACT_ID,
            "report_key": _src.AUTHORIZATION_TIMELINE_REPORT_KEY,
            "source_domain_id": domain_id,
            "state": "not_authorized",
            "time_bounds": {"from_utc": _src._iso(period_start), "to_utc_exclusive": _src._iso(period_end)},
            "items": [],
            "limits": {"input_event_limit": _src.MAX_AUTHORIZATION_TIMELINE_ROWS, "bounded": True},
        }
    events, identities, collection_coverage = _src._read_vpn_authorization_timeline_data(
        domain_id=domain_id, period_start=period_start, period_end=period_end,
        **({"failed_only": True} if failed_only else {}),
    )
    return _src.compose_vpn_authorization_timeline(
        source_domain_id=domain_id,
        period_start=period_start,
        period_end=period_end,
        events=events,
        identities=identities,
        collection_coverage=collection_coverage,
    )


def _authorization_timeline_collection_coverage(
    coverage: _src.Mapping[str, _src.Any],
    *,
    failed_event_count: int,
    observed_event_count: int,
) -> tuple[str, dict[str, _src.Any]]:
    """Describe timeline coverage without treating historical existence as a count.

    The bounded timeline reader asks only whether durable NPS history exists.
    That boolean proves neither its count nor source completeness, and must not
    be passed through the exact-count contract used by the 6273 series model.
    """

    if coverage.get("read_incomplete"):
        return "partial", {**coverage, "state": "partial", "source_completeness": "not_proven",
                           "freshness": "not_asserted", "empty_window_basis": None}
    history_event_present = bool(coverage.get("history_event_present"))
    window_success_6272_count = int(coverage.get("window_success_6272_count") or 0)
    window_failed_6273_count = int(coverage.get("window_failed_6273_count") or 0)
    clean_observed_event_count = int(observed_event_count)
    if min(
        window_success_6272_count,
        window_failed_6273_count,
        clean_observed_event_count,
    ) < 0:
        raise ValueError("vpn_audit_authorization_timeline_collection_coverage_invalid")
    if (window_failed_6273_count < failed_event_count
            or not coverage.get("truncated") and window_failed_6273_count != failed_event_count):
        raise ValueError("vpn_audit_authorization_timeline_collection_coverage_mismatch")
    if clean_observed_event_count and not history_event_present:
        raise ValueError("vpn_audit_authorization_timeline_collection_coverage_invalid")

    if clean_observed_event_count:
        state = "partial" if coverage.get("truncated") else "available"
        empty_window_basis = None
    elif not history_event_present:
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
        "history_event_present": history_event_present,
        "window_success_6272_count": window_success_6272_count,
        "window_failed_6273_count": window_failed_6273_count,
        "empty_window_basis": empty_window_basis,
        "source_completeness": "not_proven",
        "freshness": "not_asserted",
    }
