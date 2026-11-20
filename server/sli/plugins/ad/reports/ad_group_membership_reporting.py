from __future__ import annotations

"""Bounded, evidence-first AD group-membership observations on DCs."""

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from server.sli.access.access_control_v4 import capability_decision_for_resource_groups
from server.sli.reporting.reporting_common import (
    build_domain_resource_groups,
    clean_sid,
    clean_text,
    format_iso,
    get_runtime_connection,
    parse_utc,
    sanitize_public,
)
from server.sli.core.time_contract import TimeRangeError, normalize_utc_range
from server.sli.core.time_format import parse_event_time
from server.source_packs.windows_ad_dc import (
    AD_GROUP_MEMBERSHIP_EVENT_IDS,
    group_membership_change,
)


CONTRACT_ID = "sli.ad-group-membership-history.v1"
REPORT_KEY = "ad.groups.membership_changes"
EVENT_VIEW_CAPABILITY = "events.view"
SECURITY_CHANNEL = "Security"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
MAX_PERIOD_DAYS = 31
MAX_HISTORY_ROWS = 500
DEFAULT_HISTORY_ROWS = 200


_utc = parse_utc
_iso = format_iso
_text = clean_text
_sid = clean_sid
_public = sanitize_public
_domain_resource_groups = build_domain_resource_groups


def _observed_principal(event: Mapping[str, Any], *, sid_key: str, name_key: str) -> dict[str, Any]:
    sid = _sid(event.get(sid_key))
    name = _text(event.get(name_key))
    if sid is None and name is None:
        return {"state": "unknown"}
    return {"state": "observed", "sid": sid, "name": name}


def _controlled_group(event: Mapping[str, Any]) -> dict[str, Any]:
    group_sid = _sid(event.get("target_user_sid"))
    context_evidence_id = event.get("controlled_group_context_evidence_id")
    context_observed_at = _utc(event.get("controlled_group_context_observed_at_utc"))
    if group_sid is None:
        return {"state": "unknown", "reason": "group_sid_not_observed"}
    if context_evidence_id is None or context_observed_at is None:
        return {
            "state": "unknown",
            "reason": "group_not_observed_in_controlled_privileged_context",
        }
    return {
        "state": "observed",
        "basis": "exact_group_sid_in_persisted_controlled_scope",
        "context_evidence_id": int(context_evidence_id),
        "context_observed_at_utc": _iso(context_observed_at),
    }


def _interval_reference(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "event_db_id": item["event_db_id"],
        "event_id": item["event_id"],
        "time_created_utc": item["time_created_utc"],
    }


def _observation_order(item: Mapping[str, Any]) -> tuple[str, int]:
    return item["time_created_utc"], int(item["event_db_id"])


def _membership_key(item: Mapping[str, Any]) -> tuple[str, str] | None:
    member_sid = _text(item["member"].get("sid"))
    group_sid = _text(item["group"].get("sid"))
    if member_sid is None or group_sid is None:
        return None
    return member_sid.casefold(), group_sid.casefold()


def _unknown_interval(reason: str) -> dict[str, str]:
    return {"state": "unknown", "reason": reason}


def _collection_coverage(
    coverage: Mapping[str, Any], *, observed_event_count: int
) -> tuple[str, dict[str, Any]]:
    history_event_present = bool(coverage.get("history_event_present"))
    if observed_event_count < 0 or (observed_event_count and not history_event_present):
        raise ValueError("ad_group_membership_history_collection_coverage_invalid")
    state = (
        "available"
        if observed_event_count
        else "empty_unverified"
        if history_event_present
        else "not_collected"
    )
    return state, {
        "state": state,
        "history_event_present": history_event_present,
        "source_completeness": "not_proven",
    }


def compose_ad_group_membership_history(
    *,
    source_domain_id: int,
    period_start: datetime,
    period_end: datetime,
    events: Sequence[Mapping[str, Any]],
    collection_coverage: Mapping[str, Any],
) -> dict[str, Any]:
    """Compose observations without reconstructing a current group roster."""

    if not period_start.tzinfo or not period_end.tzinfo or period_start >= period_end:
        raise ValueError("ad_group_membership_history_period_invalid")
    if len(events) > MAX_HISTORY_ROWS:
        raise ValueError("ad_group_membership_history_input_bound_exceeded")
    clean_start = _utc(period_start)
    clean_end = _utc(period_end)
    assert clean_start is not None and clean_end is not None

    items: list[dict[str, Any]] = []
    seen_event_ids: set[int] = set()
    for event in events:
        event_id = int(event.get("event_id") or 0)
        change = group_membership_change(event_id)
        if event_id not in AD_GROUP_MEMBERSHIP_EVENT_IDS or change is None:
            raise ValueError("ad_group_membership_history_event_invalid")
        observed_at = _utc(event.get("time_created_utc"))
        if observed_at is None or not clean_start <= observed_at < clean_end:
            raise ValueError("ad_group_membership_history_event_outside_bounds")
        event_db_id = int(event.get("event_db_id") or 0)
        if event_db_id <= 0 or event_db_id in seen_event_ids:
            raise ValueError("ad_group_membership_history_event_identity_invalid")
        seen_event_ids.add(event_db_id)
        domain_controller = _text(event.get("domain_controller"))
        if domain_controller is None:
            raise ValueError("ad_group_membership_history_domain_controller_missing")
        operation, group_scope = change
        items.append(
            {
                "event_db_id": event_db_id,
                "event_record_id": event.get("event_record_id"),
                "event_id": event_id,
                "time_created_utc": _iso(observed_at),
                "domain_controller": domain_controller,
                "actor": _observed_principal(
                    event, sid_key="subject_user_sid", name_key="subject_user_name"
                ),
                "member": _observed_principal(
                    event, sid_key="membership_member_sid", name_key="membership_member_name"
                ),
                "group": _observed_principal(
                    event, sid_key="target_user_sid", name_key="target_user_name"
                ),
                "change": {"operation": operation, "group_scope": group_scope},
                "controlled_group": _controlled_group(event),
                "membership_interval": _unknown_interval("membership_identity_not_observed"),
                "evidence": {
                    "event_db_id": event_db_id,
                    "event_record_id": event.get("event_record_id"),
                    "source_core_sha256": _public(event.get("source_core_sha256")),
                    "source_facts_sha256": _public(event.get("source_facts_sha256")),
                },
            }
        )

    items.sort(key=lambda item: (item["time_created_utc"], item["event_db_id"]))
    grouped_items: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in items:
        key = _membership_key(item)
        if key is None:
            continue
        grouped_items.setdefault(key, []).append(item)

    for observations in grouped_items.values():
        additions = [item for item in observations if item["change"]["operation"] == "added"]
        removals = [item for item in observations if item["change"]["operation"] == "removed"]
        if len(additions) == len(removals) == 1 and _observation_order(additions[0]) < _observation_order(removals[0]):
            added, removed = additions[0], removals[0]
            interval = {
                "state": "closed_observed",
                "start": _interval_reference(added),
                "end": _interval_reference(removed),
            }
            added["membership_interval"] = interval
            removed["membership_interval"] = interval
        elif len(additions) == 1 and not removals:
            additions[0]["membership_interval"] = {
                "state": "open_observed",
                "reason": "matching_remove_not_observed_in_window",
            }
        elif not additions and len(removals) == 1:
            removals[0]["membership_interval"] = {
                "state": "partial",
                "reason": "membership_add_not_observed_in_window",
            }
        else:
            reason = (
                "exact_membership_boundaries_out_of_order"
                if len(additions) == len(removals) == 1
                else "multiple_exact_membership_boundaries_unpairable"
            )
            interval = {
                "state": "partial",
                "reason": reason,
            }
            for item in observations:
                item["membership_interval"] = interval

    state, public_coverage = _collection_coverage(
        collection_coverage, observed_event_count=len(items)
    )
    return {
        "contract_id": CONTRACT_ID,
        "report_key": REPORT_KEY,
        "source_domain_id": int(source_domain_id),
        "state": state,
        "history_state": "partial" if items else "unknown",
        "time_bounds": {"from_utc": _iso(clean_start), "to_utc_exclusive": _iso(clean_end)},
        "items": items,
        "collection_coverage": public_coverage,
        "limits": {"max_period_days": MAX_PERIOD_DAYS, "row_limit": MAX_HISTORY_ROWS, "bounded": True},
        "limitations": [
            "Rows are membership-change observations, not a reconstructed current group roster.",
            "A closed interval requires exactly one exact observed MemberSid and TargetSid add-before-remove pair; repeated or out-of-order boundaries remain unpaired partial observations.",
            "Controlled-group scope is observed separately and does not prove event-time rights or their use.",
            "Older facts without source-native MemberSid remain unknown; this reader does not backfill them.",
            "An empty window does not prove complete source coverage.",
        ],
    }


def get_ad_group_membership_history(
    access: Mapping[str, Any],
    *,
    source_domain_id: int,
    time_from: str | None,
    time_to: str | None,
    timezone_name: str = "UTC",
    limit: int = DEFAULT_HISTORY_ROWS,
) -> dict[str, Any]:
    """Read membership evidence only after a domain-scoped events.view grant."""

    domain_id = int(source_domain_id)
    if domain_id <= 0:
        raise ValueError("ad_group_membership_history_domain_invalid")
    if not time_from or not time_to:
        raise TimeRangeError("ad_group_membership_history_requires_time_bounds")
    start_raw, end_raw = normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
    period_start, period_end = _utc(start_raw), _utc(end_raw)
    if period_start is None or period_end is None or period_start >= period_end:
        raise TimeRangeError("empty_or_reversed_time_range")
    if period_end - period_start > timedelta(days=MAX_PERIOD_DAYS):
        raise TimeRangeError("ad_group_membership_history_period_too_wide")
    if not 1 <= int(limit) <= MAX_HISTORY_ROWS:
        raise ValueError("ad_group_membership_history_limit_invalid")
    if not capability_decision_for_resource_groups(
        access,
        EVENT_VIEW_CAPABILITY,
        resource_groups=_domain_resource_groups(domain_id),
    )["allowed"]:
        return {
            "contract_id": CONTRACT_ID,
            "report_key": REPORT_KEY,
            "source_domain_id": domain_id,
            "state": "not_authorized",
            "history_state": "unknown",
            "time_bounds": {"from_utc": _iso(period_start), "to_utc_exclusive": _iso(period_end)},
            "items": [],
            "limits": {"max_period_days": MAX_PERIOD_DAYS, "row_limit": int(limit), "bounded": True},
        }
    events, collection_coverage = _read_ad_group_membership_history_data(
        domain_id=domain_id, period_start=period_start, period_end=period_end, limit=int(limit)
    )
    return compose_ad_group_membership_history(
        source_domain_id=domain_id,
        period_start=period_start,
        period_end=period_end,
        events=events,
        collection_coverage=collection_coverage,
    )


def _read_ad_group_membership_history_data(
    *, domain_id: int, period_start: datetime, period_end: datetime, limit: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    event_ids = sorted(AD_GROUP_MEMBERSHIP_EVENT_IDS)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read, read only")
        cur.execute(
            """select event.id as event_db_id,event.event_record_id,event.event_id,
                      event.time_created_utc,server.hostname as domain_controller,
                      event.subject_user_sid,event.subject_user_name,
                      event.target_user_sid,event.target_user_name,
                      facts.membership_member_sid,facts.membership_member_name,
                      controlled.context_evidence_id as controlled_group_context_evidence_id,
                      controlled.context_observed_at_utc as controlled_group_context_observed_at_utc,
                      event.source_core_sha256,facts.source_facts_sha256
                 from events_v2_core event
                 join servers server on server.id=event.server_id
                 join storage_v2_channel channel on channel.id=event.channel_id
                 join storage_v2_provider provider on provider.id=event.provider_id
                 left join event_facts_v2 facts on facts.event_id=event.id
                 left join lateral (
                     select evidence.id as context_evidence_id,
                            context.last_observed_at_utc as context_observed_at_utc
                       from ad_context_entity_aliases alias
                       join ad_context_entity_versions context on context.entity_id=alias.entity_id
                       join ad_context_runs run on run.run_id=context.source_run_id
                       join ad_context_evidence evidence
                         on evidence.source_run_id=context.source_run_id
                        and evidence.locator_json->>'record_key'=context.attributes_json->>'record_key'
                      where alias.domain_id=event.domain_id
                        and alias.alias_type='object_sid'
                        and alias.normalized_value=lower(event.target_user_sid)
                        and context.source_section='privileged_membership'
                        and context.valid_to_utc is null
                        and run.status='completed'
                        and exists(
                            select 1
                              from jsonb_array_elements_text(
                                  coalesce(run.scope_json->'privileged_group_sids', '[]'::jsonb)
                              ) configured_group(sid)
                             where lower(configured_group.sid)=lower(event.target_user_sid)
                        )
                      order by context.last_observed_at_utc desc,evidence.id desc
                      limit 1
                 ) controlled on true
                where event.domain_id=%s and server.role='domain_controller'
                  and event.event_id=any(%s)
                  and channel.value=%s and provider.value=%s
                  and event.time_created_utc>=%s and event.time_created_utc<%s
                order by event.time_created_utc,event.id
                limit %s""",
            (domain_id, event_ids, SECURITY_CHANNEL, SECURITY_PROVIDER, period_start, period_end, limit + 1),
        )
        events = [dict(row) for row in cur.fetchall()]
        if len(events) > limit:
            raise ValueError("ad_group_membership_history_input_bound_exceeded")
        cur.execute(
            """select exists(
                       select 1
                         from events_v2_core history_event
                         join servers history_server on history_server.id=history_event.server_id
                         join storage_v2_channel history_channel on history_channel.id=history_event.channel_id
                         join storage_v2_provider history_provider on history_provider.id=history_event.provider_id
                        where history_event.domain_id=%s
                          and history_server.role='domain_controller'
                          and history_event.event_id=any(%s)
                          and history_channel.value=%s and history_provider.value=%s
                   ) as history_event_present""",
            (domain_id, event_ids, SECURITY_CHANNEL, SECURITY_PROVIDER),
        )
        collection_coverage = dict(cur.fetchone() or {})
    return events, collection_coverage


_connect = get_runtime_connection
