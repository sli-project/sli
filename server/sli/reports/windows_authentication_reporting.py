from __future__ import annotations

"""Bounded, source-native Windows authentication facts for ``vpn.audit``."""

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from psycopg.errors import QueryCanceled

from server.sli.core.database import QueryTimeoutError
from server.sli.reporting.read_timeout import remaining_read_ms

from server.sli.access.access_control_v4 import (
    capability_decision_for_resource_groups,
    report_action_decision,
)
from server.sli.reporting.reporting_common import (
    build_domain_resource_groups,
    clean_text,
    format_iso,
    get_runtime_connection,
    parse_utc,
    sanitize_public,
)
from server.sli.core.time_contract import TimeRangeError, normalize_utc_range
from server.sli.core.time_format import parse_event_time
from server.sli.core.platform_settings import get_setting
from server.source_packs.windows_ad_dc import (
    WINDOWS_AUTHENTICATION_REPORT_EVENT_IDS,
    WINDOWS_AUTHENTICATION_REPORT_FAILURE_EVENT_IDS,
    WINDOWS_AUTHENTICATION_REPORT_MIXED_RESULT_EVENT_IDS,
    WINDOWS_AUTHENTICATION_REPORT_SUBJECT_PRINCIPAL_EVENT_IDS,
    WINDOWS_AUTHENTICATION_REPORT_SUCCESS_EVENT_ID,
)


CONTRACT_ID = "sli.vpn-audit-windows-authentication.v1"
REPORT_KEY = "vpn.audit"
EVENT_VIEW_CAPABILITY = "events.view"
SECURITY_CHANNEL = "Security"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
EVENT_FACTS = dict(zip(
    sorted(WINDOWS_AUTHENTICATION_REPORT_EVENT_IDS),
    (
        "observed_successful_logon", "observed_failed_logon", "observed_logoff",
        "observed_user_initiated_logoff", "observed_explicit_credentials",
        "observed_special_privileges", "observed_kerberos_as_request",
        "observed_kerberos_service_ticket", "observed_kerberos_ticket_renewal",
        "observed_kerberos_preauth_failure",
        "observed_kerberos_service_ticket_failure",
        "observed_credential_validation",
    ),
))
MAX_PERIOD_DAYS = 90
MAX_HISTORY_ROWS = 500
DEFAULT_HISTORY_ROWS = 200
DISCOVERY_BATCH_LIMIT = 256
DISCOVERY_SCAN_LIMIT = 10_000
MANUAL_REVIEW_WINDOW = timedelta(minutes=15)
MANUAL_REVIEW_MIN_FAILURES = 5
MANUAL_REVIEW_MIN_TARGET_SIDS = 3
MAX_REVIEW_SIGNALS = 100
MAX_REVIEW_INPUT_ROWS = 100_000
_MIXED_RESULT_EVENT_IDS = WINDOWS_AUTHENTICATION_REPORT_MIXED_RESULT_EVENT_IDS
_ZERO_RESULT_CODES = frozenset({"0", "0x0", "0x00000000", "00000000"})
_SUBJECT_PRINCIPAL_EVENT_IDS = WINDOWS_AUTHENTICATION_REPORT_SUBJECT_PRINCIPAL_EVENT_IDS


_utc = parse_utc
_iso = format_iso
_text = clean_text
_public = sanitize_public
_domain_resource_groups = build_domain_resource_groups


def _observed_or_unknown(**values: str | None) -> dict[str, Any]:
    observed = {key: value for key, value in values.items() if value is not None}
    return {"state": "observed", **observed} if observed else {"state": "unknown"}


def _read_access_allowed(access: Mapping[str, Any], domain_id: int) -> bool:
    resource_groups = _domain_resource_groups(domain_id)
    return bool(
        report_action_decision(
            access, REPORT_KEY, "view", resource_groups=resource_groups
        )["allowed"]
        and capability_decision_for_resource_groups(
            access, EVENT_VIEW_CAPABILITY, resource_groups=resource_groups
        )["allowed"]
    )


def get_windows_authentication_sources(access: Mapping[str, Any]) -> dict[str, Any]:
    """Discover only DC Security domains approved for both read boundaries."""

    discovered_domain_count = 0
    authorized_domain_count = 0
    authorized: list[dict[str, int]] = []
    after_domain_id = 0
    while len(authorized) <= 100:
        domains = _read_windows_authentication_domain_batch(
            after_domain_id=after_domain_id, limit=DISCOVERY_BATCH_LIMIT
        )
        if not domains:
            break
        discovered_domain_count += len(domains)
        if discovered_domain_count > DISCOVERY_SCAN_LIMIT:
            raise ValueError("windows_authentication_source_discovery_scan_limit")
        for domain_id in domains:
            if _read_access_allowed(access, domain_id):
                authorized_domain_count += 1
                if _has_windows_authentication_source(domain_id):
                    authorized.append({"source_domain_id": domain_id})
        after_domain_id = domains[-1]
        if len(domains) < DISCOVERY_BATCH_LIMIT:
            break
    items = authorized[:100]
    return {
        "contract_id": CONTRACT_ID,
        "report_key": REPORT_KEY,
        "state": (
            "available" if items
            else "not_collected" if authorized_domain_count
            else "not_authorized"
        ),
        "items": items,
        "bounded": True,
        "limit": 100,
        "has_more": len(authorized) > 100,
    }


def get_windows_authentication_report(
    access: Mapping[str, Any],
    *,
    source_domain_id: int,
    time_from: str | None,
    time_to: str | None,
    timezone_name: str = "UTC",
    limit: int = DEFAULT_HISTORY_ROWS,
) -> dict[str, Any]:
    """Read one bounded domain only after ``vpn.audit`` and ``events.view``."""

    domain_id = int(source_domain_id)
    if domain_id <= 0:
        raise ValueError("windows_authentication_domain_invalid")
    if not time_from or not time_to:
        raise TimeRangeError("windows_authentication_requires_time_bounds")
    start_raw, end_raw = normalize_utc_range(
        time_from, time_to, timezone_name=timezone_name
    )
    period_start, period_end = _utc(start_raw), _utc(end_raw)
    if period_start is None or period_end is None or period_start >= period_end:
        raise TimeRangeError("empty_or_reversed_time_range")
    if period_end - period_start > timedelta(days=MAX_PERIOD_DAYS):
        raise TimeRangeError("windows_authentication_period_too_wide")
    clean_limit = int(limit)
    if not 1 <= clean_limit <= MAX_HISTORY_ROWS:
        raise ValueError("windows_authentication_limit_invalid")
    if not _read_access_allowed(access, domain_id):
        return _not_authorized_payload(domain_id, period_start, period_end, clean_limit)
    events, coverage, result_window = _read_windows_authentication_data(
        domain_id=domain_id,
        period_start=period_start,
        period_end=period_end,
        limit=clean_limit,
    )
    return compose_windows_authentication_report(
        source_domain_id=domain_id,
        period_start=period_start,
        period_end=period_end,
        events=events,
        collection_coverage=coverage,
        display_limit=clean_limit,
        truncated=result_window["truncated"],
        manual_review_policy=result_window["manual_review_policy"],
    )


def get_windows_authentication_failure_grid(
    access: Mapping[str, Any],
    *,
    source_domain_id: int,
    time_from: str | None,
    time_to: str | None,
    timezone_name: str = "UTC",
) -> dict[str, Any]:
    """Observed authentication failures per local ISO weekday and hour over the whole window.

    Same bounds and access decision as ``get_windows_authentication_report``;
    an aggregate, never a display page, so busy windows are not truncated.
    """
    domain_id = int(source_domain_id)
    if domain_id <= 0:
        raise ValueError("windows_authentication_domain_invalid")
    if not time_from or not time_to:
        raise TimeRangeError("windows_authentication_requires_time_bounds")
    start_raw, end_raw = normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
    period_start, period_end = _utc(start_raw), _utc(end_raw)
    if period_start is None or period_end is None or period_start >= period_end:
        raise TimeRangeError("empty_or_reversed_time_range")
    if period_end - period_start > timedelta(days=MAX_PERIOD_DAYS):
        raise TimeRangeError("windows_authentication_period_too_wide")
    try:
        zone = ZoneInfo(timezone_name).key
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("windows_authentication_timezone_invalid") from exc
    if not _read_access_allowed(access, domain_id):
        return {"state": "not_authorized", "cells": []}
    cells = _read_windows_authentication_failure_grid(
        domain_id=domain_id, period_start=period_start, period_end=period_end, zone=zone,
    )
    return {"state": "available", "timezone": zone, "cells": cells}


def _read_windows_authentication_failure_grid(
    *, domain_id: int, period_start: datetime, period_end: datetime, zone: str,
) -> list[dict[str, Any]]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read, read only")
        remaining_read_ms()
        cur.execute(
            """select extract(isodow from (event.time_created_utc at time zone %s))::int as isodow,
                      extract(hour from (event.time_created_utc at time zone %s))::int as hour,
                      count(*) as failures
                 from events_v2_core event
                 join servers server on server.id=event.server_id
                 join storage_v2_channel channel on channel.id=event.channel_id
                 join storage_v2_provider provider on provider.id=event.provider_id
                 left join event_facts_v2 facts on facts.event_id=event.id
                where event.domain_id=%s and server.role='domain_controller'
                  and channel.value=%s and provider.value=%s
                  and event.time_created_utc>=%s and event.time_created_utc<%s
                  and (event.event_id=any(%s)
                       or (event.event_id=any(%s)
                           and nullif(lower(trim(facts.result_code)),'') is not null
                           and lower(trim(facts.result_code))<>all(%s)))
                group by 1, 2 order by 1, 2""",
            (
                zone, zone, domain_id, SECURITY_CHANNEL, SECURITY_PROVIDER, period_start, period_end,
                sorted(WINDOWS_AUTHENTICATION_REPORT_FAILURE_EVENT_IDS),
                sorted(WINDOWS_AUTHENTICATION_REPORT_MIXED_RESULT_EVENT_IDS),
                sorted(_ZERO_RESULT_CODES),
            ),
        )
        return [dict(row) for row in cur.fetchall()]


def compose_windows_authentication_report(
    *,
    source_domain_id: int,
    period_start: datetime,
    period_end: datetime,
    events: Sequence[Mapping[str, Any]],
    collection_coverage: Mapping[str, Any],
    display_limit: int | None = None,
    truncated: bool = False,
    manual_review_policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compose only ordered source observations, never reconstructed sessions."""

    if not period_start.tzinfo or not period_end.tzinfo or period_start >= period_end:
        raise ValueError("windows_authentication_period_invalid")
    clean_display_limit = MAX_HISTORY_ROWS if display_limit is None else int(display_limit)
    if not 1 <= clean_display_limit <= MAX_HISTORY_ROWS or len(events) > clean_display_limit:
        raise ValueError("windows_authentication_input_bound_exceeded")
    clean_start, clean_end = _utc(period_start), _utc(period_end)
    assert clean_start is not None and clean_end is not None
    items: list[dict[str, Any]] = []
    seen_event_ids: set[int] = set()
    for event in events:
        event_id = int(event.get("event_id") or 0)
        if event_id not in WINDOWS_AUTHENTICATION_REPORT_EVENT_IDS:
            raise ValueError("windows_authentication_event_invalid")
        observed_at = _utc(event.get("time_created_utc"))
        if observed_at is None or not clean_start <= observed_at < clean_end:
            raise ValueError("windows_authentication_event_outside_bounds")
        event_db_id = int(event.get("event_db_id") or 0)
        if event_db_id <= 0 or event_db_id in seen_event_ids:
            raise ValueError("windows_authentication_event_identity_invalid")
        seen_event_ids.add(event_db_id)
        domain_controller = _text(event.get("domain_controller"))
        if domain_controller is None:
            raise ValueError("windows_authentication_domain_controller_missing")
        target_sid = _text(event.get("target_user_sid"))
        target_name = _text(event.get("target_user_name"))
        subject_sid = _text(event.get("subject_user_sid"))
        subject_name = _text(event.get("subject_user_name"))
        principal_role, principal_sid, principal_name = _principal_for_event(
            event_id, target_sid, target_name, subject_sid, subject_name
        )
        source_ip = _text(event.get("source_ip"))
        item = {
            "event_db_id": event_db_id,
            "event_record_id": event.get("event_record_id"),
            "event_id": event_id,
            "time_created_utc": _iso(observed_at),
            "domain_controller": domain_controller,
            "authentication_fact": EVENT_FACTS[event_id],
            "target": _observed_or_unknown(
                target_user_sid=target_sid, target_user_name=target_name
            ),
            "principal": {
                "role": principal_role,
                **_observed_or_unknown(
                    principal_user_sid=principal_sid,
                    principal_user_name=principal_name,
                ),
            },
            "source": _observed_or_unknown(
                source_ip=source_ip,
                workstation_name=_text(event.get("workstation_name")),
            ),
            "source_native": {
                key: value
                for key, value in {
                    "logon_type": _text(event.get("logon_type")),
                    "result_code": _text(event.get("result_code")),
                    "process_name": _text(event.get("process_name")),
                    "target_server_name": _text(event.get("target_server_name")),
                }.items()
                if value is not None
            },
            "evidence": _evidence(event, event_db_id),
        }
        if event_id in _MIXED_RESULT_EVENT_IDS:
            item["outcome"] = _source_native_outcome(event.get("result_code"))
        items.append(item)
    items.sort(key=lambda item: (item["time_created_utc"], item["event_db_id"]))
    _add_earlier_failure_context(items)
    state, public_coverage = _collection_coverage(
        collection_coverage, observed_event_count=len(items)
    )
    review_reason = (manual_review_policy or {}).get("reason")
    if (manual_review_policy or {}).get("state") == "unavailable":
        state = "partial"
    return {
        "contract_id": CONTRACT_ID,
        "report_key": REPORT_KEY,
        "source_domain_id": int(source_domain_id),
        "state": state,
        "unavailable_reason": collection_coverage.get("unavailable_reason") or review_reason,
        "time_bounds": {"from_utc": _iso(clean_start), "to_utc_exclusive": _iso(clean_end)},
        "items": items,
        "collection_coverage": public_coverage,
        **({"manual_review_policy": dict(manual_review_policy)} if manual_review_policy is not None else {}),
        "result_window": {
            "display_limit": clean_display_limit,
            "returned_event_count": len(items),
            "truncated": bool(truncated),
        },
        "limits": {
            "max_period_days": MAX_PERIOD_DAYS,
            "display_limit": clean_display_limit,
            "max_display_limit": MAX_HISTORY_ROWS,
            "bounded": True,
        },
        "limitations": [
            "source_events_not_windows_sessions",
            "manual_review_signal_not_attack_verdict",
            "empty_window_source_completeness_not_proven",
            "unknown_results_remain_unknown",
            "earlier_failure_context_displayed_sample_only",
            "source_completeness_not_proven",
        ],
    }


def _not_authorized_payload(
    domain_id: int, period_start: datetime, period_end: datetime, limit: int
) -> dict[str, Any]:
    return {
        "contract_id": CONTRACT_ID,
        "report_key": REPORT_KEY,
        "source_domain_id": domain_id,
        "state": "not_authorized",
        "time_bounds": {"from_utc": _iso(period_start), "to_utc_exclusive": _iso(period_end)},
        "items": [],
        "result_window": {"display_limit": limit, "returned_event_count": 0, "truncated": False},
        "limits": {
            "max_period_days": MAX_PERIOD_DAYS,
            "display_limit": limit,
            "max_display_limit": MAX_HISTORY_ROWS,
            "bounded": True,
        },
    }


def _evidence(event: Mapping[str, Any], event_db_id: int) -> dict[str, Any]:
    return {
        "event_db_id": event_db_id,
        "event_record_id": event.get("event_record_id"),
        "source_core_sha256": _public(event.get("source_core_sha256")),
        "source_facts_sha256": _public(event.get("source_facts_sha256")),
    }


def _principal_for_event(
    event_id: int,
    target_sid: str | None,
    target_name: str | None,
    subject_sid: str | None,
    subject_name: str | None,
) -> tuple[str, str | None, str | None]:
    """Choose the documented principal role without overwriting raw roles."""

    if event_id in _SUBJECT_PRINCIPAL_EVENT_IDS:
        return "subject_account", subject_sid, subject_name
    return "target_account", target_sid, target_name


def _source_native_outcome(result_code: Any) -> dict[str, str]:
    """Classify a mixed Windows event only when its saved code permits it."""

    observed_code = _text(result_code)
    if observed_code is None:
        return {"state": "unknown"}
    return {
        "state": "observed",
        "result": "success" if observed_code.casefold() in _ZERO_RESULT_CODES else "failure",
        "result_code": observed_code,
    }


def _is_failure_fact(item: Mapping[str, Any]) -> bool:
    if item["event_id"] in WINDOWS_AUTHENTICATION_REPORT_FAILURE_EVENT_IDS:
        return True
    outcome = item.get("outcome")
    return bool(isinstance(outcome, Mapping) and outcome.get("result") == "failure")


def _add_earlier_failure_context(items: Sequence[dict[str, Any]]) -> None:
    failures_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in items:
        target = item["principal"]
        source = item["source"]
        target_sid = _text(target.get("principal_user_sid"))
        source_ip = _text(source.get("source_ip"))
        if item["event_id"] == WINDOWS_AUTHENTICATION_REPORT_SUCCESS_EVENT_ID:
            if target_sid is None or source_ip is None:
                item["earlier_observed_failures_in_window"] = {
                    "state": "unknown",
                    "reason": "target_sid_or_source_ip_not_observed",
                }
            else:
                references = [
                    _failure_reference(failure)
                    for failure in failures_by_key.get((target_sid, source_ip), [])
                ]
                item["earlier_observed_failures_in_window"] = {
                    "state": "observed",
                    "event_references": references,
                }
        if _is_failure_fact(item) and target_sid is not None and source_ip is not None:
            failures_by_key.setdefault((target_sid, source_ip), []).append(item)


def _failure_reference(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "event_db_id": item["event_db_id"],
        "event_record_id": item["event_record_id"],
        "event_id": item["event_id"],
        "time_created_utc": item["time_created_utc"],
    }


def _collection_coverage(
    coverage: Mapping[str, Any], *, observed_event_count: int
) -> tuple[str, dict[str, Any]]:
    if coverage.get("read_incomplete"):
        return "partial", {**coverage, "state": "partial", "source_completeness": "not_proven"}
    history_event_present = bool(coverage.get("history_event_present"))
    if observed_event_count < 0 or (observed_event_count and not history_event_present):
        raise ValueError("windows_authentication_collection_coverage_invalid")
    state = "available" if observed_event_count else "empty_unverified" if history_event_present else "not_collected"
    return state, {
        "state": state,
        "history_event_present": history_event_present,
        "source_completeness": "not_proven",
    }


def _read_windows_authentication_domain_batch(
    *, after_domain_id: int, limit: int
) -> list[int]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            """select id as domain_id from domains
                where id>%s order by id limit %s""",
            (after_domain_id, limit),
        )
        return [int(row["domain_id"]) for row in cur.fetchall()]


def _has_windows_authentication_source(domain_id: int) -> bool:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            """select exists(
                       select 1 from events_v2_core event
                       join servers server on server.id=event.server_id
                       join storage_v2_channel channel on channel.id=event.channel_id
                       join storage_v2_provider provider on provider.id=event.provider_id
                      where event.domain_id=%s and server.role='domain_controller'
                        and event.event_id=any(%s)
                        and channel.value=%s and provider.value=%s
                   ) as source_present""",
            (
                domain_id,
                sorted(WINDOWS_AUTHENTICATION_REPORT_EVENT_IDS),
                SECURITY_CHANNEL,
                SECURITY_PROVIDER,
            ),
        )
        return bool((cur.fetchone() or {}).get("source_present"))


def _read_windows_authentication_data(
    *, domain_id: int, period_start: datetime, period_end: datetime, limit: int
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    event_ids = sorted(WINDOWS_AUTHENTICATION_REPORT_EVENT_IDS)
    events = []
    coverage = {}
    truncated = False
    policy = {}
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute("set transaction isolation level repeatable read, read only")
            remaining_read_ms()
            cur.execute(
                """select event.id as event_db_id,event.event_record_id,event.event_id,
                          event.time_created_utc,server.hostname as domain_controller,
                          event.target_user_sid,event.target_user_name,
                          event.subject_user_sid,event.subject_user_name,event.ip_address as source_ip,
                          event.workstation_name,facts.logon_type,facts.result_code,
                          facts.process_name,facts.target_server_name,event.source_core_sha256,
                          facts.source_facts_sha256
                     from events_v2_core event
                     join servers server on server.id=event.server_id
                     join storage_v2_channel channel on channel.id=event.channel_id
                     join storage_v2_provider provider on provider.id=event.provider_id
                     left join event_facts_v2 facts on facts.event_id=event.id
                    where event.domain_id=%s and server.role='domain_controller'
                      and event.event_id=any(%s) and channel.value=%s and provider.value=%s
                      and event.time_created_utc>=%s and event.time_created_utc<%s
                    order by event.time_created_utc,event.id limit %s""",
                (domain_id, event_ids, SECURITY_CHANNEL, SECURITY_PROVIDER, period_start, period_end, limit + 1),
            )
            events, truncated = _bounded_events(
                [dict(row) for row in cur.fetchall()], limit
            )
            remaining_read_ms()
            cur.execute(
                """select exists(
                           select 1 from events_v2_core history_event
                           join servers history_server on history_server.id=history_event.server_id
                           join storage_v2_channel history_channel on history_channel.id=history_event.channel_id
                           join storage_v2_provider history_provider on history_provider.id=history_event.provider_id
                          where history_event.domain_id=%s and history_server.role='domain_controller'
                            and history_event.event_id=any(%s)
                            and history_channel.value=%s and history_provider.value=%s
                       ) as history_event_present""",
                (domain_id, event_ids, SECURITY_CHANNEL, SECURITY_PROVIDER),
            )
            coverage = dict(cur.fetchone() or {})
            policy = _read_manual_review_policy(cur, period_start, period_end, domain_id)
    except (QueryTimeoutError, QueryCanceled):
        # Leave the failed transaction before returning previously fetched facts.
        coverage = {"history_event_present": True if events else None,
                    **coverage, "read_incomplete": True,
                    "unavailable_reason": "source_read_timeout"}
        policy = {"state": "unavailable", "coverage_scope": "not_evaluated",
                  "signals": [], "not_a_verdict": True}
    return events, coverage, {"truncated": truncated, "manual_review_policy": policy}


def _bounded_events(
    events: Sequence[dict[str, Any]], limit: int
) -> tuple[list[dict[str, Any]], bool]:
    """Keep a deterministic display prefix instead of rejecting busy windows."""

    return list(events[:limit]), len(events) > limit


def _read_manual_review_policy(
    cur: Any, period_start: datetime, period_end: datetime, domain_id: int,
) -> dict[str, Any]:
    """Evaluate the whole retained period only when its bounded read completes.

    Windows are anchored at observed failures, so boundary-straddling series are
    included. An input limit or timeout never becomes a negative finding.
    Source hostnames are fallbacks, not additional sources for an observed IP.
    """
    conditions = {
        "minimum_failure_facts": MANUAL_REVIEW_MIN_FAILURES,
        "minimum_distinct_target_sids": MANUAL_REVIEW_MIN_TARGET_SIDS,
        "source_ip": "nonempty_source_native",
        "rolling_window_minutes": int(MANUAL_REVIEW_WINDOW.total_seconds() // 60),
    }
    distributed = {
        "rolling_window_hours": int(get_setting("windows_auth.distributed_window_hours")),
        "minimum_distinct_target_sids": int(get_setting("windows_auth.distributed_min_accounts")),
        "minimum_distinct_sources": int(get_setting("windows_auth.distributed_min_sources")),
        "maximum_failures_per_target": int(get_setting("windows_auth.distributed_max_failures_per_account")),
    }
    # Settings reads may consume the deadline while this connection is idle.
    # Its one-shot watchdog is not a permit to start new work afterward.
    remaining = remaining_read_ms()
    timeout_ms = min(10_000, remaining) if remaining is not None else 10_000
    cur.execute(f"set local statement_timeout = '{timeout_ms}ms'")
    remaining_read_ms()
    cur.execute(
        """select event.id, event.time_created_utc as at,
                    nullif(trim(event.target_user_sid),'') as sid,
                    nullif(trim(event.ip_address),'') as ip,
                    coalesce('ip:' || nullif(trim(event.ip_address),''),
                             'host:' || nullif(lower(trim(event.workstation_name)),'')) as source
               from events_v2_core event
               join servers server on server.id=event.server_id
               join storage_v2_channel channel on channel.id=event.channel_id
               join storage_v2_provider provider on provider.id=event.provider_id
               left join event_facts_v2 facts on facts.event_id=event.id
              where event.domain_id=%s and server.role='domain_controller'
                and channel.value=%s and provider.value=%s
                and event.time_created_utc>=%s and event.time_created_utc<%s
                and nullif(trim(event.target_user_sid),'') is not null
                and (event.event_id=any(%s)
                     or (event.event_id=any(%s)
                         and nullif(lower(trim(facts.result_code)),'') is not null
                         and lower(trim(facts.result_code))<>all(%s)))
              order by event.time_created_utc, event.id limit %s""",
        (
            domain_id, SECURITY_CHANNEL, SECURITY_PROVIDER, period_start, period_end,
            sorted(WINDOWS_AUTHENTICATION_REPORT_FAILURE_EVENT_IDS), sorted(_MIXED_RESULT_EVENT_IDS),
            sorted(_ZERO_RESULT_CODES), MAX_REVIEW_INPUT_ROWS + 1,
        ),
    )
    failures = cur.fetchall()
    if len(failures) > MAX_REVIEW_INPUT_ROWS:
        return {"state": "unavailable", "reason": "review_input_limit", "coverage_scope": "not_evaluated",
                "signals": [], "not_a_verdict": True, "input_limit": MAX_REVIEW_INPUT_ROWS}
    remaining_read_ms()
    by_ip: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for failure in failures:
        if failure["ip"] is not None:
            by_ip[failure["ip"]].append(failure)
    rows = []
    for ip, ip_failures in by_ip.items():
        signal = _first_manual_review_window(
            ip_failures, rule="single_ip", source_ip=ip, duration=MANUAL_REVIEW_WINDOW,
            minimum_failures=MANUAL_REVIEW_MIN_FAILURES, minimum_targets=MANUAL_REVIEW_MIN_TARGET_SIDS,
        )
        if signal is not None:
            rows.append(signal)
    signal = _first_manual_review_window(
        failures, rule="distributed", source_ip=None,
        duration=timedelta(hours=distributed["rolling_window_hours"]), minimum_failures=0,
        minimum_targets=distributed["minimum_distinct_target_sids"],
        minimum_sources=distributed["minimum_distinct_sources"],
        maximum_failures_per_target=distributed["maximum_failures_per_target"],
    )
    if signal is not None:
        rows.append(signal)
    rows.sort(key=lambda row: (row["rule"], row["window_start"], row["source_ip"] or ""))
    signals = [{
        "state": "manual_review_signal", "rule": row["rule"], "source_ip": row["source_ip"],
        "window": {"from_utc": _iso(row["window_start"]), "to_utc_exclusive": _iso(min(row["window_end"], period_end))},
        "failure_fact_count": int(row["failure_fact_count"]),
        "distinct_target_sid_count": int(row["distinct_target_sid_count"]),
        "distinct_source_count": int(row["distinct_source_count"]),
        "event_references": [], "evidence_event_db_id": int(row["evidence_event_db_id"]),
        "not_a_verdict": True,
    } for row in rows[:MAX_REVIEW_SIGNALS]]
    return {
        "id": "windows-authentication-failure-manual-review", "version": "v2",
        "conditions": conditions, "distributed_conditions": distributed,
        "coverage_scope": "whole_period",
        "time_bounds": {"from_utc": _iso(period_start), "to_utc_exclusive": _iso(period_end)},
        "state": "manual_review_signal" if signals else "no_observed_signal_unverified",
        "signals": signals, "not_a_verdict": True,
        "signals_truncated": len(rows) > MAX_REVIEW_SIGNALS,
        "signal_limit": MAX_REVIEW_SIGNALS,
        "signal_selection": "first_matching_window_per_ip_and_first_distributed_window",
    }


def _change_count(counts: Counter, key: str, delta: int) -> None:
    counts[key] += delta
    if not counts[key]:
        del counts[key]


class _ManualReviewWindow:
    """Incremental counts, including sourceless failures in each account's cap."""

    def __init__(self, maximum_failures_per_target: int | None):
        self.maximum = maximum_failures_per_target
        self.accounts: Counter[str] = Counter()
        self.account_sources: dict[str, Counter[str]] = defaultdict(Counter)
        self.targets: Counter[str] = Counter()
        self.sources: Counter[str] = Counter()
        self.failure_count = 0

    def eligible(self, sid: str) -> bool:
        return self.maximum is None or self.accounts[sid] <= self.maximum

    def _contribute(self, sid: str, source: str, delta: int) -> None:
        _change_count(self.targets, sid, delta)
        _change_count(self.sources, source, delta)
        self.failure_count += delta

    def change(self, row: Mapping[str, Any], delta: int) -> None:
        sid, source = row["sid"], row["source"]
        was_eligible = self.eligible(sid)
        _change_count(self.accounts, sid, delta)
        is_eligible = self.eligible(sid)
        sources = self.account_sources[sid]
        if was_eligible and not is_eligible:
            for previous_source, count in sources.items():
                self._contribute(sid, previous_source, -count)
        if source is not None:
            _change_count(sources, source, delta)
        if is_eligible and not was_eligible:
            for current_source, count in sources.items():
                self._contribute(sid, current_source, count)
        elif is_eligible and was_eligible and source is not None:
            self._contribute(sid, source, delta)
        if sid not in self.accounts:
            del self.account_sources[sid]


def _first_manual_review_window(
    failures: Sequence[Mapping[str, Any]], *, rule: str, source_ip: str | None,
    duration: timedelta, minimum_failures: int, minimum_targets: int, minimum_sources: int = 1,
    maximum_failures_per_target: int | None = None,
) -> dict[str, Any] | None:
    """Visit each sorted failure once on entry and once on exit, without pair joins.

    Equal timestamps are one anchor. Only sourced failures anchor a window, but
    all failures count towards the distributed account cap. Evidence is scanned
    only for the first matching window, after all its counts are known.
    """
    window = _ManualReviewWindow(maximum_failures_per_target)
    remaining_read_ms()
    left = right = 0
    while left < len(failures):
        if left % 1024 == 0:
            remaining_read_ms()
        at = failures[left]["at"]
        anchor_end = left + 1
        while anchor_end < len(failures) and failures[anchor_end]["at"] == at:
            anchor_end += 1
        end = at + duration
        while right < len(failures) and failures[right]["at"] < end:
            if right % 1024 == 0:
                remaining_read_ms()
            window.change(failures[right], 1)
            right += 1
        if (any(failures[i]["source"] is not None for i in range(left, anchor_end))
                and window.failure_count >= minimum_failures
                and len(window.targets) >= minimum_targets and len(window.sources) >= minimum_sources):
            return {
                "rule": rule, "source_ip": source_ip, "window_start": at, "window_end": end,
                "failure_fact_count": window.failure_count,
                "distinct_target_sid_count": len(window.targets), "distinct_source_count": len(window.sources),
                "evidence_event_db_id": min(
                    failures[i]["id"] for i in range(left, right)
                    if failures[i]["source"] is not None and window.eligible(failures[i]["sid"])
                ),
            }
        while left < anchor_end:
            window.change(failures[left], -1)
            left += 1
    return None


_connect = get_runtime_connection
