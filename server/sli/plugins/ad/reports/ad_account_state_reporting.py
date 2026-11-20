from __future__ import annotations

"""Bounded evidence-first AD account-change history on domain controllers.

The report publishes individual Security-account-management observations.  It
does not reconstruct a current AD account state: each row says only what its
source event proves, and its prior state remains unknown unless the source
event itself supplies a before value (the two names in Event 4781).
"""

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

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
from server.source_packs.windows_ad_dc import (
    AD_ACCOUNT_CHANGE_EVENT_IDS,
    account_change_kind,
    is_account_rename_event,
    observed_account_state_after_change,
)


CONTRACT_ID = "sli.ad-account-change-history.v1"
REPORT_KEY = "ad.state.account_changes"
ACCESS_REPORT_KEY = "ad.state"
EVENT_VIEW_CAPABILITY = "events.view"
SECURITY_CHANNEL = "Security"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
MAX_PERIOD_DAYS = 31
MAX_HISTORY_ROWS = 500
DEFAULT_HISTORY_ROWS = 200
DISCOVERY_BATCH_LIMIT = 256
DISCOVERY_SCAN_LIMIT = 10_000

_utc = parse_utc
_iso = format_iso
_text = clean_text
_public = sanitize_public
_domain_resource_groups = build_domain_resource_groups


def _read_access_allowed(access: Mapping[str, Any], domain_id: int) -> bool:
    resource_groups = _domain_resource_groups(domain_id)
    return bool(
        report_action_decision(
            access,
            ACCESS_REPORT_KEY,
            "view",
            resource_groups=resource_groups,
        )["allowed"]
        and capability_decision_for_resource_groups(
            access,
            EVENT_VIEW_CAPABILITY,
            resource_groups=resource_groups,
        )["allowed"]
    )


def get_ad_account_change_sources(access: Mapping[str, Any]) -> dict[str, Any]:
    """Discover bounded DC domains with account-change evidence after access."""

    discovered_count = 0
    authorized_count = 0
    authorized: list[dict[str, int]] = []
    after_domain_id = 0
    while len(authorized) <= 100:
        domains = _read_ad_account_change_domain_batch(
            after_domain_id=after_domain_id,
            limit=DISCOVERY_BATCH_LIMIT,
        )
        if not domains:
            break
        discovered_count += len(domains)
        if discovered_count > DISCOVERY_SCAN_LIMIT:
            raise ValueError("ad_account_change_source_discovery_scan_limit")
        for domain_id in domains:
            if not _read_access_allowed(access, domain_id):
                continue
            authorized_count += 1
            if _has_ad_account_change_source(domain_id):
                authorized.append({"source_domain_id": domain_id})
        after_domain_id = domains[-1]
        if len(domains) < DISCOVERY_BATCH_LIMIT:
            break
    items = authorized[:100]
    return {
        "contract_id": CONTRACT_ID,
        "report_key": REPORT_KEY,
        "state": (
            "available"
            if items
            else "not_collected"
            if authorized_count
            else "not_authorized"
        ),
        "items": items,
        "bounded": True,
        "limit": 100,
        "has_more": len(authorized) > 100,
    }


def _account(event: Mapping[str, Any]) -> dict[str, Any]:
    observed_sid = _text(event.get("target_user_sid"))
    observed_name = _text(event.get("target_user_name"))
    if observed_sid is None and observed_name is None:
        return {"state": "unknown"}
    return {
        "state": "observed",
        "target_user_sid": observed_sid,
        "target_user_name": observed_name,
    }


def _actor(event: Mapping[str, Any]) -> dict[str, Any]:
    observed_sid = _text(event.get("subject_user_sid"))
    observed_name = _text(event.get("subject_user_name"))
    if observed_sid is None and observed_name is None:
        return {"state": "unknown"}
    return {
        "state": "observed",
        "subject_user_sid": observed_sid,
        "subject_user_name": observed_name,
    }


def _unknown_prior_state() -> dict[str, str]:
    return {"state": "unknown", "reason": "prior_account_state_not_observed"}


def _observed_transition(event: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    event_id = int(event["event_id"])
    if is_account_rename_event(event_id):
        before = _text(event.get("account_name_before"))
        after = _text(event.get("account_name_after"))
        if before is not None and after is not None:
            return {
                "before": {"state": "observed", "value": before},
                "after": {"state": "observed", "value": after},
            }
        return {
            "before": {
                "state": "unknown",
                "reason": "source_native_rename_names_not_observed",
            },
            "after": {
                "state": "unknown",
                "reason": "source_native_rename_names_not_observed",
            },
        }
    observed_after = observed_account_state_after_change(event_id)
    if observed_after is None:
        return {
            "before": _unknown_prior_state(),
            "after": {
                "state": "unknown",
                "reason": "event_does_not_prove_account_state",
            },
        }
    return {
        "before": _unknown_prior_state(),
        "after": {
            "state": "observed",
            "value": observed_after,
        },
    }


def _change(event: Mapping[str, Any]) -> dict[str, Any]:
    event_id = int(event["event_id"])
    kind = account_change_kind(event_id)
    if kind in {"password_change_attempt", "password_reset_attempt"}:
        result_code = _text(event.get("result_code"))
        change = {"kind": kind}
        if result_code is not None:
            change["result"] = {"state": "observed", "value": result_code}
        return change
    if kind == "attributes_changed":
        return {
            "kind": kind,
            "detail": {
                "state": "unknown",
                "reason": "changed_attribute_fields_not_in_warm_contract",
            },
        }
    return {"kind": kind}


def account_change_observation(event: Mapping[str, Any]) -> dict[str, Any]:
    """Return the source-owned account-change meaning shared by report consumers."""

    return {
        "change": _change(event),
        "observed_transition": _observed_transition(event),
    }


def apply_observed_account_history(
    items: Sequence[dict[str, Any]],
    *,
    account_field: str = "account",
    sid_field: str = "target_user_sid",
    observation_field: str | None = None,
) -> None:
    """Attach a prior observation without claiming continuous AD state."""

    last_observed_by_target_sid: dict[str, dict[str, Any]] = {}
    ordered = sorted(
        items,
        key=lambda item: (item["time_created_utc"], item["event_db_id"]),
    )
    for item in ordered:
        account = item[account_field]
        target_sid = _text(account.get(sid_field))
        if target_sid is None:
            continue
        observation = item if observation_field is None else item[observation_field]
        prior = last_observed_by_target_sid.get(target_sid)
        observed_after = observed_account_state_after_change(item["event_id"])
        if prior is not None and observed_after is not None:
            observation["observed_transition"]["before"] = {
                "state": "partial",
                "last_observed": prior,
                "reason": "intervening_account_state_not_proven",
            }
        if observed_after is not None:
            last_observed_by_target_sid[target_sid] = {
                "value": observed_after,
                "event_db_id": item["event_db_id"],
                "time_created_utc": item["time_created_utc"],
            }


def _evidence(event: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "event_db_id": int(event["event_db_id"]),
        "event_record_id": event.get("event_record_id"),
        "source_core_sha256": _public(event.get("source_core_sha256")),
        "source_facts_sha256": _public(event.get("source_facts_sha256")),
    }
    missing = [key for key, value in fields.items() if value is None]
    return {
        "state": "partial" if missing else "complete",
        "missing_fields": missing,
        **fields,
    }


def _collection_coverage(
    coverage: Mapping[str, Any],
    *,
    observed_event_count: int,
) -> tuple[str, dict[str, Any]]:
    history_event_present = bool(coverage.get("history_event_present"))
    if observed_event_count < 0:
        raise ValueError("ad_account_change_history_collection_coverage_invalid")
    if observed_event_count and not history_event_present:
        raise ValueError("ad_account_change_history_collection_coverage_invalid")
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


def compose_ad_account_change_history(
    *,
    source_domain_id: int,
    period_start: datetime,
    period_end: datetime,
    events: Sequence[Mapping[str, Any]],
    collection_coverage: Mapping[str, Any],
) -> dict[str, Any]:
    """Compose a bounded event history without synthesising missing account state."""

    if not period_start.tzinfo or not period_end.tzinfo or period_start >= period_end:
        raise ValueError("ad_account_change_history_period_invalid")
    if len(events) > MAX_HISTORY_ROWS:
        raise ValueError("ad_account_change_history_input_bound_exceeded")
    clean_start = _utc(period_start)
    clean_end = _utc(period_end)
    assert clean_start is not None and clean_end is not None

    items: list[dict[str, Any]] = []
    seen_event_ids: set[int] = set()
    for event in events:
        event_id = int(event.get("event_id") or 0)
        if event_id not in AD_ACCOUNT_CHANGE_EVENT_IDS:
            raise ValueError("ad_account_change_history_event_invalid")
        observed_at = _utc(event.get("time_created_utc"))
        if observed_at is None or not clean_start <= observed_at < clean_end:
            raise ValueError("ad_account_change_history_event_outside_bounds")
        event_db_id = int(event.get("event_db_id") or 0)
        if event_db_id <= 0 or event_db_id in seen_event_ids:
            raise ValueError("ad_account_change_history_event_identity_invalid")
        seen_event_ids.add(event_db_id)
        domain_controller = _text(event.get("domain_controller"))
        if domain_controller is None:
            raise ValueError("ad_account_change_history_domain_controller_missing")
        items.append({
            "event_db_id": event_db_id,
            "event_record_id": event.get("event_record_id"),
            "event_id": event_id,
            "time_created_utc": _iso(observed_at),
            "domain_controller": domain_controller,
            "account": _account(event),
            "actor": _actor(event),
            **account_change_observation(event),
            "evidence": _evidence(event),
        })
    items.sort(key=lambda item: (item["time_created_utc"], item["event_db_id"]))
    apply_observed_account_history(items)
    state, public_coverage = _collection_coverage(
        collection_coverage,
        observed_event_count=len(items),
    )
    return {
        "contract_id": CONTRACT_ID,
        "report_key": REPORT_KEY,
        "source_domain_id": int(source_domain_id),
        "state": state,
        "history_state": "partial" if items else "unknown",
        "time_bounds": {
            "from_utc": _iso(clean_start),
            "to_utc_exclusive": _iso(clean_end),
        },
        "items": items,
        "collection_coverage": public_coverage,
        "limits": {
            "max_period_days": MAX_PERIOD_DAYS,
            "row_limit": MAX_HISTORY_ROWS,
            "bounded": True,
        },
        "limitations": [
            "Rows are source-event observations, not a reconstructed current AD account status.",
            "A prior account state remains unknown unless the same source event supplies it.",
            "An empty window does not prove complete source coverage.",
            *(
                ["Some rows have partial source provenance; inspect each evidence.missing_fields value."]
                if any(item["evidence"]["state"] == "partial" for item in items)
                else []
            ),
        ],
    }


def get_ad_account_change_history(
    access: Mapping[str, Any],
    *,
    source_domain_id: int,
    time_from: str | None,
    time_to: str | None,
    timezone_name: str = "UTC",
    limit: int = DEFAULT_HISTORY_ROWS,
) -> dict[str, Any]:
    """Read DC account-change evidence only after a domain-scoped grant."""

    domain_id = int(source_domain_id)
    if domain_id <= 0:
        raise ValueError("ad_account_change_history_domain_invalid")
    if not time_from or not time_to:
        raise TimeRangeError("ad_account_change_history_requires_time_bounds")
    start_raw, end_raw = normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
    period_start, period_end = _utc(start_raw), _utc(end_raw)
    if period_start is None or period_end is None or period_start >= period_end:
        raise TimeRangeError("empty_or_reversed_time_range")
    if period_end - period_start > timedelta(days=MAX_PERIOD_DAYS):
        raise TimeRangeError("ad_account_change_history_period_too_wide")
    if not 1 <= int(limit) <= MAX_HISTORY_ROWS:
        raise ValueError("ad_account_change_history_limit_invalid")

    if not _read_access_allowed(access, domain_id):
        return {
            "contract_id": CONTRACT_ID,
            "report_key": REPORT_KEY,
            "source_domain_id": domain_id,
            "state": "not_authorized",
            "history_state": "unknown",
            "time_bounds": {
                "from_utc": _iso(period_start),
                "to_utc_exclusive": _iso(period_end),
            },
            "items": [],
            "limits": {
                "max_period_days": MAX_PERIOD_DAYS,
                "row_limit": int(limit),
                "bounded": True,
            },
        }
    events, collection_coverage = _read_ad_account_change_history_data(
        domain_id=domain_id,
        period_start=period_start,
        period_end=period_end,
        limit=int(limit),
    )
    return compose_ad_account_change_history(
        source_domain_id=domain_id,
        period_start=period_start,
        period_end=period_end,
        events=events,
        collection_coverage=collection_coverage,
    )


def _read_ad_account_change_history_data(
    *,
    domain_id: int,
    period_start: datetime,
    period_end: datetime,
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read bounded DC Security observations and a separate history-presence witness."""

    event_ids = sorted(AD_ACCOUNT_CHANGE_EVENT_IDS)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read, read only")
        cur.execute(
            """select event.id as event_db_id,event.event_record_id,event.event_id,
                      event.time_created_utc,server.hostname as domain_controller,
                      event.subject_user_sid,event.subject_user_name,
                      coalesce(nullif(btrim(event.target_user_sid),''),
                               nullif(btrim(facts.account_target_sid),'')) as target_user_sid,
                      coalesce(nullif(btrim(event.target_user_name),''),
                               nullif(btrim(facts.account_target_name),'')) as target_user_name,
                      facts.account_name_before,facts.account_name_after,facts.result_code,
                      event.source_core_sha256,facts.source_facts_sha256
                 from events_v2_core event
                 join servers server on server.id=event.server_id
                 join storage_v2_channel channel on channel.id=event.channel_id
                 join storage_v2_provider provider on provider.id=event.provider_id
                 left join event_facts_v2 facts on facts.event_id=event.id
                where event.domain_id=%s and server.role='domain_controller'
                  and event.event_id=any(%s)
                  and channel.value=%s and provider.value=%s
                  and event.time_created_utc>=%s and event.time_created_utc<%s
                order by event.time_created_utc,event.id
                limit %s""",
            (
                domain_id,
                event_ids,
                SECURITY_CHANNEL,
                SECURITY_PROVIDER,
                period_start,
                period_end,
                limit + 1,
            ),
        )
        events = [dict(row) for row in cur.fetchall()]
        if len(events) > limit:
            raise ValueError("ad_account_change_history_input_bound_exceeded")
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


def _read_ad_account_change_domain_batch(
    *, after_domain_id: int, limit: int
) -> list[int]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            "select id as domain_id from domains where id>%s order by id limit %s",
            (after_domain_id, limit),
        )
        return [int(row["domain_id"]) for row in cur.fetchall()]


def _has_ad_account_change_source(domain_id: int) -> bool:
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
                sorted(AD_ACCOUNT_CHANGE_EVENT_IDS),
                SECURITY_CHANNEL,
                SECURITY_PROVIDER,
            ),
        )
        return bool((cur.fetchone() or {}).get("source_present"))


_connect = get_runtime_connection
