"""Bounded account-revocation candidates inside security.events.chains."""

from __future__ import annotations

import re
from bisect import bisect_left
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from server.sli.reports import security_event_reporting as security
from server.sli.semantic.semantic_processing import (
    NORMALIZER_ID,
    NORMALIZER_VERSION,
    SEMANTIC_CONTRACT_VERSION,
)

IDEA_KEY = "security.account-revocation"
MAX_SOURCE_ROWS = 10_000
EXPECTED_TYPES = {
    4725: "directory.account.disabled", 4726: "directory.account.deleted",
    4722: "directory.account.enabled", 4624: "authentication.session.created",
    6272: "remote_access.authentication.allowed",
}


def _sid(row: Mapping[str, Any]) -> str | None:
    field = "subject_user_sid" if row.get("event_id") == 6272 else "target_user_sid"
    sid = security.clean_text(row.get(field))
    return sid.casefold() if sid and re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-\d+", sid, re.IGNORECASE) else None


def _usable(row: Mapping[str, Any]) -> bool:
    return row.get("processing_status") == "normalized" and row.get("semantic_type") == EXPECTED_TYPES.get(row["event_id"])


def _iso(value: Any) -> str | None:
    return security.format_iso(value) if value is not None else None


def _read_events(cur: Any, *, domain_id: int, start: datetime, end: datetime,
                 event_ids: Sequence[int]) -> tuple[list[dict[str, Any]], bool]:
    # Cap the indexed source scan before joins. The current tuple is unique per
    # event; an ignored/missing current version must not fall back to old replays.
    cur.execute(
        """with source_page as (
             select event.* from events_v2_core event
              where event.domain_id=%s and event.event_id=any(%s)
                and event.time_created_utc>=%s and event.time_created_utc<%s
                and event.channel_id=(select id from storage_v2_channel where value=%s)
                and event.provider_id=(select id from storage_v2_provider where value=%s)
              order by event.time_created_utc desc,event.id desc limit %s
           ) select event.id as event_db_id,event.domain_id,event.event_id,event.time_created_utc,
                    coalesce(nullif(btrim(event.target_user_sid),''),facts.account_target_sid) as target_user_sid,
                    event.target_user_name,event.subject_user_sid,event.subject_user_name,
                    computer.value as source,facts.logon_type,normalized.normalized_event_id,
                    normalized.processing_status,normalized.semantic_type
               from source_page event
               left join storage_v2_computer computer on computer.id=event.computer_id
               left join event_facts_v2 facts on facts.event_id=event.id
               left join normalized_events normalized on normalized.source_event_id=event.id
                and normalized.semantic_contract_version=%s
                and normalized.normalizer_id=%s and normalized.normalizer_version=%s
              order by event.time_created_utc,event.id""",
        [domain_id, list(event_ids), start, end, security.SECURITY_CHANNEL,
         security.SECURITY_AUDITING_PROVIDER, MAX_SOURCE_ROWS + 1,
         SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION],
    )
    rows = [dict(row) for row in cur.fetchall()]
    return rows[:MAX_SOURCE_ROWS], len(rows) > MAX_SOURCE_ROWS


def _read_sessions(cur: Any, *, domain_id: int, start: datetime, end: datetime,
                   sids: list[str]) -> tuple[list[dict[str, Any]], str, bool]:
    if not sids:
        return [], "not_checked", False
    from server.sli.plugins.registry import plugin_hook

    hook = plugin_hook("sli.remote-access", "revocation_sessions")
    if hook is None:
        return [], "not_installed", False
    return hook(cur, domain_id=domain_id, start=start, end=end, sids=sids)


def shape_candidates(events: Sequence[Mapping[str, Any]], sessions: Sequence[Mapping[str, Any]], *,
                     start: datetime, end: datetime, follow_minutes: int,
                     account: str | None = None, source: str | None = None,
                     activity_type: str | None = None, minimum_delay: int = 0,
                     exact_only: bool = False, truncated: bool = False) -> tuple[list[dict[str, Any]], bool]:
    ordered = sorted({row["event_db_id"]: row for row in events}.values(),
                     key=lambda row: (row["time_created_utc"], row["event_db_id"]))
    anchors: dict[tuple[Any, str], list[Mapping[str, Any]]] = defaultdict(list)
    enables: dict[tuple[Any, str], list[Mapping[str, Any]]] = defaultdict(list)
    rows: list[dict[str, Any]] = []
    delta = timedelta(minutes=follow_minutes)

    def append(anchor: Mapping[str, Any] | None, activity: Mapping[str, Any] | None, kind: str) -> None:
        observation = anchor or activity
        assert observation is not None
        sid = _sid(observation)
        at = anchor["time_created_utc"] if anchor else None
        moment = activity.get("time_created_utc", activity.get("last_observed_at_utc")) if activity else None
        released = next((event for event in enables.get((observation["domain_id"], sid), [])
                         if at and at < event["time_created_utc"] < at + delta), None)
        observed_source = activity.get("source") if activity else observation.get("source")
        delay = (moment - at).total_seconds() if moment and at else None
        quality = "unknown_sid" if not sid else "partial" if truncated or not _usable(observation) else "exact_sid"
        name_field = "subject_user_name" if observation.get("event_id") == 6272 else "target_user_name"
        name = observation.get(name_field) or sid
        if account and account.casefold() not in {str(name).casefold(), sid}:
            return
        if source and source.casefold() != str(observed_source or "").casefold():
            return
        if activity_type and kind != activity_type or exact_only and (not sid or not _usable(observation)):
            return
        if minimum_delay and (delay is None or delay < minimum_delay):
            return
        evidence = [anchor["event_db_id"]] if anchor else []
        if activity:
            evidence.append(activity.get("event_db_id", activity.get("session_row_id")))
        if released:
            evidence.append(released["event_db_id"])
        rows.append({
            "candidate_key": f"{anchor['event_db_id'] if anchor else 'unknown'}:{kind}:{activity.get('event_db_id', activity.get('session_row_id')) if activity else ''}",
            "account": name, "sid": sid, "qualification": "candidate" if kind != "insufficient" else "insufficient",
            "disable_event": anchor["event_db_id"] if anchor else None,
            "disable_code": anchor["event_id"] if anchor else None, "disabled_at": _iso(at),
            "activity_event": activity.get("event_db_id") if activity else None,
            "activity_at": _iso(moment), "activity_type": kind, "delay_seconds": delay,
            "source": observed_source, "logon_type": activity.get("logon_type") if activity else None,
            "reenabled_at": _iso(released["time_created_utc"]) if released else None,
            "reenable_event": released["event_db_id"] if released else None,
            "reenable_relation": "not_observed" if not released else "before_activity" if moment and released["time_created_utc"] < moment
            else "same_time" if moment == released["time_created_utc"] else "after_activity",
            "evidence": evidence, "quality": quality,
            "clock_quality": "uncertain" if delay is not None and delay <= 60 else "unverified",
            "session_id": activity.get("session_row_id") if activity else None,
            "session_started_at": _iso(activity.get("started_at_utc")) if activity else None,
            "session_completeness": activity.get("completeness") if activity else None,
        })

    unresolved = []
    for event in ordered:
        sid = _sid(event)
        key = (event["domain_id"], sid)
        if event["event_id"] == 4722 and sid and _usable(event):
            enables[key].append(event)
        elif event["event_id"] in {4725, 4726} and start <= event["time_created_utc"] < end:
            if sid and _usable(event):
                anchors[key].append(event)
            else:
                unresolved.append(event)
    for event in unresolved:
        append(event, None, "insufficient")
    anchor_times = {key: [anchor["time_created_utc"] for anchor in episodes] for key, episodes in anchors.items()}
    for event in ordered:
        if event["event_id"] not in {4624, 6272}:
            continue
        sid = _sid(event)
        if not sid or not _usable(event):
            append(None, event, "insufficient")
            continue
        key = (event["domain_id"], sid)
        episodes = anchors.get(key, [])
        index = bisect_left(anchor_times.get(key, []), event["time_created_utc"]) - 1
        if index >= 0 and event["time_created_utc"] < episodes[index]["time_created_utc"] + delta:
            append(episodes[index], event, "logon" if event["event_id"] == 4624 else "nps_allow")
    output_cut = False
    for session in {row["session_row_id"]: row for row in sessions}.values():
        for anchor in anchors.get((session["domain_id"], _sid(session)), []):
            at = anchor["time_created_utc"]
            stop = session.get("stopped_at_utc") or session["last_observed_at_utc"]
            if session.get("started_at_utc") and session["started_at_utc"] < at < stop:
                append(anchor, {**session, "source": "RADIUS Accounting"}, "vpn_continuation")
                if len(rows) >= MAX_SOURCE_ROWS:
                    output_cut = True
                    break
        if output_cut:
            break
    return rows[:MAX_SOURCE_ROWS], output_cut or len(rows) > MAX_SOURCE_ROWS


def get_account_revocation(access: Mapping[str, Any], *, domain_id: int, time_from: str, time_to: str,
                           limit: int, follow_minutes: int = 1440, minimum_delay: int = 0,
                           account: str | None = None, source: str | None = None,
                           activity_type: str | None = None, exact_only: bool = False,
                           action: str = "view") -> dict[str, Any]:
    start, end = security.parse_utc(time_from), security.parse_utc(time_to)
    if start is None or end is None or not timedelta(0) < end - start <= timedelta(days=security.MAX_PERIOD_DAYS):
        raise ValueError("security_events_period_too_wide")
    if (domain_id <= 0 or not 1 <= limit <= security.MAX_ROWS or not 1 <= follow_minutes <= 1440
            or minimum_delay < 0 or action not in {"view", "export"}
            or activity_type not in {None, "logon", "nps_allow", "vpn_continuation", "insufficient"}):
        raise ValueError("security_events_filter_invalid")
    if not security._read_access_allowed(access, domain_id, action=action):
        return {"state": "denied", "rows": []}
    follow_end = end + timedelta(minutes=follow_minutes)
    with security._connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute("set local statement_timeout='3000ms'")
        anchors, anchors_cut = _read_events(cur, domain_id=domain_id, start=start, end=end, event_ids=[4725, 4726])
        enables, enables_cut = _read_events(cur, domain_id=domain_id, start=start, end=follow_end, event_ids=[4722])
        activity, activity_cut = _read_events(cur, domain_id=domain_id, start=start, end=follow_end, event_ids=[4624, 6272])
        sessions, accounting_state, sessions_cut = _read_sessions(
            cur, domain_id=domain_id, start=start, end=end,
            sids=sorted({_sid(row) for row in anchors if _sid(row) and _usable(row)}),
        )
    truncated = anchors_cut or enables_cut or activity_cut or sessions_cut
    rows, output_cut = shape_candidates([*anchors, *enables, *activity], sessions, start=start, end=end,
                                        follow_minutes=follow_minutes, minimum_delay=minimum_delay, account=account,
                                        source=source, activity_type=activity_type, exact_only=exact_only, truncated=truncated)
    missing_semantics = sum(not _usable(row) for row in [*anchors, *enables, *activity])
    partial = truncated or output_cut or len(rows) > limit
    return {
        "state": "partial" if partial or missing_semantics or accounting_state == "unavailable" else "ok" if rows else "empty",
        "rows": rows[:limit], "filtered_count": len(rows),
        "totals": {"logon_accounts": len({row["sid"] for row in rows if row["activity_type"] == "logon"}),
                   "nps_allows": sum(row["activity_type"] == "nps_allow" for row in rows),
                   "vpn_sessions": len({row["session_id"] for row in rows if row["activity_type"] == "vpn_continuation"}),
                   "insufficient": sum(row["activity_type"] == "insufficient" for row in rows)},
        "coverage": {"state": "bounded_slice" if partial else "coverage_unverified", "completeness": "not_proven",
                     "source_truncated": truncated, "rows_truncated": output_cut or len(rows) > limit,
                     "accounting_state": accounting_state,
                     "missing_current_semantics": missing_semantics},
        "window": {"from_utc": security.format_iso(start), "to_utc_exclusive": security.format_iso(end),
                   "activity_to_utc_exclusive": security.format_iso(follow_end), "follow_minutes": follow_minutes,
                   "idea_key": IDEA_KEY, "source_row_limit": MAX_SOURCE_ROWS},
    }
