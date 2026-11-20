"""Bounded, SID-only lockout correlations inside security.events.chains."""

from __future__ import annotations

from bisect import bisect_left, bisect_right
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

IDEA_KEY = "security.lockout-recurring"
MAX_SOURCE_ROWS = 10_000
MAX_FAILURE_ROWS = 20_000
MAX_FAILURE_WINDOW_MINUTES = 1440


def _text(value: Any) -> str | None:
    text = security.clean_text(value)
    return None if text in {None, "-"} else text


def _sid(row: Mapping[str, Any]) -> str | None:
    sid = _text(row.get("target_user_sid"))
    return sid.casefold() if sid and sid.casefold().startswith("s-1-") and sid.casefold() != "s-1-0-0" else None


def _codes(row: Mapping[str, Any]) -> list[str]:
    facts = row.get("facts_json") or {}
    return sorted({str(code).casefold() for code in (
        _text(facts.get("failure_status")), _text(facts.get("result_code")), _text(row.get("result_code")),
    ) if code})


def _is_failure(row: Mapping[str, Any]) -> bool:
    if row["event_id"] in {4625, 4771}:
        return True
    # 4776 includes successful credential validations. Missing status is unknown.
    if row["event_id"] == 4776:
        codes = _codes(row)
        try:
            return bool(codes) and all(int(code, 16) != 0 for code in codes)
        except ValueError:
            return False
    return False


def _read_events(cur: Any, *, domain_id: int, start: datetime, end: datetime,
                 event_ids: Sequence[int], limit: int) -> tuple[list[dict[str, Any]], bool]:
    # The current contract/version tuple is unique per source event (migration
    # 022); old replay versions cannot multiply or supply stale semantic facts.
    cur.execute(
        """select event.id as event_db_id,event.event_id,event.time_created_utc,
                  event.target_user_sid,event.target_user_name,event.ip_address,
                  event.workstation_name,facts.result_code,
                  normalized.normalized_event_id,normalized.facts_json
             from events_v2_core event
             join servers server on server.id=event.server_id
             join storage_v2_channel channel on channel.id=event.channel_id
             join storage_v2_provider provider on provider.id=event.provider_id
             left join event_facts_v2 facts on facts.event_id=event.id
             left join normalized_events normalized
               on normalized.source_event_id=event.id
              and normalized.semantic_contract_version=%s
              and normalized.normalizer_id=%s and normalized.normalizer_version=%s
              and normalized.processing_status='normalized'
            where event.domain_id=%s and event.event_id=any(%s)
              and event.time_created_utc>=%s and event.time_created_utc<%s
              and server.role='domain_controller' and channel.value=%s and provider.value=%s
            order by event.time_created_utc desc,event.id desc limit %s""",
        [SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION,
         domain_id, list(event_ids), start, end, security.SECURITY_CHANNEL,
         security.SECURITY_AUDITING_PROVIDER, limit + 1],
    )
    rows = [dict(row) for row in cur.fetchall()]
    return rows[:limit], len(rows) > limit


def aggregate_lockouts(events: Sequence[Mapping[str, Any]], *, failure_window_minutes: int,
                       minimum_repeats: int, account: str | None = None,
                       caller: str | None = None, failure_code: str | None = None,
                       truncated: bool = False) -> list[dict[str, Any]]:
    """Match only exact SIDs; unknown lockouts each retain their own identity.

    A failure belongs to at most one lockout: after the previous lockout and
    strictly before this one, within the preceding window. Equal timestamps
    provide no ordering evidence for failures or unlock/re-lock claims.
    """
    locks: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    failures: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    unlocks: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    unique = {int(row["event_db_id"]): row for row in events}
    for row in sorted(unique.values(), key=lambda item: (item["time_created_utc"], item["event_db_id"])):
        sid = _sid(row)
        if row["event_id"] == 4740:
            identity = sid or f"unknown:{row['event_db_id']}"
            locks[identity].append(row)
        elif sid and row["event_id"] == 4767:
            unlocks[sid].append(row)
        elif sid and _is_failure(row):
            failures[sid].append(row)
    rows = []
    delta = timedelta(minutes=failure_window_minutes)
    for identity, episodes in locks.items():
        if len(episodes) < minimum_repeats:
            continue
        names = {_text(event.get("target_user_name")) for event in episodes} - {None}
        if account and account.casefold() not in {identity, *(name.casefold() for name in names)}:
            continue
        sid = _sid(episodes[0])
        prior = failures.get(identity, [])
        prior_times = [event["time_created_utc"] for event in prior]
        released = unlocks.get(identity, [])
        release_times = [event["time_created_utc"] for event in released]
        matched: list[Mapping[str, Any]] = []
        matched_episodes = relocks = 0
        intervals = []
        previous = None
        for episode in episodes:
            moment = episode["time_created_utc"]
            lower = bisect_left(prior_times, moment - delta)
            if previous is not None:
                lower = max(lower, bisect_right(prior_times, previous))
                intervals.append((moment - previous).total_seconds())
                relocks += int(bisect_right(release_times, previous) < bisect_left(release_times, moment))
            associated = prior[lower:bisect_left(prior_times, moment)]
            matched.extend(associated)
            matched_episodes += bool(associated)
            previous = moment
        # Unlocks before the first observed lockout are not evidence for re-lock.
        observed_unlocks = released[bisect_right(release_times, episodes[0]["time_created_utc"]):]
        codes = sorted({code for event in matched for code in _codes(event)})
        callers = sorted({_text((event.get("facts_json") or {}).get("caller_computer")) for event in episodes} - {None})
        ips = sorted({_text(event.get("ip_address")) for event in [*episodes, *matched]} - {None})
        workstations = sorted({_text(event.get("workstation_name")) or _text((event.get("facts_json") or {}).get("workstation"))
                               for event in [*episodes, *matched]} - {None})
        if caller and caller.casefold() not in {value.casefold() for value in [*callers, *ips, *workstations]}:
            continue
        if failure_code and failure_code.casefold() not in codes:
            continue
        semantic_missing = any(not event.get("normalized_event_id") for event in [*episodes, *matched, *observed_unlocks])
        rows.append({
            "account_key": identity, "account": episodes[-1].get("target_user_name") or sid,
            "sid": episodes[0].get("target_user_sid") if sid else None,
            "first_lockout": security.format_iso(episodes[0]["time_created_utc"]),
            "last_lockout": security.format_iso(episodes[-1]["time_created_utc"]),
            "lockouts": len(episodes), "relocks": relocks, "unlocks": len(observed_unlocks),
            "callers": callers, "ips": ips, "workstations": workstations, "failure_codes": codes,
            "failures": len(matched), "matched_lockouts": matched_episodes,
            "intervals_seconds": intervals, "last_interval_seconds": intervals[-1] if intervals else None,
            "matching": "unknown_sid" if not sid else "partial" if truncated or semantic_missing
            else "all_with_failures" if matched_episodes == len(episodes) else "some_with_failures" if matched_episodes else "no_failures",
            "caller_lockouts": sum(bool(_text((event.get("facts_json") or {}).get("caller_computer"))) for event in episodes),
            "first_event": episodes[0]["event_db_id"], "last_event": episodes[-1]["event_db_id"],
            "unlock_event": observed_unlocks[-1]["event_db_id"] if observed_unlocks else None,
            "failure_event": matched[-1]["event_db_id"] if matched else None,
            "event_ids": [event["event_db_id"] for event in [*episodes, *observed_unlocks, *matched]],
        })
    return sorted(rows, key=lambda row: (-row["lockouts"], row["account_key"]))


def get_recurring_lockouts(access: Mapping[str, Any], *, domain_id: int, time_from: str, time_to: str,
                          limit: int, account: str | None = None, caller: str | None = None,
                          failure_code: str | None = None, minimum_repeats: int = 2,
                          failure_window_minutes: int = 15, action: str = "view") -> dict[str, Any]:
    start, end = security.parse_utc(time_from), security.parse_utc(time_to)
    if start is None or end is None or start >= end or end - start > timedelta(days=security.MAX_PERIOD_DAYS):
        raise ValueError("security_events_period_too_wide")
    if domain_id <= 0 or not 1 <= limit <= security.MAX_ROWS or minimum_repeats < 1:
        raise ValueError("security_events_filter_invalid")
    if not 1 <= failure_window_minutes <= MAX_FAILURE_WINDOW_MINUTES or action not in {"view", "export"}:
        raise ValueError("security_events_filter_invalid")
    if not security._read_access_allowed(access, domain_id, action=action):
        return {"state": "denied", "rows": []}
    with security._connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute("set local statement_timeout='3000ms'")
        locks, locks_cut = _read_events(cur, domain_id=domain_id, start=start, end=end, event_ids=[4740], limit=MAX_SOURCE_ROWS)
        unlocks, unlocks_cut = _read_events(cur, domain_id=domain_id, start=start, end=end, event_ids=[4767], limit=MAX_SOURCE_ROWS)
        failures, failures_cut = _read_events(cur, domain_id=domain_id, start=start - timedelta(minutes=failure_window_minutes),
                                              end=end, event_ids=[4625, 4771, 4776], limit=MAX_FAILURE_ROWS)
    truncated = locks_cut or unlocks_cut or failures_cut
    events = [*locks, *unlocks, *failures]
    rows = aggregate_lockouts(events, failure_window_minutes=failure_window_minutes, minimum_repeats=minimum_repeats,
                              account=account, caller=caller, failure_code=failure_code, truncated=truncated)
    lockout_count = sum(row["lockouts"] for row in rows)
    return {
        "state": "partial" if truncated or len(rows) > limit else "ok" if rows else "empty",
        "rows": rows[:limit], "filtered_count": len(rows),
        "coverage": {"state": "bounded_slice" if truncated else "coverage_unverified", "completeness": "not_proven",
                     "source_truncated": truncated, "accounts_truncated": len(rows) > limit,
                     "unknown_sid_lockouts": sum(_sid(event) is None for event in locks),
                     "unmatched_identity_failures": sum(_sid(event) is None and _is_failure(event) for event in failures),
                     "missing_current_semantics": sum(not event.get("normalized_event_id") for event in events)},
        "totals": {"accounts": sum(row["lockouts"] >= 2 and row["sid"] is not None for row in rows),
                   "lockouts": lockout_count, "relocked_accounts": sum(row["relocks"] > 0 for row in rows),
                   "caller_percent": round(100 * sum(row["caller_lockouts"] for row in rows) / lockout_count, 1) if lockout_count else None,
                   "sources": len({(kind, value.casefold()) for row in rows for kind in ("callers", "ips", "workstations") for value in row[kind]})},
        "window": {"from_utc": security.format_iso(start), "to_utc_exclusive": security.format_iso(end),
                   "failure_window_minutes": failure_window_minutes, "idea_key": IDEA_KEY,
                   "source_row_limits": {"lockouts": MAX_SOURCE_ROWS, "unlocks": MAX_SOURCE_ROWS, "failures": MAX_FAILURE_ROWS}},
    }
