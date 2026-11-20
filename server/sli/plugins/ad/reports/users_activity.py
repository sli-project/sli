"""Bounded observations for the Users report; sequences are not causal proof."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from psycopg import errors

from server.sli.core.database import query_rows_bounded

SCAN_LIMIT = 10_000
MEMBERSHIP_PAIRS = {4728: 4729, 4732: 4733, 4756: 4757}
MEMBERSHIP_IDS = [*MEMBERSHIP_PAIRS, *MEMBERSHIP_PAIRS.values()]
CHAIN = "investigation.group.membership.removed-after-add"
UNREADABLE = (errors.UndefinedTable, errors.UndefinedColumn, errors.InsufficientPrivilege)


def window(params: Any) -> tuple[datetime, datetime, int, int]:
    period = params.get("period") or {}
    end = _utc(period.get("to_utc")) or datetime.now(timezone.utc)
    start = _utc(period.get("from_utc")) or end - timedelta(days=7)
    minutes = int(params.get("max_minutes") or 60)
    repeats = int(params.get("min_repeats") or 1)
    if not timedelta(0) < end - start <= timedelta(days=31):
        raise ValueError("users_activity_period_invalid")
    if not 1 <= minutes <= 1440 or not 1 <= repeats <= 100:
        raise ValueError("users_activity_threshold_invalid")
    return start, end, minutes, repeats


def _utc(value: Any) -> datetime | None:
    if not value:
        return None
    at = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return at.replace(tzinfo=timezone.utc) if at.tzinfo is None else at.astimezone(timezone.utc)


def event_sql(domain_ids: list[int] | None, event_ids: list[int], start: datetime, end: datetime) -> tuple[str, list[Any]]:
    scope = " and e.domain_id=any(?)" if domain_ids is not None else ""
    # Bound the indexed source scan BEFORE semantic joins. Select the current
    # interpretation before inspecting its status, so ignored replays stay ignored.
    sql = f"""with source_page as (
        select e.* from events_v2_core e
        where e.event_id=any(?) and e.time_created_utc>=? and e.time_created_utc<?{scope}
        order by e.time_created_utc desc,e.id desc limit ?
    ) select e.id,e.domain_id,e.event_id,e.time_created_utc,
        coalesce(nullif(btrim(e.target_user_sid),''),nullif(btrim(f.account_target_sid),'')) as target_user_sid,
        e.subject_user_sid,e.server_id,e.ip_address,f.logon_type,
        f.membership_member_sid,n.normalized_event_id,n.processing_status,n.semantic_type,
        n.facts_json
    from source_page e
    left join event_facts_v2 f on f.event_id=e.id
    left join lateral (
        select n.normalized_event_id,n.processing_status,n.semantic_type,n.facts_json
        from normalized_events n where n.source_event_id=e.id
        order by n.semantic_contract_version desc,n.normalized_at desc,n.normalized_event_id desc limit 1
    ) n on true
    order by e.time_created_utc,e.id"""
    return sql, [event_ids, start, end, *([domain_ids] if domain_ids is not None else []), SCAN_LIMIT + 1]


def _read(sql: str, params: Any) -> list[dict[str, Any]]:
    return query_rows_bounded(sql, tuple(params), statement_timeout_ms=10_000)


def _identities(current: dict[str, Any], domain_ids: list[int] | None) -> tuple[dict, dict, bool]:
    users = {int(u["entityId"]): u for u in current.get("users") or [] if u.get("entityId")}
    groups = {int(str(g["id"]).split(":")[1]): g for g in (current.get("metadata") or {}).get("watch_groups") or []
              if str(g.get("id", "")).startswith("group:") and g.get("watchGroup") is True}
    ids = sorted(users.keys() | groups.keys())
    if not ids:
        return {}, {}, False
    scope = " and e.domain_id=any(?)" if domain_ids is not None else ""
    rows = _read(f"""select a.entity_id,e.domain_id,a.alias_value as sid
        from ad_context_entity_aliases a join entities_v2 e on e.id=a.entity_id
        where a.entity_id=any(?) and a.alias_type='object_sid'{scope}
        order by a.entity_id,a.alias_value limit ?""", [ids, *([domain_ids] if domain_ids is not None else []), SCAN_LIMIT + 1])
    # Multiple exact aliases pointing at different entities are ambiguous.
    by_key: dict[tuple, set[int]] = defaultdict(set)
    for row in rows:
        by_key[(row["domain_id"], row["sid"])].add(int(row["entity_id"]))
    return (
        {key: users[next(iter(values))] for key, values in by_key.items() if len(values) == 1 and next(iter(values)) in users},
        {key: groups[next(iter(values))] for key, values in by_key.items() if len(values) == 1 and next(iter(values)) in groups},
        len(rows) > SCAN_LIMIT,
    )


def _candidates(events: list[dict[str, Any]], start: datetime, end: datetime) -> dict[int, dict]:
    anchors = [str(e["normalized_event_id"]) for e in events if e["event_id"] in MEMBERSHIP_PAIRS and e.get("normalized_event_id")]
    if not anchors:
        return {}
    rows = _read("""select distinct on (anchor.source_event_id)
        anchor.source_event_id as add_id,c.candidate_id,c.evidence_count,c.confidence
        from semantic_correlation_candidate_evidence ae
        join normalized_events anchor on anchor.normalized_event_id=ae.normalized_event_id
        join semantic_correlation_candidates c on c.candidate_id=ae.candidate_id
        where ae.normalized_event_id=any(?::uuid[]) and ae.evidence_order=0
          and c.rule_id=? and c.candidate_status='matched'
          and c.window_start_utc>=? and c.window_start_utc<?
          and not exists (select 1 from semantic_correlation_rules r where r.rule_id=c.rule_id
              and r.rule_version>c.rule_version and r.lifecycle_status in ('shadow','enabled'))
          and not exists (
              select 1 from semantic_correlation_candidate_evidence ce
              join normalized_events old on old.normalized_event_id=ce.normalized_event_id
              where ce.candidate_id=c.candidate_id and old.normalized_event_id<>(
                  select latest.normalized_event_id from normalized_events latest
                  where latest.source_event_id=old.source_event_id
                  order by latest.semantic_contract_version desc,latest.normalized_at desc,latest.normalized_event_id desc limit 1))
        order by anchor.source_event_id,c.rule_version desc,c.last_matched_at desc,c.candidate_id
        limit ?""", [anchors, CHAIN, start, end, SCAN_LIMIT])
    return {int(row["add_id"]): row for row in rows}


def _principal(event: dict[str, Any]) -> tuple[Any, Any]:
    sid = event.get("subject_user_sid") if event["event_id"] == 6272 else event.get("target_user_sid")
    return event["domain_id"], sid


def shape(current: dict[str, Any], events: list[dict[str, Any]], identities: dict, groups: dict,
          candidates: dict, *, max_minutes: int, min_repeats: int) -> dict[str, Any]:
    # SQL already selects one version; source IDs remain the unit of counting.
    unique = {int(e["id"]): e for e in events}
    ordered = sorted(unique.values(), key=lambda e: (_utc(e["time_created_utc"]), e["id"]))
    usable = [e for e in ordered if e.get("processing_status") == "normalized"]
    auth: dict[tuple, list[dict]] = defaultdict(list)
    lifecycle: dict[tuple, list[dict]] = defaultdict(list)
    membership: dict[tuple, list[dict]] = defaultdict(list)
    unknown = 0
    for event in usable:
        code = event["event_id"]
        key = _principal(event)
        if code in {4624, 6272}:
            expected = "authentication.session.created" if code == 4624 else "remote_access.authentication.allowed"
            if event.get("semantic_type") != expected:
                continue
            if key[1] and key in identities:
                auth[key].append(event)
            else:
                unknown += 1
        elif code in {4722, 4725}:
            if event.get("semantic_type") != ("directory.account.enabled" if code == 4722 else "directory.account.disabled"):
                continue
            if key[1] and key in identities:
                lifecycle[key].append(event)
            else:
                unknown += 1
        elif code in MEMBERSHIP_IDS:
            if event.get("semantic_type") != ("group.member.added" if code in MEMBERSHIP_PAIRS else "group.member.removed"):
                continue
            facts = event.get("facts_json") or {}
            member = facts.get("relation_member_sid") or event.get("membership_member_sid")
            group = facts.get("relation_group_sid") or event.get("target_user_sid")
            key = (event["domain_id"], member)
            if not member or key not in identities or not group:
                unknown += 1
            elif (event["domain_id"], group) in groups:
                membership[(event["domain_id"], member, group)].append(event)
    disabled = []
    for key, changes in lifecycle.items():
        user = identities[key]
        if user.get("enabled") is not False or changes[-1]["event_id"] != 4725:
            continue
        disable = changes[-1]
        at = _utc(disable["time_created_utc"])
        for event in auth.get(key, []):
            activity = _utc(event["time_created_utc"])
            if activity <= at:
                continue
            disabled.append({"id": str(event["id"]), "entity_id": user["entityId"], "display_name": user.get("displayName"),
                             "disabled_at": at.isoformat(), "activity_at": activity.isoformat(), "activity_type": str(event["event_id"]),
                             "delay_minutes": round((activity - at).total_seconds() / 60, 2), "source_id": event["server_id"],
                             "logon_type": event.get("logon_type"), "evidence": [disable["id"], event["id"]], "quality": "exact_sid"})
    temporary = []
    for key, changes in membership.items():
        domain, member, group_sid = key
        user, group = identities[(domain, member)], groups[(domain, group_sid)]
        for index, add in enumerate(changes):
            if add["event_id"] not in MEMBERSHIP_PAIRS:
                continue
            at = _utc(add["time_created_utc"])
            removals = []
            for follow in changes[index + 1:]:
                elapsed = (_utc(follow["time_created_utc"]) - at).total_seconds() / 60
                if elapsed > max_minutes or follow["event_id"] in MEMBERSHIP_PAIRS:
                    break
                if elapsed > 0 and follow["event_id"] == MEMBERSHIP_PAIRS[add["event_id"]]:
                    removals.append(follow)
            if not removals:
                continue
            candidate = candidates.get(add["id"], {})
            ambiguous = len(removals) > 1 or int(candidate.get("evidence_count") or 0) > 2
            end = _utc(removals[0]["time_created_utc"])
            during = [e["id"] for e in auth.get((domain, member), []) if at < _utc(e["time_created_utc"]) < end]
            temporary.append({"id": str(add["id"]), "entity_id": user["entityId"], "display_name": user.get("displayName"),
                              "group_id": group["id"], "group": group.get("name"), "added_at": at.isoformat(),
                              "removed_at": None if ambiguous else end.isoformat(),
                              "interval_minutes": None if ambiguous else round((end - at).total_seconds() / 60, 2),
                              "added_by": add.get("subject_user_sid"), "removed_by": [e.get("subject_user_sid") for e in removals],
                              "activity_count": None if ambiguous else len(during), "activity_evidence": [] if ambiguous else during,
                              "evidence": [add["id"], *[e["id"] for e in removals]],
                              "candidate_id": str(candidate["candidate_id"]) if candidate else None,
                              "quality": "ambiguous" if ambiguous else "observed_pair", "_key": key})
    repeats = Counter(row["_key"] for row in temporary)
    for row in temporary:
        row["repeats"] = repeats[row.pop("_key")]
    temporary = [row for row in temporary if row["repeats"] >= min_repeats]
    return {"disabled_active": disabled, "temporary_memberships": temporary, "unknown_identity_events": unknown,
            "unprocessed_events": sum(e.get("processing_status") != "normalized" for e in ordered)}


def load(current: dict[str, Any], domain_ids: list[int] | None, params: Any, *, disabled: bool = False) -> dict[str, Any]:
    start, end, minutes, repeats = window(params)
    empty = {"disabled_active": [], "temporary_memberships": [], "unknown_identity_events": 0, "unprocessed_events": 0,
             "state": "partial", "truncated": False, "window": {"from_utc": start.isoformat(), "to_utc_exclusive": end.isoformat()}}
    if domain_ids == []:
        return empty
    try:
        identities, groups, truncated = _identities(current, domain_ids)
        if not identities or (not disabled and not groups):
            return {**empty, "truncated": truncated}
        events = []
        scans = [[4722, 4725], [4624, 6272]] if disabled else [MEMBERSHIP_IDS, [4624, 6272]]
        for ids in scans:
            sql, values = event_sql(domain_ids, ids, start, end)
            batch = _read(sql, values)
            truncated |= len(batch) > SCAN_LIMIT
            events.extend(batch[-SCAN_LIMIT:])  # final SQL order is ascending
        candidates = {} if disabled else _candidates(events, start, end)
        return {**empty, **shape(current, events, identities, groups, candidates, max_minutes=minutes, min_repeats=repeats), "truncated": truncated}
    except UNREADABLE:
        return {**empty, "state": "unavailable"}
