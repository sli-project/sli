"""Bounded observation history of services and scheduled tasks on DCs."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any
from xml.etree.ElementTree import ParseError

from server.sli.reports import security_event_reporting as security
from server.sli.semantic.semantic_processing import (
    NORMALIZER_ID,
    NORMALIZER_VERSION,
    SEMANTIC_CONTRACT_VERSION,
)
from server.sli.storage.xml_safety import UnsafeXmlError, parse_bounded_xml

IDEA_KEY = "security.persistence-changes"
MAX_SOURCE_ROWS = 10_000
EVENT_IDS = [4697, 4698, 4699, 4700, 4701, 4702, 7045]
CHANGES = {4697: "installed", 7045: "installed", 4698: "created", 4699: "deleted",
           4700: "enabled", 4701: "disabled", 4702: "updated"}


def _text(value: Any) -> str | None:
    text = security.clean_text(value)
    return None if text in {None, "-"} else text


def _read_events(cur: Any, *, domain_id: int, start: datetime, end: datetime,
                 limit: int) -> tuple[list[dict[str, Any]], bool]:
    # The tuple pinned here is unique per source event (migration 022).
    # Event ID/time and server/time predicates have Storage V2 indexes (009).
    cur.execute(
        """select event.id as event_db_id,event.event_id,event.domain_id,event.server_id,
                  server.hostname as dc,event.time_created_utc,
                  facts.service_name,facts.service_file,facts.service_account,facts.service_start_type,
                  facts.task_name,facts.task_content,facts.task_change,facts.task_action,facts.run_as,
                  facts.process_user_sid,facts.process_user_name,facts.process_user_domain,
                  normalized.normalized_event_id
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
              and server.role='domain_controller'
              and ((event.event_id=7045 and channel.value=%s and provider.value=%s)
                or (event.event_id<>7045 and channel.value=%s and provider.value=%s))
            order by event.time_created_utc desc,event.id desc limit %s""",
        [SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION, domain_id, EVENT_IDS, start, end,
         "System", "Service Control Manager", security.SECURITY_CHANNEL, security.SECURITY_AUDITING_PROVIDER, limit + 1],
    )
    rows = [dict(row) for row in cur.fetchall()]
    return rows[:limit], len(rows) > limit


def _task_values(event: Mapping[str, Any]) -> tuple[str | None, str | None]:
    content = event.get("task_content")
    if not content:
        action = _text(event.get("task_action"))
        # Older facts may contain truncated Task XML in task_action.
        return action if action and "<" not in action else None, _text(event.get("run_as"))
    try:
        root = parse_bounded_xml(str(content), max_bytes=8192, max_depth=32, max_nodes=2048)
    except (ParseError, UnsafeXmlError, UnicodeError):
        return None, _text(event.get("run_as"))
    principals = root.findall("./{*}Principals/{*}Principal")
    # Multiple principals cannot be collapsed into an invented RunAs identity.
    run_as = _text(event.get("run_as"))
    if not run_as and len(principals) == 1:
        run_as = _text(principals[0].findtext("{*}UserId")) or _text(principals[0].findtext("{*}GroupId"))
    actions = []
    for action in root.findall("./{*}Actions/*"):
        kind = action.tag.rsplit("}", 1)[-1]
        if kind == "Exec":
            command = _text(action.findtext("{*}Command"))
            if command:
                parts = [command, _text(action.findtext("{*}Arguments"))]
                directory = _text(action.findtext("{*}WorkingDirectory"))
                actions.append(" ".join(part for part in parts if part) + (f" ({directory})" if directory else ""))
        else:
            # Preserve non-Exec actions without claiming they are executable paths.
            parts = [f"{child.tag.rsplit('}', 1)[-1]}={child.text or ''}" for child in action]
            actions.append(f"{kind}: " + "; ".join(parts))
    return "; ".join(actions) or None, run_as


def _observation(event: Mapping[str, Any]) -> dict[str, Any]:
    sid = _text(event.get("process_user_sid"))
    if not sid or not sid.casefold().startswith("s-1-") or sid.casefold() == "s-1-0-0":
        sid = None
    return {"event_db_id": event["event_db_id"], "event_id": event["event_id"],
            "initiator_sid": sid, "initiator_name": _text(event.get("process_user_name")),
            "initiator_domain": _text(event.get("process_user_domain")),
            "href": f"/app/events/{event['event_db_id']}"}


def shape_history(events: Sequence[Mapping[str, Any]], *, truncated: bool = False,
                  source: str | None = None, object_type: str | None = None, path: str | None = None,
                  initiator: str | None = None, change: str | None = None,
                  max_frequency: int | None = None) -> list[dict[str, Any]]:
    unique = {int(event["event_db_id"]): event for event in events}
    ordered = sorted(unique.values(), key=lambda event: (event["time_created_utc"], event["event_db_id"]))
    pairs: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    if not truncated:
        for event in ordered:
            values = tuple(_text(event.get(key)) for key in
                           ("service_name", "service_file", "service_account", "service_start_type"))
            if event["event_id"] in {4697, 7045} and event.get("normalized_event_id") and all(values) and event.get("server_id"):
                pairs[(event.get("domain_id"), event["server_id"], event["time_created_utc"], *values)].append(event)
    linked = {}
    consumed = set()
    for candidates in pairs.values():
        if len(candidates) == 2 and {event["event_id"] for event in candidates} == {4697, 7045}:
            primary = next(event for event in candidates if event["event_id"] == 4697)
            secondary = next(event for event in candidates if event["event_id"] == 7045)
            linked[primary["event_db_id"]] = secondary
            consumed.add(secondary["event_db_id"])
    objects: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for event in ordered:
        if event["event_db_id"] in consumed:
            continue
        kind = "service" if event["event_id"] in {4697, 7045} else "task"
        name = _text(event.get("service_name" if kind == "service" else "task_name"))
        known = bool(name and event.get("server_id") and event.get("normalized_event_id"))
        key = (event.get("domain_id"), event.get("server_id"), kind, name) if known else ("unknown", event["event_db_id"])
        action, run_as = (_text(event.get("service_file")), _text(event.get("service_account"))) if kind == "service" else _task_values(event)
        observations = [_observation(event)]
        other = linked.get(event["event_db_id"])
        if other:
            observations.append(_observation(other))
        actor = observations[0]
        objects[key].append({
            "event_db_id": event["event_db_id"], "linked_event": other["event_db_id"] if other else None,
            "dc": _text(event.get("dc")), "object": name, "object_type": kind, "object_key": key,
            "change": _text(event.get("task_change")) or CHANGES[event["event_id"]],
            "action": action, "run_as": run_as, "service_start_type": _text(event.get("service_start_type")) if kind == "service" else None,
            "initiator": actor["initiator_sid"] or actor["initiator_name"], "initiator_sid": actor["initiator_sid"],
            "initiator_quality": "exact_sid" if all(item["initiator_sid"] for item in observations)
                                 else "partially_known" if any(item["initiator_sid"] for item in observations) else "unknown_sid",
            "observed_at": security.format_iso(event["time_created_utc"]), "_time": event["time_created_utc"],
            "quality": "missing_semantics" if not event.get("normalized_event_id") else "unknown_object" if not known
                       else "exact_link" if other else "exact_object",
            "observations": observations, "event_ids": [item["event_db_id"] for item in observations],
            "evidence": [f"{item['event_id']}: {item['href']}" for item in observations],
            "task_content": None,
        })
    rows = []
    for history in objects.values():
        first, last = history[0]["observed_at"], history[-1]["observed_at"]
        previous = None
        by_time: dict[datetime, list[dict[str, Any]]] = defaultdict(list)
        for row in history:
            by_time[row["_time"]].append(row)
        for same_time in by_time.values():
            values = [{key: row[key] for key in ("action", "run_as", "service_start_type", "change")} for row in same_time]
            for row in same_time:
                row.update(first_seen=first, last_seen=last, frequency=len(history), previous=previous,
                           previous_value=previous["action"] if previous else None)
                if len(same_time) > 1:
                    row["quality"] = "ambiguous_order"
                if truncated:
                    row["quality"] = "partial"
                rows.append(row)
            previous = values[0] if all(value == values[0] for value in values) else None
    def contains(value: Any, needle: str | None) -> bool:
        return not needle or needle.casefold() in str(value or "").casefold()
    rows = [row for row in rows if contains(row["dc"], source) and (not object_type or row["object_type"] == object_type)
            and contains(row["action"], path) and (not change or row["change"] == change)
            and (not max_frequency or row["frequency"] <= max_frequency)
            and (not initiator or any(contains(item["initiator_sid"], initiator) or contains(item["initiator_name"], initiator)
                                      for item in row["observations"]))]
    rows.sort(key=lambda row: (row["_time"], row["event_db_id"]), reverse=True)
    for row in rows:
        del row["_time"]
    return rows


def get_persistence_changes(access: Mapping[str, Any], *, domain_id: int, time_from: str, time_to: str,
                            limit: int, source: str | None = None, object_type: str | None = None,
                            path: str | None = None, initiator: str | None = None, change: str | None = None,
                            max_frequency: int | None = None, action: str = "view") -> dict[str, Any]:
    start, end = security.parse_utc(time_from), security.parse_utc(time_to)
    if start is None or end is None or start >= end or end - start > timedelta(days=security.MAX_PERIOD_DAYS):
        raise ValueError("security_events_period_too_wide")
    if domain_id <= 0 or not 1 <= limit <= security.MAX_ROWS or action not in {"view", "export"}:
        raise ValueError("security_events_filter_invalid")
    if object_type not in {None, "service", "task"} or change not in {None, *CHANGES.values()} or (max_frequency is not None and max_frequency < 1):
        raise ValueError("security_events_filter_invalid")
    if not security._read_access_allowed(access, domain_id, action=action):
        return {"state": "denied", "rows": []}
    with security._connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute("set local statement_timeout='3000ms'")
        events, cut = _read_events(cur, domain_id=domain_id, start=start, end=end, limit=MAX_SOURCE_ROWS)
    rows = shape_history(events, truncated=cut, source=source, object_type=object_type, path=path,
                         initiator=initiator, change=change, max_frequency=max_frequency)
    path_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        if row["action"]:
            path_counts[row["action"]] += 1
    def known_objects(predicate):
        return {row["object_key"] for row in rows if row["object_key"][0] != "unknown" and predicate(row)}
    missing = sum(not event.get("normalized_event_id") for event in events)
    return {
        "state": "partial" if cut or len(rows) > limit or missing else "ok" if rows else "empty",
        "rows": rows[:limit], "filtered_count": len(rows),
        "totals": {"new_services": len(known_objects(lambda row: row["object_type"] == "service" and row["change"] == "installed")),
                   "new_tasks": len(known_objects(lambda row: row["object_type"] == "task" and row["change"] == "created")),
                   "changed_actions": len(known_objects(lambda row: row["action"] is not None and row["previous"] is not None
                                                        and row["previous"]["action"] is not None and row["action"] != row["previous"]["action"])),
                   "rare_paths": sum(count <= (max_frequency or 1) for count in path_counts.values()),
                   "repeated_objects": len(known_objects(lambda row: row["frequency"] > 1)),
                   "unknown_initiator": sum(not item["initiator_sid"] for row in rows for item in row["observations"])},
        "coverage": {"state": "bounded_slice" if cut else "coverage_unverified", "completeness": "not_proven",
                     "source_truncated": cut, "rows_truncated": len(rows) > limit,
                     "missing_current_semantics": missing},
        "window": {"from_utc": security.format_iso(start), "to_utc_exclusive": security.format_iso(end),
                   "idea_key": IDEA_KEY, "source_row_limit": MAX_SOURCE_ROWS},
    }
