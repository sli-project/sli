"""C05 native creation episodes, evaluated inside the WR05 publication fence.

Only an exact, unique Security/System installation pair shares an episode.
Matching configurations provide a bulk-review candidate, not proof of one
installer or a complete inventory. Native event time is never import time.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import json
import re

from .check_catalog import BY_ID
from .importer import digest
from .normalizers import SECURITY_PROVIDER, text
from .overview_contracts import Quality, Reason

PROJECTOR = "workstations.C05"
RULE_VERSION = BY_ID["C05"].rule_version
MAX_OBJECT_EVENTS = 200
CHANGES = {4697: "installed", 7045: "installed", 4698: "created", 4699: "deleted",
           4700: "enabled", 4701: "disabled", 4702: "updated"}
QUALITY = Quality("partial", (Reason("service_task_baseline_unknown"),)).to_dict()


def _stamp(value):
    stamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if stamp.utcoffset() is None:
        raise ValueError("workstation_c05_timestamp_invalid")
    return stamp.astimezone(timezone.utc)


def _exact(facts, key, limit=512):
    value = facts.get(key)
    # Truncated prefixes must never become an exact installation identity.
    if not isinstance(value, str) or len(value.encode("utf-8")) > limit:
        return None
    return text(facts, key, limit=limit)


def event(row, station_id):
    number, observation = row["event_id"], row["observation"]
    expected = ("System", "Service Control Manager") if number == 7045 else ("Security", SECURITY_PROVIDER)
    if (row.get("family") != "processes" or number not in CHANGES
            or tuple(str(observation.get(key, "")).casefold() for key in ("channel", "provider_name"))
            != tuple(value.casefold() for value in expected)):
        return None
    if not isinstance(row["id"], str) or not re.fullmatch(r"[a-f0-9]{64}", row["id"]):
        raise ValueError("workstation_c05_observation_id_invalid")
    facts = observation.get("facts", {})
    kind = "service" if number in (4697, 7045) else "task"
    actor = {"kind": "workstation_account", "station_id": station_id, "ad_entity_id": None,
             "sid": None, "name": None, "domain": None, "status": "unknown"}
    # RunAs/AccountName on 7045 describes the service account, not the installer.
    if number != 7045:
        sid = text(facts, "process_user_sid")
        actor.update(sid=sid if sid and re.fullmatch(r"S-1-\d+(?:-\d+)+", sid, re.IGNORECASE)
                     and sid.upper() != "S-1-0-0" else None,
                     name=text(facts, "process_user_name"), domain=text(facts, "process_user_domain"))
        if actor["sid"] or actor["name"]:
            actor["status"] = "observed"
    content = _exact(facts, "task_content", limit=8192)
    record = observation.get("record_id")
    return {"id": row["id"], "agent_key": row["agent_key"], "event_id": number, "kind": kind,
            "name": _exact(facts, f"{kind}_name"), "change": CHANGES[number], "at": _stamp(row["observed_at"]),
            "program": _exact(facts, "service_file", limit=2048), "run_as": _exact(facts, "service_account"),
            "start_type": _exact(facts, "service_start_type"), "content_sha256": digest(content) if content else None,
            "actor": actor, "generation": text(observation, "generation"),
            "record_id": record if type(record) is int and record >= 0 else None,
            "ref": {"kind": "workstation_observation", "observation_id": row["id"],
                    "agent_key": row["agent_key"], "source_sha256": observation.get("source_sha256")}}


def _configuration(item):
    if item["kind"] == "service":
        fields = [item[key] for key in ("program", "run_as", "start_type")]
    else:
        fields = [item["content_sha256"]]
    return [item["kind"], *fields] if all(fields) else None


def _pair_key(item, station_id):
    config = _configuration(item)
    if item["kind"] == "service" and item["name"] and config:
        return digest([PROJECTOR, RULE_VERSION, station_id, item["agent_key"],
                       item["at"].isoformat(), item["name"], config])
    return None


def _episode_id(station_id, item):
    return digest([PROJECTOR, RULE_VERSION, station_id, item["id"]])


def _after(later, earlier):
    if later["at"] != earlier["at"]:
        return later["at"] > earlier["at"]
    return bool(later["generation"] and later["generation"] == earlier["generation"]
                and later["record_id"] is not None and earlier["record_id"] is not None
                and later["record_id"] > earlier["record_id"])


def _order(item):
    return item["at"], item["generation"] or "", item["record_id"] or 0, item["id"]


def episodes(events, station_id):
    """Return stable episode IDs and obsolete ambiguous aggregate IDs.

    A singleton with a complete installation signature uses the future pair's
    ID, so either native arrival order preserves first detection and review refs.
    If another native record makes that signature ambiguous, retain the old
    aggregate as a resolved superseded row and publish separate native episodes.
    """
    buckets, groups, superseded = defaultdict(list), [], []
    for item in sorted(events, key=_order):
        if item["change"] not in ("installed", "created"):
            continue
        key = _pair_key(item, station_id)
        if key:
            buckets[key].append(item)
        else:
            groups.append((_episode_id(station_id, item), [item], "separate"))
    for key, items in buckets.items():
        counts = [sum(item["event_id"] == number for item in items) for number in (4697, 7045)]
        if max(counts) == 1:
            groups.append((key, items, "exact_pair" if len(items) == 2 else "single"))
        else:
            superseded.append(key)
            groups.extend((_episode_id(station_id, item), [item], "ambiguous") for item in items)
    return groups, superseded


def finding(identifier, items, dedup_status, events, station_id, detected_at):
    first = min(items, key=_order)
    # Only Security has native actor evidence, including when System arrived first.
    actor = next((item["actor"] for item in items if item["event_id"] != 7045), first["actor"])
    deletion = next((item for item in sorted(events, key=_order)
                     if first["kind"] == "task" and first["name"] and item["name"] == first["name"]
                     and item["change"] == "deleted" and _after(item, first)), None)
    refs = [item["ref"] for item in sorted(items, key=_order)] + ([deletion["ref"]] if deletion else [])
    config = _configuration(first)
    params = {"object_kind": first["kind"], "object_name": first["name"], "change": first["change"],
              "program": first["program"], "run_as": first["run_as"], "start_type": first["start_type"],
              "content_sha256": first["content_sha256"],
              **{f"actor_{key}": actor[key] for key in ("sid", "name", "domain", "status")},
              "created_at": first["at"].isoformat(), "deleted_at": deletion["at"].isoformat() if deletion else None,
              "history_start_at": min(item["at"] for item in events).isoformat(),
              "baseline_status": "unknown", "current_presence": "unknown", "dedup_status": dedup_status,
              "common_cause_id": digest([PROJECTOR, "configuration", config]) if config else None,
              "common_cause_basis": "matching_configuration" if config else "unknown"}
    subject = {"kind": f"workstation_{first['kind']}", "station_id": station_id, "name": first["name"]}
    return {"id": identifier, "station_id": station_id, "check_id": "C05", "rule_version": RULE_VERSION,
            "subject_id": digest([first["kind"], first["name"]]) if first["name"] else None,
            "subject_ref": subject, "episode_id": identifier, "condition_sha256": digest([params, refs]),
            "severity": "medium", "status": "resolved" if deletion else "active", "fact_at": first["at"],
            "first_detected_at": detected_at, "last_observed_at": deletion["at"] if deletion else first["at"],
            "materially_changed_at": detected_at, "resolved_at": detected_at if deletion else None,
            "reason_code": "service_or_task_changed", "reason_params": params,
            "quality": QUALITY, "evidence_refs": refs}


def _insert(cur, table, row, conflict):
    slots = ["%s::jsonb" if isinstance(value, (dict, list)) else "%s" for value in row.values()]
    values = tuple(json.dumps(value) if isinstance(value, (dict, list)) else value for value in row.values())
    cur.execute(f"""insert into sli_plugin_workstations.{table} ({','.join(row)})
        values ({','.join(slots)}) on conflict(id) {conflict}""", values)


def _save_finding(cur, row):
    updates = [f"{key}=excluded.{key}" for key in (
        "condition_sha256", "status", "last_observed_at", "materially_changed_at", "reason_params", "evidence_refs")]
    _insert(cur, "check_findings", row, f"""do update set {','.join(updates)},
        resolved_at=case when check_findings.status='resolved' and excluded.status='resolved'
            then check_findings.resolved_at else excluded.resolved_at end,
        revision=check_findings.revision+1
        where check_findings.condition_sha256<>excluded.condition_sha256""")


def _save_change(cur, item, station_id, detected_at):
    change = f"{item['kind']}_{item['change']}"
    _insert(cur, "station_changes", {
        "id": digest([PROJECTOR, "change", station_id, item["id"]]), "station_id": station_id,
        "change_kind": change, "event_at": item["at"], "detected_at": detected_at,
        "actor_ref": item["actor"],
        "subject_ref": {"kind": f"workstation_{item['kind']}", "station_id": station_id, "name": item["name"]},
        "reason_code": change, "reason_params": {}, "quality": QUALITY, "evidence_refs": [item["ref"]],
    }, "do nothing")


def apply(conn, station_id, fact):
    if fact["kind"] != "observations":
        return
    current = event(fact["payload"], station_id)
    if current is None:
        return
    with conn.cursor() as cur:
        cur.execute("set local statement_timeout='5000ms'")
        cur.execute("select transaction_timestamp() as detected_at")
        detected_at = cur.fetchone()["detected_at"]
        # WR05 inputs survive hot observation retention. Never read XML or scan
        # ClickHouse inside publication. Overflow leaves the receipt pending.
        cur.execute("""select payload from sli_plugin_workstations.projection_work
            where kind='observations' and agent_key=%s and payload->>'family'='processes'
              and payload->>'event_id'=any(%s)
              and payload->'observation'->'facts'->>%s is not distinct from %s
            order by work_id limit %s""",
            (current["agent_key"], [str(n) for n in ((4697, 7045) if current["kind"] == "service"
                                                   else (4698, 4699, 4700, 4701, 4702))],
             f"{current['kind']}_name", current["name"], MAX_OBJECT_EVENTS + 1))
        rows = cur.fetchall()
        if len(rows) > MAX_OBJECT_EVENTS:
            raise ValueError("workstation_c05_history_too_large")
        events = {item["id"]: item for row in rows if (item := event(row["payload"], station_id)) is not None}
        events[current["id"]] = current
        events = list(events.values())
        _save_change(cur, current, station_id, detected_at)
        groups, superseded = episodes(events, station_id)
        for identifier in superseded:
            # No source, review or evidence deletion. Superseded aggregates are
            # excluded from active counts; each native episode retains its refs.
            cur.execute("""update sli_plugin_workstations.check_findings set status='resolved',
                resolved_at=%s,materially_changed_at=%s,revision=revision+1,
                reason_params=reason_params || '{"superseded_by_native_episodes":true}'::jsonb
                where id=%s and status='active'""", (detected_at, detected_at, identifier))
        for identifier, items, dedup_status in groups:
            _save_finding(cur, finding(identifier, items, dedup_status, events, station_id, detected_at))
