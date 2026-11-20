"""C02 native local Administrators episodes, inside WR05's publication fence.

An unresolved addition is evidence to review, not proof of current membership.
There is no full group snapshot. Event time and first detection stay separate,
including for initial backfill. No name or local SID creates an AD account link.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .check_catalog import BY_ID
from .importer import digest
from .normalizers import SECURITY_PROVIDER, text
from .overview_contracts import Quality, Reason

PROJECTOR = "workstations.C02"
RULE_VERSION = BY_ID["C02"].rule_version
ADMINISTRATORS = "S-1-5-32-544"
MAX_MEMBER_EVENTS = 1000
SID = re.compile(r"S-1-\d{1,15}(?:-\d{1,10}){1,15}", re.IGNORECASE)


def _sid(value):
    if not isinstance(value, str) or not SID.fullmatch(value) or value.upper() == "S-1-0-0":
        return None
    return value.upper()


def _stamp(value):
    stamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if stamp.utcoffset() is None:
        raise ValueError("workstation_c02_timestamp_invalid")
    return stamp.astimezone(timezone.utc)


def _account(station_id, sid, name=None, domain=None):
    return {"kind": "workstation_account", "station_id": station_id, "sid": sid,
            "name": name, "domain": domain, "status": "observed" if sid or name else "unknown",
            "ad_entity_id": None}


def event(row, station_id):
    """Read both WR08 native fields and observations normalized before WR08."""
    observation = row["observation"]
    facts, roles = observation.get("facts", {}), observation.get("roles", {})
    number = row["event_id"]
    if (row.get("family") != "protection" or number not in (4732, 4733)
            or observation.get("channel", "").casefold() != "security"
            or observation.get("provider_name", "").casefold() != SECURITY_PROVIDER.casefold()
            or facts.get("group_sid", facts.get("group")) != ADMINISTRATORS):
        return None
    source_id = row["id"]
    if not isinstance(source_id, str) or not re.fullmatch(r"[a-f0-9]{64}", source_id):
        raise ValueError("workstation_c02_observation_id_invalid")
    member_sid = _sid(facts.get("member_sid") or facts.get("member"))
    actor_sid = _sid(facts.get("actor_sid"))
    if actor_sid is None:
        # Legacy normalized identity keys may be exact SIDs. Never interpret a
        # name-based/provisional identity key as an account or directory link.
        role = roles.get("actor")
        actor_sid = _sid(role.removeprefix("sid:") if isinstance(role, str) else None)
    record = observation.get("record_id")
    generation = text(observation, "generation")
    return {"id": source_id, "agent_key": row["agent_key"], "event_id": number,
            "at": _stamp(row["observed_at"]), "generation": generation,
            "record_id": record if type(record) is int and record >= 0 else None,
            "member": _account(station_id, member_sid, text(facts, "member_name")),
            "actor": _account(station_id, actor_sid, text(facts, "actor_name"), text(facts, "actor_domain")),
            "ref": {"kind": "workstation_observation", "observation_id": source_id,
                    "agent_key": row["agent_key"], "source_sha256": observation.get("source_sha256")}}


def _after(removal, addition):
    if removal["at"] != addition["at"]:
        return removal["at"] > addition["at"]
    # Hash order is not event order. Only native record IDs within one log
    # generation can order simultaneous events; otherwise leave it unresolved.
    return bool(removal["generation"] and removal["generation"] == addition["generation"]
                and removal["record_id"] is not None and addition["record_id"] is not None
                and removal["record_id"] > addition["record_id"])


def _order(item):
    return item["at"], item["generation"] or "", item["record_id"] or 0, item["id"]


def finding(addition, removal, *, station_id, detected_at, history_start_at):
    episode = digest([PROJECTOR, RULE_VERSION, station_id, addition["member"]["sid"], addition["id"]])
    params = {"actor_sid": addition["actor"]["sid"], "actor_name": addition["actor"]["name"],
              "actor_domain": addition["actor"]["domain"], "actor_status": addition["actor"]["status"],
              "group_sid": ADMINISTRATORS,
              "history_start_at": history_start_at.isoformat(), "baseline_status": "unknown",
              "current_membership": "unknown", "added_at": addition["at"].isoformat(),
              "removed_at": removal["at"].isoformat() if removal else None}
    refs = [addition["ref"]] + ([removal["ref"]] if removal else [])
    condition = digest([addition["member"], params, refs])
    return {"id": episode, "station_id": station_id, "check_id": "C02", "rule_version": RULE_VERSION,
            "subject_id": addition["member"]["sid"], "subject_ref": addition["member"],
            "episode_id": episode, "condition_sha256": condition, "severity": "high",
            "status": "resolved" if removal else "active", "fact_at": addition["at"],
            "first_detected_at": detected_at, "last_observed_at": removal["at"] if removal else addition["at"],
            "materially_changed_at": detected_at, "resolved_at": detected_at if removal else None,
            "reason_code": "local_admin_added", "reason_params": params,
            "quality": Quality("partial", (Reason("local_admin_baseline_unknown"),)).to_dict(),
            "evidence_refs": refs}


def _save_finding(cur, row):
    import json

    columns = tuple(row)
    values = tuple(json.dumps(value) if isinstance(value, (dict, list)) else value for value in row.values())
    slots = ["%s::jsonb" if isinstance(value, (dict, list)) else "%s" for value in row.values()]
    # Preserve the original detection time across replays and late reconciliation.
    # resolved_at is the projection closure time; removed_at is the native time.
    updates = [f"{key}=excluded.{key}" for key in (
        "subject_ref", "condition_sha256", "status", "last_observed_at", "materially_changed_at",
        "reason_params", "quality", "evidence_refs")]
    cur.execute(f"""insert into sli_plugin_workstations.check_findings ({','.join(columns)})
        values ({','.join(slots)}) on conflict(id) do update set {','.join(updates)},
        resolved_at=case when check_findings.status='resolved' and excluded.status='resolved'
            then check_findings.resolved_at else excluded.resolved_at end,
        revision=check_findings.revision+1
        where check_findings.condition_sha256<>excluded.condition_sha256""", values)


def _save_change(cur, item, station_id, detected_at):
    import json

    added = item["event_id"] == 4732
    row = {"id": digest([PROJECTOR, "change", station_id, item["id"]]), "station_id": station_id,
           "change_kind": "local_admin_added" if added else "local_admin_removed", "event_at": item["at"],
           "detected_at": detected_at, "actor_ref": item["actor"], "subject_ref": item["member"],
           "reason_code": "local_admin_added" if added else "local_admin_removed", "reason_params": {},
           "quality": Quality("partial", (Reason("local_admin_baseline_unknown"),)).to_dict(),
           "evidence_refs": [item["ref"]]}
    values = tuple(json.dumps(value) if isinstance(value, (dict, list)) else value for value in row.values())
    slots = ["%s::jsonb" if isinstance(value, (dict, list)) else "%s" for value in row.values()]
    cur.execute(f"""insert into sli_plugin_workstations.station_changes ({','.join(row)})
        values ({','.join(slots)}) on conflict(id) do nothing""", values)


def apply(conn, station_id, fact):
    """WR05 evaluator; bounded per-member reconciliation, no commits or I/O.

    C02 evidence stays in PostgreSQL (the retention family is processes/usb).
    Re-read the member's native history to handle removal-before-add delivery,
    late imports and replay without using observation hashes as a watermark.
    Overflow rolls back without acknowledging the receipt or claiming coverage.
    """
    if fact["kind"] != "observations":
        return
    current = event(fact["payload"], station_id)
    if current is None:
        return
    with conn.cursor() as cur:
        cur.execute("set local statement_timeout='5000ms'")
        cur.execute("select transaction_timestamp() as detected_at")
        detected_at = cur.fetchone()["detected_at"]
        _save_change(cur, current, station_id, detected_at)
        if current["member"]["sid"] is None:
            return  # A display name cannot close or establish an exact member episode.
        cur.execute("""select id,agent_key,family,event_id,observed_at,observation
            from sli_plugin_workstations.observations
            where agent_key=%s and family='protection' and event_id in (4732,4733)
              and upper(coalesce(observation->'facts'->>'member_sid',observation->'facts'->>'member'))=%s
              and coalesce(observation->'facts'->>'group_sid',observation->'facts'->>'group')=%s
            order by observed_at,id limit %s""",
            (current["agent_key"], current["member"]["sid"], ADMINISTRATORS, MAX_MEMBER_EVENTS + 1))
        rows = cur.fetchall()
        if len(rows) > MAX_MEMBER_EVENTS:
            raise ValueError("workstation_c02_history_too_large")
        events = sorted((item for row in rows if (item := event(row, station_id)) is not None), key=_order)
        removals = [item for item in events if item["event_id"] == 4733]
        for addition in (item for item in events if item["event_id"] == 4732):
            removal = next((item for item in removals if _after(item, addition)), None)
            _save_finding(cur, finding(addition, removal, station_id=station_id, detected_at=detected_at,
                                      history_start_at=events[0]["at"]))
