"""C06 station-local media sightings, published atomically by WR05.

Full native instance IDs group observations within a station. They are not
serial numbers, proof of a first-ever connection, file copying or an actor.
Compact occurrences preserve exact rolling-window membership after retention;
the observed history boundary never claims a complete collection baseline.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from .check_catalog import BY_ID
from .importer import digest
from .normalizers import NEW_IDENTITIES
from .overview_contracts import Count, Quality, Reason

PROJECTOR = "workstations.C06"
RULE_VERSION = BY_ID["C06"].rule_version


def timestamp(value):
    value = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("workstation_c06_timestamp_invalid")
    return value.astimezone(timezone.utc)


def event(row):
    observation = row["observation"]
    identity = (observation.get("channel", "").casefold(),
                observation.get("provider_name", "").casefold(), row["event_id"])
    native_usb = {(channel.casefold(), provider.casefold(), number)
                  for (channel, provider, number), (family, _) in NEW_IDENTITIES.items() if family == "usb"}
    facts = observation.get("facts", {})
    device_id = facts.get("device_id")
    if (row.get("family") != "usb" or identity not in native_usb
            or facts.get("storage_evidence") is not True
            or not isinstance(device_id, str) or not device_id.strip() or device_id.strip() == "-"
            or len(device_id) >= 512):
        return None
    if not isinstance(row["id"], str) or not re.fullmatch(r"[a-f0-9]{64}", row["id"]):
        raise ValueError("workstation_c06_observation_id_invalid")
    # The normalizer caps IDs at 512 characters. An ID at that cap may be
    # truncated, so it cannot safely establish identity or merge devices.
    # Case-insensitive Windows instance ID, never a suffix/description match.
    device_id = device_id.strip().upper()
    description = facts.get("device_description")
    return {"device_key": digest(["station_instance", device_id]), "device_id": device_id,
            "description": description[:512] if isinstance(description, str) else None,
            "at": timestamp(row["observed_at"]),
            "ref": {"kind": "workstation_observation", "observation_id": row["id"],
                    "agent_key": row["agent_key"], "source_sha256": observation.get("source_sha256")}}


def merge(station_id, current, previous=None):
    """Delivery-order independent endpoints, with deterministic simultaneous refs."""
    first = last = (current["at"], current["ref"]["observation_id"], current["ref"])
    description = current["description"]
    if previous:
        old_first = (timestamp(previous["first_seen_at"]), previous["first_ref"]["observation_id"], previous["first_ref"])
        old_last = (timestamp(previous["last_seen_at"]), previous["last_ref"]["observation_id"], previous["last_ref"])
        first = min(first, old_first, key=lambda item: item[:2])
        if old_last[:2] > last[:2]:
            last, description = old_last, previous["description"]
    return {"station_id": station_id, "device_key": current["device_key"], "device_id": current["device_id"],
            "description": description, "identity_quality": "station_instance", "storage_evidence": True,
            "first_seen_at": first[0], "last_seen_at": last[0], "first_ref": first[2], "last_ref": last[2]}


def _upsert(cur, table, row, *, updates=()):
    values = tuple(json.dumps(value) if isinstance(value, (dict, list)) else value for value in row.values())
    slots = ["%s::jsonb" if isinstance(value, (dict, list)) else "%s" for value in row.values()]
    conflict = "do nothing"
    if updates:
        conflict = "do update set " + ",".join(f"{key}=excluded.{key}" for key in updates)
        if table == "check_findings":
            # Repeat sightings update endpoints without becoming a new finding
            # revision at every connection. Only changed first-seen evidence is
            # material to the claim that this device is new in observed history.
            conflict += """,revision=check_findings.revision+
                case when check_findings.condition_sha256<>excluded.condition_sha256 then 1 else 0 end,
                materially_changed_at=case when check_findings.condition_sha256<>excluded.condition_sha256
                    then excluded.materially_changed_at else check_findings.materially_changed_at end"""
    target = "(id)" if table == "check_findings" else "(station_id,device_key)"
    cur.execute(f"""insert into sli_plugin_workstations.{table} ({','.join(row)})
        values ({','.join(slots)}) on conflict {target} {conflict}""", values)


def _finding(cur, row, detected_at):
    episode = digest([PROJECTOR, RULE_VERSION, row["station_id"], row["device_key"]])
    params = {"first_seen_at": row["first_seen_at"].isoformat(), "last_seen_at": row["last_seen_at"].isoformat(),
              "history_start_at": row["first_seen_at"].isoformat(), "baseline_status": "unknown",
              "identity_quality": row["identity_quality"], "cross_station_status": "unavailable",
              "actor_status": "unknown"}
    refs = [row["first_ref"]]
    if row["last_ref"] != refs[0]:
        refs.append(row["last_ref"])
    subject = {"kind": "workstation_device", "station_id": row["station_id"], "device_id": row["device_id"],
               "description": row["description"], "identity_quality": row["identity_quality"], "serial": None}
    finding = {"id": episode, "station_id": row["station_id"], "check_id": "C06", "rule_version": RULE_VERSION,
               "subject_id": row["device_key"], "subject_ref": subject, "episode_id": episode,
               "condition_sha256": digest([row["station_id"], row["device_key"], params["first_seen_at"]]),
               "status": "active", "severity": "medium",
               "fact_at": row["first_seen_at"], "first_detected_at": detected_at,
               "last_observed_at": row["last_seen_at"], "materially_changed_at": detected_at,
               "reason_code": BY_ID["C06"].reason_code, "reason_params": params,
               "quality": Quality("partial", (Reason("device_history_incomplete"),)).to_dict(), "evidence_refs": refs}
    _upsert(cur, "check_findings", finding, updates=(
        "subject_ref", "condition_sha256", "fact_at", "last_observed_at",
        "reason_params", "quality", "evidence_refs"))


def apply(conn, station_id, fact):
    """One immutable queue input; no raw-history scan, commits or external I/O."""
    if fact["kind"] != "observations":
        return
    current = event(fact["payload"])
    if current is None:
        return
    with conn.cursor() as cur:
        cur.execute("set local statement_timeout='5000ms'")
        cur.execute("select transaction_timestamp() as detected_at")
        detected_at = cur.fetchone()["detected_at"]
        cur.execute("""select * from sli_plugin_workstations.device_seen
            where station_id=%s and device_key=%s for update""", (station_id, current["device_key"]))
        previous = cur.fetchone()
        row = merge(station_id, current, previous)
        if row != previous:
            _upsert(cur, "device_seen", row, updates=(
                "description", "first_seen_at", "last_seen_at", "first_ref", "last_ref"))
        # Exact timestamps, not day buckets: [now-7d,now) excludes future events
        # without losing earlier sightings of a device whose latest time is future.
        cur.execute("""insert into sli_plugin_workstations.device_seen_occurrences
            (station_id,device_key,observed_at) values(%s,%s,%s) on conflict do nothing""",
            (station_id, current["device_key"], current["at"]))
        _finding(cur, row, detected_at)


def summary(cur, station_id, *, now):
    """Internal reader: caller must authorize the station before any counts.

    No complete baseline is available from enumeration events. Counts are lower
    bounds even if the observed boundary predates the entire requested window.
    Empty/uncollected history is unknown. This never reads raw or cold events.
    """
    now = timestamp(now)
    start = now - timedelta(days=7)
    cur.execute("""select min(first_seen_at) as history_start_at
        from sli_plugin_workstations.device_seen where station_id=%s and first_seen_at<%s""", (station_id, now))
    boundary = cur.fetchone()["history_start_at"]
    count = Count(None, "unknown")
    if boundary is not None:
        cur.execute("""select count(distinct device_key) as value
            from sli_plugin_workstations.device_seen_occurrences
            where station_id=%s and observed_at>=%s and observed_at<%s""", (station_id, start, now))
        count = Count(cur.fetchone()["value"], "at_least")
    return _summary_value(boundary, count.value, start, now)


def summaries(cur, station_ids, *, now):
    """One aggregate for an already-authorized page, never a fleet-wide scan.

    Same lower-bound contract as summary(); no identity is compared across
    stations. The caller applies WR03 admission before supplying these IDs.
    """
    if (not isinstance(station_ids, (list, tuple)) or len(station_ids) > 51
            or any(not isinstance(key, str) or not 1 <= len(key) <= 256 for key in station_ids)
            or len(set(station_ids)) != len(station_ids)):
        raise ValueError('workstation_device_summary_batch_invalid')
    now = timestamp(now)
    if not station_ids:
        return {}
    start = now - timedelta(days=7)
    cur.execute("""with selected as (select unnest(%s::text[]) as station_id),
        boundaries as (
            select d.station_id,min(d.first_seen_at) as history_start_at
            from sli_plugin_workstations.device_seen d join selected s using(station_id)
            where d.first_seen_at<%s group by d.station_id
        ), counts as (
            select d.station_id,count(distinct d.device_key) as value
            from sli_plugin_workstations.device_seen_occurrences d join selected s using(station_id)
            where d.observed_at>=%s and d.observed_at<%s group by d.station_id
        ) select s.station_id,b.history_start_at,coalesce(c.value,0) as value
        from selected s left join boundaries b using(station_id) left join counts c using(station_id)""",
        (list(station_ids), now, start, now))
    rows = cur.fetchall()
    if len(rows) != len(station_ids) or {row['station_id'] for row in rows} != set(station_ids):
        raise ValueError('workstation_device_summary_result_invalid')
    return {row['station_id']: _summary_value(row['history_start_at'], row['value'], start, now) for row in rows}


def _summary_value(boundary, value, start, now):
    count = Count(value, 'at_least') if boundary is not None else Count(None, 'unknown')
    return {'devices_7d': count.to_dict(), 'window_start_at': start.isoformat(), 'window_end_at': now.isoformat(),
            'history_start_at': timestamp(boundary).isoformat() if boundary else None, 'baseline_status': 'unknown',
            'quality': Quality('partial' if boundary else 'not_collected',
                               (Reason('device_history_incomplete' if boundary else 'not_collected'),)).to_dict()}
