"""C03 received failures, with bounded, versioned five-minute finding buckets.

The threshold uses a sliding (end - 5 minutes, end] window, even across UTC
bucket boundaries. Endpoints are partitioned into five-minute buckets to keep
one finding per station/account/source/direction/bucket. A late event can affect
only its own and the following endpoint bucket. WR05 owns the transaction,
receipts and replay fence; no polling-time history scan or network I/O occurs.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from ipaddress import ip_address
import json
import re

from .check_catalog import BY_ID
from .importer import digest
from .normalizers import SECURITY_PROVIDER, text
from .overview_contracts import Quality, Reason
from .protection import timestamp

PROJECTOR = "workstations.C03"
RULE_VERSION = BY_ID["C03"].rule_version
THRESHOLD = 20
WINDOW = timedelta(minutes=5)
MAX_EVENTS = 1000
MAX_EVIDENCE = 20
DIRECTIONS = {"on_station", "from_station"}


def bucket_start(at):
    at = timestamp(at)
    return at.replace(minute=at.minute // 5 * 5, second=0, microsecond=0)


def event(row):
    """Only native 4625 is an attempt. A receiving WS never proves an origin WS.

    Supplemental password-validation events are deliberately not counted. The
    native source IP is only a grouping label, never a device association.
    Missing remote source/target identities cannot be pooled into one attacker.
    """
    observation = row.get("observation", {})
    if (row.get("family") != "logons" or row.get("event_id") != 4625
            or observation.get("channel", "").casefold() != "security"
            or observation.get("provider_name", "").casefold() != SECURITY_PROVIDER.casefold()):
        return None
    roles, facts = observation.get("roles", {}), observation.get("facts", {})
    target = text(roles, "affected_entity")
    source = text(roles, "source_ip")
    if source:
        try:
            address = ip_address(source)
        except ValueError:
            return None
        source = str(getattr(address, "ipv4_mapped", None) or address)
    elif str(facts.get("logon_type")) == "2":
        source = "local"  # Native interactive logon on this receiving station.
    if not target or not source:
        return None
    identifier = row["id"]
    if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{64}", identifier):
        raise ValueError("workstation_c03_observation_id_invalid")
    return {"id": identifier, "at": timestamp(row["observed_at"]),
            "target": target.casefold(), "source": source, "direction": "on_station",
            "ref": {"kind": "workstation_observation", "observation_id": identifier,
                    "agent_key": row["agent_key"], "source_sha256": observation.get("source_sha256")}}


def buckets(events, *, station_id, start, detected_at):
    """Return the two affected endpoint buckets, independently for each group.

    Trusted adapters may supply from_station events later; local event data can
    never set that direction. Direction participates in both grouping and IDs.
    Counts describe observed failures, not a proven attack or full coverage.
    """
    if len(events) > MAX_EVENTS:
        raise ValueError("workstation_c03_window_too_large")
    groups = defaultdict(dict)
    for item in events:
        if item["direction"] not in DIRECTIONS:
            raise ValueError("workstation_c03_direction_invalid")
        key = (item["direction"], item["target"], item["source"])
        groups[key][item["id"]] = item
    findings = []
    for (direction, target, source), items in sorted(groups.items()):
        ordered = sorted(items.values(), key=lambda item: (item["at"], item["id"]))
        peaks = {}
        left = 0
        for right, item in enumerate(ordered):
            while ordered[left]["at"] <= item["at"] - WINDOW:
                left += 1
            block = bucket_start(item["at"])
            count = right - left + 1
            if (start <= block < start + 2 * WINDOW and count >= THRESHOLD
                    and count > peaks.get(block, (0, 0, 0))[0]):
                peaks[block] = (count, left, right)
        for block, (count, left, right) in sorted(peaks.items()):
            first, last = ordered[left], ordered[right]
            episode = digest([PROJECTOR, RULE_VERSION, station_id, direction, target, source, block.isoformat()])
            subject = {"kind": "workstation_account", "station_id": station_id,
                       "identity_key": target, "ad_entity_id": None}
            params = {"count": count, "count_relation": "at_least", "window_minutes": 5,
                      "threshold": THRESHOLD, "direction": direction, "source": source,
                      "window_start": (last["at"] - WINDOW).isoformat(), "window_end": last["at"].isoformat(),
                      "bucket_start": block.isoformat(), "bucket_end": (block + WINDOW).isoformat(),
                      "evidence_sampled": count > MAX_EVIDENCE}
            refs = [item["ref"] for item in ordered[left:min(right + 1, left + MAX_EVIDENCE)]]
            condition = digest([subject, params, refs])
            findings.append({"id": episode, "station_id": station_id, "check_id": "C03",
                             "rule_version": RULE_VERSION, "subject_id": digest([station_id, target]),
                             "subject_ref": subject, "episode_id": episode, "condition_sha256": condition,
                             "status": "active", "severity": "high", "fact_at": first["at"],
                             "first_detected_at": detected_at, "last_observed_at": last["at"],
                             "materially_changed_at": detected_at, "reason_code": "password_failures",
                             "reason_params": params,
                             "quality": Quality("partial", (Reason("coverage_incomplete"),)).to_dict(),
                             "evidence_refs": refs})
    return findings


def _save(cur, row):
    values = tuple(json.dumps(value) if isinstance(value, (dict, list)) else value for value in row.values())
    slots = ["%s::jsonb" if isinstance(value, (dict, list)) else "%s" for value in row.values()]
    cur.execute(f"""insert into sli_plugin_workstations.check_findings ({','.join(row)})
        values ({','.join(slots)}) on conflict(id) do update set
            condition_sha256=excluded.condition_sha256,fact_at=excluded.fact_at,
            last_observed_at=excluded.last_observed_at,materially_changed_at=excluded.materially_changed_at,
            reason_params=excluded.reason_params,quality=excluded.quality,evidence_refs=excluded.evidence_refs,
            revision=check_findings.revision+1
        where check_findings.condition_sha256<>excluded.condition_sha256""", values)


def apply(conn, station_id, fact):
    if fact["kind"] != "observations":
        return
    current = event(fact["payload"])
    if current is None:
        return
    agent = fact["payload"]["agent_key"]
    start = bucket_start(current["at"])
    with conn.cursor() as cur:
        cur.execute("set local statement_timeout='5000ms'")
        cur.execute("select agent_key from sli_plugin_workstations.station_inventory where station_id=%s", (station_id,))
        station = cur.fetchone()
        if not station or station["agent_key"] != agent:
            raise ValueError("workstation_projection_input_conflict")
        # Uses workstation_report_window(agent_key,family,observed_at,id).
        # Bounded native metadata only: never fetch XML or all station history.
        cur.execute("""select id,agent_key,family,event_id,observed_at,observation
            from sli_plugin_workstations.observations
            where agent_key=%s and family='logons' and event_id=4625
                and observed_at>%s and observed_at<%s
            order by observed_at,id limit %s""", (agent, start - WINDOW, start + 2 * WINDOW, MAX_EVENTS + 1))
        rows = cur.fetchall()
        if len(rows) > MAX_EVENTS:
            # Roll back without acknowledging WR05's receipt or claiming zero.
            raise ValueError("workstation_c03_window_too_large")
        events = [item for row in rows if (item := event(row)) is not None
                  and item["target"] == current["target"] and item["source"] == current["source"]]
        cur.execute("select transaction_timestamp() as detected_at")
        detected_at = cur.fetchone()["detected_at"]
        for row in buckets(events, station_id=station_id, start=start, detected_at=detected_at):
            _save(cur, row)
