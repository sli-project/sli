"""Transactional packet projection; caller owns evidence import and commit."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from server.sli.plugins.workstations.contracts import IdentityAdapter, Workstation
from server.sli.plugins.workstations.normalizers import normalize
from server.sli.storage.xml_safety import parse_bounded_xml
from sli_agent.signature_contract import packet_entries
from sli_agent.workstations import DEFENDER_CHANNEL, validate_protection_state
from sli_collect.eventlog import NS, parse_event_xml

MAX_PACKET_RECORDS = 500
MAX_PACKET_BYTES = 8 * 1024 * 1024


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(",", ":")).encode()).hexdigest()


def project_packet(conn, packet, rows, *, agent_key: str, identity: IdentityAdapter) -> dict[str, int]:
    if len(rows) > MAX_PACKET_RECORDS:
        raise ValueError("workstation_packet_too_large")
    if sum(len(row["xml"].encode()) for row in rows) > MAX_PACKET_BYTES:
        raise ValueError("workstation_packet_too_large")
    generation = packet["header"].get("generation")
    if not isinstance(generation, str) or not generation.strip() or len(generation) > 512:
        raise ValueError("workstation_generation_required")
    # agent_key comes from authenticated enrollment, NEVER header.source or XML.
    station = identity.workstation(conn, agent_key)
    if not isinstance(station, Workstation) or station.agent_key != agent_key:
        raise ValueError("workstation_agent_mismatch")
    state = packet.get("context", {}).get("workstations", {}).get("protection_state")
    if state is not None:
        if packet["header"]["channel"] != DEFENDER_CHANNEL:
            raise ValueError("workstation_protection_channel_invalid")
        validate_protection_state(state)
    signatures = packet_entries(packet, rows)
    pending = []
    for row in rows:
        if type(row.get("record_id")) is not int or row["record_id"] < 0:
            raise ValueError("workstation_record_id_required")
        if len(row["xml"].encode()) > 1048576:
            raise ValueError("workstation_evidence_too_large")
        parsed = parse_event_xml(row["xml"], source_name=row["computer_name"],
                                 connect_address="", channel=row["channel"])
        for field in ("event_id", "provider_name", "record_id", "time_created"):
            if row.get(field) != parsed.get(field):
                raise ValueError("workstation_xml_identity_mismatch")
        root = parse_bounded_xml(row["xml"])
        xml_channel = root.find("e:System/e:Channel", NS)
        if xml_channel is not None and xml_channel.text != row["channel"]:
            raise ValueError("workstation_xml_channel_mismatch")
        data = {}
        for item in root.findall(".//e:EventData/e:Data", NS):
            name = item.get("Name")
            if name:
                if name in data:
                    raise ValueError("workstation_duplicate_event_field")
                data[name] = item.text
        projection = normalize(parsed, data, station)
        if projection is None:
            continue
        observed_at = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+(?=Z$)", r"\1",
            str(parsed["time_created"])).replace("Z", "+00:00"))
        if observed_at.utcoffset() is None:
            raise ValueError("workstation_timestamp_requires_timezone")
        observation_id = digest([agent_key, row["channel"], generation, row["record_id"]])
        observation = {**projection, "event_id": parsed["event_id"], "channel": row["channel"],
                       "provider_name": parsed["provider_name"], "generation": generation,
                       "record_id": row["record_id"], "observed_at": observed_at.astimezone(timezone.utc).isoformat(),
                       "keywords": parsed.get("keywords"),
                       "source_sha256": hashlib.sha256(row["xml"].encode()).hexdigest()}
        if row["record_id"] in signatures:
            observation["file_signature"] = signatures[row["record_id"]]
        pending.append((observation_id, observation, row["xml"]))
    inserted = 0
    with conn.cursor() as cur:
        for observation_id, observation, xml in pending:
            fingerprint = digest(observation)
            cur.execute("""
                insert into sli_plugin_workstations.observations
                  (id,agent_key,entity_id,ad_computer_id,family,event_id,observed_at,
                   observation,observation_sha256,source_xml)
                values (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
                on conflict(id) do nothing returning id
            """, (observation_id, agent_key, station.entity_id, station.ad_computer_id,
                  observation["family"], observation["event_id"], observation["observed_at"],
                  json.dumps(observation), fingerprint, xml))
            if cur.fetchone():
                inserted += 1
            else:
                cur.execute("select observation_sha256,observation from sli_plugin_workstations.observations where id=%s",
                            (observation_id,))
                existing = cur.fetchone()
                if (not existing or digest(existing["observation"]) != existing["observation_sha256"]
                        or existing["observation"].get("source_sha256") != observation["source_sha256"]):
                    raise ValueError("workstation_packet_replay_conflict")
                # Preserve the original enrichment snapshot on exact-source
                # replay, including after a later AD association or entity merge.
        if state is not None:
            observed_at = packet["header"]["observed_at_utc"]
            state_id = digest([agent_key, "protection_state"])
            cur.execute("""insert into sli_plugin_workstations.protection_state
                (id,agent_key,entity_id,ad_computer_id,observed_at,state,state_sha256)
                values(%s,%s,%s,%s,%s,%s::jsonb,%s)
                on conflict(agent_key) do update set entity_id=excluded.entity_id,
                    ad_computer_id=excluded.ad_computer_id,observed_at=excluded.observed_at,
                    state=excluded.state,state_sha256=excluded.state_sha256
                where protection_state.observed_at<excluded.observed_at
                returning id""", (state_id, agent_key, station.entity_id, station.ad_computer_id,
                                  observed_at, json.dumps(state), digest(state)))
            if not cur.fetchone():
                cur.execute("select observed_at,state_sha256 from sli_plugin_workstations.protection_state where agent_key=%s",
                            (agent_key,))
                previous = cur.fetchone()
                stamp = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
                if not previous or previous["observed_at"] == stamp and previous["state_sha256"] != digest(state):
                    raise ValueError("workstation_protection_replay_conflict")
    return {"observed": len(pending), "inserted": inserted, "ignored": len(rows) - len(pending)}
