# SPDX-License-Identifier: Apache-2.0
"""Opt-in NPS streams; source progress is published only through the spool."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from xml.etree import ElementTree as ET

from sli_agent.envelope import canonical
from sli_agent.modules import Sample
from sli_collect.bookmarked_eventlog import read_local
from sli_collect.eventlog import NS, parse_event_xml
from sli_collect.packets import make_packet
from sli_collect.radius import collect_radius_packet
from sli_collect.radius_accounting import parse_database_compatible_record
from sli_collect.radius_contract import RadiusFileCursor
from sli_collect.radius_tail import RadiusTailReadError, read_bounded_tail
from server.sli.storage.xml_safety import parse_bounded_xml

NPS_MODULE = "sli.vpn-nps"
ACCOUNTING_MODULE = "sli.radius-accounting"
MODULES = (NPS_MODULE, ACCOUNTING_MODULE)
FAMILIES = {NPS_MODULE: "nps", ACCOUNTING_MODULE: "radius_accounting"}
MAX_PAYLOAD_BYTES = 44 * 1024
PROVIDER = "Microsoft-Windows-Security-Auditing"
# Bundled windows-nps-radius-v1 currently declares these native decisions only.
EVENT_IDS = frozenset({6272, 6273})
NPS_FIELDS = frozenset({
    "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "FullyQualifiedSubjectUserName",
    "SubjectMachineSID", "SubjectMachineName", "FullyQualifiedSubjectMachineName",
    "CalledStationID", "CallingStationID", "NASIPv4Address", "NASIPv6Address", "NASIdentifier",
    "NASPortType", "NASPort", "ClientName", "ClientIPAddress", "ProxyPolicyName",
    "NetworkPolicyName", "AuthenticationProvider", "AuthenticationServer", "AuthenticationType",
    "EAPType", "AccountSessionIdentifier", "LoggingResult", "ReasonCode", "Reason",
})


def masked_event(raw):
    root = parse_bounded_xml(raw)
    changed = False
    for child in list(root):
        if child.tag not in (f"{{{NS['e']}}}System", f"{{{NS['e']}}}EventData"):
            root.remove(child)
            changed = True
        elif child.tag == f"{{{NS['e']}}}EventData":
            names = set()
            for field in list(child):
                name = field.get("Name")
                if name in names:
                    raise ValueError("agent_nps_duplicate_field")
                names.add(name)
                if field.tag != f"{{{NS['e']}}}Data" or name not in NPS_FIELDS:
                    child.remove(field)
                    changed = True
    return ET.tostring(root, encoding="unicode") if changed else raw


def file_cursor(value):
    try:
        if not isinstance(value, dict):
            raise TypeError()
        value = dict(value)
        recovery = value.pop("exact_boundary_recovery", True)
        if type(recovery) is not bool or set(value) != set(RadiusFileCursor.__dataclass_fields__):
            raise ValueError()
        for name in ("source_instance_id", "stream_id", "transport_binding", "file_generation"):
            if not isinstance(value[name], str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value[name]) is None:
                raise ValueError()
        if (value["stream_id"] != "radius-accounting" or type(value["byte_offset"]) is not int
                or not 0 <= value["byte_offset"] <= 2**63 - 1):
            raise ValueError()
        if value["last_record_sha256"] is not None and (
                not isinstance(value["last_record_sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", value["last_record_sha256"]) is None):
            raise ValueError()
        return RadiusFileCursor(**value)
    except (ValueError, KeyError, TypeError):
        raise ValueError("agent_radius_cursor_invalid") from None


def accounting_cursor_value(cursor, previous, packet, *, initial_unanchored=False):
    """Keep recovery provenance in the opaque signed token, not SQL geometry.

    Historical last-record hashes survive empty rotations but cannot establish
    an anchor in that generation. Legacy flag absence retains prior behavior.
    """
    value = asdict(cursor)
    if packet["records"]:
        if "exact_boundary_recovery" in previous:
            value["exact_boundary_recovery"] = True
    elif (initial_unanchored or "empty_progress_v1" in packet["context"]
            and packet["header"]["generation"] != previous["file_generation"]):
        value["exact_boundary_recovery"] = False
    elif "exact_boundary_recovery" in previous:
        value["exact_boundary_recovery"] = previous["exact_boundary_recovery"]
    return value


def policy(module, value):
    try:
        common = {"source_instance_id", "policy_revision", "paused", "families"}
        specific = ({"source_name", "connect_address", "event_generation", "batch_size"}
                    if module == NPS_MODULE else {"accounting_directory", "initial_cursor", "subscription_id",
                        "source_timezone_id", "source_utc_offset_minutes", "batch_size"})
        if module not in MODULES or not isinstance(value, dict) or set(value) - common - specific:
            raise ValueError()
        result = {"policy_revision": "1", "paused": False, "batch_size": 32, **deepcopy(value)}
        families = result.get("families", {})
        if (not isinstance(families, dict) or set(families) - {FAMILIES[module]}
                or any(type(enabled) is not bool for enabled in families.values())):
            raise ValueError()
        result["families"] = {FAMILIES[module]: True, **families}
        if module == NPS_MODULE:
            result = {"batch_size": 32, "event_generation": "1", **result}
        required = common - {"paused", "families"} | specific - {"batch_size", "initial_cursor", "source_utc_offset_minutes"}
        for name in required:
            if not isinstance(result[name], str) or not result[name].strip() or len(result[name]) > 512:
                raise ValueError()
        if type(result["paused"]) is not bool:
            raise ValueError()
        if type(result["batch_size"]) is not int or not 1 <= result["batch_size"] <= 128:
            raise ValueError()
        if module == NPS_MODULE:
            if len(result["event_generation"]) > 128:
                raise ValueError()
        else:
            cursor = file_cursor(result["initial_cursor"])
            if (cursor.source_instance_id != result["source_instance_id"]
                    or type(result["source_utc_offset_minutes"]) is not int
                    or not -840 <= result["source_utc_offset_minutes"] <= 840):
                raise ValueError()
        return result
    except (ValueError, KeyError, TypeError):
        raise ValueError("agent_nps_config_invalid") from None


def assignment_for(assignments, module, *, active=True):
    matches = [item for item in assignments if isinstance(item, dict) and item.get("module_id") == module]
    if len(matches) != 1 or matches[0].get("enabled") is not True:
        raise ValueError("agent_module_not_assigned")
    result = policy(module, matches[0].get("config", {}))
    if active and (result["paused"] or not result["families"][FAMILIES[module]]):
        raise ValueError("agent_module_paused")
    return result


def bookmark_state(cursor, generation):
    try:
        if cursor["strategy"] != "bookmark":
            raise ValueError()
        if not cursor["token"]:
            return {"record_id": None, "bookmark": "", "generation": generation}
        state = json.loads(cursor["token"])
        if (set(state) - {"record_id", "bookmark", "generation", "coverage_from_utc", "anchor_sha256"}
                or not {"record_id", "bookmark", "generation"} <= set(state)
                or state["record_id"] is not None and (type(state["record_id"]) is not int or state["record_id"] <= 0)
                or not isinstance(state["bookmark"], str) or len(state["bookmark"]) > 2048
                or bool(state["bookmark"]) != (state["record_id"] is not None)
                or not isinstance(state["generation"], str) or not state["generation"] or len(state["generation"]) > 128):
            raise ValueError()
        if "coverage_from_utc" in state:
            from sli_agent.envelope import timestamp
            timestamp(state["coverage_from_utc"])
            if "anchor_sha256" not in state:
                raise ValueError()
        if "anchor_sha256" in state and (not isinstance(state["anchor_sha256"], str)
                or re.fullmatch(r"[a-f0-9]{64}", state["anchor_sha256"]) is None or state["record_id"] is None):
            raise ValueError()
        return state
    except (ValueError, KeyError, TypeError):
        raise ValueError("agent_nps_cursor_invalid") from None


def window_continuity(previous, after, *, observed, drained, contiguous, reset):
    """Attest time only after reaching a verified local Security tail.

    The first drained tail starts coverage at observation time, never at the
    oldest returned event. Later packets extend it only through uninterrupted
    RecordID progress. A restart retains the origin in the durable signed cursor.
    """
    from sli_agent.envelope import timestamp

    after = {key: value for key, value in after.items() if key != "coverage_from_utc"}
    observed = timestamp(observed).isoformat()
    origin = previous.get("coverage_from_utc") if contiguous and not reset else None
    if origin and timestamp(origin) > timestamp(observed):
        origin = None
    continuity = {"status": "not_proven"}
    if drained and after.get("anchor_sha256"):
        if origin and timestamp(origin) < timestamp(observed):
            continuity = {"status": "complete", "from_utc": origin, "to_utc": observed}
        after["coverage_from_utc"] = origin or observed
    elif origin:
        after["coverage_from_utc"] = origin
    return after, continuity


class NPSModule:
    module_id = NPS_MODULE

    def __init__(self, host_id, config, *, reader=None):
        self.host_id = host_id
        self.policy = policy(self.module_id, config)
        self.reader = reader or read_local

    def collect(self, captured=None, *, now=None):
        if self.policy["paused"] or not self.policy["families"][FAMILIES[self.module_id]]:
            raise ValueError("agent_module_paused")
        if captured and captured["generation"] != self.host_id:
            raise ValueError("agent_nps_cursor_invalid")
        before = deepcopy(captured["cursor_after"]) if captured else {"strategy": "bookmark", "token": ""}
        generation = self.policy["event_generation"]
        progress = bookmark_state(before, generation)
        reset = progress["generation"] != generation
        if reset:
            progress = bookmark_state({"strategy": "bookmark", "token": ""}, generation)
        previous = deepcopy(progress)
        start = progress["record_id"]
        records, filtered = [], 0
        rows = self.reader("Security", deepcopy(progress), self.policy["batch_size"])
        if len(rows) > self.policy["batch_size"]:
            raise ValueError("agent_nps_range_invalid")
        for raw, bookmark in rows:
            root = parse_bounded_xml(raw)
            channel = root.find("e:System/e:Channel", NS)
            if channel is None or channel.text != "Security":
                raise ValueError("agent_nps_channel_invalid")
            row = parse_event_xml(masked_event(raw), source_name=self.policy["source_name"],
                                  connect_address=self.policy["connect_address"], channel="Security")
            record_id = row["record_id"]
            if (type(record_id) is not int or record_id <= 0
                    or progress["record_id"] is not None and record_id <= progress["record_id"]
                    or not isinstance(bookmark, str) or not bookmark or len(bookmark) > 2048):
                raise ValueError("agent_nps_range_invalid")
            if row["provider_name"] == PROVIDER and row["event_id"] in EVENT_IDS:
                record = {"format": "event_xml", "record_id": record_id, "payload": row}
                if len(canonical(records + [record])) > MAX_PAYLOAD_BYTES - 4096:
                    if not records:
                        raise ValueError("agent_nps_size_limit")
                    break
                records.append(record)
            else:
                filtered += 1
            progress = {"record_id": record_id, "bookmark": bookmark, "generation": generation,
                        "anchor_sha256": sha256(raw.encode("utf-8")).hexdigest()}
        # A short EvtNext batch is not proof of EOF. Probe the exact new anchor;
        # this bounded read is not consumed and cannot advance the signed cursor.
        drained = not self.reader("Security", deepcopy(progress), 1) if progress["record_id"] is not None else False
        contiguous = start is not None and progress["record_id"] - start == len(records) + filtered
        observed = now or datetime.now(timezone.utc)
        progress, continuity = window_continuity(previous, progress, observed=observed.isoformat(),
            drained=drained, contiguous=contiguous, reset=reset)
        payload = make_packet(source=self.policy["source_name"], channel="Security", generation=generation,
            cursor={"after_record_id": start, "last_record_id": progress["record_id"]}, records=records,
            continuity=continuity, observed_at=observed,
            context={"normalizer": "windows-nps-radius-v1", "filtered_count": filtered, "channel_reset": reset,
                     "tail_drained": drained})
        return Sample(self.module_id, self.policy["source_instance_id"], "Security", self.host_id, before,
            {"strategy": "bookmark", "token": canonical(progress).decode("ascii")}, payload,
            policy_revision=self.policy["policy_revision"], filtered_count=filtered,
            continuity_state="gap" if reset else "filtered" if filtered else "not_proven",
            lost_count=None if reset else 0)


class AccountingModule:
    module_id = ACCOUNTING_MODULE

    def __init__(self, host_id, config, *, reader=None):
        self.host_id = host_id
        self.policy = policy(self.module_id, config)
        self.reader = reader or self._read

    def _read(self, directory, **kwargs):
        return read_bounded_tail(directory, maximum_records=self.policy["batch_size"],
                                 maximum_payload_bytes=MAX_PAYLOAD_BYTES - 4096, **kwargs)

    def collect(self, captured=None, *, now=None):
        if self.policy["paused"] or not self.policy["families"][FAMILIES[self.module_id]]:
            raise ValueError("agent_module_paused")
        if captured and captured["generation"] != self.host_id:
            raise ValueError("agent_radius_cursor_invalid")
        before = deepcopy(captured["cursor_after"]) if captured else {"strategy": "file_offset", "token": ""}
        if before["strategy"] != "file_offset":
            raise ValueError("agent_radius_cursor_invalid")
        previous = json.loads(before["token"]) if before["token"] else self.policy["initial_cursor"]
        cursor = file_cursor(previous)
        initial = file_cursor(self.policy["initial_cursor"])
        if any(getattr(cursor, name) != getattr(initial, name) for name in (
                "source_instance_id", "stream_id", "transport_binding")):
            raise ValueError("agent_radius_cursor_invalid")
        recovery = previous.get("exact_boundary_recovery", True)
        try:
            payload = collect_radius_packet(Path(self.policy["accounting_directory"]), cursor=cursor,
                source_timezone_id=self.policy["source_timezone_id"],
                source_utc_offset_minutes=self.policy["source_utc_offset_minutes"], observed_at=now,
                read_tail=self.reader, allow_exact_boundary_recovery=recovery)
        except RadiusTailReadError as exc:
            if not recovery and exc.code in {"tail_cursor_generation_not_found", "tail_accounting_file_not_observed"}:
                raise RadiusTailReadError("tail_recovery_unanchored_generation") from None
            raise
        # Exact legacy shape contains no password/shared-secret attributes.
        for record in payload["records"]:
            parse_database_compatible_record(record["payload"])
        if len(canonical(payload)) > MAX_PAYLOAD_BYTES:
            raise ValueError("agent_radius_size_limit")
        updated = cursor
        if payload["records"] or "empty_progress_v1" in payload["context"]:
            updated = replace(cursor, file_generation=payload["header"]["generation"],
                byte_offset=payload["header"]["cursor"]["end_offset"],
                last_record_sha256=(sha256(payload["records"][-1]["payload"].encode("utf-8")).hexdigest()
                                    if payload["records"] else cursor.last_record_sha256))
        value = accounting_cursor_value(updated, previous, payload,
            initial_unanchored=not before["token"] and cursor.byte_offset == 0)
        after = {"strategy": "file_offset", "token": canonical(value).decode("ascii")}
        return Sample(self.module_id, cursor.source_instance_id, cursor.stream_id, self.host_id,
                      before, after, payload, policy_revision=self.policy["policy_revision"],
                      continuity_state="not_proven", lost_count=0)
