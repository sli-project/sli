"""Validate NPS streams against owner policy, before acknowledging evidence."""
from dataclasses import asdict, replace
from hashlib import sha256
import json

from server.sli.sources.collection_packet_import import event_rows_from_packet
from sli_agent.nps import (
    NPS_MODULE, EVENT_IDS, PROVIDER, MAX_PAYLOAD_BYTES, assignment_for, bookmark_state, file_cursor, masked_event,
    window_continuity, accounting_cursor_value,
)
from sli_agent.envelope import canonical, timestamp
from sli_collect.eventlog import NS, parse_event_xml
from sli_collect.packets import validate_packet
from sli_collect.radius_accounting import parse_database_compatible_record
from sli_collect.radius_tail import MAXIMUM_READ_BYTES
from server.sli.storage.xml_safety import parse_bounded_xml


def admitted_nps_rows(ledger, identity, envelope, packet):
    current = assignment_for(identity.get("assigned_modules", []), envelope["module_id"], active=False)
    if current["policy_revision"] != envelope["policy_revision"]:
        history = getattr(ledger, "policy_assignment", None)
        retained = history(envelope["agent_id"], envelope["module_id"], envelope["policy_revision"]) if history else None
        if not retained or retained.get("config", {}).get("source_instance_id") != current["source_instance_id"]:
            raise ValueError("agent_nps_policy_not_retained")
        identity = {**identity, "assigned_modules": [retained]}
    return nps_rows(identity, envelope, packet)


def nps_rows(identity, envelope, packet):
    validate_packet(packet)
    module = envelope["module_id"]
    policy = assignment_for(identity.get("assigned_modules", []), module)
    header = packet["header"]
    if (envelope["source_instance_id"] != policy["source_instance_id"]
            or envelope["generation"] != str(identity["host_id"])
            or envelope["module_version"] != "1.0.0" or envelope["policy_revision"] != policy["policy_revision"]
            or envelope["payload_contract"] != "sli.collection-packet.v1"
            or timestamp(header["observed_at_utc"]) != timestamp(envelope["observed_at_utc"])
            or len(canonical(packet)) > MAX_PAYLOAD_BYTES):
        raise ValueError("agent_nps_binding_invalid")
    if module == NPS_MODULE:
        rows = event_rows_from_packet(packet)
        generation = policy["event_generation"]
        previous = bookmark_state(envelope["cursor_before"], generation)
        reset = previous["generation"] != generation
        if reset:
            previous = bookmark_state({"strategy": "bookmark", "token": ""}, generation)
        after = bookmark_state(envelope["cursor_after"], generation)
        start, last = previous["record_id"], after["record_id"]
        filtered = envelope["filtered_count"]
        ids = [row["record_id"] for row in rows]
        context = {"normalizer": "windows-nps-radius-v1", "filtered_count": filtered, "channel_reset": reset}
        expected_after, continuity = after, {"status": "not_proven"}
        if "tail_drained" in packet["context"]:
            drained = packet["context"]["tail_drained"]
            if type(drained) is not bool:
                raise ValueError("agent_nps_cursor_invalid")
            context["tail_drained"] = drained
            contiguous = start is not None and last is not None and last - start == len(rows) + filtered
            expected_after, continuity = window_continuity(previous, after, observed=header["observed_at_utc"],
                drained=drained, contiguous=contiguous, reset=reset)
        elif "coverage_from_utc" in after or "coverage_from_utc" in previous:
            raise ValueError("agent_nps_cursor_invalid")
        if (header["source"] != policy["source_name"] or header["channel"] != "Security"
                or envelope["channel"] != "Security" or header["generation"] != generation
                or after["generation"] != generation
                or header["cursor"] != {"after_record_id": start, "last_record_id": last}
                or packet["context"] != context or after != expected_after
                or packet["continuity"] != continuity
                or len(rows) + filtered > policy["batch_size"]
                or any(type(n) is not int or n <= 0 for n in ids) or ids != sorted(set(ids))
                or any(start is not None and n <= start or last is None or n > last for n in ids)
                or start is not None and (last is None or last < start)
                or not filtered and last != (ids[-1] if ids else start)
                or filtered and (last is None or start is not None and last <= start)
                or not rows and not filtered and any(after[key] != previous[key] for key in ("record_id", "bookmark", "generation"))
                or not rows and not filtered and after.get("anchor_sha256") != previous.get("anchor_sha256")
                or envelope["lost_count"] != (None if reset else 0)
                or envelope["continuity_state"] != ("gap" if reset else "filtered" if filtered else "not_proven")):
            raise ValueError("agent_nps_cursor_invalid")
        for row in rows:
            native_channel = parse_bounded_xml(row["xml"]).find("e:System/e:Channel", NS)
            if (row["event_id"] not in EVENT_IDS or row["provider_name"] != PROVIDER
                    or native_channel is None or native_channel.text != "Security"
                    or masked_event(row["xml"]) != row["xml"]
                    or parse_event_xml(row["xml"], source_name=policy["source_name"],
                        connect_address=policy["connect_address"], channel="Security") != row):
                raise ValueError("agent_nps_event_invalid")
        return rows
    before = envelope["cursor_before"]
    after = envelope["cursor_after"]
    if before["strategy"] != "file_offset" or after["strategy"] != "file_offset":
        raise ValueError("agent_radius_cursor_invalid")
    previous_value = json.loads(before["token"]) if before["token"] else policy["initial_cursor"]
    after_value = json.loads(after["token"])
    cursor = file_cursor(previous_value)
    updated = file_cursor(after_value)
    bounds = header["cursor"]
    rotated = header["generation"] != cursor.file_generation
    lines = [item["payload"] for item in packet["records"]]
    for item in packet["records"]:
        if item["format"] != "accounting_line":
            raise ValueError("agent_radius_record_invalid")
        parse_database_compatible_record(item["payload"])
    progress = "empty_progress_v1" in packet["context"]
    if progress:
        # Signed bounded producer assertions. Source whitespace and EOF cannot
        # be re-observed here, just as the provenance of nonempty rows cannot.
        proof = packet["context"]["empty_progress_v1"]
        if (lines or not isinstance(proof, dict) or set(proof) != {"skipped_bytes", "physical_lines"}
                or type(proof["skipped_bytes"]) is not int or type(proof["physical_lines"]) is not int
                or not 0 <= proof["skipped_bytes"] <= MAXIMUM_READ_BYTES
                or not 0 <= proof["physical_lines"] <= min(policy["batch_size"], proof["skipped_bytes"])
                or proof["skipped_bytes"] != bounds["end_offset"] - bounds["start_offset"]
                or bool(proof["skipped_bytes"]) != bool(proof["physical_lines"])
                or not proof["skipped_bytes"] and not rotated):
            raise ValueError("agent_radius_cursor_invalid")
    expected = replace(cursor, file_generation=header["generation"], byte_offset=bounds["end_offset"],
        last_record_sha256=(sha256(lines[-1].encode("utf-8")).hexdigest()
                            if lines else cursor.last_record_sha256)) if lines or progress else cursor
    expected_value = accounting_cursor_value(expected, previous_value, packet,
        initial_unanchored=not before["token"] and cursor.byte_offset == 0)
    # Existing unchanged empty packets have no provenance flag or progress
    # summary. Their compatibility cannot re-enable a flag already set false.
    if (not lines and not progress and "exact_boundary_recovery" not in previous_value
            and "exact_boundary_recovery" not in after_value):
        expected_value.pop("exact_boundary_recovery", None)
    initial = file_cursor(policy["initial_cursor"])
    if (any(getattr(cursor, key) != getattr(initial, key) for key in (
            "source_instance_id", "stream_id", "transport_binding"))
            or header["source"] != cursor.source_instance_id or header["channel"] != cursor.stream_id
            or len(lines) > policy["batch_size"]
            or envelope["channel"] != cursor.stream_id or bounds["before"] != asdict(cursor)
            or type(bounds["start_offset"]) is not int or type(bounds["end_offset"]) is not int
            or bounds["start_offset"] != (0 if rotated else cursor.byte_offset)
            or bounds["end_offset"] < bounds["start_offset"] or lines and bounds["end_offset"] <= bounds["start_offset"]
            or rotated and packet["continuity"]["previous_generation_eof"] is not True
            or not rotated and packet["continuity"]["previous_generation_eof"] is not False
            or packet["continuity"]["status"] != "complete" or updated != expected or after_value != expected_value
            or packet["context"]["source_timezone_id"] != policy["source_timezone_id"]
            or packet["context"]["source_utc_offset_minutes"] != policy["source_utc_offset_minutes"]
            or envelope["continuity_state"] != "not_proven" or envelope["filtered_count"] or envelope["lost_count"] != 0):
        raise ValueError("agent_radius_cursor_invalid")
    return []
