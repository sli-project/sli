"""Validate the attested, multiplexed workstation stream before its receipt."""
from copy import deepcopy

from server.sli.agents.assignments import workstation_assignment
from server.sli.sources.collection_packet_import import event_rows_from_packet
from sli_agent.signature_contract import packet_entries
from sli_agent.workstations import CHANNELS, MODULE_VERSION, POWERSHELL_CHANNEL, SCRIPT_BYTES, WorkstationsModule


def workstation_rows(identity, envelope, packet):
    rows = event_rows_from_packet(packet)
    assignment = workstation_assignment(identity.get("assigned_modules"))
    if assignment is None:
        raise ValueError("agent_module_not_assigned")
    host = str(identity["host_id"])
    collector = WorkstationsModule(host, assignment.get("config", {}))
    # Queued 1.0 packets retain the original six-channel rotation.
    if envelope["module_version"] == "1.0.0":
        collector.channels = CHANNELS[:-1]
    channels = collector.channels
    policy = collector.policy
    header = packet["header"]
    if (envelope["source_instance_id"] != host or envelope["generation"] != host
            or envelope["channel"] != "workstations" or envelope["module_version"] not in ("1.0.0", MODULE_VERSION)
            or envelope["payload_contract"] != "sli.collection-packet.v1"
            or envelope["policy_revision"] != policy["policy_revision"] or header["source"] != host):
        raise ValueError("agent_workstations_binding_invalid")
    before = envelope["cursor_before"]
    if before["strategy"] != "bookmark":
        raise ValueError("agent_workstations_cursor_invalid")
    state = collector._state({"generation": host, "cursor_after": before}) if before["token"] else collector._state(None)
    updated = collector._state({"generation": host, "cursor_after": envelope["cursor_after"]})
    enabled = collector.enabled_channels()
    if not enabled:
        raise ValueError("agent_workstations_channel_disabled")
    index = next((state["next"] + offset) % len(channels) for offset in range(len(channels))
                 if channels[(state["next"] + offset) % len(channels)] in enabled)
    previous = (state["next"] - 1) % len(channels)
    # Bounded catch-up may repeat the last captured channel. Only its cursor
    # may advance; the same range, continuity and owner-policy checks apply.
    if (header["channel"] == channels[previous] and header["channel"] in enabled
            and header["channel"] in state["channels"]):
        index = previous
    channel = channels[index]
    generation = policy["channel_generations"].get(channel, host)
    old = state["channels"].get(channel, {"record_id": None, "bookmark": "", "generation": generation})
    reset = old["generation"] != generation
    if reset:
        old = {"record_id": None, "bookmark": "", "generation": generation}
    progress = updated["channels"].get(channel)
    if (header["channel"] != channel or header["generation"] != generation or not progress
            or progress["generation"] != generation or updated["next"] != (index + 1) % len(channels)
            or {k: v for k, v in state["channels"].items() if k != channel}
                != {k: v for k, v in updated["channels"].items() if k != channel}
            or header["cursor"] != {"after_record_id": old["record_id"], "last_record_id": progress["record_id"]}):
        raise ValueError("agent_workstations_cursor_invalid")
    ids = [row["record_id"] for row in rows]
    last = progress["record_id"]
    if (len(rows) > policy["batch_size"] or any(type(n) is not int or n < 0 for n in ids)
            or ids != sorted(set(ids)) or any(old["record_id"] is not None and n <= old["record_id"] for n in ids)
            or any(last is None or n > last for n in ids)
            or old["record_id"] is not None and (last is None or last < old["record_id"])
            or last is not None and not progress["bookmark"]):
        raise ValueError("agent_workstations_range_invalid")
    context = packet.get("context", {}).get("workstations", {})
    if not isinstance(context, dict):
        raise ValueError("agent_workstations_continuity_invalid")
    dropped = context.get("dropped_count")
    filtered = context.get("filtered_count")
    read_error = context.get("read_error")
    bookmark_recovered = context.get("bookmark_recovered", False)
    dropped_by_id = context.get("dropped_by_event_id")
    if (context.get("policy_revision") != policy["policy_revision"]
            or type(filtered) is not int or filtered < 0 or type(dropped) is not int or dropped < 0
            or filtered + dropped + len(rows) > policy["batch_size"]
            or not isinstance(dropped_by_id, dict)
            or any(k not in policy["rate_limits"] or type(v) is not int or v < 1 for k, v in dropped_by_id.items())
            or sum(dropped_by_id.values()) != dropped
            or context.get("channel_reset") is not reset
            or context.get("rate_window_seconds") != policy["rate_window_seconds"]
            or read_error not in (None, "agent_workstations_read_failed")
            or type(bookmark_recovered) is not bool
            or bookmark_recovered and (reset or read_error or old["record_id"] is None or not old["bookmark"])
            or envelope["filtered_count"] != filtered
            or envelope["lost_count"] != (None if read_error or reset or bookmark_recovered else dropped)
            or envelope["continuity_state"] != ("gap" if dropped or reset or read_error or bookmark_recovered else "filtered" if filtered else "not_proven")
            or packet["continuity"]["status"] != "not_proven"):
        raise ValueError("agent_workstations_continuity_invalid")
    if read_error and (rows or filtered or dropped or progress != old):
        raise ValueError("agent_workstations_cursor_invalid")
    # Source filters are owner policy; signed data cannot override them.
    from server.sli.storage.xml_safety import parse_bounded_xml
    from sli_collect.eventlog import NS

    for row in rows:
        data = {}
        root = parse_bounded_xml(row["xml"])
        for item in root.findall(".//e:EventData/e:Data", NS):
            name = item.get("Name")
            if name:
                if name in data:
                    raise ValueError("agent_workstations_duplicate_field")
                data[name] = item.text
        if not collector._allowed(row, data):
            raise ValueError("agent_workstations_policy_invalid")
        if row["event_id"] in (1102, 7036, 7040, 4104):
            if envelope["module_version"] != MODULE_VERSION:
                raise ValueError("agent_workstations_binding_invalid")
            if any(len((v or "").encode("utf-8")) > (SCRIPT_BYTES if k == "ScriptBlockText" else 512)
                   for k, v in data.items()):
                raise ValueError("agent_workstations_field_size_limit")
    if envelope["module_version"] == MODULE_VERSION:
        from datetime import datetime

        window = int(datetime.fromisoformat(header["observed_at_utc"].replace("Z", "+00:00")).timestamp()) // policy["rate_window_seconds"]
        old_rate = state["rate"]
        expected_window = max(window, old_rate["window"]) if old_rate["window"] is not None else window
        previous_count = old_rate["counts"].get("4104", 0) if old_rate["window"] == expected_window else 0
        admitted = len(rows) if channel == POWERSHELL_CHANNEL else 0
        count = previous_count + admitted
        if (admitted > max(policy["rate_limits"]["4104"] - previous_count, 0) or updated["rate"]["window"] != expected_window
                or updated["rate"]["counts"].get("4104", 0) != count):
            raise ValueError("agent_workstations_rate_invalid")
    packet_entries(packet, rows)
    return deepcopy(rows)
