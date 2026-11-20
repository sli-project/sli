"""Revalidate owner policy and native XML before the core agent receipt."""
from server.sli.sources.collection_packet_import import event_rows_from_packet
from sli_agent.envelope import canonical, timestamp
from sli_agent.file_audit_collection import FileAuditModule, WIRE_BYTES
from sli_agent.file_audit_events import admitted_event, fields_are_masked, native_event
from sli_agent.file_audit_journal import valid_generation


def assignment_for(assignments):
    matches = [item for item in assignments if isinstance(item, dict) and item.get("module_id") == "sli.file-audit"]
    if len(matches) != 1 or matches[0].get("enabled") is not True:
        raise ValueError("file_audit_not_assigned")
    return matches[0]


def admitted_rows(ledger, identity, envelope, packet):
    from server.sli.agent_ingest import _capture_assignment
    assignment = _capture_assignment(ledger, identity, envelope)
    if assignment is None:
        raise ValueError("file_audit_not_assigned")
    return packet_rows(identity, assignment, envelope, packet)


def packet_rows(identity, assignment, envelope, packet):
    rows = event_rows_from_packet(packet)
    host = str(identity["host_id"])
    collector = FileAuditModule(host, assignment_for([assignment]).get("config", {}))
    config = collector.policy
    header = packet["header"]
    if (envelope["module_id"] != "sli.file-audit" or envelope["source_instance_id"] != host
            or not valid_generation(envelope["generation"], host) or envelope["channel"] != "Security"
            or envelope["module_version"] != "1.0.0" or envelope["payload_contract"] != "sli.collection-packet.v1"
            or envelope["policy_revision"] != config["policy_revision"]
            or header["source"] != collector.source_name or header["generation"] != envelope["generation"] or header["channel"] != "Security"
            or timestamp(header["observed_at_utc"]) != timestamp(envelope["observed_at_utc"])
            or len(canonical(packet)) > min(config["max_bytes"], WIRE_BYTES)):
        raise ValueError("file_audit_binding_invalid")
    before = collector.state(envelope["cursor_before"])
    after = collector.state(envelope["cursor_after"])
    start, last = before["record_id"], after["record_id"]
    context = packet["context"]
    filtered, lost, error = context.get("filtered_count"), context.get("lost_count"), context.get("read_error")
    journal_gap = error == "file_audit_journal_gap"
    bound = after.get('since_utc')
    old_bound = before.get('since_utc')
    if bound != old_bound:
        from datetime import timedelta
        depth = config.get('initial_read_hours', 'all')
        if (old_bound is not None or start is not None or bound is None or depth == 'all'
                or timestamp(bound) != timestamp(envelope['observed_at_utc']) - timedelta(hours=depth)):
            raise ValueError('file_audit_initial_window_invalid')
    comparable_after = {k: v for k, v in after.items() if k != 'since_utc'}
    comparable_before = {k: v for k, v in before.items() if k != 'since_utc'}
    if (set(context) != {"policy_revision", "filtered_count", "lost_count", "read_error"}
            or context["policy_revision"] != config["policy_revision"]
            or type(filtered) is not int or filtered < 0
            or lost is not None and (type(lost) is not int or lost < 0)
            or error not in (None, "file_audit_read_failed", "file_audit_journal_gap") or (lost is None) != bool(error)
            or len(rows) + filtered + (lost or 0) > min(config["max_events"], 256)
            or envelope["filtered_count"] != filtered or envelope["lost_count"] != lost
            or envelope["continuity_state"] != ("gap" if error or lost else "filtered" if filtered else "not_proven")
            or packet["continuity"] != {"status": "not_proven"}
            or header["cursor"] != {"after_record_id": start, "last_record_id": last}):
        raise ValueError("file_audit_continuity_invalid")
    if (after["generation"] != envelope["generation"]
            or before["generation"] != envelope["generation"] and not (journal_gap and start is None)
            or journal_gap and not rows and (start is not None or last is not None
                or envelope["generation"] == host or before["bookmark"] or after["bookmark"])
            or journal_gap and rows and not any(row["event_id"] == 1102 for row in rows)):
        raise ValueError("file_audit_generation_invalid")
    ids = [row["record_id"] for row in rows]
    if (any(type(n) is not int or n <= 0 for n in ids) or ids != sorted(set(ids))
            or any(start is not None and n <= start or last is None or n > last for n in ids)
            or start is not None and (last is None or last < start)
            or not filtered and not lost and not journal_gap and last != (ids[-1] if ids else start)
            or (filtered or lost) and (last is None or start is not None and last <= start)
            or error == "file_audit_read_failed" and (rows or filtered or comparable_after != comparable_before)
            or not rows and not filtered and not lost and comparable_after != comparable_before and not journal_gap):
        raise ValueError("file_audit_range_invalid")
    for row in rows:
        parsed, data = native_event(row["xml"], collector.source_name)
        if (bound is not None and start is None and timestamp(row['time_created']) < timestamp(bound)
                or parsed != row or not fields_are_masked(row["xml"], config)
                or not admitted_event(parsed, data, config)[0]):
            raise ValueError("file_audit_event_invalid")
    return rows
