"""Bounded XML/ACL cleanup; facts, receipts and evidence links are permanent."""
from datetime import timedelta
import json
import os

from server.sli.plugins.file_audit.contracts import RETENTION

MAX_PACKETS = 4  # each packet contains at most 256 source events
MAX_SNAPSHOTS = 100


def cleanup_enabled():
    value = os.environ.get("SLI_FILE_AUDIT_RETENTION_ENABLED", "0")
    if value not in ("0", "1"):
        raise ValueError("file_audit_retention_config_invalid")
    return value == "1"


def retain_batch(conn, *, now, preservation_check, limit=MAX_PACKETS):
    """The existing core lifecycle owns the transaction and deletion admission.

    The verifier must check live history availability even for an empty event
    list. No XML or ACL is removed on an unavailable verification dependency.
    Applied holds and finding references are fenced against concurrent writes.
    """
    if now.utcoffset() is None or type(limit) is not int or not 1 <= limit <= MAX_PACKETS:
        raise ValueError("file_audit_retention_budget_invalid")
    result = {"status": "blocked", "packets_deleted": 0, "snapshots_deleted": 0, "held_count": 0}
    result["tables"] = {name: {"selected_count": 0, "deleted_count": 0,
        "logical_bytes_deleted": 0, "partitions": []} for name in
        ("sli_agent_packet_inbox", "sli_plugin_file_audit.access_snapshots")}
    if preservation_check is None:
        return {**result, "reason": "file_audit_history_unavailable"}
    cutoff = now - timedelta(days=RETENTION["source_payload_days"])
    acl_cutoff = now - timedelta(days=RETENTION["acl_history_days"])
    with conn.cursor() as cur:
        cur.execute("set local statement_timeout = '5000ms'")
        cur.execute("set local lock_timeout = '1000ms'")
        # Both fences precede candidate selection. FK evidence writers are
        # additionally serialized by row locks on the exact core endpoints.
        cur.execute("lock table sli_plugin_file_audit.retention_holds in share mode nowait")
        cur.execute("lock table public.investigation_events in share mode nowait")
        cur.execute("lock table sli_plugin_file_audit.rule_snapshots in share mode nowait")
        cur.execute("lock table sli_plugin_file_audit.rule_actions in share mode nowait")
        cur.execute("""
            /* file_retention_packets */
            select i.packet_id,jsonb_array_length(i.event_rows) as record_count,
              coalesce((select jsonb_agg(jsonb_build_object('id',e.id,
                         'record_id',e.event_record_id,
                         'normalized_hash',encode(e.normalized_hash,'hex')) order by e.id)
                from public.events_v2_core e
                join public.servers s on s.id=e.server_id
                join public.storage_v2_channel c on c.id=e.channel_id
                join public.storage_v2_provider p on p.id=e.provider_id
                join lateral jsonb_array_elements(i.event_rows) r on
                  e.event_record_id=(r->>'record_id')::bigint and e.event_id=(r->>'event_id')::integer
                  and e.time_created_utc=(r->>'time_created')::timestamptz
                  and p.value=r->>'provider_name'
                where s.hostname=i.packet->'header'->>'source' and c.value='Security'), '[]'::jsonb) as events,
              (exists(select 1 from sli_plugin_file_audit.retention_holds h
                      where h.packet_id=i.packet_id)
               or exists(select 1 from sli_plugin_file_audit.observations o
                  join sli_plugin_file_audit.action_evidence ae on ae.evidence_key=o.evidence_key
                  join sli_plugin_file_audit.rule_actions ra on ra.action_id=ae.action_id
                  where o.agent_id=(i.envelope->>'agent_id')::uuid
                    and o.source_instance_id=i.envelope->>'source_instance_id'
                    and o.generation=i.envelope->>'generation'
                    and exists(select 1 from jsonb_array_elements(i.event_rows) r
                               where (r->>'record_id')::bigint=o.record_id))) as held
            from public.sli_agent_packet_inbox i
            where i.envelope->>'module_id'='sli.file-audit' and i.imported_at is not null
              and i.imported_at<%s and i.received_at<%s
              and exists(select 1 from sli_plugin_file_audit.collection_publications p where p.packet_id=i.packet_id)
              and not exists(select 1 from sli_plugin_file_audit.observations o
                  where o.agent_id=(i.envelope->>'agent_id')::uuid
                    and o.source_instance_id=i.envelope->>'source_instance_id'
                    and o.generation=i.envelope->>'generation'
                    and o.core_evidence_ref like 'agent-workstation-event:%'
                    and exists(select 1 from jsonb_array_elements(i.event_rows) r
                               where (r->>'record_id')::bigint=o.record_id))
            order by i.received_at,i.packet_id for update of i skip locked limit %s
        """, (cutoff, cutoff, limit))
        # Workstation source packets remain evidence until their permanent
        # fact-history verifier exists; they must not block server cleanup.
        packets = [dict(row) for row in cur.fetchall()]
        result["tables"]["sli_agent_packet_inbox"]["selected_count"] = len(packets)
        candidates = {}
        for packet in packets:
            if not 0 <= packet["record_count"] <= 256:
                raise RuntimeError("file_audit_retention_budget_invalid")
            events = packet["events"]
            if (packet["held"] or len(events) != packet["record_count"]
                    or len({event["id"] for event in events}) != len(events)):
                result["held_count"] += 1
                continue
            for event in events:
                candidates[int(event["id"])] = bytes.fromhex(event["normalized_hash"])
        if result["held_count"]:
            return {**result, "reason": "file_audit_payload_held_or_unresolved"}
        ids = sorted(candidates)
        if ids:
            cur.execute("""
                /* file_retention_event_locks */
                select id,normalized_hash from public.events_v2_core
                where id=any(%s::bigint[]) order by id for update nowait
            """, (ids,))
            if {int(r["id"]): bytes(r["normalized_hash"]) for r in cur.fetchall()} != candidates:
                raise RuntimeError("file_audit_retention_source_changed")
            cur.execute("""
                /* file_retention_semantic_locks */
                select source_event_id,status from public.semantic_processing_outbox
                where source_event_id=any(%s::bigint[]) for update nowait
            """, (ids,))
            semantic = cur.fetchall()
            if ({int(row["source_event_id"]) for row in semantic} != set(ids)
                    or any(row["status"] != "completed" for row in semantic)):
                return {**result, "held_count": 1, "reason": "file_audit_semantic_pending"}
            cur.execute("""
                /* file_retention_event_holds */
                select e.id from public.events_v2_core e where e.id=any(%s::bigint[]) and (
                  e.time_created_utc>=%s
                  or coalesce((to_jsonb(e)->>'legal_hold')::boolean,false)
                  or exists(select 1 from public.investigation_events i where i.event_db_id=e.id)
                  or exists(select 1 from public.finding_evidence f where f.event_id=e.id)
                  or exists(select 1 from public.detections d where d.primary_event_id=e.id)
                  or not exists(select 1 from public.semantic_processing_outbox s
                                where s.source_event_id=e.id and s.status='completed')
                  or exists(select 1 from public.semantic_processing_outbox s
                            where s.source_event_id=e.id and s.status<>'completed'))
            """, (ids, cutoff))
            if cur.fetchall():
                return {**result, "held_count": 1, "reason": "file_audit_evidence_held"}
        # This exact readback compares all facts, hashes, links and the unique
        # publication receipt. XML is the only packet data removed below.
        preservation_check([{"id": key, "normalized_hash": candidates[key]} for key in ids])
        for packet in packets:
            cur.execute("""
                insert into sli_plugin_file_audit.payload_expirations(packet_id,events,expired_at)
                values(%s,%s::jsonb,%s)
            """, (packet["packet_id"], json.dumps(packet["events"]), now))
            cur.execute("delete from public.sli_agent_packet_inbox where packet_id=%s and imported_at is not null",
                        (packet["packet_id"],))
            if cur.rowcount != 1:
                raise RuntimeError("file_audit_retention_delete_mismatch")
            cur.execute("/* file_retention_readback */ select packet_id from public.sli_agent_packet_inbox where packet_id=%s",
                        (packet["packet_id"],))
            if cur.fetchall():
                raise RuntimeError("file_audit_retention_readback_mismatch")
            result["packets_deleted"] += 1
            result["tables"]["sli_agent_packet_inbox"]["deleted_count"] += 1
        cur.execute("""
            /* file_retention_snapshots */
            select s.snapshot_id from sli_plugin_file_audit.access_snapshots s
            where s.observed_at<%s
              and not exists(select 1 from sli_plugin_file_audit.retention_holds h where h.snapshot_id=s.snapshot_id)
              and not exists(select 1 from sli_plugin_file_audit.rule_snapshots r where r.snapshot_id=s.snapshot_id)
            order by s.observed_at,s.snapshot_id for update of s skip locked limit %s
        """, (acl_cutoff, MAX_SNAPSHOTS))
        snapshots = cur.fetchall()
        result["tables"]["sli_plugin_file_audit.access_snapshots"]["selected_count"] = len(snapshots)
        for snapshot in snapshots:
            cur.execute("delete from sli_plugin_file_audit.access_snapshots where snapshot_id=%s and observed_at<%s",
                        (snapshot["snapshot_id"], acl_cutoff))
            if cur.rowcount != 1:
                raise RuntimeError("file_audit_retention_delete_mismatch")
            cur.execute("/* file_retention_readback */ select snapshot_id from sli_plugin_file_audit.access_snapshots where snapshot_id=%s",
                        (snapshot["snapshot_id"],))
            if cur.fetchall():
                raise RuntimeError("file_audit_retention_readback_mismatch")
            result["snapshots_deleted"] += 1
            result["tables"]["sli_plugin_file_audit.access_snapshots"]["deleted_count"] += 1
    return {**result, "status": "partial" if len(packets) == limit or len(snapshots) == MAX_SNAPSHOTS else "complete"}


def run_batch(*, port, now):
    """Use the core's protected connection only after publication is complete."""
    from server.sli.storage import permanent_fact_history as history
    from server.sli.storage.purge_audit import PurgeRun, failure_reason
    from server.sli.storage.tier_retention_delete_executor_runtime import _connect_write

    def verify(candidates):
        # Empty capture packets and ACL-only runs also require a live history.
        history._rows(port, f"SELECT count() FROM {history.DATABASE}.published_batches")
        history.verify_preserved_candidates(port, candidates)

    audit = PurgeRun("file_audit")
    transaction = "rolled_back"
    try:
        with _connect_write() as conn:
            result = retain_batch(conn, now=now, preservation_check=verify)
            if result["status"] == "blocked":
                conn.rollback()
            else:
                audit.checkpoint({**result, "status": "verified_pending_commit"})
                transaction = "commit_unconfirmed"
                conn.commit()
                transaction = "committed"
    except Exception as error:
        audit.finish({"status": "blocked", "reason": failure_reason(error), "transaction": transaction})
        raise
    audit.finish({**result, "transaction": transaction})
    return result
