"""Bounded noise retention; preserved links remain readable from history."""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import datetime

from server.sli.storage.postgres_profile_retention import (
    DIRECT_NO_ARCHIVE_KNOWN_DEPENDENCIES,
    NOISE_DELETE_EVENT_KEYS,
    direct_no_archive_descriptors,
)
from server.sli.storage.storage_policy import load_storage_policy
from server.sli.storage.purge_audit import PurgeRun, failure_reason
from server.sli.plugins.file_audit.retention import cleanup_enabled
from sli_agent.file_audit_policy import EVENT_IDS, OPTIONAL_EVENT_IDS, PACK_ID, PROVIDER

FILE_RETENTION_GUARDS = """
                when c.source='sli.windows.file-audit' and not exists (
                    select 1 from sli_plugin_file_audit.payload_expirations x
                    where x.events @> jsonb_build_array(jsonb_build_object('id',c.id))
                ) then 'file_payload_pending'
                when c.source='sli.windows.file-audit' and exists (
                    select 1 from sli_plugin_file_audit.payload_expirations x
                    join sli_agent_receipts r on r.packet_id=x.packet_id
                    cross join lateral jsonb_array_elements(x.events) e
                    join sli_plugin_file_audit.observations o
                      on o.agent_id=r.agent_id and o.generation=r.envelope->>'generation'
                      and o.source_instance_id=r.envelope->>'source_instance_id'
                      and o.record_id=(e->>'record_id')::bigint
                    join sli_plugin_file_audit.action_evidence ae on ae.evidence_key=o.evidence_key
                    join sli_plugin_file_audit.rule_actions ra on ra.action_id=ae.action_id
                    where x.events @> jsonb_build_array(jsonb_build_object('id',c.id))
                      and (e->>'id')::bigint=c.id
                ) then 'evidence_reference'
"""


def retain_batch(
    connection, *, cutoff: datetime, preservation_check: Callable[[list[dict]], None],
    after_id: int = 0, batch_size: int = 1_000, apply: bool = True,
) -> dict:
    audit = PurgeRun("event_history")
    result = {}
    try:
        result = _retain_batch(
            connection, cutoff=cutoff, preservation_check=preservation_check,
            after_id=after_id, batch_size=batch_size, apply=apply, result=result,
            before_commit=lambda result: audit.checkpoint({**result, "status": "verified_pending_commit"}),
        )
    except Exception as error:
        transaction = "commit_unconfirmed" if result.get("transaction") == "commit_pending" else "rolled_back"
        try:
            connection.rollback()
        except Exception:
            transaction = "rollback_unconfirmed"
        for table in result.get("tables", {}).values():
            table.update(deleted_count=0, logical_bytes_deleted=0)
        audit.finish({**result, "status": "blocked", "reason": failure_reason(error),
                      "deleted_count": 0, "logical_bytes_deleted": 0,
                      "transaction": transaction})
        raise
    audit.finish(result)
    return result


def _retain_batch(
    connection, *, cutoff: datetime, preservation_check: Callable[[list[dict]], None],
    after_id: int, batch_size: int, apply: bool, result: dict, before_commit: Callable[[dict], None],
) -> dict:
    """Scan at most 1,000 exact descriptor rows, holding unfinished evidence.

    Packed PostgreSQL links are kept intact. Their complete identity set and
    canonical retained details must pass the ClickHouse preservation check
    before the redundant hot event/facts may be removed.
    """
    descriptors = direct_no_archive_descriptors(
        load_storage_policy(), event_keys=NOISE_DELETE_EVENT_KEYS,
    )
    file_cleanup = cleanup_enabled()
    file_guards = FILE_RETENTION_GUARDS if file_cleanup else ""
    if file_cleanup:
        descriptors.extend({"source": PACK_ID, "stream": "Security", "event_key": str(event),
                            "provider_name": PROVIDER} for event in (*EVENT_IDS, *OPTIONAL_EVENT_IDS))
    result.update({
        "status": "blocked", "cutoff_utc": cutoff.isoformat(),
        "selected_count": 0, "deleted_count": 0, "held_count": 0,
        "held_reasons": {}, "last_scanned_id": max(0, int(after_id)),
        "archive_rows_written": 0,
        "tables": {name: {"selected_count": 0, "deleted_count": 0, "logical_bytes_deleted": 0,
                           "partitions": []} for name in ("events_v2_core", "event_facts_v2")},
        "bytes_reclaimed": 0, "logical_bytes_deleted": 0,
        "physical_reclaim_performed": False,
    })
    if not descriptors:
        return {**result, "reason": "direct_no_archive_descriptors_missing"}
    with connection.cursor() as cur:
        cur.execute("set local statement_timeout = '5000ms'")
        cur.execute("set local lock_timeout = '1000ms'")
        if apply:
            # Freeze FK/trigger DDL across dependency inventory and deletion.
            cur.execute("lock table events_v2_core in row exclusive mode nowait")
            if file_cleanup:
                # File findings refer to permanent projection identities, not
                # core FK endpoints. Fence their publication before selection.
                cur.execute("lock table sli_plugin_file_audit.rule_actions in share mode nowait")
        cur.execute("""
            /* history_retention_dependencies */
            select conrelid::regclass::text as dependent_relation,
                   confdeltype as delete_action
            from pg_constraint where contype='f'
              and confrelid=to_regclass('events_v2_core')
        """)
        for dependency in cur.fetchall():
            name = str(dependency["dependent_relation"]).rsplit(".", 1)[-1].strip('"')
            if not (
                name == "event_facts_v2" and dependency["delete_action"] == "c"
                or name in DIRECT_NO_ARCHIVE_KNOWN_DEPENDENCIES
                and dependency["delete_action"] in {"a", "r"}
            ):
                return {**result, "reason": "unknown_event_dependency"}
        cur.execute(f"""
            /* history_retention_candidates */
            with descriptor(source,event_id,channel,provider_name) as (
                select * from unnest(%s::text[],%s::integer[],%s::text[],%s::text[])
            ), source_window as materialized (
                select id,normalized_hash,log_source_id,event_id,channel_id,
                       provider_id,time_created_utc,
                       coalesce((to_jsonb(e)->>'legal_hold')::boolean,false) as legal_hold
                from events_v2_core e where id > %s order by id limit %s
            ), candidates as materialized (
                select e.id,e.normalized_hash,e.log_source_id,e.time_created_utc,
                       e.legal_hold,d.source,d.channel,d.provider_name,d.event_id as noise_event_id
                from source_window e
                join storage_v2_channel ch on ch.id=e.channel_id
                left join storage_v2_provider p on p.id=e.provider_id
                left join descriptor d on d.event_id=e.event_id and d.channel=ch.value
                  and d.provider_name=coalesce(p.value,'')
            )
            select c.id,c.normalized_hash,
              case
                when c.noise_event_id is null or c.time_created_utc >= %s
                  then 'out_of_scope'
                when c.legal_hold then 'legal_hold'
                {file_guards}
                when exists (select 1 from investigation_events i where i.event_db_id=c.id)
                  then 'investigation_evidence'
                when not exists (
                    select 1 from source_capture_continuity_declarations d
                    where d.log_source_id=c.log_source_id
                      and d.descriptor_source=c.source and d.descriptor_stream=c.channel
                      and d.provider_name=c.provider_name and d.channel_value=c.channel
                ) then 'continuity_missing'
                when not exists (
                    select 1 from semantic_processing_outbox s where s.source_event_id=c.id
                ) then 'semantic_missing'
                when exists (
                    select 1 from semantic_processing_outbox s
                    where s.source_event_id=c.id and s.status <> 'completed'
                ) then 'semantic_pending'
                when exists (select 1 from event_links l where l.source_event_id=c.id or l.target_event_id=c.id)
                  or exists (select 1 from entity_states s where s.evidence_event_id=c.id)
                  or exists (select 1 from entity_state_current s where s.source_event_db_id=c.id)
                  or exists (select 1 from detections d where d.primary_event_id=c.id)
                  or exists (select 1 from finding_evidence f where f.event_id=c.id)
                  then 'evidence_reference'
                else 'eligible'
              end as classification
            from candidates c order by c.id
        """, (
            [d["source"] for d in descriptors], [int(d["event_key"]) for d in descriptors],
            [d["stream"] for d in descriptors], [d["provider_name"] for d in descriptors],
            max(0, int(after_id)), max(1, min(int(batch_size), 1_000)), cutoff,
        ))
        rows = [dict(row) for row in cur.fetchall()]
        if not rows:
            return {**result, "status": "complete", "last_scanned_id": 0}
        eligible = [row for row in rows if row["classification"] == "eligible"]
        held = [row for row in rows if row["classification"] not in {"eligible", "out_of_scope"}]
        result.update(
            status="partial", selected_count=len(rows), eligible_count=len(eligible),
            held_count=len(held), last_scanned_id=int(rows[-1]["id"]),
            held_reasons=dict(Counter(row["classification"] for row in held)),
        )
        result["tables"]["events_v2_core"]["selected_count"] = len(eligible)
        if not apply:
            return {**result, "mode": "dry_run"}
        if eligible:
            # Lock unkeyed packed links and both FK endpoints before the
            # independent readback. Fail immediately on concurrent writers.
            cur.execute("lock table event_entity_link_blocks_v2 in share mode nowait")
            # Investigation references deliberately have no event FK. Fence
            # their writers, then recheck after locking the event endpoints.
            cur.execute("lock table investigation_events in share mode nowait")
            ids = [int(row["id"]) for row in eligible]
            hashes = [bytes(row["normalized_hash"]) for row in eligible]
            cur.execute(
                "select id,normalized_hash,pg_column_size(e) as row_bytes from events_v2_core e "
                "where id=any(%s::bigint[]) order by id for update nowait", (ids,),
            )
            locked_rows = cur.fetchall()
            locked = {int(row["id"]): bytes(row["normalized_hash"]) for row in locked_rows}
            if locked != dict(zip(ids, hashes)):
                raise RuntimeError("history_retention_source_changed")
            cur.execute("""
                /* history_retention_locked_holds */
                select e.id from events_v2_core e where e.id=any(%s::bigint[]) and (
                  coalesce((to_jsonb(e)->>'legal_hold')::boolean,false)
                  or exists (select 1 from investigation_events i where i.event_db_id=e.id)
                  or exists (select 1 from finding_evidence f where f.event_id=e.id)
                  or exists (select 1 from detections d where d.primary_event_id=e.id)
                  or exists (select 1 from event_links l where l.source_event_id=e.id or l.target_event_id=e.id)
                  or exists (select 1 from entity_states s where s.evidence_event_id=e.id)
                  or exists (select 1 from entity_state_current s where s.source_event_db_id=e.id)
                )
            """, (ids,))
            if cur.fetchall():
                raise RuntimeError("history_retention_evidence_changed")
            cur.execute(
                "select source_event_id,status from semantic_processing_outbox "
                "where source_event_id=any(%s::bigint[]) for update nowait", (ids,),
            )
            semantic = cur.fetchall()
            if (
                {int(row["source_event_id"]) for row in semantic} != set(ids)
                or any(row["status"] != "completed" for row in semantic)
            ):
                raise RuntimeError("history_retention_semantic_state_changed")
            cur.execute(
                "select event_id,pg_column_size(f) as row_bytes from event_facts_v2 f where event_id=any(%s::bigint[]) "
                "order by event_id for update nowait", (ids,),
            )
            fact_rows = cur.fetchall()
            result["tables"]["event_facts_v2"]["selected_count"] = len(fact_rows)
            preservation_check(eligible)
            cur.execute("""
                delete from events_v2_core e using
                  unnest(%s::bigint[],%s::bytea[]) as manifest(id,normalized_hash)
                where e.id=manifest.id and e.normalized_hash=manifest.normalized_hash
                  and e.time_created_utc < %s
                returning e.id
            """, (ids, hashes, cutoff))
            deleted = sorted(int(row["id"]) for row in cur.fetchall())
            if deleted != sorted(ids):
                raise RuntimeError("history_retention_delete_mismatch")
            cur.execute("""
                /* history_retention_delete_readback */
                select id from events_v2_core where id=any(%s::bigint[])
                union all select event_id from event_facts_v2 where event_id=any(%s::bigint[])
            """, (ids, ids))
            if cur.fetchall():
                raise RuntimeError("history_retention_delete_readback_mismatch")
            result["deleted_count"] = len(deleted)
            for name, deleted_rows in (("events_v2_core", locked_rows), ("event_facts_v2", fact_rows)):
                result["tables"][name].update(
                    selected_count=len(deleted_rows),
                    deleted_count=len(deleted_rows),
                    logical_bytes_deleted=sum(int(row["row_bytes"]) for row in deleted_rows),
                )
            result["logical_bytes_deleted"] = sum(
                table["logical_bytes_deleted"] for table in result["tables"].values()
            )
        result["transaction"] = "prepared"
        before_commit(result)
        result["transaction"] = "commit_pending"
        connection.commit()
        result["transaction"] = "committed"
    if result["held_count"]:
        result["reason"] = "source_rows_held_for_processing_or_evidence"
    return result
