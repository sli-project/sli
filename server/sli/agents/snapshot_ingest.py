"""Snapshot admission and storage only; no directory or GPO publication."""
from __future__ import annotations

import json

from sli_agent.envelope import canonical, timestamp
from sli_agent.snapshot_stream import object_budget, policy, validate_chunk


def snapshot_policy(ledger, identity, envelope, payload):
    module = envelope["module_id"]
    matches = [item for item in identity.get("assigned_modules", [])
               if isinstance(item, dict) and item.get("module_id") == module]
    if len(matches) != 1 or matches[0].get("enabled") is not True:
        raise ValueError("agent_module_not_assigned")
    current = policy(module, matches[0].get("config", {}))
    binding = ledger.binding(envelope["agent_id"], module)
    if not binding or binding["policy"] != current:
        raise ValueError("agent_source_not_bound")
    cycle = ledger.snapshot_cycle(payload.get("cycle_id"))
    config = cycle["policy"] if cycle else current
    if cycle is None and envelope["policy_revision"] != current["policy_revision"]:
        historical = ledger.snapshot_policy_revision(envelope["agent_id"], module, envelope["policy_revision"])
        if (not historical or not historical["enabled"] or historical["superseded_at"] is None
                or timestamp(payload.get("slot_start_utc")) > historical["superseded_at"]):
            raise ValueError("agent_snapshot_chunk_invalid")
        config = historical["config"]
    if cycle and (cycle["agent_id"] != envelope["agent_id"] or cycle["module_id"] != module
                  or cycle["slot_start_utc"] != payload.get("slot_start_utc")
                  or cycle.get("transport_state", "pending") != "pending"):
        raise ValueError("agent_snapshot_cycle_conflict")
    # Revisions can change during delivery, but source/domain identity cannot.
    if any(current[name] != config[name] for name in ("source_instance_id", "domain_sid", "domain_dns", "scope")):
        raise ValueError("agent_source_not_bound")
    try:
        validate_chunk(envelope, payload, config)
    except (ValueError, TypeError, KeyError):
        raise ValueError("agent_snapshot_chunk_invalid") from None
    if ledger.snapshot_conflict(envelope, payload, config):
        raise ValueError("agent_snapshot_chunk_conflict")
    return config


def conflict(cur, envelope, payload, config):
    """Caller holds the agent lock; slot lock serializes collector replacement."""
    cur.execute("select pg_advisory_xact_lock(170,1)")
    cur.execute("""select cycle_id from sli_agent_snapshot_cycles
        where domain_sid=%s and module_id=%s and slot_start_utc=%s""",
        (config["domain_sid"], envelope["module_id"], payload["slot_start_utc"]))
    existing = cur.fetchone()
    if existing and str(existing["cycle_id"]) != payload["cycle_id"]:
        return True
    cur.execute("""select payload from sli_agent_snapshot_chunks
        where cycle_id=%s and family=%s order by chunk_index limit 1""", (payload["cycle_id"], payload["family"]))
    existing = cur.fetchone()
    if existing and any(existing["payload"][name] != payload[name] for name in
            ("chunk_count", "total_objects", "total_bytes", "family_sha256", "cycle_families")):
        return True
    cur.execute("select packet_id from sli_agent_snapshot_chunks where cycle_id=%s and family=%s and chunk_index=%s",
                (payload["cycle_id"], payload["family"], payload["chunk_index"]))
    if cur.fetchone():
        return True
    cur.execute("""select distinct family,payload->>'total_bytes' as bytes,payload->>'total_objects' as objects
        from sli_agent_snapshot_chunks where cycle_id=%s and family<>%s""", (payload["cycle_id"], payload["family"]))
    families = cur.fetchall()
    objects = object_budget(envelope["module_id"], [payload["total_objects"], *(int(row["objects"]) for row in families)])
    size = (0 if payload["family"] == "computers_v6" else payload["total_bytes"]) + sum(
        int(row["bytes"]) for row in families if row["family"] != "computers_v6")
    return objects > config["max_objects"] or size > config["max_bytes"]


def store_chunk(cur, value):
    """No commit here: the HTTP transaction owns receipt + chunk durability."""
    envelope, payload = value["envelope"], value["payload"]
    cur.execute("""insert into sli_agent_snapshot_cycles
        (cycle_id,agent_id,module_id,slot_start_utc,domain_sid,policy)
        select %s,%s,%s,%s,%s,config from sli_agent_snapshot_policies
        where agent_id=%s and module_id=%s and policy_revision=%s and enabled
        on conflict(cycle_id) do nothing""", (payload["cycle_id"], envelope["agent_id"], envelope["module_id"],
        payload["slot_start_utc"], payload["domain_sid"], envelope["agent_id"], envelope["module_id"], envelope["policy_revision"]))
    cur.execute("""insert into sli_agent_snapshot_chunks(packet_id,cycle_id,family,chunk_index,payload)
        values(%s,%s,%s,%s,%s::jsonb)""", (envelope["packet_id"], payload["cycle_id"], payload["family"],
        payload["chunk_index"], json.dumps(payload)))


def quota_error(cur, value, receipt):
    """Separate durable snapshot budgets; never use the event-only inbox."""
    from server.sli.agents.inbox_quota import InboxLimits
    limits = InboxLimits.from_environment()
    envelope = value["envelope"]
    cur.execute("select pg_advisory_xact_lock(170,1)")
    cur.execute("""select
        count(*) filter(where r.agent_id=%s) as agent_count,
        coalesce(sum(octet_length(c.payload::text)+2048) filter(where r.agent_id=%s),0) as agent_bytes,
        count(*) filter(where r.module_id=%s) as module_count,
        coalesce(sum(octet_length(c.payload::text)+2048) filter(where r.module_id=%s),0) as module_bytes,
        count(*) as global_count,coalesce(sum(octet_length(c.payload::text)+2048),0) as global_bytes
        from sli_agent_snapshot_chunks c join sli_agent_receipts r using(packet_id)
        join sli_agent_snapshot_cycles s using(cycle_id) where s.transport_state='pending'""",
        (envelope["agent_id"], envelope["agent_id"], envelope["module_id"], envelope["module_id"]))
    usage = cur.fetchone()
    addition = len(canonical(value["payload"])) + len(canonical(envelope)) + len(canonical(receipt)) + 4096
    for name in ("agent_count", "agent_bytes", "module_count", "module_bytes", "global_count", "global_bytes"):
        if int(usage[name]) + (addition if name.endswith("bytes") else 1) > getattr(limits, name):
            return "agent_snapshot_" + name + "_limit"
    cur.execute("""select pg_total_relation_size('sli_agent_snapshot_chunks') +
        pg_total_relation_size('sli_agent_snapshot_cycles') + pg_total_relation_size('sli_agent_snapshot_policies') +
        pg_total_relation_size('sli_agent_snapshot_bindings') + pg_total_relation_size('sli_agent_receipts') as bytes""")
    if int(cur.fetchone()["bytes"]) + 2 * addition + 65536 > limits.storage_bytes:
        return "agent_snapshot_storage_bytes_limit"
    return None
