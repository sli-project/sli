"""Server-owned durable inbox budgets; accepted evidence is never evicted."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass

from server.sli.ops.logging_config import log_audit_action, log_event


@dataclass(frozen=True)
class InboxLimits:
    agent_count: int = 4096
    agent_bytes: int = 256 * 1024**2
    module_count: int = 32768
    module_bytes: int = 2 * 1024**3
    global_count: int = 65536
    global_bytes: int = 4 * 1024**3
    # Receipts and imported inbox rows remain durable too. A separate storage
    # high-water mark bounds receipt-only traffic without deleting replay state.
    storage_bytes: int = 16 * 1024**3

    @classmethod
    def from_environment(cls):
        values = {}
        for name, default in asdict(cls()).items():
            value = int(os.environ.get("SLI_AGENT_INBOX_" + name.upper(), default))
            if value < 1:
                raise ValueError("agent_inbox_invalid_limit")
            values[name] = value
        return cls(**values)


def quota_error(cur, value, receipt, rows, *, limits=None):
    """Check and reserve through the caller's receipt/inbox transaction.

    Ingress already holds its agent row lock. This transaction advisory lock
    serializes quota read + INSERT across agents/processes; it must remain held
    until the HTTP caller commits. Usage is rebuilt from durable rows on every
    admission, so restarts and consumer rollbacks cannot reset the budgets.
    Module limits cover that module across all agents, agent limits all modules.
    Bytes count UTF-8 JSON (including duplicated evidence) plus row overhead,
    independently of PostgreSQL compression, rather than wire packet length.
    """
    limits = limits or InboxLimits.from_environment()
    envelope = value["envelope"]
    agent, module = envelope["agent_id"], envelope["module_id"]
    cur.execute("select pg_advisory_xact_lock(157, 1)")
    cur.execute("""with stored as (
        select r.agent_id, r.module_id,
            i.packet_id is not null and i.imported_at is null as pending,
            1024 + octet_length(r.envelope::text) + octet_length(r.receipt::text)
                + case when i.packet_id is null then 0 else
                    coalesce(i.quota_payload_bytes,
                        1024 + octet_length(i.envelope::text) + octet_length(i.packet::text)
                             + octet_length(i.event_rows::text)) end as bytes
        from sli_agent_packet_inbox i join sli_agent_receipts r using(packet_id)
        where i.imported_at is null
    ) select
        count(*) filter(where pending and agent_id=%s) as agent_count,
        coalesce(sum(bytes) filter(where pending and agent_id=%s),0) as agent_bytes,
        count(*) filter(where pending and module_id=%s) as module_count,
        coalesce(sum(bytes) filter(where pending and module_id=%s),0) as module_bytes,
        count(*) filter(where pending) as global_count,
        coalesce(sum(bytes) filter(where pending),0) as global_bytes
        from stored""", (agent, agent, module, module))
    usage = {name: int(amount) for name, amount in cur.fetchone().items()}
    # Let PostgreSQL normalize JSON exactly as for the persisted JSONB fields.
    # The signature is not stored. Both copies of the envelope are charged.
    documents = [envelope, receipt]
    overhead = 1024
    if rows is not None:
        documents += [envelope, value["payload"], rows]
        overhead += 1024
    cur.execute("select coalesce(sum(octet_length(document::text)),0) as bytes, "
                "pg_total_relation_size('sli_agent_receipts') + "
                "pg_total_relation_size('sli_agent_packet_inbox') as storage_bytes "
                "from unnest(%s::jsonb[]) as document", ([json.dumps(item) for item in documents],))
    measured = cur.fetchone()
    packet_bytes = overhead + int(measured["bytes"])
    usage["storage_bytes"] = int(measured["storage_bytes"])
    pending = rows is not None
    for name, limit in asdict(limits).items():
        # Physical storage includes TOAST, indexes and already imported rows.
        # Reserve headroom for page/index allocation, also for receipt-only ACKs.
        addition = (2 * packet_bytes + 65536 if name == "storage_bytes" else
                    (packet_bytes if name.endswith("bytes") else 1) if pending else 0)
        if usage[name] + addition > limit:
            code = "agent_inbox_" + name + "_limit"
            # Fixed codes, UUID identity and numeric budget telemetry only;
            # never include payload, source names or native event evidence.
            fields = {"component": "agents", "event": "packet_quota_rejected",
                      "agent_id": agent, "error_code": code, "module_id": module,
                      "usage": usage, "limit": limit, "packet_bytes": packet_bytes}
            try:
                # The existing bounded audit log needs no new DB action enum
                # and cannot become an unbounded rejection ledger itself.
                log_audit_action("agent_packet_admission", "retry_later", **fields)
            except OSError:
                # A log failure must not turn backpressure into an accepted ACK.
                log_event("agents", "packet_quota_rejected", "Agent inbox quota exceeded",
                          agent_id=agent, error_code=code, module_id=module,
                          usage=usage, limit=limit, packet_bytes=packet_bytes)
            return code
    return None
