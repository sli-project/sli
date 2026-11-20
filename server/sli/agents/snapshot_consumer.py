"""Durable cycle validation and dispatch to the AD/GPO publication owners."""
from __future__ import annotations

import hashlib
import json
from contextlib import ExitStack
from datetime import datetime, timezone

from server.sli.agents.import_authorization import PacketPending, authorize_packet, authorize_plugin
from server.sli.plugins.registry import require_plugin
from sli_agent.envelope import canonical, digest, validate_envelope
from sli_agent.snapshot_stream import object_budget, validate_chunk


def import_ad_cycle(conn, cycle, families):
    return require_plugin("sli.ad", "import_snapshot_cycle", conn, cycle, families)


def import_gpo_cycle(conn, cycle, families):
    return require_plugin("sli.gpo", "import_snapshot_cycle", conn, cycle, families)


def validate_cycle(cycle, rows):
    """Check frozen membership, attestation and hashes without importing rows."""
    config = cycle["policy"]
    by_family = {family: [] for family in config["families"]}
    previous = None
    object_counts = []
    total_bytes = 0
    try:
        for row in rows:
            envelope, payload = row["envelope"], row["payload"]
            validate_envelope(envelope)
            if (envelope["agent_id"] != cycle["agent_id"] or envelope["module_id"] != cycle["module_id"]
                    or payload["cycle_id"] != cycle["cycle_id"] or payload["slot_start_utc"] != cycle["slot_start_utc"]
                    or digest(envelope) != row["envelope_sha256"] or digest(payload) != envelope["payload_sha256"]
                    or len(canonical(payload)) != envelope["payload_bytes"] or envelope["record_count"] != 1):
                raise ValueError()
            fragment = validate_chunk(envelope, payload, config)
            if previous and (envelope["sequence"] != previous["sequence"] + 1
                             or envelope["cursor_before"] != previous["cursor_after"]):
                raise ValueError()
            previous = envelope
            by_family[payload["family"]].append((payload, fragment))
        for family, chunks in by_family.items():
            if not chunks:
                return False
            header = chunks[0][0]
            if len(chunks) != header["chunk_count"]:
                return False
            sha = hashlib.sha256()
            size = 0
            for index, (payload, fragment) in enumerate(chunks):
                if payload["chunk_index"] != index or any(payload[name] != header[name] for name in
                        ("chunk_count", "total_objects", "total_bytes", "family_sha256")):
                    raise ValueError()
                sha.update(fragment)
                size += len(fragment)
            if size != header["total_bytes"] or sha.hexdigest() != header["family_sha256"]:
                raise ValueError()
            object_counts.append(header["total_objects"])
            total_bytes += 0 if family == "computers_v6" else size
        if object_budget(cycle["module_id"], object_counts) > config["max_objects"] or total_bytes > config["max_bytes"]:
            raise ValueError()
        return True
    except (ValueError, TypeError, KeyError):
        raise ValueError("agent_snapshot_cycle_invalid") from None


def consume_snapshot_cycles(conn, *, limit=4, after=None, on_scan=None, publication_connection_factory=None):
    if type(limit) is not int or not 1 <= limit <= 16:
        raise ValueError("agent_snapshot_limit_invalid")
    # End the read transaction before taking lifecycle locks. Each bounded
    # cycle then releases its locks before the next agent is examined.
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("""select cycle_id::text,agent_id::text,module_id,slot_start_utc,domain_sid,policy
            from sli_agent_snapshot_cycles where (transport_state='pending'
                or publication_state='pending')
            and (%s::uuid is null or (slot_start_utc::timestamptz,cycle_id)>
                (select slot_start_utc::timestamptz,cycle_id from sli_agent_snapshot_cycles where cycle_id=%s::uuid))
            order by slot_start_utc::timestamptz,cycle_id limit %s""", (after, after, limit))
        cycles = cur.fetchall()
    completed = 0
    reasons = {}
    for cycle in cycles:
        transport_completed = False
        if on_scan:
            on_scan(cycle["cycle_id"])
        try:
            if isinstance(cycle["slot_start_utc"], datetime):
                # Keep the validator and publication owners on the signed UTC text contract.
                cycle = {**cycle, "slot_start_utc": cycle["slot_start_utc"].astimezone(timezone.utc).isoformat()}
            with ExitStack() as stack:
                cycle_conn = conn
                if publication_connection_factory is not None:
                    try:
                        cycle_conn = stack.enter_context(publication_connection_factory())
                    except Exception:  # noqa: BLE001 - connection diagnostics may contain credentials
                        raise PacketPending("agent_snapshot_import_unavailable") from None
                stack.enter_context(cycle_conn.transaction())
                cur = stack.enter_context(cycle_conn.cursor())
                # Match lifecycle lock order used by other agent consumers.
                cur.execute("""select c.payload,r.envelope,r.envelope_sha256
                    from sli_agent_snapshot_chunks c join sli_agent_receipts r using(packet_id)
                    where c.cycle_id=%s order by r.sequence limit 1""", (cycle["cycle_id"],))
                first = cur.fetchone()
                if not first:
                    continue
                agent = authorize_packet(cur, first["envelope"], first["payload"],
                                         module=cycle["module_id"], snapshot=True)
                matches = [item for item in agent["assigned_modules"] if isinstance(item, dict)
                           and item.get("module_id") == cycle["module_id"]]
                current = matches[0].get("config", {})
                if any(current.get(name) != cycle["policy"][name] for name in
                        ("source_instance_id", "domain_sid", "domain_dns", "scope")):
                    raise PacketPending("agent_source_not_bound")
                authorize_plugin(cur, "sli.ad" if cycle["module_id"] == "sli.ad-snapshot" else "sli.gpo")
                cur.execute("select transport_state,publication_state from sli_agent_snapshot_cycles where cycle_id=%s for update",
                            (cycle["cycle_id"],))
                state = cur.fetchone()
                if state["transport_state"] != "pending" and state["publication_state"] != "pending":
                    continue
                cur.execute("""select c.payload,r.envelope,r.envelope_sha256
                    from sli_agent_snapshot_chunks c join sli_agent_receipts r using(packet_id)
                    where c.cycle_id=%s order by r.sequence""", (cycle["cycle_id"],))
                rows = cur.fetchall()
                if validate_cycle(cycle, rows):
                    if state["transport_state"] == "pending":
                        cur.execute("""update sli_agent_snapshot_cycles set transport_state='complete',
                            completed_at=clock_timestamp() where cycle_id=%s""", (cycle["cycle_id"],))
                        transport_completed = True
                    if state["publication_state"] == "pending":
                        families = {family: bytearray() for family in cycle["policy"]["families"]}
                        for row in rows:
                            families[row["payload"]["family"]].extend(validate_chunk(row["envelope"], row["payload"], cycle["policy"]))
                        try:
                            # Source incompleteness must retain a publication
                            # pending cycle without consuming transport quotas.
                            # A savepoint rolls back every report mutation.
                            with cycle_conn.transaction():
                                decoded = {family: json.loads(raw) for family, raw in families.items()}
                                for family, data in decoded.items():
                                    actual = len(data["objects"] if family == "computers_v6" else data["gpos"] if family == "gpo_v2" else data["records"])
                                    declared = next(row["payload"]["total_objects"] for row in rows if row["payload"]["family"] == family)
                                    if actual != declared:
                                        raise ValueError("agent_snapshot_object_count_mismatch")
                                if cycle["module_id"] == "sli.ad-snapshot":
                                    result = import_ad_cycle(cycle_conn, cycle, decoded)
                                    cur.execute("""update sli_agent_snapshot_cycles set publication_state='published',
                                        manifest_id=%s,published_at=clock_timestamp() where cycle_id=%s""",
                                        (result["manifest_id"], cycle["cycle_id"]))
                                else:
                                    result = import_gpo_cycle(cycle_conn, cycle, decoded)
                                    cur.execute("""update sli_agent_snapshot_cycles set publication_state='published',
                                        gpo_source_run_id=%s,published_at=clock_timestamp() where cycle_id=%s""",
                                        (result["source_run_id"], cycle["cycle_id"]))
                        except PacketPending as exc:
                            code = str(exc)
                            if code in {"agent_ad_snapshot_superseded", "agent_gpo_snapshot_superseded"}:
                                # The import savepoint has rolled back. A stale cycle
                                # can never become current; retain its terminal receipt.
                                cur.execute("""update sli_agent_snapshot_cycles set publication_state='superseded',
                                    superseded_reason=%s,superseded_at=clock_timestamp() where cycle_id=%s""",
                                            (code, cycle["cycle_id"]))
                            else:
                                reasons[code] = reasons.get(code, 0) + 1
                        except Exception:  # noqa: BLE001 - no source diagnostics
                            code = "agent_ad_publication_failed" if cycle["module_id"] == "sli.ad-snapshot" else "agent_gpo_publication_failed"
                            reasons[code] = reasons.get(code, 0) + 1
            completed += int(transport_completed)
        except PacketPending as exc:
            reasons[str(exc)] = reasons.get(str(exc), 0) + 1
        except Exception:  # noqa: BLE001 - payloads and DB diagnostics stay private
            reasons["agent_snapshot_cycle_invalid"] = reasons.get("agent_snapshot_cycle_invalid", 0) + 1
    return {"completed": completed, "scanned": len(cycles), "pending_reasons": reasons}
