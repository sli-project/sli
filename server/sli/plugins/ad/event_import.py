"""Bounded AD inbox adapter over the unchanged collector's Storage V2 pipeline."""
from __future__ import annotations

import importlib
import json
import os
from collections import Counter
from hashlib import sha256

from server.sli.agents.import_authorization import (
    PacketPending,
    authorize_packet,
    authorize_plugin,
)
from server.sli.plugins.registry import plugin_hook
from server.sli.sources.collection_packet_import import (
    consume_agent_packets,
    event_rows_from_packet,
)

_after = None


def import_ad_agent_packet(conn, rows, *, packet, envelope):
    """Publish admitted DC evidence from the core poller's inbox transaction."""
    from server.sli.storage.storage_v2_worker_connection import (
        connect_storage_v2_worker,
    )

    importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")
    with conn.cursor() as cur:
        runtime = importer.load_authorized_direct_runtime(
            cur, connect_factory=connect_storage_v2_worker, publish_archive=False)
    if runtime is None:
        raise PacketPending("agent_storage_unavailable")
    return import_ad_dc_packet(conn, rows, packet=packet, envelope=envelope, direct_runtime=runtime)


def import_ad_dc_packet(conn, rows, *, packet, envelope, direct_runtime):
    importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")
    if not importer.is_authorized_direct_runtime(direct_runtime):
        raise RuntimeError("storage_v2_admission_required")
    if envelope.get("module_id") not in ("sli.windows.ad-dc", "sli.windows.ad-dc-history") or event_rows_from_packet(packet) != rows:
        raise ValueError("agent_ad_dc_packet_invalid")
    header = packet["header"]
    with conn.cursor() as cur:
        authorize_packet(cur, envelope, packet, module=envelope["module_id"])
        authorize_plugin(cur, "sli.ad")
        cur.execute("""select source_instance_id,source_name,channel,module_version,policy_revision
            from sli_agent_module_bindings where agent_id=%s and module_id=%s""",
            (envelope["agent_id"], "sli.windows.ad-dc"))
        binding = cur.fetchone()
        if (not binding or binding["source_name"] != header["source"] or any(
                binding[key] != envelope.get(key) for key in
                ("source_instance_id", "channel", "module_version"))):
            raise PacketPending("agent_ad_dc_source_not_bound")
        # The inbox was admitted under its original policy. A later policy
        # revision must not strand already acknowledged evidence.
        validator = plugin_hook("sli.ad", "ad_agent_rows")
        if validator is None:
            raise PacketPending("agent_packet_attestation_invalid")
        try:
            validated_rows = validator(envelope, packet, binding)
        except ValueError as exc:
            # The native attestation hook uses one fixed code for malformed
            # signed inputs. Other importer errors remain projection failures.
            if str(exc) != "agent_collection_cursor_invalid":
                raise
            raise PacketPending("agent_packet_attestation_invalid") from None
        if validated_rows != rows:
            raise PacketPending("agent_packet_attestation_invalid")
        # Use the existing DC/domain IDs. Ambiguous names require an operator
        # binding decision; never create a parallel domain/server for an agent.
        cur.execute("""select id as server_id,domain_id,site_id from servers
            where hostname=%s and role='domain_controller' and is_active""",
                    (binding["source_name"],))
        sources = cur.fetchall()
        if len(sources) != 1:
            raise ValueError("agent_ad_dc_source_not_configured")
        source = sources[0]
        return import_event_rows(cur, rows, source=source, header=header,
                                 envelope=envelope, direct_runtime=direct_runtime)


def import_event_rows(cur, rows, *, source, header, envelope, direct_runtime, publication_rows=None):
    """Shared native-event publication into the existing Storage V2 pipeline."""
    importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")
    if not importer.is_authorized_direct_runtime(direct_runtime):
        raise RuntimeError("storage_v2_admission_required")
    if not rows:
        return {"inserted": 0, "skipped": 0}
    core_rows = rows if publication_rows is None else publication_rows
    if any(row not in rows for row in core_rows):
        raise ValueError("agent_core_publication_rows_invalid")
    if not core_rows:
        return {"inserted": 0, "skipped": 0}
    cur.execute("select id from log_sources where name=%s", (header["channel"],))
    log_source = cur.fetchone()
    if not log_source:
        raise ValueError("agent_ad_dc_channel_not_configured")
    importer.require_entity_state_projection_schema(cur)
    # Content-addressed raw metadata is identical across retries. Evidence
    # remains in the durable inbox; no temporary source files or DB on agent.
    # A publication subset never changes the complete packet's raw identity.
    raw = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows).encode("utf-8")
    raw_hash = sha256(raw).hexdigest()
    reserved = direct_runtime.repository.reserve_raw_log_file(
        server_id=source["server_id"], log_source_id=log_source["id"],
        file_path="agent-packet:" + envelope["packet_id"], sha256=raw_hash,
        size_bytes=len(raw), file_format="jsonl")
    profile = importer.ImportProfile(file="agent-packet", rows=len(rows))
    inserted, skipped = importer.import_direct_event_batch(
        cur, [(row, importer.parse_event_data(row.get("xml"))) for row in core_rows],
        direct_runtime=direct_runtime, **source, log_source_id=log_source["id"],
        raw_log_file_id=int(reserved["id"]), normalized_at=str(reserved["imported_at"]),
        batch_identity=lambda ids, batch: f"{source['server_id']}:{raw_hash}:{batch}:{min(ids)}-{max(ids)}",
        entity_cache={}, profile=profile,
        # Storage publication is independently idempotent. If a crash occurs
        # before inbox/state jobs commit, retry must still enqueue those jobs.
        relink_existing_events=True,
        resolve_identity_merges=importer._entity_merge_resolver_available(cur),
    )
    importer.finalize_raw_log_file(cur, raw_log_file_id=int(reserved["id"]),
        server_id=source["server_id"], log_source_id=log_source["id"],
        sha256_value=raw_hash, rows_count=len(rows), repair_v1_references=False)
    return {"inserted": inserted, "skipped": skipped}


def agent_import_enabled():
    enabled = os.environ.get("SLI_AD_DC_AGENT_IMPORT_ENABLED", "0")
    if enabled not in ("0", "1"):
        raise ValueError("agent_ad_dc_import_config_invalid")
    return enabled == "1"


def run_agent_import_once(*, limit=16):
    """Opt-in stage 8A seam in the existing core post-collection executor."""
    global _after
    if not agent_import_enabled():
        return 0
    from server.sli.core.postgres_runtime_pipeline import connect
    from server.sli.storage.storage_v2_worker_connection import (
        connect_storage_v2_worker,
    )
    importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")
    reasons = Counter()
    scanned = []
    pending_packets = []
    try:
        if type(limit) is not int or not 1 <= limit <= 128:
            raise ValueError("agent_import_limit_invalid")
        with connect() as conn:
            with conn.cursor() as cur:
                runtime = importer.load_authorized_direct_runtime(
                    cur, connect_factory=connect_storage_v2_worker, publish_archive=False)
            def sink(connection, rows, **kwargs):
                try:
                    with connection.transaction():
                        import_ad_dc_packet(connection, rows, direct_runtime=runtime, **kwargs)
                except PacketPending as exc:
                    reasons[str(exc)] += 1
                    pending_packets.append({"packet_id": kwargs["envelope"]["packet_id"], "reason": str(exc)})
                    return False
                except Exception:  # noqa: BLE001 - never expose DB/source diagnostics
                    reasons["agent_ad_dc_projection_failed"] += 1
                    pending_packets.append({"packet_id": kwargs["envelope"]["packet_id"], "reason": "agent_ad_dc_projection_failed"})
                    return False
                return True
            imported = 0
            position = _after
            for _ in range(limit):
                before = len(scanned)
                imported += consume_agent_packets(conn, module_id="sli.windows.ad-dc", limit=1,
                    import_rows=sink, after=position, on_scan=scanned.append)
                if len(scanned) == before:
                    break
                # Keep each packet's projection and inbox progress atomic, but
                # release its agent/plugin lifecycle locks before the next one.
                conn.commit()
                position = scanned[-1]
        _after = scanned[-1] if scanned else None
        if reasons:
            from server.sli.ops.logging_config import log_event
            log_event("agents", "agent_ad_dc_packets_pending", "AD/DC packets remain pending.",
                      pending_reasons=dict(reasons), pending_packets=pending_packets)
        return imported
    except Exception:  # noqa: BLE001 -- fixed diagnostic at the worker boundary
        # The existing worker logs exception text; DB/source diagnostics stay private.
        raise RuntimeError("agent_ad_dc_import_failed") from None
