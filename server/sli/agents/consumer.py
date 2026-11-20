"""Bounded core inbox polling, using only admitted server-owned importers."""
from collections import Counter
from time import monotonic

from server.sli.agents.import_authorization import PacketPending, authorize_packet, authorize_plugin
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.ops import shutdown
from server.sli.plugins.registry import plugin_hook
from server.sli.plugins.workstations.contracts import Workstation
from server.sli.sources.collection_packet_import import consume_agent_packets, event_rows_from_packet, import_workstation_packet
from server.sli.storage.storage_v2_repository import SourceEventIdentityConflict
from server.sli.agents.runtime_switch import source_agent


class WorkstationIdentity:
    def __init__(self, packet_id, transport_agent=None):
        self.packet_id = packet_id
        self.transport_agent = transport_agent

    def workstation(self, conn, agent_key):
        # Narrow DB capability: no generic identity writes by the API login.
        with conn.cursor() as cur:
            cur.execute("select * from public.resolve_agent_workstation_v160(%s,%s)", (self.transport_agent or agent_key, self.packet_id))
            row = cur.fetchone()
        if not row:
            raise PacketPending("agent_identity_unavailable")
        return Workstation(agent_key, int(row["entity_id"]), row["ad_computer_id"])


def dispatch_packet(conn, rows, *, packet, envelope):
    module = envelope.get("module_id")
    if module == "sli.radius-accounting":
        raise PacketPending("agent_radius_importer_required")
    if module == "sli.file-audit":
        importer = plugin_hook("sli.file-audit", "import_file_audit_agent_packet")
        if importer is None:
            raise PacketPending("agent_plugin_not_installed")
        importer(conn, rows, packet=packet, envelope=envelope)
        return
    if module in ("sli.windows.ad-dc", "sli.windows.ad-dc-history"):
        importer = plugin_hook("sli.ad", "import_ad_agent_packet")
        if importer is None:
            raise PacketPending("agent_plugin_not_installed")
        importer(conn, rows, packet=packet, envelope=envelope)
        return
    if module == "sli.vpn-nps":
        importer = plugin_hook("sli.remote-access", "import_nps_agent_packet")
        if importer is None:
            raise PacketPending("agent_plugin_not_installed")
        importer(conn, rows, packet=packet, envelope=envelope)
        return
    if module != "sli.workstations":
        # The legacy eventlog module has no admitted importer.
        raise PacketPending("dc_importer_unavailable" if module == "sli.windows-eventlog" else "agent_module_unknown")
    with conn.cursor() as cur:
        agent = authorize_packet(cur, envelope, packet, module=module)
        if (event_rows_from_packet(packet) != rows
                or envelope["source_instance_id"] != str(agent["host_id"])
                or packet["header"]["source"] != str(agent["host_id"])):
            raise PacketPending("agent_packet_attestation_invalid")
        # Serialize publication with lifecycle disable; a poll never enables it.
        authorize_plugin(cur, "sli.workstations")
    import_workstation_packet(conn, packet, agent_key=source_agent(agent),
                              identity=WorkstationIdentity(envelope["packet_id"], str(agent["id"])))


class AgentPacketConsumer:
    def __init__(self):
        self.after = None
        self.snapshot_after = None
        self.snapshot_poll_at = 0.0

    def run_once(self, *, limit=16):
        if type(limit) is not int or not 1 <= limit <= 128:
            raise ValueError("agent_import_limit_invalid")
        reasons = Counter()
        scanned = []
        pending_packets = []
        quarantine_reasons = Counter()
        quarantined_packets = []

        def sink(conn, rows, **kwargs):
            try:
                # A bad packet must roll back its own effects and not starve the
                # rest of the batch. All retained reasons are fixed safe codes.
                with conn.transaction():
                    dispatch_packet(conn, rows, **kwargs)
            except SourceEventIdentityConflict as exc:
                # The projection savepoint has rolled back. Retain the evidence
                # and isolate only a proven immutable identity conflict; never
                # turn infrastructure failures into terminal packet states.
                envelope = kwargs["envelope"]
                with conn.cursor() as cur:
                    cur.execute("""insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal)
                        values(%s,%s,%s) on conflict(packet_id) do nothing""",
                        (envelope["packet_id"], exc.reason, exc.ordinal))
                quarantine_reasons[exc.reason] += 1
                quarantined_packets.append({"packet_id": envelope["packet_id"],
                    "module_id": envelope["module_id"], "agent_id": envelope["agent_id"],
                    "reason": exc.reason, "event_ordinal": exc.ordinal})
                return False
            except PacketPending as exc:
                reasons[str(exc)] += 1
                pending_packets.append({"packet_id": kwargs["envelope"]["packet_id"], "reason": str(exc)})
                return False
            except Exception as exc:  # noqa: BLE001 - never log bind values or source XML
                reasons["agent_projection_failed"] += 1
                envelope = kwargs["envelope"]
                pending_packets.append({"packet_id": envelope["packet_id"],
                    "module_id": envelope["module_id"], "agent_id": envelope["agent_id"],
                    "reason": "agent_projection_failed", "error_type": type(exc).__name__})
                return False
            return True

        with connect() as conn:
            imported = 0
            position = self.after
            for _ in range(limit):
                if shutdown.requested():
                    break
                before = len(scanned)
                imported += consume_agent_packets(conn, import_rows=sink, limit=1,
                                                 after=position, on_scan=scanned.append)
                if len(scanned) == before:
                    break
                # Publication and inbox progress stay atomic for each packet.
                # Release agent/plugin lifecycle locks before the next packet
                # so a backlog batch cannot block check-in for its full duration.
                conn.commit()
                position = scanned[-1]
            from server.sli.agents.snapshot_consumer import consume_snapshot_cycles
            from server.sli.agents.snapshot_publication_connection import snapshot_import_connect
            snapshot_scanned = []
            snapshot_poll_at = None
            snapshots = {"completed": 0, "scanned": 0, "pending_reasons": {}}
            if not shutdown.requested() and monotonic() >= self.snapshot_poll_at:
                snapshots = consume_snapshot_cycles(conn, limit=min(limit, 4), after=self.snapshot_after,
                                                    on_scan=snapshot_scanned.append,
                                                    publication_connection_factory=snapshot_import_connect)
                # A busy event inbox must not retry the same failed publication
                # on every bounded batch. Keep snapshot progress independent.
                full_snapshot_batch = snapshots["scanned"] == min(limit, 4)
                snapshot_poll_at = monotonic() + (0 if full_snapshot_batch and not snapshots["pending_reasons"] else 30)
            conn.commit()
        if snapshot_poll_at is not None:
            self.snapshot_after = snapshot_scanned[-1] if snapshot_scanned else None
            self.snapshot_poll_at = snapshot_poll_at
        # Walk past deferred evidence; wrap at the end. Restart simply rescans.
        self.after = scanned[-1] if scanned else None
        if reasons or quarantine_reasons:
            from server.sli.ops.logging_config import log_event
        if quarantine_reasons:
            log_event("agents", "agent_packets_quarantined", "Agent packets have immutable source identity conflicts.",
                      quarantine_reasons=dict(quarantine_reasons), quarantined_packets=quarantined_packets)
        if reasons:
            log_event("agents", "agent_packets_pending", "Agent packets remain pending.",
                      pending_reasons=dict(reasons), pending_packets=pending_packets)
        return {"imported": imported, "scanned": len(scanned), "pending_reasons": dict(reasons),
                "snapshots": snapshots, "quarantined": sum(quarantine_reasons.values()),
                "quarantine_reasons": dict(quarantine_reasons)}
