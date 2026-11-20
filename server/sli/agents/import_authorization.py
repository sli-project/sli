"""Import-time authority, serialized with agent and plugin lifecycle changes."""
from sli_agent.envelope import digest
from sli_agent.snapshot_stream import MODULE_FAMILIES
from server.sli.agents.runtime_switch import source_host


class PacketPending(ValueError):
    pass


def authorize_packet(cur, envelope, packet, *, module, snapshot=False):
    # Snapshot publication reads lifecycle state without changing the agent.
    # KEY SHARE still excludes explicit FOR UPDATE policy/revoke writers, but
    # permits transport NO KEY UPDATE and its last_seen write. Other importers
    # keep their existing strong lock, including workstation identity dispatch.
    if snapshot and module not in MODULE_FAMILIES:
        raise PacketPending("agent_snapshot_module_invalid")
    lock = "for key share" if snapshot else "for update"
    cur.execute("select * from sli_agents where id=%s " + lock, (envelope["agent_id"],))
    agent = cur.fetchone()
    if not agent or agent["status"] != "active":
        raise PacketPending("agent_disabled")
    assignments = agent["assigned_modules"]
    matches = [item for item in assignments if isinstance(item, dict) and item.get("module_id") == module]
    if len(matches) != 1 or matches[0].get("enabled") is not True:
        raise PacketPending("agent_module_not_assigned")
    cur.execute("select envelope,envelope_sha256 from sli_agent_receipts where packet_id=%s and agent_id=%s and module_id=%s",
                (envelope["packet_id"], envelope["agent_id"], module))
    receipt = cur.fetchone()
    if (not receipt or receipt["envelope"] != envelope or receipt["envelope_sha256"] != digest(envelope)
            or digest(packet) != envelope.get("payload_sha256")):
        raise PacketPending("agent_packet_attestation_invalid")
    # Only a replacement changes source identity. Legacy AD/snapshot imports
    # authorize through retained bindings and do not require a host projection.
    # Both host fields come from the locked registry row, never the packet.
    if agent.get("source_host_id"):
        return {**agent, "host_id": source_host(agent)}
    if module == "sli.workstations" and not agent.get("host_id"):
        raise PacketPending("agent_identity_unavailable")
    return agent


def authorize_plugin(cur, plugin_id):
    cur.execute("select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'))")
    cur.execute("select installed,enabled from read_plugin_states_v1() where plugin_id=%s", (plugin_id,))
    plugin = cur.fetchone()
    if not plugin or not plugin["installed"] or not plugin["enabled"]:
        raise PacketPending("agent_plugin_disabled")
