"""Plugin projection on the core inbox transaction; no permanent worker."""
import importlib
import json
from datetime import timedelta

from server.sli.agents.import_authorization import (
    PacketPending,
    authorize_packet,
    authorize_plugin,
)
from server.sli.plugins.file_audit.agent_ingest import assignment_for, packet_rows
from server.sli.plugins.file_audit.correlation import (
    WINDOW_SECONDS,
    delete_context,
    observation_from_xml,
    project_actions,
)
from server.sli.plugins.file_audit.rule_runtime import evaluate_packet
from server.sli.sources.collection_packet_import import event_rows_from_packet
from sli_agent.envelope import timestamp
from sli_agent.file_audit_policy import CONTEXT_EVENT_IDS, policy


def import_packet(conn, rows, *, packet, envelope):
    with conn.cursor() as cur:
        agent = authorize_packet(cur, envelope, packet, module="sli.file-audit")
        authorize_plugin(cur, "sli.file-audit")
        current = assignment_for(agent["assigned_modules"])
        captured = current
        if current.get("config", {}).get("policy_revision", "1") != envelope["policy_revision"]:
            from server.sli.agent_ingest import PostgresLedger
            retained = PostgresLedger(cur).policy_assignment(
                envelope["agent_id"], "sli.file-audit", envelope["policy_revision"])
            if not retained:
                raise PacketPending("file_audit_policy_not_retained")
            captured = assignment_for([retained])
        config = policy(captured.get("config", {}))
        if (current.get("config", {}).get("source_name") != config.get("source_name")
                or current.get("config", {}).get("source_kind", "server") != config.get("source_kind", "server")):
            raise PacketPending("file_audit_source_binding_changed")
        if event_rows_from_packet(packet) != rows or packet_rows(agent, captured, envelope, packet) != rows:
            raise PacketPending("agent_packet_attestation_invalid")
        # The administrator binds to an existing source; XML Computer is never
        # authority to create a server or domain, or to choose a storage scope.
        workstation = config.get("source_kind") == "workstation"
        if workstation:
            authorize_plugin(cur, "sli.workstations")
            if not any(isinstance(item, dict) and item.get("module_id") == "sli.workstations"
                       and item.get("enabled") is True for item in agent["assigned_modules"]):
                raise PacketPending("file_audit_workstation_not_assigned")
        else:
            cur.execute("select id as server_id,domain_id,site_id from servers where hostname=%s and is_active",
                        (packet["header"]["source"],))
            sources = cur.fetchall()
            if len(sources) != 1:
                raise PacketPending("file_audit_source_not_configured")
        # Published correlation is immutable. Later context or a replay's
        # pending predecessors must not change a packet's retained projection.
        cur.execute("select sli_plugin_file_audit.collection_replay(%s,%s) as publication",
                    (envelope["agent_id"], envelope["packet_id"]))
        publication = cur.fetchone()["publication"]
        if publication is not None:
            if publication["observed"] != len(rows):
                raise PacketPending("file_audit_replay_conflict")
            return publication
        core_rows = rows
        if not workstation and any(row["event_id"] in CONTEXT_EVENT_IDS for row in rows):
            cur.execute("select exists(select 1 from sli_agent_module_bindings "
                        "where agent_id=%s and module_id='sli.windows.ad-dc' "
                        "and source_name=%s and channel='ad-dc') as ad_context_bound",
                        (envelope["agent_id"], packet["header"]["source"]))
            if cur.fetchone()["ad_context_bound"]:
                # File context is deliberately masked. The bound AD/DC source
                # owns its full core event; republishing the masked copy would
                # conflict with its immutable hash. Keep all file observations
                # for correlation, and retain standalone server publication.
                core_rows = [row for row in rows if row["event_id"] not in CONTEXT_EVENT_IDS]
        if core_rows and not workstation:
            from server.sli.plugins.ad.event_import import import_event_rows
            from server.sli.storage.storage_v2_worker_connection import (
                connect_storage_v2_worker,
            )
            native = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")
            runtime = native.load_authorized_direct_runtime(cur, connect_factory=connect_storage_v2_worker,
                                                          publish_archive=False)
            if runtime is None:
                raise PacketPending("agent_storage_unavailable")
            import_event_rows(cur, rows, source=sources[0], header=packet["header"], envelope=envelope,
                              direct_runtime=runtime, publication_rows=core_rows)
        observations = [observation_from_xml(row["xml"], agent_id=envelope["agent_id"],
            source_instance_id=envelope["source_instance_id"], generation=envelope["generation"],
            policy_revision=envelope["policy_revision"],
            core_evidence_ref=(f"{'agent-workstation-event' if workstation else 'agent-event'}:"
                f"{envelope['agent_id']}:{envelope['generation']}:{row['record_id']}"),
            config=config) for row in rows]
        contexts, actions = [], []
        if observations:
            start = min(timestamp(row["observed_at"]) for row in observations) - timedelta(seconds=WINDOW_SECONDS)
            end = max(timestamp(row["observed_at"]) for row in observations)
            if end - start > timedelta(days=1):
                # Historical backlog is processed without guessing correlations.
                complete = False
            else:
                keys = [{"policy_revision": item["policy_revision"], "facts": item["facts"]}
                        for item in observations]
                cur.execute("select sli_plugin_file_audit.collection_context_for_packet(%s,%s,%s,%s,%s::jsonb) as context",
                            (envelope["agent_id"], envelope["packet_id"], start, end, json.dumps(keys)))
                retained = cur.fetchone()["context"]
                complete, contexts = retained["complete"], retained["observations"]
            if envelope["continuity_state"] == "gap":
                complete = False
            for item in observations:
                if item["event_id"] == 4660:
                    item["correlation_state"] = delete_context(item, contexts)[0] if complete else "partial"
                projected = project_actions(item, contexts if complete else ())
                if not complete:
                    for action in projected:
                        action["correlation_state"] = "partial"
                actions.extend(projected)
                contexts.append(item)
        projection = {"observations": observations, "actions": actions}
        cur.execute("select sli_plugin_file_audit.store_collection(%s,%s,%s::jsonb)",
                    (envelope["agent_id"], envelope["packet_id"], json.dumps(projection)))
        evaluate_packet(cur, envelope=envelope, actions=actions, config=config)
        return {"observed": len(observations), "actions": len(actions)}
