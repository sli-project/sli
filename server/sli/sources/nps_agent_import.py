"""Remote-access-owned agent adapter over the unchanged NPS/Accounting sinks."""
import importlib
import json
import os
from dataclasses import asdict
from pathlib import Path

from server.sli.agents.consumer import PacketPending
from server.sli.sources.ad_dc_agent_import import import_event_rows
from server.sli.sources.collection_packet_import import event_rows_from_packet
from sli_agent.envelope import digest
from sli_agent.nps import NPS_MODULE, assignment_for, file_cursor


class AccountingConnection:
    """Keep the legacy tuple-row contract on the same inbox transaction."""
    def __init__(self, conn):
        self.conn = conn

    def cursor(self):
        from psycopg.rows import tuple_row

        return self.conn.cursor(row_factory=tuple_row)

    def transaction(self):
        return self.conn.transaction()


def import_nps_agent_packet(conn, rows, *, packet, envelope):
    # Serialize with owner policy/revocation and plugin lifecycle changes.
    with conn.cursor() as cur:
        cur.execute("select status,assigned_modules from public.lock_nps_import_agent_v304(%s)", (envelope["agent_id"],))
        agent = cur.fetchone()
        if not agent or agent["status"] != "active":
            raise PacketPending("agent_disabled")
        try:
            policy = assignment_for(agent["assigned_modules"], envelope["module_id"], active=False)
        except ValueError:
            raise PacketPending("agent_module_not_assigned") from None
        # An acknowledged revision survives pause/revision changes. Its source
        # must still be bound to the same owner-approved stream.
        if envelope["source_instance_id"] != policy["source_instance_id"]:
            raise PacketPending("agent_source_binding_changed")
        cur.execute("select envelope,envelope_sha256 from sli_agent_receipts where packet_id=%s and agent_id=%s and module_id=%s",
                    (envelope["packet_id"], envelope["agent_id"], envelope["module_id"]))
        receipt = cur.fetchone()
        if (not receipt or receipt["envelope"] != envelope or receipt["envelope_sha256"] != digest(envelope)
                or digest(packet) != envelope["payload_sha256"]):
            raise PacketPending("agent_packet_attestation_invalid")
        cur.execute("select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'))")
        cur.execute("select installed,enabled from read_plugin_states_v1() where plugin_id=%s", ("sli.remote-access",))
        plugin = cur.fetchone()
        if not plugin or not plugin["installed"] or not plugin["enabled"]:
            raise PacketPending("agent_plugin_disabled")
        if envelope["module_id"] == NPS_MODULE:
            if packet["header"]["source"] != policy["source_name"] or event_rows_from_packet(packet) != rows:
                raise PacketPending("agent_packet_attestation_invalid")
            # Match the legacy configured server. No agent-owned server/entity.
            cur.execute("select id as server_id,domain_id,site_id from servers where hostname=%s and is_active",
                        (policy["source_name"],))
            sources = cur.fetchall()
            if len(sources) != 1:
                raise PacketPending("agent_nps_source_not_configured")
            if not rows:
                return
            from server.sli.storage.storage_v2_worker_connection import connect_storage_v2_worker
            importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")
            runtime = importer.load_authorized_direct_runtime(cur, connect_factory=connect_storage_v2_worker)
            import_event_rows(cur, rows, source=sources[0], header=packet["header"],
                              envelope=envelope, direct_runtime=runtime)
            return
    from server.sli.sources import radius_plugin_runtime as radius

    if rows:
        raise PacketPending("agent_packet_attestation_invalid")
    with conn.transaction(), conn.cursor() as cur:
        cur.execute("select current_user as role_name")
        previous_role = cur.fetchone()["role_name"]
        accounting_conn = AccountingConnection(conn)
        state = radius.load_runtime_state(accounting_conn, subscription_id=policy["subscription_id"])
        if packet["header"]["cursor"]["before"] != asdict(state.cursor):
            # A legacy owner advanced the shared cursor. Never rebase evidence.
            raise PacketPending("agent_radius_cursor_conflict")
        initial = policy["initial_cursor"]
        if any(getattr(state.cursor, key) != initial[key] for key in (
                "source_instance_id", "stream_id", "transport_binding")):
            raise PacketPending("agent_source_binding_changed")
        from server.sli.core.paths import DATA_DIR

        if not packet["records"] and "empty_progress_v1" in packet["context"]:
            from server.source_packs.radius.accounting_postgres import (
                commit_admitted_empty_radius_progress,
            )

            # The accepted receipt above binds the proof and cursor_after. The
            # shared cursor CAS and inbox imported_at commit atomically outside.
            after = file_cursor(json.loads(envelope["cursor_after"]["token"]))
            proof = packet["context"]["empty_progress_v1"]
            commit_admitted_empty_radius_progress(accounting_conn, subscription_id=policy["subscription_id"],
                cursor_epoch=state.cursor_epoch, expected_revision=state.revision,
                current_cursor=state.cursor, next_cursor=after, **proof)
        else:
            radius.import_acquisition_packet(accounting_conn, packet, state=state, subscription_id=policy["subscription_id"],
                                             evidence_root=Path(DATA_DIR))
        # The legacy adapter uses SET LOCAL ROLE. Restore the core role before
        # consume_agent_packets updates its inbox in this same transaction.
        cur.execute("select set_config('role',%s,true)", (previous_role,))


def agent_import_enabled():
    value = os.environ.get("SLI_NPS_AGENT_IMPORT_ENABLED", "0")
    if value not in ("0", "1"):
        raise ValueError("agent_nps_import_config_invalid")
    return value == "1"


def connect_agent_import_worker():
    """Server-only credential; no fallback to the HTTP login or an admin DSN."""
    import psycopg
    from psycopg.rows import dict_row
    from server.sli.core.secret_files import postgres_secret_parts

    parts = postgres_secret_parts("SLI_NPS_AGENT_WORKER_DSN")
    if not parts:
        raise RuntimeError("agent_nps_worker_not_configured")
    parts.update(connect_timeout=5, options="-c statement_timeout=30000 -c lock_timeout=2000")
    conn = psycopg.connect(**parts, row_factory=dict_row)
    try:
        with conn.cursor() as cur:
            cur.execute("set role adlog_nps_agent_import_worker")
        conn.commit()
        return conn
    except Exception:
        conn.close()
        raise RuntimeError("agent_nps_worker_role_unavailable") from None


def run_accounting_import_once(*, limit=16):
    if not agent_import_enabled():
        return 0
    from server.sli.sources.collection_packet_import import consume_agent_packets
    from sli_agent.nps import ACCOUNTING_MODULE

    try:
        with connect_agent_import_worker() as conn:
            imported = consume_agent_packets(conn, module_id=ACCOUNTING_MODULE, limit=limit,
                                             import_rows=import_nps_agent_packet)
            conn.commit()
            return imported
    except Exception:
        # Worker exception logging must never see DB/source bind diagnostics.
        raise RuntimeError("agent_radius_import_failed") from None
