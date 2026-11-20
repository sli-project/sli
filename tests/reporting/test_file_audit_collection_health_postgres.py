"""Accepted synthetic file-audit packets through the runtime health SQL."""
import json
from copy import deepcopy
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents import collection_health as health
from server.sli.core.database import _pg_sql
from server.sli.plugins.file_audit.agent_ingest import packet_rows
from sli_agent.envelope import make_packet
from sli_agent.file_audit_collection import FileAuditModule
from sli_agent.file_audit_journal import JournalGap
from tests.reporting.test_agent_collection_query_plan_postgres import (
    database as database,  # noqa: PLC0414 -- pytest fixture registration
)
from tests.reporting.test_agent_collection_query_plan_postgres import migrate
from tests.unit.test_agent_file_audit_health import AGENT, NOW, agent

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def accepted_packet(error=False):
    config = {"roots": [{"collection_scope_id": "scope:fixture", "share_name": "synthetic",
                        "path": "C:\\synthetic", "important": False,
                        "sacl": {"trustee_sids": ["S-1-1-0"], "inherit_files": True, "inherit_directories": True}}]}
    def reader(*_):
        if error == "gap":
            raise JournalGap()
        if error:
            raise RuntimeError("synthetic-private-detail")
        return []
    sample = FileAuditModule(AGENT, config, reader=reader).collect(now=NOW)
    value = make_packet(ec.generate_private_key(ec.SECP256R1()), agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    assignment = {"module_id": "sli.file-audit", "enabled": True, "config": config}
    assert packet_rows({"id": AGENT, "host_id": AGENT}, assignment, value["envelope"], value["payload"]) == []
    expected_error = "file_audit_journal_gap" if error == "gap" else "file_audit_read_failed" if error else None
    assert value["payload"]["context"]["read_error"] == expected_error
    # Audit management responses are not collection evidence.
    with pytest.raises(ValueError):
        packet_rows({"id": AGENT, "host_id": AGENT}, assignment, value["envelope"],
                    {"contract_id": "sli.file-audit.audit-result.v1", "scopes": []})
    return value["payload"]


def insert_packet(conn, sequence, received, packet, *, imported=True, revision="1", module="sli.file-audit"):
    packet_id = uuid4()
    conn.execute("insert into sli_agent_receipts values(%s,%s,%s,%s,%s)",
                 (UUID(AGENT), module, sequence, packet_id, received))
    # Match migration237 exactly: file-audit top-level error is NOT represented
    # by its generated compact flag. Only the bounded latest lookup fixes this.
    conn.execute("""insert into sli_agent_packet_inbox values(%s,%s,%s,'Security',false,%s::jsonb)""",
                 (packet_id, received + timedelta(seconds=1) if imported else None, revision, json.dumps(packet)))


def test_actual_packets_preserve_latest_order_queue_grace_and_unknown(database):
    migrate(database)
    clean, failed, gap = accepted_packet(), accepted_packet(True), accepted_packet("gap")
    malformed = deepcopy(clean)
    malformed["context"]["read_error"] = []
    unknown = deepcopy(clean)
    del unknown["context"]["read_error"]
    cases = [
        ([(1, 30, failed, True)], "error", "read_error"),
        ([(1, 30, gap, True)], "error", "read_error"),
        ([(1, 30, malformed, True)], "unknown", None),
        ([(1, 30, clean, True)], "current", None),
        ([(2, 60, failed, True), (1, 30, clean, True)], "current", None),
        ([(1, 30, clean, True), (2, 30, failed, True)], "error", "read_error"),
        ([(1, 30, unknown, True)], "unknown", None),
        ([(1, 30, clean, False)], "lagging", None),
        ([(1, 1000, failed, False), (2, 30, clean, True)], "error", "import_overdue"),
    ]
    for rows, expected, reason in cases:
        database.execute("truncate sli_agent_receipts,sli_agent_packet_inbox,sli_agent_stream_import_health")
        for sequence, age, packet, imported in rows:
            insert_packet(database, sequence, NOW - timedelta(seconds=age), packet, imported=imported)
        streams = database.execute(_pg_sql(health._STREAMS_SQL), (json.dumps(health._requested_streams([agent()])),)).fetchall()
        result = health.collection_health_view([agent()], streams, now=NOW)
        check = result["items"][0]["modules"][0]["channels"][0]
        assert (check["state"], check["failure_reason"]) == (expected, reason)
        assert result["items"][0]["connection"] == "online"
        # New policy grace remains authoritative even with no matching stream.
        waiting = health.collection_health_view([agent(policy_applied_at=NOW)], [], now=NOW)
        assert waiting["items"][0]["state"] == "waiting"


def _nodes(node):
    return [node] + [item for child in node.get("Plans", []) for item in _nodes(child)]


def test_latest_payload_access_is_one_pk_lookup_per_file_audit_stream(database):
    clean = accepted_packet()
    # Unrelated large packet history remains compact; no payload decode per row.
    database.execute("""insert into sli_agent_receipts
        select '00000000-0000-4000-8000-000000000002'::uuid,'sli.windows.ad-dc',n,
               md5(n::text)::uuid,'2026-01-01'::timestamptz+n*interval '1 second'
        from generate_series(1,40000) n""")
    database.execute("""insert into sli_agent_packet_inbox
        select packet_id,received_at,'1','Security',false,
               '{"context":{"ad_dc":{"read_error":null}}}'::jsonb from sli_agent_receipts""")
    for revision in ("1", "2"):
        insert_packet(database, int(revision), NOW, clean, revision=revision)
    for table in ("sli_agent_receipts", "sli_agent_packet_inbox"):
        database.execute(f"analyze {table}")
    migrate(database)
    plan = database.execute("explain (analyze,buffers,format json) " + _pg_sql(health._STREAMS_SQL),
                            (json.dumps(health._requested_streams([agent()])),)).fetchone()["QUERY PLAN"][0]
    nodes = _nodes(plan["Plan"])
    payload_reads = [node for node in nodes if node.get("Alias") == "payload"]
    assert len(payload_reads) == 1
    assert payload_reads[0]["Node Type"] == "Index Scan"
    assert payload_reads[0]["Actual Loops"] == payload_reads[0]["Actual Rows"] == 1
    assert "packet_id" in payload_reads[0]["Index Cond"]
    print("T006 latest file-audit payload lookup: " + json.dumps({
        "history_rows": 40002, "file_audit_streams": 1, "payload_lookup_loops": payload_reads[0]["Actual Loops"],
        "execution_ms": plan["Execution Time"], "scope": "synthetic, not stand latency",
    }, sort_keys=True))

