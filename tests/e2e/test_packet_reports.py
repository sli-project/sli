"""Real PostgreSQL -> admitted inbox -> production handlers -> HTTP report API."""
import json
import os

import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.postgres_integration]


def test_synthetic_packets_reach_reports():
    from tools.e2e.scenario import admin_connection, run_replay

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable migrated PostgreSQL required")
    result = run_replay(dsn, synthetic=True, hours=24)
    # A short string keeps the safe stage codes visible in pytest's CI output.
    assert result["status"] == "verified", "stage_errors=" + json.dumps(result["stage_errors"], sort_keys=True)
    assert {row["family"] for row in result["rows"]} == {"ad-dc", "file-audit", "workstations"}
    for row in result["rows"]:
        assert all(row[step] > 0 for step in ("inbox", "imported", "facts", "projection", "api")), row
    assert len(result["file_reports"]) == 8
    assert all(row["status"] in ("verified", "empty_explained") for row in result["file_reports"])
    with admin_connection(dsn) as conn:
        event_time = conn.execute("select observed_at from sli_plugin_file_audit.observations "
                                  "where event_id=4663").fetchone()["observed_at"].isoformat()
        action_time = conn.execute("select observed_at from sli_plugin_file_audit.actions "
                                   "where operation='write'").fetchone()["observed_at"].isoformat()
    assert result["file_source"]["events"] == [{"event_id": 4663, "observations": 1, "scoped": 1,
                                               "latest_event_utc": event_time}]
    assert result["file_source"]["actions"] == [{"operation": "write", "outcome": "success", "actions": 1,
                                                "distinct_objects": 1, "latest_action_utc": action_time}]
    for kind, time_key, expected_time in [("event_recency", "latest_event_utc", event_time),
                                         ("action_recency", "latest_action_utc", action_time)]:
        recency = result["file_source"][kind]
        assert recency["state"] == "recent" and recency[time_key] == expected_time


def test_file_replay_selects_only_file_packets_and_checks_all_eight_tabs():
    from tools.e2e.scenario import admin_connection, run_replay

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable migrated PostgreSQL required")
    result = run_replay(dsn, synthetic=True, family="file-audit")
    assert result["status"] == "verified", result
    assert len(result["rows"]) == 1 and result["rows"][0]["family"] == "file-audit"
    assert len(result["file_reports"]) == 8
    with admin_connection(dsn) as conn:
        assert conn.execute("select count(*) as n from sli_agent_packet_inbox "
                            "where envelope->>'module_id'<>'sli.file-audit' and imported_at is null").fetchone()["n"] == 0
        assert conn.execute("select count(*) as n from sli_e2e.cohort "
                            "where family<>'file-audit'").fetchone()["n"] == 0
        assert conn.execute("select count(*) as n from sli_plugin_workstations.observations").fetchone()["n"] == 0


def test_masked_file_context_keeps_ad_core_hash_and_native_file_actions():
    from datetime import datetime, timezone

    from cryptography.hazmat.primitives.asymmetric import ec
    from psycopg.types.json import Jsonb

    from server.sli.agents.consumer import dispatch_packet
    from server.sli.agents.policies import assign_module
    from server.sli.sources.collection_packet_import import (
        event_rows_from_packet,
        store_agent_packet,
    )
    from sli_agent.ad_dc import ADDCModule
    from sli_agent.envelope import digest, make_packet
    from sli_agent.file_audit_collection import FileAuditModule
    from tools.e2e.scenario import admin_connection, configure, run_replay
    from tools.e2e.synthetic import seed, xml

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable migrated PostgreSQL required")
    now = datetime.now(timezone.utc)
    with admin_connection(dsn) as conn:
        seed(conn)
        agent = conn.execute("select * from sli_agents where assigned_modules->0->>'module_id'='sli.file-audit'").fetchone()
        config = agent["assigned_modules"][0]["config"]
        source = config["source_name"]
        ad_config = {"source_name": source, "connect_address": "fixture-endpoint",
                     "channels": {"Security": True, "System": False, "Directory Service": False},
                     "initial_read_hours": "all"}
        conn.execute("update servers set role='domain_controller' where hostname=%s", (source,))
        # Use the normal CAS/history/issuer/audit path and collect with its R.
        with conn.cursor() as cur:
            assigned = assign_module(cur, {"agent_id": str(agent["id"]), "module_id": "sli.windows.ad-dc",
                "enabled": True, "config": ad_config, "expected_revision": agent["policy_revision"]},
                actor="synthetic-e2e")
        ad_config = next(m["config"] for m in assigned["assigned_modules"] if m["module_id"] == "sli.windows.ad-dc")
        config = next(m["config"] for m in assigned["assigned_modules"] if m["module_id"] == "sli.file-audit")
        assert assigned["policy_revision"] == agent["policy_revision"] + 1
        issued = conn.execute("select source_instance_id,source_name,channel,module_version,policy_revision "
            "from sli_agent_module_bindings where agent_id=%s and module_id='sli.windows.ad-dc'",
            (agent["id"],)).fetchone()
        assert dict(issued) == {"source_instance_id": str(agent["host_id"]), "source_name": source,
            "channel": "ad-dc", "module_version": "1.0.0", "policy_revision": ad_config["policy_revision"]}
        assert ad_config["policy_revision"] == str(assigned["policy_revision"])
        history = conn.execute("select assigned_modules,staged_xact_id=pg_current_xact_id() as current_tx "
            "from sli_agent_policy_history where agent_id=%s and revision=%s",
            (agent["id"], assigned["policy_revision"])).fetchone()
        assert history["assigned_modules"] == assigned["assigned_modules"] and history["current_tx"] is True
        raw = xml(source, 4624, now, {"TargetUserName": "fixture-user", "LogonType": "3",
                  "TargetUserSid": "S-1-5-21-100000001-200000001-300000001-1001"}).replace(
                      "<EventRecordID>1</EventRecordID>", "<EventRecordID>2</EventRecordID>")
        native = xml(source, 4663, now, {"SubjectUserSid": "S-1-5-18", "ObjectName": r"C:\replay\next.txt",
                     "ObjectType": "File", "AccessMask": "0x2"}).replace(
                         "<EventRecordID>1</EventRecordID>", "<EventRecordID>3</EventRecordID>")
        ad = ADDCModule(str(agent["host_id"]), ad_config, reader=lambda *_: [(raw, "b2")]).collect(now=now)
        # A compatible mask is a subset under identity v2. Conflict requires a
        # different shared native value, retained by the file-context mask.
        conflicting = raw.replace("300000001-1001", "300000001-1002")
        file = FileAuditModule(str(agent["host_id"]), config,
            reader=lambda *_: [(conflicting, "b2"), (native, "b3")], path_check=lambda *_: "file").collect(now=now)
        packets = []
        for sequence, sample in ((1, ad), (2, file)):
            value = make_packet(ec.generate_private_key(ec.SECP256R1()), agent_id=str(agent["id"]),
                                sequence=sequence, sample=sample, now=now)
            envelope, payload = value["envelope"], value["payload"]
            conn.execute("insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt) "
                "values(%s,%s,%s,%s,%s,%s,%s)", (agent["id"], envelope["module_id"], sequence,
                envelope["packet_id"], digest(envelope), Jsonb(envelope), Jsonb({"status": "committed"})))
            with conn.cursor() as cur:
                store_agent_packet(cur, packet_id=envelope["packet_id"], envelope=envelope,
                                   packet=payload, event_rows=event_rows_from_packet(payload))
            packets.append((envelope, payload))
        envelope, payload = packets[0]
    configure(dsn)
    with admin_connection(dsn) as conn:
        admitted = conn.execute("select event_rows from sli_agent_packet_inbox where packet_id=%s",
                                (envelope["packet_id"],)).fetchone()["event_rows"]
        dispatch_packet(conn, admitted, packet=payload, envelope=envelope)
        before = conn.execute("select id,normalized_hash,source_core_sha256 from events_v2_core "
                              "where event_id=4624").fetchall()
        conn.commit()
        conn.execute("delete from sli_agent_module_bindings where agent_id=%s", (agent["id"],))
        envelope, payload = packets[1]
        admitted = conn.execute("select event_rows from sli_agent_packet_inbox where packet_id=%s",
                                (envelope["packet_id"],)).fetchone()["event_rows"]
        with pytest.raises(RuntimeError, match="source event allocation hash mismatch"):
            dispatch_packet(conn, admitted, packet=payload, envelope=envelope)
        conn.rollback()
        conn.execute("drop schema sli_e2e cascade")
    result = run_replay(dsn, family="file-audit")
    assert result["status"] == "verified", json.dumps(result["failure_sites"], indent=2)
    assert result["rows"][0]["facts"] == 3 and result["rows"][0]["projection"] == 2
    with admin_connection(dsn) as conn:
        assert conn.execute("select id,normalized_hash,source_core_sha256 from events_v2_core "
                            "where event_id=4624").fetchall() == before
        assert conn.execute("select count(*) as n from sli_plugin_file_audit.observations where event_id=4624").fetchone()["n"] == 1


def test_disabled_plugin_is_a_visible_chain_break():
    from tools.e2e.scenario import run_replay

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable migrated PostgreSQL required")
    result = run_replay(dsn, synthetic=True, hours=24, disabled_plugin="sli.workstations")
    row = next(row for row in result["rows"] if row["family"] == "workstations")
    assert result["status"] == "failed"
    assert row["inbox"] > 0 and row["imported"] == 0
    assert row["reason"] == "agent_plugin_disabled"


def test_report_losing_imported_rows_is_not_a_success(monkeypatch):
    from server.sli.plugins.file_audit import reports
    from tools.e2e.scenario import run_replay

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable migrated PostgreSQL required")
    monkeypatch.setattr(reports, "_read", lambda *_: {
        "items": [], "filtered_count": 0, "has_more": False, "after": None})
    result = run_replay(dsn, synthetic=True, hours=24)
    row = next(row for row in result["rows"] if row["family"] == "file-audit")
    assert result["status"] == "failed"
    assert row["imported"] > 0 and row["facts"] > 0 and row["projection"] > 0
    assert row["api"] == 0


def test_completed_packets_reexecute_semantics_without_duplicating_facts(monkeypatch):
    from server.sli.semantic import semantic_worker_runtime
    from tools.e2e.scenario import admin_connection, run_replay

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable migrated PostgreSQL required")
    first = run_replay(dsn, synthetic=True, hours=24)
    assert first["status"] == "verified", "stage_errors=" + json.dumps(first["stage_errors"], sort_keys=True)
    calls = []
    normalize = semantic_worker_runtime.normalize_semantic_source_payload

    def track(source):
        calls.append(source["id"])
        return normalize(source)

    monkeypatch.setattr(semantic_worker_runtime, "normalize_semantic_source_payload", track)
    with admin_connection(dsn) as conn:
        conn.execute("drop schema sli_e2e cascade")
    second = run_replay(dsn, hours=24)
    assert second["status"] == "verified", "stage_errors=" + json.dumps(second["stage_errors"], sort_keys=True)
    assert calls, "completed inbox/outbox must execute current semantic code again"
    assert [(r["facts"], r["projection"], r["api"]) for r in first["rows"]] == [
        (r["facts"], r["projection"], r["api"]) for r in second["rows"]]
