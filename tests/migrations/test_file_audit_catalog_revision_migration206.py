"""Register file catalogue metadata without bypassing the core trigger."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.migrations.historical_postgres import historical_connection

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/206_file_audit_catalog_revision.sql"


def accepted_file_packet(conn):
    """Seed one committed receipt, then use the real observation projector."""
    from psycopg.types.json import Jsonb

    from server.sli.events.event_catalog import event_noise_classification
    from server.sli.plugins.file_audit.correlation import observation_from_xml, project_actions
    from sli_agent.file_audit_policy import PROVIDER, policy
    from tools.e2e.synthetic import digest, xml

    agent, host, packet = map(str, (uuid4(), uuid4(), uuid4()))
    stamp = datetime(2026, 1, 1, tzinfo=UTC)
    source = "file-replay.example.test"
    config = policy({"source_name": source, "policy_revision": "1", "roots": [{
        "collection_scope_id": "synthetic-root", "share_name": "fixture", "path": r"C:\fixture",
        "important": False, "sacl": {"trustee_sids": ["S-1-1-0"],
                                      "inherit_files": True, "inherit_directories": True},
    }]})
    native = xml(source, 4663, stamp, {
        "SubjectUserSid": "S-1-5-21-100000001-200000001-300000001-1002",
        "SubjectUserName": "synthetic-reader", "SubjectDomainName": "EXAMPLE",
        "ObjectName": r"C:\fixture\report.txt", "ObjectType": "File", "SubjectLogonId": "0x10",
        "ProcessId": "0x20", "HandleId": "0x30", "AccessMask": "0x2",
    })
    content_hash = sha256(native.encode("utf-8")).digest()
    observation = observation_from_xml(
        native, agent_id=agent, source_instance_id=host, generation=host, policy_revision="1",
        core_evidence_ref=f"agent-event:{agent}:{host}:1", config=config,
    )
    projection = {"observations": [observation], "actions": project_actions(observation)}
    assert len(projection["actions"]) == 1
    classification, revision = event_noise_classification(4663, "Security", PROVIDER)
    assert revision == "1.0.0"
    envelope = {"agent_id": agent, "module_id": "sli.file-audit", "packet_id": packet,
                "source_instance_id": host, "generation": host, "policy_revision": "1", "sequence": "1",
                "cursor_before": {"token": ""}, "cursor_after": {"token": '{"record_id":1}'}}
    event_rows = [{"record_id": 1, "event_id": 4663, "xml": native}]
    body = {"contract": "sli.collection-packet.v1", "header": {"source": source, "channel": "Security"},
            "event_rows": event_rows}
    conn.execute("insert into sli_agents(id,host_id,key_fingerprint) values(%s,%s,%s)", (agent, host, "a" * 64))
    conn.execute("""insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                    values(%s,'sli.file-audit',1,%s,%s,%s,'{"status":"committed"}')""",
                 (agent, packet, digest(envelope), Jsonb(envelope)))
    conn.execute("insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows) values(%s,%s,%s,%s)",
                 (packet, Jsonb(envelope), Jsonb(body), Jsonb(event_rows)))
    conn.execute("insert into log_sources(name) values('Security') on conflict do nothing")
    conn.execute("insert into storage_v2_channel(value) values('Security') on conflict do nothing")
    conn.execute("insert into servers(id,domain_id,hostname) select 99001,id,%s from domains where fqdn='example.test'", (source,))
    conn.execute("""insert into raw_log_files(id,server_id,log_source_id,file_path,file_format,sha256)
                    select 99001,99001,id,%s,'jsonl',%s from log_sources where name='Security'""",
                 (f"agent-packet:{packet}", content_hash.hex()))
    return {"agent": agent, "host": host, "id": packet, "stamp": stamp, "hash": content_hash,
            "classification": classification, "revision": revision, "projection": projection}


def store_historical_file_packet(conn, packet):
    """The historical transaction writes through the storage trigger and actual projection entry point."""
    from psycopg.types.json import Jsonb

    source = conn.execute("""select r.server_id,s.domain_id,r.log_source_id,c.id as channel_id
                             from raw_log_files r join servers s on s.id=r.server_id
                             join storage_v2_channel c on c.value='Security' where r.id=99001""").fetchone()
    with conn.transaction():
        conn.execute("set local role adlog_storage_worker")
        conn.execute("""insert into events_v2_core(id,raw_log_file_id,server_id,domain_id,log_source_id,
                        event_id,event_record_id,channel_id,time_created_utc,normalized_at,normalized_hash,
                        source_core_sha256,noise_class,noise_catalog_version)
                        values(99001,99001,%s,%s,%s,4663,1,%s,%s,now(),%s,%s,%s,%s)""",
                     (source["server_id"], source["domain_id"], source["log_source_id"], source["channel_id"],
                      packet["stamp"], packet["hash"], packet["hash"], packet["classification"], packet["revision"]))
        conn.execute("set local role adlog_user")
        conn.execute("select sli_plugin_file_audit.store_collection(%s,%s,%s)",
                     (packet["agent"], packet["id"], Jsonb(packet["projection"])))
        conn.execute("update sli_agent_packet_inbox set imported_at=now() where packet_id=%s", (packet["id"],))


def test_catalogue_migration_follows_predecessor_and_versions_are_unique():
    inventory = forward_migration_inventory(PATH.parent)
    pairs = [(item.version, item.name) for item in inventory]
    position = pairs.index((206, "file_audit_catalog_revision"))
    assert position > 0
    assert pairs[position - 1] == (205, "security_event_identity_category")
    assert max(version for version, _ in pairs[:position]) + 1 == 206
    assert len(pairs) == len({version for version, _ in pairs})
    assert inventory[position].path == PATH
    assert list(PATH.parent.glob("206_*.sql")) == [PATH]
    sql = PATH.read_text("utf-8")
    assert "version=205 and name='security_event_identity_category'" in sql
    assert "where version>=206" in sql
    assert "values(206,'file_audit_catalog_revision')" in sql


@pytest.fixture
def predecessor205(tmp_path, monkeypatch):
    from psycopg.rows import dict_row

    with historical_connection(tmp_path, monkeypatch, (205, "security_event_identity_category")) as conn:
        conn.row_factory = dict_row
        yield conn


@pytest.mark.postgres_integration
@pytest.mark.postgres_owned_cluster
def test_missing_catalogue_blocks_native_import_then_migration_retries_exact_packet(predecessor205):
    import psycopg
    from psycopg.types.json import Jsonb

    conn = predecessor205
    packet = accepted_file_packet(conn)
    trigger_sql = "select pg_get_functiondef('set_event_noise_catalog_revision'::regproc) as definition"
    trigger_before = conn.execute(trigger_sql).fetchone()
    with pytest.raises(psycopg.errors.RaiseException, match="unregistered event catalogue revision: 1.0.0"):
        store_historical_file_packet(conn, packet)
    assert conn.execute("select count(*) as n from events_v2_core").fetchone()["n"] == 0
    assert conn.execute("select count(*) as n from sli_plugin_file_audit.collection_publications").fetchone()["n"] == 0
    assert conn.execute("select imported_at from sli_agent_packet_inbox where packet_id=%s", (packet["id"],)).fetchone()["imported_at"] is None

    conn.execute(PATH.read_text("utf-8"))
    store_historical_file_packet(conn, packet)
    assert conn.execute(trigger_sql).fetchone() == trigger_before
    assert conn.execute("select name from schema_migrations where version=206").fetchone()["name"] == "file_audit_catalog_revision"
    core = conn.execute("""select e.source_core_sha256,r.version from events_v2_core e
                           join event_catalog_revisions r on r.id=e.noise_catalog_revision_id
                           where e.event_id=4663""").fetchall()
    assert core == [{"source_core_sha256": packet["hash"], "version": packet["revision"]}]
    assert conn.execute("select count(*) as n from sli_plugin_file_audit.collection_publications where packet_id=%s",
                        (packet["id"],)).fetchone()["n"] == 1
    roots = [{"agent_id": packet["agent"], "source_instance_id": packet["host"], "collection_scope_id": "synthetic-root"}]
    action_at = datetime.fromisoformat(packet["projection"]["actions"][0]["observed_at"])
    with conn.transaction():
        conn.execute("set local role adlog_user")
        report = conn.execute("""select sli_plugin_file_audit.report_rows(%s,'actions',%s,%s,null,false,null,null,null,10)
                                 as report""", (Jsonb(roots), action_at - timedelta(minutes=1),
                                                  action_at + timedelta(minutes=1))).fetchone()["report"]
    assert report["filtered_count"] == 1
    assert report["items"][0]["evidence"][0]["event_id"] == 4663
    assert report["items"][0]["evidence"][0]["record_id"] == 1


@pytest.mark.postgres_integration
@pytest.mark.postgres_owned_cluster
def test_registration_preserves_an_existing_catalogue_identity(predecessor205):
    conn = predecessor205
    conn.execute("insert into event_catalog_revisions(version) values('1.0.0')")
    before = conn.execute("select * from event_catalog_revisions order by id").fetchall()
    conn.execute(PATH.read_text("utf-8"))
    assert conn.execute("select * from event_catalog_revisions order by id").fetchall() == before


@pytest.mark.postgres_integration
@pytest.mark.postgres_owned_cluster
def test_registration_refuses_a_missing_admission_trigger(predecessor205):
    import psycopg

    conn = predecessor205
    conn.execute("drop trigger events_v2_core_catalog_revision on events_v2_core")
    with pytest.raises(psycopg.errors.RaiseException, match="migration 206 requires the catalog revision trigger"):
        conn.execute(PATH.read_text("utf-8"))
    conn.rollback()
    assert conn.execute("select count(*) as n from schema_migrations where version=206").fetchone()["n"] == 0
