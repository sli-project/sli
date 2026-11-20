"""AD poller transaction boundaries with real import authority and heartbeat.

Only downstream StorageV2 publication/runtime admission are replaced by a
transactional probe. This does not claim full downstream lock-graph coverage.
"""
from concurrent.futures import ThreadPoolExecutor
import importlib
import json
from queue import Queue
from threading import Event
from uuid import uuid4

import pytest

from server.sli.core import postgres_runtime_pipeline
from server.sli.plugins.ad import event_import
from server.sli.sources.collection_packet_import import event_rows_from_packet
from sli_agent.ad_dc import ADDCModule
from sli_agent.envelope import digest, make_packet
from tests.migrations.test_agent_snapshot_locks_postgres_integration import (
    _heartbeat, _lifecycle_write, _wait_for_lock, snapshot_database,  # noqa: F401
)
from tests.unit.test_ad_dc_agent_import import CONFIG, NOW, event_xml
from tests.unit.test_agent_registry import lifecycle  # noqa: F401

pytestmark = pytest.mark.postgres_integration


@pytest.fixture
def ad_batch(snapshot_database, monkeypatch):
    db = snapshot_database
    agent_ids = [db["agent_id"], str(uuid4())]
    packets = []
    with db["connect"]() as conn:
        conn.execute("""create table sli_agent_packet_quarantine(packet_id uuid primary key);
            create table sli_agent_module_bindings(agent_id uuid,module_id text,
                source_instance_id text,source_name text,channel text,module_version text,policy_revision text);
            create table servers(id integer,domain_id integer,site_id integer,hostname text,role text,is_active boolean);
            insert into servers values(1,1,1,'fixture-dc','domain_controller',true)""")
        conn.execute("""insert into sli_agents(id,host_id,key_fingerprint,assigned_modules)
            values(%s,%s,%s,'[]')""", (agent_ids[1], str(uuid4()), "a" * 64))
        for ordinal, agent in enumerate(agent_ids):
            conn.execute("""update sli_agents set assigned_modules=assigned_modules || %s::jsonb where id=%s""",
                (json.dumps([{"module_id": "sli.windows.ad-dc", "enabled": True}]), agent))
            raw = event_xml("Security", "Microsoft-Windows-Security-Auditing", 4624, ordinal + 1)
            sample = ADDCModule(db["host_id"], CONFIG, reader=lambda *_: [(raw, "fixture-bookmark")]).collect(
                now=NOW, channel="Security")
            value = make_packet(db["key"], agent_id=agent, sequence=1, sample=sample, now=NOW)
            envelope, packet = value["envelope"], value["payload"]
            # An already-admitted inbox: exact immutable receipt and packet
            # digests are verified by the real import-time authorization path.
            conn.execute("""insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,
                envelope_sha256,envelope,receipt) values(%s,%s,1,%s,%s,%s::jsonb,%s::jsonb)""",
                (agent, envelope["module_id"], envelope["packet_id"], digest(envelope), json.dumps(envelope),
                 json.dumps({"status": "committed"})))
            conn.execute("""insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at)
                values(%s,%s::jsonb,%s::jsonb,%s::jsonb,%s)""",
                (envelope["packet_id"], json.dumps(envelope), json.dumps(packet),
                 json.dumps(event_rows_from_packet(packet)), NOW.replace(second=ordinal)))
            conn.execute("""insert into sli_agent_module_bindings values(%s,%s,%s,%s,%s,%s,%s)""",
                (agent, envelope["module_id"], envelope["source_instance_id"], CONFIG["source_name"],
                 envelope["channel"], envelope["module_version"], envelope["policy_revision"]))
            packets.append(envelope["packet_id"])
    runtime = object()
    importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")
    monkeypatch.setattr(importer, "load_authorized_direct_runtime", lambda *_args, **_kw: runtime)
    monkeypatch.setattr(importer, "is_authorized_direct_runtime", lambda value: value is runtime)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", db["connect"])
    monkeypatch.setattr(event_import, "_after", None)
    monkeypatch.setenv("SLI_AD_DC_AGENT_IMPORT_ENABLED", "1")
    return db, packets


def _publication(monkeypatch, packets, *, pause=None, fail=None):
    entered, release = Event(), Event()
    def publish(cur, rows, *, envelope, **_):
        ordinal = packets.index(envelope["packet_id"])
        assert rows
        cur.execute("insert into publication_probe values(%s)", (ordinal,))
        if ordinal == pause:
            entered.set()
            assert release.wait(5), "publication was not released"
        if ordinal == fail:
            raise ValueError("synthetic-projection-failure")
        return {"inserted": len(rows), "skipped": 0}
    monkeypatch.setattr(event_import, "import_event_rows", publish)
    return entered, release


def _progress(db):
    with db["connect"]() as conn:
        probes = [row["id"] for row in conn.execute("select id from publication_probe order by id")]
        imported = conn.execute("select count(*) as n from sli_agent_packet_inbox where imported_at is not null").fetchone()["n"]
    return probes, imported


def test_ad_batch_releases_first_agent_before_second_publication(ad_batch, monkeypatch):
    db, packets = ad_batch
    entered, release = _publication(monkeypatch, packets, pause=1)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(event_import.run_agent_import_once, limit=2)
        try:
            assert entered.wait(3), "second publication did not start"
            assert _progress(db) == ([0], 1)
            value, receipt = _heartbeat(db)
            assert receipt["status"] == "committed"
            assert _heartbeat(db, value)[1]["status"] == "duplicate"
        finally:
            release.set()
        assert future.result(timeout=6) == 2
    assert _progress(db) == ([0, 1], 2)


def test_ad_own_packet_still_fences_lifecycle(ad_batch, monkeypatch):
    db, packets = ad_batch
    entered, release = _publication(monkeypatch, packets, pause=0)
    pids = Queue()
    with ThreadPoolExecutor(max_workers=2) as pool:
        publication = pool.submit(event_import.run_agent_import_once, limit=1)
        try:
            assert entered.wait(3)
            writer = pool.submit(_lifecycle_write, db, "disable", pids)
            _wait_for_lock(db, pids.get(timeout=2))
            assert not writer.done()
            assert _progress(db) == ([], 0)
        finally:
            release.set()
        assert publication.result(timeout=6) == 1
        writer.result(timeout=6)
    assert _progress(db) == ([0], 1)


def test_ad_failed_packet_rolls_back_and_retry_does_not_repeat_committed_packet(ad_batch, monkeypatch):
    db, packets = ad_batch
    _publication(monkeypatch, packets, fail=1)
    assert event_import.run_agent_import_once(limit=2) == 1
    assert _progress(db) == ([0], 1)
    _publication(monkeypatch, packets)
    # Scan position wraps only after exhaustion; failed evidence stays pending.
    assert event_import.run_agent_import_once(limit=2) == 0
    assert event_import.run_agent_import_once(limit=2) == 1
    assert _progress(db) == ([0, 1], 2)
    assert event_import.run_agent_import_once(limit=2) == 0
