"""Runtime snapshot/transport fences in an isolated PostgreSQL schema.

The expensive AD projection is replaced with a bounded, transactional probe;
TLS verification, signed packet admission, lifecycle helpers and snapshot
consumer transactions are real. No production database or roles are modified.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
from queue import Queue
import re
from threading import Event
from time import monotonic
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agent_ingest import PostgresLedger, receive_packet
from server.sli.agents import policies, registry, snapshot_consumer
from server.sli.agents.ca import AgentError, utcnow
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_agent_registry import enroll, lifecycle, request  # noqa: F401
from tests.unit.test_agent_snapshot_stream import NOW, config
from sli_agent.envelope import make_packet
from sli_agent.modules import HeartbeatModule
from sli_agent.snapshot_stream import SnapshotStream

pytestmark = pytest.mark.postgres_integration
MIGRATIONS = Path(__file__).resolve().parents[2] / "config/postgres_migrations"


@pytest.fixture
def snapshot_database(lifecycle, tmp_path):
    dsn = os.environ.get("ADLOG_TEST_PG_DSN", "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN required for disposable PostgreSQL concurrency")
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.rows import dict_row

    schema = "sli_test_snapshot_locks_" + uuid4().hex
    def connect(*, lock_ms=5000):
        conn = psycopg.connect(dsn, row_factory=dict_row)
        conn.execute(sql.SQL("set search_path to {}").format(sql.Identifier(schema)))
        conn.execute("select set_config('lock_timeout',%s,false)", (f"{lock_ms}ms",))
        conn.execute("set statement_timeout='8s'")
        conn.commit()
        return conn

    fake, ca, key, _ = lifecycle
    response, der = enroll(lifecycle)
    agent_id = response["agent_id"]
    identity = fake.agents[agent_id]
    certificate = x509.load_der_x509_certificate(der)
    cfg = config()
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert_disposable_database(admin)
        admin.execute(sql.SQL("create schema {}").format(sql.Identifier(schema)))
        try:
            with connect() as conn:
                for filename, tables in (
                    ("156_agent_registry.sql", ("sli_agents", "sli_agent_certificates", "sli_agent_audit")),
                    ("157_agent_packets.sql", ("sli_agent_receipts", "sli_agent_packet_inbox")),
                    ("170_agent_snapshot_stream.sql", ("sli_agent_snapshot_bindings", "sli_agent_snapshot_policies",
                        "sli_agent_snapshot_cycles", "sli_agent_snapshot_chunks")),
                    ("169_agent_collection_control.sql", ("sli_agent_policy_history",)),
                ):
                    source = (MIGRATIONS / filename).read_text()
                    for table in tables:
                        ddl = re.search(rf"create table (?:public\.)?{table} \(.*?\n\);", source, re.S)
                        assert ddl, table
                        conn.execute(ddl.group().replace("public.", ""))
                # Only the columns used by these current runtime helpers. No
                # installed production migrations or existing tables are edited.
                conn.execute("""alter table sli_agents
                    add column policy_revision bigint not null default 1,
                    add column applied_policy_revision bigint not null default 0,
                    add column rights_probe jsonb not null default '{}'::jsonb,
                    add column collection_policy jsonb not null default '{}'::jsonb,
                    add column applied_collection_state text not null default 'unknown',
                    add column source_host_id uuid,
                    add column source_agent_id uuid references sli_agents(id),
                    add column runtime_resume jsonb not null default '{}'::jsonb check(jsonb_typeof(runtime_resume)='object');
                    alter table sli_agent_packet_inbox add column quota_payload_bytes bigint;
                    alter table sli_agent_snapshot_cycles
                    add column publication_state text not null default 'pending',
                    add column manifest_id uuid, add column gpo_source_run_id uuid,
                    add column published_at timestamptz;
                    alter table sli_agent_audit drop constraint sli_agent_audit_action_check;
                    create table publication_probe(id integer primary key);
                    create function read_plugin_states_v1() returns table(plugin_id text,installed boolean,enabled boolean)
                    language sql as $$ select 'sli.ad'::text,true,true $$""")
                conn.execute("""insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,collection_policy)
                    values(%s,%s,%s,%s::jsonb,%s::jsonb)""", (agent_id, identity["host_id"], identity["key_fingerprint"],
                    json.dumps([{"module_id": "sli.ad-snapshot", "enabled": True, "config": cfg}]),
                    json.dumps(identity["collection_policy"])))
                registry._store_cert(conn.cursor(), certificate, agent_id)
                conn.execute("insert into sli_agent_snapshot_bindings(agent_id,module_id,config,enabled) values(%s,'sli.ad-snapshot',%s::jsonb,true)",
                             (agent_id, json.dumps(cfg)))
                conn.execute("insert into sli_agent_snapshot_policies(agent_id,module_id,config,enabled) values(%s,'sli.ad-snapshot',%s::jsonb,true)",
                             (agent_id, json.dumps(cfg)))
                stream = SnapshotStream(tmp_path / "capture", "sli.ad-snapshot")
                state = stream.begin(cfg, now=NOW)
                stream.freeze(state, {"ad_context_base": ({"records": [{}]}, 1)})
                sample = stream.next_sample(None)
                packet = make_packet(key, agent_id=agent_id, sequence=1, sample=sample, now=NOW)
                with conn.cursor() as cur:
                    authenticated = registry.authenticate(cur, ca, der)
                    result = receive_packet(PostgresLedger(cur), identity=authenticated,
                        public_key=key.public_key(), value=packet, now=NOW)
                    assert result["status"] == "committed", result
            yield {"connect": connect, "ca": ca, "der": der, "key": key, "agent_id": agent_id,
                   "host_id": identity["host_id"], "serial": format(certificate.serial_number, "x"), "config": cfg}
        finally:
            admin.execute(sql.SQL("drop schema {} cascade").format(sql.Identifier(schema)))


def _heartbeat(db, value=None):
    now = utcnow()
    value = value or make_packet(db["key"], agent_id=db["agent_id"], sequence=1,
        sample=HeartbeatModule(db["host_id"]).collect(None, now=now), now=now)
    with db["connect"](lock_ms=500) as conn, conn.cursor() as cur:
        agent = registry.authenticate(cur, db["ca"], db["der"])
        receipt = receive_packet(PostgresLedger(cur), identity=agent,
            public_key=db["key"].public_key(), value=value, now=now)
        conn.commit()  # Exactly as the route: no successful ACK before commit.
    return value, receipt


def _consume(db):
    with db["connect"]() as conn:
        return snapshot_consumer.consume_snapshot_cycles(conn, publication_connection_factory=db["connect"])


def _paused_publication(monkeypatch, *, fail=False):
    entered, release = Event(), Event()
    def publish(conn, cycle, families):
        conn.execute("insert into publication_probe values(1)")
        entered.set()
        assert release.wait(5), "test failed to release publication"
        if fail:
            raise ValueError("synthetic-publication-failure")
        return {"manifest_id": str(uuid4())}
    monkeypatch.setattr(snapshot_consumer, "import_ad_cycle", publish)
    return entered, release


def _wait_for_lock(db, pid):
    deadline = monotonic() + 3
    with db["connect"]() as observer:
        while monotonic() < deadline:
            row = observer.execute("select cardinality(pg_blocking_pids(%s)) as blockers", (pid,)).fetchone()
            if row["blockers"]:
                return
            Event().wait(0.01)
    pytest.fail("lifecycle writer did not wait on the snapshot fence")


def test_snapshot_publication_allows_heartbeat_commit(snapshot_database, monkeypatch):
    db = snapshot_database
    entered, release = _paused_publication(monkeypatch)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_consume, db)
        try:
            assert entered.wait(3), "snapshot did not enter publication"
            value, receipt = _heartbeat(db)
            assert receipt["status"] == "committed"
            assert _heartbeat(db, value)[1]["status"] == "duplicate"
            with db["connect"]() as conn:
                assert conn.execute("select last_seen from sli_agents").fetchone()["last_seen"] is not None
                assert conn.execute("select count(*) as n from publication_probe").fetchone()["n"] == 0
        finally:
            release.set()
        result = future.result(timeout=6)
        assert result["completed"] == 1 and result["pending_reasons"] == {}
    with db["connect"]() as conn:
        assert conn.execute("select publication_state from sli_agent_snapshot_cycles").fetchone()["publication_state"] == "published"
        assert conn.execute("select count(*) as n from publication_probe").fetchone()["n"] == 1


def _lifecycle_write(db, operation, pids=None):
    with db["connect"]() as conn, conn.cursor() as cur:
        if pids is not None:
            pids.put(conn.info.backend_pid)
        if operation == "renew":
            registry.renew(cur, db["ca"], db["der"], {"csr_pem": request(ec.generate_private_key(ec.SECP256R1()))})
        elif operation == "policy":
            policies.assign_module(cur, {"agent_id": db["agent_id"], "module_id": "sli.ad-snapshot",
                "enabled": False, "config": db["config"], "expected_revision": 1}, actor="session:1")
        else:
            registry.revoke(cur, {"agent_id": db["agent_id"], "serial": db["serial"]},
                            actor="session:1", disable=operation == "disable")


@pytest.mark.parametrize("operation", ["disable", "revoke", "renew", "policy"])
def test_snapshot_still_fences_lifecycle_writers(snapshot_database, monkeypatch, operation):
    db = snapshot_database
    entered, release = _paused_publication(monkeypatch)
    pids = Queue()
    with ThreadPoolExecutor(max_workers=2) as pool:
        publication = pool.submit(_consume, db)
        try:
            assert entered.wait(3)
            writer = pool.submit(_lifecycle_write, db, operation, pids)
            _wait_for_lock(db, pids.get(timeout=2))
            assert not writer.done()
        finally:
            release.set()
        result = publication.result(timeout=6)
        assert result["completed"] == 1 and result["pending_reasons"] == {}
        writer.result(timeout=6)
    if operation in ("disable", "revoke"):
        with pytest.raises(AgentError, match="agent_certificate_rejected"):
            _heartbeat(db)


@pytest.mark.parametrize("operation,reason", [("disable", "agent_disabled"), ("policy", "agent_module_not_assigned")])
def test_committed_lifecycle_change_rejects_later_snapshot(snapshot_database, monkeypatch, operation, reason):
    db = snapshot_database
    _lifecycle_write(db, operation)
    monkeypatch.setattr(snapshot_consumer, "import_ad_cycle", lambda *args: pytest.fail("unauthorized publication"))
    assert _consume(db)["pending_reasons"] == {reason: 1}
    with db["connect"]() as conn:
        assert conn.execute("select publication_state from sli_agent_snapshot_cycles").fetchone()["publication_state"] == "pending"


def test_snapshot_publication_failure_rolls_back_projection(snapshot_database, monkeypatch):
    db = snapshot_database
    entered, release = _paused_publication(monkeypatch, fail=True)
    release.set()
    result = _consume(db)
    assert entered.is_set()
    assert result["pending_reasons"] == {"agent_ad_publication_failed": 1}
    with db["connect"]() as conn:
        assert conn.execute("select count(*) as n from publication_probe").fetchone()["n"] == 0
        row = conn.execute("select transport_state,publication_state from sli_agent_snapshot_cycles").fetchone()
        assert row == {"transport_state": "complete", "publication_state": "pending"}


@pytest.mark.parametrize("exact", [True, False])
def test_concurrent_signed_heartbeat_replay_remains_serialized(snapshot_database, exact):
    db = snapshot_database
    now = utcnow()
    value = make_packet(db["key"], agent_id=db["agent_id"], sequence=1,
        sample=HeartbeatModule(db["host_id"]).collect(None, now=now), now=now)
    other = value if exact else make_packet(db["key"], agent_id=db["agent_id"], sequence=1,
        sample=HeartbeatModule(db["host_id"]).collect(None, now=now), now=now)
    start = Event()
    def send(packet):
        assert start.wait(3)
        return _heartbeat(db, packet)[1]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(send, packet) for packet in (value, other)]
        start.set()
        receipts = [future.result(timeout=6) for future in futures]
    assert sorted(r["status"] for r in receipts) == ["committed", "duplicate" if exact else "rejected"]
    if not exact:
        assert next(r for r in receipts if r["status"] == "rejected")["error_code"] == "agent_sequence_conflict"
    with db["connect"]() as conn:
        assert conn.execute("select count(*) as n from sli_agent_receipts where module_id='sli.heartbeat'").fetchone()["n"] == 1


@pytest.mark.parametrize("mutation", ["disabled", "revoked", "fingerprint"])
def test_current_certificate_and_status_checked_on_every_transport(snapshot_database, mutation):
    db = snapshot_database
    with db["connect"]() as conn:
        if mutation == "disabled":
            registry.revoke(conn.cursor(), {"agent_id": db["agent_id"]}, actor="session:1", disable=True)
        elif mutation == "revoked":
            registry.revoke(conn.cursor(), {"agent_id": db["agent_id"], "serial": db["serial"]}, actor="session:1")
        else:
            # Synthetic registry corruption must fail closed, never accept TLS
            # validity alone as the current enrollment authority.
            conn.execute("update sli_agent_certificates set fingerprint=%s", ("0" * 64,))
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        _heartbeat(db)
    with db["connect"]() as conn:
        assert conn.execute("select count(*) as n from sli_agent_receipts where module_id='sli.heartbeat'").fetchone()["n"] == 0


def test_bad_signature_does_not_commit_receipt_or_last_seen(snapshot_database):
    from sli_agent.envelope import EnvelopeError
    db = snapshot_database
    now = utcnow()
    value = make_packet(ec.generate_private_key(ec.SECP256R1()), agent_id=db["agent_id"], sequence=1,
        sample=HeartbeatModule(db["host_id"]).collect(None, now=now), now=now)
    with db["connect"]() as conn:
        before = conn.execute("select last_seen from sli_agents").fetchone()["last_seen"]
    with pytest.raises(EnvelopeError):
        _heartbeat(db, value)
    with db["connect"]() as conn:
        assert conn.execute("select last_seen from sli_agents").fetchone()["last_seen"] == before
        assert conn.execute("select count(*) as n from sli_agent_receipts where module_id='sli.heartbeat'").fetchone()["n"] == 0


def test_renew_revoke_race_keeps_agent_certificate_order(snapshot_database, monkeypatch):
    db = snapshot_database
    entered, release = _paused_publication(monkeypatch)
    renew_pids, revoke_pids = Queue(), Queue()
    with ThreadPoolExecutor(max_workers=3) as pool:
        publication = pool.submit(_consume, db)
        try:
            assert entered.wait(3)
            renewal = pool.submit(_lifecycle_write, db, "renew", renew_pids)
            revocation = pool.submit(_lifecycle_write, db, "revoke", revoke_pids)
            _wait_for_lock(db, renew_pids.get(timeout=2))
            _wait_for_lock(db, revoke_pids.get(timeout=2))
        finally:
            release.set()
        result = publication.result(timeout=6)
        assert result["completed"] == 1 and result["pending_reasons"] == {}
        revocation.result(timeout=6)
        try:
            renewal.result(timeout=6)
        except AgentError as exc:
            # Revoke may win before renewal acquires the agent lock; then no
            # new certificate may be issued using that revoked credential.
            assert str(exc) == "agent_certificate_rejected"
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        _heartbeat(db)
