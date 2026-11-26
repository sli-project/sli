"""T009 synthetic conveyor on the fully migrated, per-test PostgreSQL clone.

No reduced schema, replacement definer, direct signal/finding/outbox seed or
extra SQL grant. Only Telegram's send boundary is replaced; no credential or
network access is possible. This is not installed-system/provider acceptance.
"""
import os
from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

import pytest

from server.sli.agents import policies
from server.sli.core import notification_outbox as outbox
from server.sli.core import notification_telegram as telegram
from server.sli.core import postgres_runtime_pipeline as pipeline
from server.sli.ops.postgres_schema_guard import clear_schema_guard_cache
from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
from tests.migrations.test_password_attacks_v2_migration import _xml
from tests.migrations.short_detection_fixture import run_semantic_worker, store_short_event
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = pytest.mark.postgres_integration


@pytest.fixture
def delivery_db(isolated_postgres_integration_database, monkeypatch):
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Fully migrated disposable PostgreSQL required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    with psycopg.connect(dsn) as conn:
        assert_disposable_database(conn)

    def connect(role=None):
        conn = psycopg.connect(dsn, row_factory=dict_row)
        if role:
            # Test harness changes identity, not ACLs. Both session_user and
            # current_user are the existing production role, never the admin.
            assert role in {"adlog_user", "adlog_notification_worker"}
            conn.execute("set session authorization " + role)
            identity = conn.execute("select session_user as s,current_user as c").fetchone()
            assert identity == {"s": role, "c": role}
        return conn

    def no_transport(*_, **__):
        pytest.fail("Unexpected real Telegram credential/config/network access")

    monkeypatch.setattr(telegram, "send", no_transport)
    monkeypatch.setattr(telegram, "_config", no_transport)
    monkeypatch.setattr(telegram, "read_notification_secret", no_transport)
    monkeypatch.setattr(telegram, "_connection", no_transport)
    clear_schema_guard_cache()
    yield connect
    clear_schema_guard_cache()


def _bind_runtime(monkeypatch, connect, role):
    clear_schema_guard_cache()  # Cold worker must not borrow a web/admin check.
    monkeypatch.setattr(pipeline, "connect", lambda: connect(role))
    monkeypatch.setattr(outbox, "connect", lambda: connect(role))


def _users(conn):
    return [conn.execute(
        "insert into auth_users(username,password_hash,role) values(%s,'synthetic-only','admin') returning id",
        ("t009-" + uuid4().hex,),
    ).fetchone()["id"] for _ in range(2)]


def test_cold_delivery_role_can_resolve_recipient_without_service_marker_access(delivery_db, monkeypatch):
    """The delivery role does not need account-inventory classification data."""
    with delivery_db() as admin:
        owner, recipient = _users(admin)
    _bind_runtime(monkeypatch, delivery_db, "adlog_notification_worker")
    with delivery_db("adlog_notification_worker") as worker:
        assert not worker.execute("select has_column_privilege(current_user,'auth_users','password_hash','SELECT') as v").fetchone()["v"]
        assert not worker.execute("select has_column_privilege(current_user,'auth_users','is_service','SELECT') as v").fetchone()["v"]
    # Real resolver + real queue_access, with a cold role-specific schema check.
    outbox.require_recipient(owner)
    outbox.require_recipient(recipient)


def _native_source(connect, failures, with_success):
    """Synthetic imported native receipts only, not detector state or findings."""
    from psycopg.types.json import Jsonb

    agent, host = uuid4(), uuid4()
    with connect() as conn:
        forest = conn.execute("insert into forests(name) values('t009.example.test') returning id").fetchone()["id"]
        domain = conn.execute("insert into domains(forest_id,fqdn) values(%s,'t009.example.test') returning id", (forest,)).fetchone()["id"]
        server = conn.execute("insert into servers(domain_id,hostname,fqdn,role) values(%s,'t009-dc','t009-dc.example.test','domain_controller') returning id", (domain,)).fetchone()["id"]
        conn.execute("insert into sli_agents(id,host_id,key_fingerprint) values(%s,%s,%s)", (agent, host, "0" * 64))
        at = conn.execute("select clock_timestamp()-interval '400 seconds' as at").fetchone()["at"]
        natives = []
        event_ids = []
        for number in range(1, failures + int(with_success) + 1):
            success = number > failures
            kind = 4624 if success else 4625
            timestamp = at + timedelta(seconds=1) if success else at
            packet = uuid4()
            digest = sha256(f"t009-native-{number}".encode()).digest()
            envelope = {"agent_id": str(agent), "source_instance_id": str(host), "generation": str(host)}
            xml = _xml(timestamp, number).replace(
                '<System>', '<System><Provider Name="Microsoft-Windows-Security-Auditing"/><Channel>Security</Channel>'
            )
            if success:
                xml = xml.replace("<EventID>4625</EventID>", "<EventID>4624</EventID>").replace(
                    '<Data Name="Status">0xc000006a</Data>', '<Data Name="LogonType">3</Data>'
                )
            row = {"record_id": number, "event_id": kind, "time_created": timestamp.isoformat(),
                   "computer_name": "fixture-collector", "channel": "Security", "xml": xml}
            conn.execute("""insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                values(%s,'sli.windows.ad-dc',%s,%s,%s,%s,%s)""",
                (agent, number, packet, digest.hex(), Jsonb(envelope), Jsonb({"status": "committed"})))
            conn.execute("""insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
                values(%s,%s,%s,%s,clock_timestamp())""", (packet, Jsonb(envelope), Jsonb({
                    "contract": "sli.collection-packet.v1", "header": {"source": "fixture-collector", "channel": "Security"}}), Jsonb([row])))
            natives.append((packet, row, digest))
    with connect("adlog_user") as web, web.cursor() as cur:
        policies.assign_module(cur, {"agent_id": str(agent), "module_id": "sli.windows.ad-dc",
            "expected_revision": 1, "enabled": True,
            "config": {"source_name": "t009-dc.example.test", "connect_address": "t009-dc.example.test"}}, actor="session:1")
    with connect() as conn:
        for packet, row, digest in natives:
            event_ids.append(store_short_event(conn, server=server, domain=domain, packet=packet, row=row, digest=digest))
    return agent, domain, event_ids


def _produce(connect, worker_dsn, directory, failures, with_success):
    import psycopg
    from psycopg.rows import dict_row

    agent, domain, events = _native_source(connect, failures, with_success)
    with psycopg.connect(worker_dsn, autocommit=True, row_factory=dict_row) as worker:
        worker.execute("set role adlog_semantic_worker")
        assert assert_semantic_worker_least_privilege(worker.cursor())["exclusive_worker_membership"]
        # The actual source issuer binds this physical LOGIN to imported receipt
        # authority. No direct source binding or detector state is inserted.
        source, = worker.execute("select source from default_detection_sources()").fetchall()
        assert source["source"]["scope"]["plugin_id"] == "sli.windows.ad-dc"
        with connect("adlog_user") as web:
            assert web.execute("select provision_password_detection_domain_v2(%s,2,null,'t009.example.test','session:1') as v", (agent,)).fetchone()["v"]["status"] == "configured"
        run_semantic_worker(worker_dsn, directory)
        with connect() as admin:
            publications = admin.execute("select finding_id,scenario_id from semantic_finding_publications").fetchall()
            assert admin.execute("select count(*) as n from semantic_password_checkpoints").fetchone()["n"] == 0
            assert admin.execute("select count(*) as n from event_hot where source_sha256 is not null").fetchone()["n"] == len(events)
        for table in ("notification_outbox", "notification_subscriptions"):
            assert not worker.execute("select has_table_privilege(current_user,%s,'SELECT') as v", (table,)).fetchone()["v"]
    return publications, domain, events


@pytest.mark.parametrize(("with_success", "revoke"), [
    pytest.param(False, None, id="subthreshold-does-not-notify"),
    pytest.param(True, None, id="critical-delivered"),
    pytest.param(True, "owner", id="critical-owner-revoked"),
    pytest.param(True, "recipient", id="critical-recipient-revoked"),
])
def test_password_publication_retained_events_and_real_delivery_dispatch(
    delivery_db, postgres_semantic_worker_dsn, monkeypatch, tmp_path, with_success, revoke,
):
    with delivery_db() as admin:
        owner, recipient = _users(admin)
        subscription = uuid4()
        admin.execute("""insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
            values(%s,%s,%s,'telegram',true)""", (subscription, owner, recipient))
        admin.execute("update notification_channels set enabled=true where kind='telegram'")
    failures = 20 if with_success else 19
    publications, domain, events = _produce(delivery_db, postgres_semantic_worker_dsn, tmp_path, failures, with_success)
    with delivery_db() as admin:
        queued = admin.execute("select * from notification_outbox").fetchall()
        if not with_success:
            assert publications == []
            assert queued == []
            return
        published, = publications
        assert published["finding_id"] is not None
        finding = admin.execute("select * from findings where id=%s", (published["finding_id"],)).fetchone()
        assert finding["rule_code"] == "semantic.qw.password-brute-force"
        assert finding["evidence_count"] == len(events)
        assert finding["severity"] == "critical"
        pending, = queued
        assert pending["state"] == "pending" and pending["attempts"] == 0
        assert pending["object_kind"] == "semantic_finding" and pending["channel"] == "telegram"
        assert str(pending["publication_scenario_id"]) == str(published["scenario_id"])
        assert pending["object_severity"] == "critical"
    _bind_runtime(monkeypatch, delivery_db, "adlog_user")
    with delivery_db("adlog_user") as web:
        copies = web.execute("select event_id,domain_id from finding_event_copies337 where finding_id=%s",
                             (published["finding_id"],)).fetchall()
        assert {row["event_id"] for row in copies} == set(events)
        assert all(row["domain_id"] == domain for row in copies)
    if revoke:
        with delivery_db() as admin:
            admin.execute("update auth_users set is_active=false where id=%s", (owner if revoke == "owner" else recipient,))
    _bind_runtime(monkeypatch, delivery_db, "adlog_notification_worker")
    sent = []

    def fake_send(job, channel):
        sent.append((job, channel))
        return telegram.Outcome("accepted")

    monkeypatch.setattr(telegram, "send", fake_send)
    assert outbox.process_one(telegram=True, telegram_only=True)
    with delivery_db() as admin:
        final, = admin.execute("select * from notification_outbox").fetchall()
        attempt, = admin.execute("select * from notification_attempts").fetchall()
        expected = "blocked" if revoke else "accepted"
        code = "recipient_denied" if revoke else "accepted"
        assert (final["state"], final["result_code"], final["attempts"]) == (expected, code, 1)
        assert (attempt["state"], attempt["result_code"], attempt["attempt"]) == (expected, code, 1)
        assert final["id"] == pending["id"] and final["lease_token"] is None and final["lease_until"] is None
    assert len(sent) == (0 if revoke else 1)
    if sent:
        assert sent[0][0]["finding_id"] == published["finding_id"]
        assert str(sent[0][0]["object_id"]) == str(published["scenario_id"])
        assert sent[0][1]["enabled"] is True
    assert not outbox.process_one(telegram=True, telegram_only=True)
