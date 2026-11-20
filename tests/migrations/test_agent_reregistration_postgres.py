"""Real enrollment, revocation and inventory under migrated PostgreSQL grants."""
import os
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents import registry, removal
from server.sli.agents.ca import AgentError, IssuingCA, fingerprint
from server.sli.agents.provision import create_issuer_request, create_root, sign_issuer
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_agent_registry import request

pytestmark = pytest.mark.postgres_integration


@pytest.fixture
def database():
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Disposable migrated PostgreSQL required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        conn.execute("set local role adlog_user")
        yield conn
        conn.rollback()


@pytest.fixture
def authority():
    root_key, root = create_root()
    issuer_key, csr = create_issuer_request()
    return IssuingCA(root, sign_issuer(root, root_key, csr), issuer_key)


def register(cur, ca, name):
    host, key = str(uuid4()), ec.generate_private_key(ec.SECP256R1())
    token = registry.create_token(cur, {"host_id": host, "key_fingerprint": fingerprint(key.public_key()), "registration_host_name": name}, actor="session:1")
    return registry.enroll(cur, ca, {"token": token["token"], "csr_pem": request(key, host), "reported_hostname": name})


def der(result):
    return x509.load_pem_x509_certificate(result["certificate_pem"].encode()).public_bytes(serialization.Encoding.DER)


def test_three_registrations_leave_one_working_identity_and_two_retired_never_seen(database, authority):
    name = "pc-" + uuid4().hex + ".example.invalid"
    with database.cursor() as cur:
        results = [register(cur, authority, claim) for claim in (name, name.upper(), name)]
        ids = [r["agent_id"] for r in results]
        cur.execute("select id,status,last_seen from sli_agents where id=any(%s::uuid[])", (ids,))
        rows = {str(r["id"]): r for r in cur.fetchall()}
        assert [rows[i]["status"] for i in ids] == ["disabled", "disabled", "active"]
        assert all(r["last_seen"] is None for r in rows.values())
        for result in results[:2]:
            with pytest.raises(AgentError, match="agent_certificate_rejected"):
                registry.authenticate(cur, authority, der(result))
            detail = registry.list_agents(cur, actor="session:1", agent_id=result["agent_id"])["items"][0]
            assert detail["last_seen"] is None and detail["created_at"]
            assert detail["inventory_hidden_reason"] == "registration_replaced"
            assert all(c["revoked_at"] for c in detail["certificates"])
        registry.authenticate(cur, authority, der(results[-1]))
        items = registry.list_agents(cur, actor="session:1")["items"]
        assert {str(a["id"]) for a in items} & set(ids) == {ids[-1]}
        assert next(a for a in items if str(a["id"]) == ids[-1])["last_seen"] is not None
        feed = registry.revocations(cur, 0)["items"]
        assert {r["serial"] for r in feed if str(r["agent_id"]) in ids[:2]} == {r["serial"] for r in results[:2]}


def test_admin_removal_revokes_and_hides_but_retains_exact_readback(database, authority):
    with database.cursor() as cur:
        result = register(cur, authority, "pc-" + uuid4().hex + ".example.invalid")
        agent_id = result["agent_id"]
        removal.request(cur, {"operation_id": str(uuid4()), "agent_ids": [agent_id]}, actor="session:1")
        with pytest.raises(AgentError, match="agent_certificate_rejected"):
            registry.authenticate(cur, authority, der(result))
        assert agent_id not in {str(a["id"]) for a in registry.list_agents(cur, actor="session:1")["items"]}
        detail = registry.list_agents(cur, actor="session:1", agent_id=agent_id)["items"][0]
        assert detail["status"] == "disabled"
        assert detail["inventory_hidden_reason"] == "administrator_removed"
        assert detail["certificates"][0]["revoked_at"]


@pytest.mark.parametrize("approved", [None, "other.example.invalid"])
def test_claimed_name_without_matching_admin_approval_cannot_revoke(database, authority, approved):
    name = "pc-" + uuid4().hex + ".example.invalid"
    with database.cursor() as cur:
        first = register(cur, authority, name)
        host, key = str(uuid4()), ec.generate_private_key(ec.SECP256R1())
        token = registry.create_token(cur, {"host_id": host, "key_fingerprint": fingerprint(key.public_key()),
            "registration_host_name": approved}, actor="session:1")
        body = {"token": token["token"], "csr_pem": request(key, host), "reported_hostname": name}
        if approved:
            with pytest.raises(AgentError, match="agent_registration_name_mismatch"):
                registry.enroll(cur, authority, body)
        else:
            registry.enroll(cur, authority, body)
        registry.authenticate(cur, authority, der(first))
        detail = registry.list_agents(cur, actor="session:1", agent_id=first["agent_id"])["items"][0]
        assert detail["status"] == "active"
        assert detail["certificates"][0]["revoked_at"] is None


def test_24_hour_orphan_filter_applies_before_limit_and_preserves_working_records(database):
    # Inserting synthetic old rows needs no new UPDATE(created_at) grant.
    orphan, recent, contacted = uuid4(), uuid4(), uuid4()
    with database.cursor() as cur:
        for agent_id, age, seen in ((orphan, 25, False), (recent, 23, False), (contacted, 25, True)):
            cur.execute("""insert into sli_agents(id,host_id,key_fingerprint,created_at,last_seen)
                values(%s,%s,%s,clock_timestamp() - %s * interval '1 hour',
                    case when %s then clock_timestamp() - interval '2 days' end)""",
                (agent_id, uuid4(), "a" * 64, age, seen))
        items = registry.list_agents(cur, actor="session:1")["items"]
        assert {a["id"] for a in items} & {orphan, recent, contacted} == {recent, contacted}
        detail = registry.list_agents(cur, actor="session:1", agent_id=str(orphan))["items"][0]
        assert detail["inventory_hidden_reason"] == "never_seen_expired"
        assert detail["last_seen"] is None
