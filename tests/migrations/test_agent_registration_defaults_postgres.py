"""T094: committed enrollment -> persisted role policy -> authenticated check-in.

Requires the migrated, disposable PostgreSQL template used by the postgres CI
job. Runs the normal runtime role, including real DC binding/history triggers.
"""
import os
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents import policies, registry
from server.sli.agents.ca import IssuingCA, fingerprint
from server.sli.agents.provision import create_issuer_request, create_root, sign_issuer
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_agent_registry import request

pytestmark = pytest.mark.postgres_integration


@pytest.mark.parametrize("role,module", [
    (None, "sli.workstations"),
    ("workstation", "sli.workstations"),
    ("domain_controller", "sli.windows.ad-dc"),
])
def test_registration_and_next_check_in_receive_active_role_policy(role, module):
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Disposable migrated PostgreSQL required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    root_key, root = create_root()
    issuer_key, issuer_request = create_issuer_request()
    authority = IssuingCA(root, sign_issuer(root, root_key, issuer_request), issuer_key)
    key, host = ec.generate_private_key(ec.SECP256R1()), str(uuid4())
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        conn.execute("set local role adlog_user")
        with conn.cursor() as cur:
            token = registry.create_token(cur, {"host_id": host, "key_fingerprint": fingerprint(key.public_key())},
                                          actor="session:t094")
            body = {"token": token["token"], "csr_pem": request(key, host), "reported_hostname": "pc.example.invalid"}
            if role is not None:
                body["machine_role"] = role
            result = registry.enroll(cur, authority, body)
    # A separate committed connection ensures that registration did not merely
    # return an in-memory policy or rely on a privileged enrollment session.
    der = x509.load_pem_x509_certificate(result["certificate_pem"].encode()).public_bytes(serialization.Encoding.DER)
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        conn.execute("set local role adlog_user")
        stored = conn.execute("select * from sli_agents where id=%s", (result["agent_id"],)).fetchone()
        assert stored["collection_policy"]["state"] == "active"
        assert stored["collection_policy"]["manage_windows_audit"] is True
        assert stored["assigned_modules"][0]["module_id"] == module
        assert stored["assigned_modules"][0]["enabled"] is True
        history = conn.execute("select assigned_modules,collection_policy from sli_agent_policy_history "
                               "where agent_id=%s and revision=%s", (result["agent_id"], stored["policy_revision"])).fetchone()
        assert history["assigned_modules"] == stored["assigned_modules"]
        assert history["collection_policy"] == stored["collection_policy"]
        with conn.cursor() as cur:
            wire = policies.check_in(registry.authenticate(cur, authority, der))
        assert wire["assigned_modules"] == stored["assigned_modules"]
        assert wire["collection_policy"]["state"] == "active"
        assert wire["collection_policy"]["manage_windows_audit"] is True
        if role == "domain_controller":
            assert wire["assigned_modules"][0]["config"]["channels"] == {
                "Security": True, "System": True, "Directory Service": True,
            }
            binding = conn.execute("select source_instance_id,policy_revision from sli_agent_module_bindings "
                                   "where agent_id=%s and module_id=%s", (result["agent_id"], module)).fetchone()
            assert binding["source_instance_id"] == host
            assert binding["policy_revision"] == str(wire["policy_revision"])
        else:
            assert wire["assigned_modules"][0]["config"]["families"]["processes"] is True
