"""Stage 6 MSI -> attested admission -> profile -> signal, with no DB/network."""
import json
from copy import deepcopy
from datetime import timedelta
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents import group_deployment, group_enrollment as groups, onboarding, registry
from server.sli.agents.ca import AgentError, utcnow
from sli_agent import msi
from sli_agent.config import AgentConfig
from sli_agent.enrollment import IdentityStore
from tests.unit.test_agent_deployment_scope import Cursor
from tests.unit.test_agent_group_enrollment import directory_record
from tests.unit.test_agent_registry import HOST, lifecycle as lifecycle, request


class BootstrapCursor(Cursor):
    def execute(self, sql, params=()):
        if not sql.startswith("select r.id,r.host_id,r.instance_name,r.key_fingerprint"):
            return super().execute(sql, params)
        self.calls.append((sql, params))
        self.rows = []
        for row in self.requests.values():
            if row["token_id"] != params[0]:
                continue
            enrollment_id = self.approvals.get(row["id"])
            issued = next((event for event in self.audits if event["action"] == "issue"
                           and event["actor"] == "enrollment:" + str(enrollment_id)), None)
            agent = self.agents.get(issued["target"], {}) if issued else {}
            template = self.policy_templates.get(enrollment_id, {})
            self.rows.append({**deepcopy(row), "agent_id": agent.get("id"), "last_seen": agent.get("last_seen"),
                "template_id": template.get("id"), "template_version": template.get("version"),
                "applied_policy_revision": agent.get("applied_policy_revision")})


def approved_request(cur, token, submission):
    pending = groups.submit(cur, submission)
    row = cur.requests[pending["request_id"]]
    evidence = {"request_id": row["id"], **{key: row[key] for key in
        ("host_id", "instance_name", "key_fingerprint", "computer_entity_id")}}
    body = {"filter": {"group_id": token["group_id"], "token_id": token["id"]}, "evidence": [evidence]}
    return group_deployment.approve(cur, body, actor="session:1")["items"][0]


@pytest.fixture
def batch():
    cur = BootstrapCursor()
    token = groups.create_token(cur, {"domain_id": 1, "ou_entity_ids": [2], "computer_entity_ids": [3],
        "ttl_seconds": 604800, "max_uses": 2, "template_id": HOST, "template_version": 1}, actor="session:1")
    key = ec.generate_private_key(ec.SECP256R1())
    submission = {"token": token["token"], "host_id": HOST, "computer_entity_id": 3, "csr_pem": request(key)}
    return cur, token, submission


@pytest.mark.posix_only
def test_msi_pending_restart_independent_attestation_personal_profile_and_signal(tmp_path, lifecycle):
    cur = BootstrapCursor()
    token = groups.create_token(cur, {"domain_id": 1, "ou_entity_ids": [2], "computer_entity_ids": [3],
        "ttl_seconds": 604800, "max_uses": 1, "template_id": HOST, "template_version": 1}, actor="session:1")
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path / "state", collection_enabled=False)
    file = tmp_path / "enrollment.group"
    file.write_text(json.dumps({"kind": "group", "token": token["token"],
                               "computer_entity_id": 3, "expires_at": token["expires_at"]}))
    file.chmod(0o600)
    public = IdentityStore(config).prepare()  # Read from the trusted station console.

    class Transport:
        def post(self, path, body):
            if path == "/api/v1/agent/group-enroll":
                return groups.submit(cur, body)
            assert path == "/api/v1/agent/enroll"
            return registry.enroll(cur, lifecycle[1], body)

    transport = Transport()
    for _ in range(2):
        assert msi.enroll_once(config, IdentityStore(config), transport) == "agent_approval_pending"
        assert not cur.agents and not cur.certificates
        assert IdentityStore(config).prepare() == public and not config.collection_enabled
    assert cur.groups[token["id"]]["uses_count"] == 1
    assert onboarding.list_requests(cur, token["id"], actor="session:1")["items"][0]["deployment_status"] == "pending"
    row = next(iter(cur.requests.values()))
    # The independent evidence uses the console's key/host, not the queue's.
    result = group_deployment.approve(cur, {"filter": {"group_id": token["group_id"], "token_id": token["id"]},
        "evidence": [{"request_id": row["id"], **public, "computer_entity_id": 3, "instance_name": None}]}, actor="session:1")
    assert result["items"][0]["status"] == "approved" and not cur.certificates
    assert onboarding.list_requests(cur, token["id"], actor="session:1")["items"][0]["deployment_status"] == "approved"
    assert msi.enroll_once(config, IdentityStore(config), transport) == "enrolled"
    identity = IdentityStore(config).load()
    assert not file.exists() and identity is not None
    agent = cur.agents[identity.agent_id]
    assert agent["collection_policy"] == cur.template["collection_policy"]
    assert agent["template_id"] == cur.template["id"] and agent["template_version"] == 1
    registered = onboarding.list_requests(cur, token["id"], actor="session:1")["items"][0]
    assert registered["deployment_status"] == "registered" and registered["last_seen"] is None
    der = x509.load_pem_x509_certificate(identity.certificate_pem.encode()).public_bytes(serialization.Encoding.DER)
    registry.authenticate(cur, lifecycle[1], der)
    signaled = onboarding.list_requests(cur, token["id"], actor="session:1")["items"][0]
    assert signaled["deployment_status"] == "signaled" and signaled["last_seen"] is not None
    assert signaled["template_id"] == cur.template["id"] and signaled["applied_policy_revision"] == 0
    assert cur.groups[token["id"]]["expires_at"] - cur.groups[token["id"]]["created_at"] == timedelta(days=7)
    assert cur.members[identity.agent_id] == token["group_id"]
    for raw in (token["token"], result["items"][0]["token"]):
        assert raw not in repr(cur.audits) and raw not in repr(signaled)
        assert raw not in repr(cur.calls)


def test_manual_approval_retry_rotates_only_unused_key_bound_token_and_preserves_copy(batch, lifecycle):
    cur, token, body = batch
    first = approved_request(cur, token, body)
    expiry = cur.groups[token["id"]]["expires_at"]
    copies = deepcopy(cur.policy_templates)
    second = groups.submit(cur, body)
    third = groups.submit(cur, body)  # A lost approval response is retriable.
    assert second["status"] == third["status"] == "approved"
    assert len({first["token"], second["token"], third["token"]}) == 3
    assert len(cur.tokens) == len(cur.copies) == cur.groups[token["id"]]["uses_count"] == 1
    assert cur.policy_templates == copies and cur.groups[token["id"]]["expires_at"] == expiry
    with pytest.raises(AgentError):
        registry.enroll(cur, lifecycle[1], {"token": second["token"], "csr_pem": body["csr_pem"]})
    registry.enroll(cur, lifecycle[1], {"token": third["token"], "csr_pem": body["csr_pem"]})
    with pytest.raises(groups.AuditedRejection):
        groups.submit(cur, body)
    assert len(cur.certificates) == 1


@pytest.mark.parametrize("change", ["revoked", "expired", "disabled", "outside", "used", "withdrawn", "key", "entity", "lock_wait"])
def test_approved_poll_never_bypasses_batch_scope_or_key(batch, monkeypatch, change):
    cur, token, body = batch
    approved_request(cur, token, body)
    if change == "revoked":
        groups.revoke_token(cur, token["id"], actor="session:1")
    elif change == "expired":
        cur.groups[token["id"]]["expires_at"] = utcnow() - timedelta(seconds=1)
    elif change == "disabled":
        cur.directory[(3, 1)]["record"]["attributes"]["enabled"] = False
    elif change == "outside":
        cur.directory[(3, 1)]["record"] = directory_record(dn="CN=Fixture,OU=Other,DC=example,DC=test")
    elif change in ("used", "withdrawn"):
        next(iter(cur.tokens.values()))["used_at" if change == "used" else "revoked_at"] = utcnow()
    elif change == "key":
        body["csr_pem"] = request(ec.generate_private_key(ec.SECP256R1()))
    elif change == "entity":
        body["computer_entity_id"] = 4
    else:
        cur.expire_on_host_lock = True
        expiry = cur.groups[token["id"]]["expires_at"]
        monkeypatch.setattr(group_deployment, "utcnow", lambda: expiry if cur.waited else utcnow())
    before = deepcopy(cur.tokens)
    if change == "key":
        assert groups.submit(cur, body)["status"] == "pending"
    else:
        with pytest.raises(groups.AuditedRejection):
            groups.submit(cur, body)
    assert cur.tokens == before and not cur.agents and not cur.certificates


@pytest.mark.parametrize("other_batch", [False, True])
def test_second_station_and_spoofed_target_never_inherit_approved_key(batch, lifecycle, other_batch):
    cur, token, body = batch
    first = approved_request(cur, token, body)
    if other_batch:
        token = groups.create_token(cur, {"domain_id": 1, "ou_entity_ids": [2], "computer_entity_ids": [3],
            "max_uses": 1, "template_id": HOST, "template_version": 1}, actor="session:1")
    host = str(UUID(int=123))
    other_key = ec.generate_private_key(ec.SECP256R1())
    spoof = {**body, "token": token["token"], "host_id": host, "csr_pem": request(other_key, host)}
    assert groups.submit(cur, spoof)["status"] == "pending"
    with pytest.raises(AgentError, match="agent_csr_key_mismatch"):
        registry.enroll(cur, lifecycle[1], {"token": first["token"], "csr_pem": request(other_key)})
    with pytest.raises(AgentError, match="agent_csr_subject_mismatch"):
        registry.enroll(cur, lifecycle[1], {"token": first["token"], "csr_pem": spoof["csr_pem"]})
    registry.enroll(cur, lifecycle[1], {"token": first["token"], "csr_pem": body["csr_pem"]})
    # Even a separate administrator approval cannot register the target twice.
    second = approved_request(cur, token, spoof)
    with pytest.raises(AgentError, match="enrollment_token_rejected"):
        registry.enroll(cur, lifecycle[1], {"token": second["token"], "csr_pem": spoof["csr_pem"]})
    assert len(cur.certificates) == len(cur.agents) == 1


def test_manual_retry_without_template_uses_the_same_approval_link(batch):
    cur, token, body = batch
    cur.groups[token["id"]]["enrollment_policy"] = {}
    approved_request(cur, token, body)
    assert groups.submit(cur, body)["status"] == "approved"
    assert len(cur.tokens) == 1 and not cur.copies


def test_certificate_issue_rechecks_current_directory_scope(batch, lifecycle):
    cur, token, body = batch
    approved = approved_request(cur, token, body)
    cur.directory[(3, 1)]["record"]["attributes"]["enabled"] = False
    with pytest.raises(AgentError):
        registry.enroll(cur, lifecycle[1], {"token": approved["token"], "csr_pem": body["csr_pem"]})
    assert not cur.certificates and not cur.agents
