"""Domain/OU selection and opt-in approval with accepted-directory cursor fakes."""
from copy import deepcopy
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents import deployment_scope, group_deployment, group_enrollment as groups, onboarding, policies, registry
from server.sli.agents.ca import AgentError, fingerprint, utcnow
from tests.unit.test_agent_group_deployment import DeploymentCursor
from tests.unit.test_agent_group_enrollment import directory_record
from tests.unit.test_agent_registry import HOST, lifecycle as lifecycle, request
from tests.unit.test_agent_policies import Cursor as PolicyCursor


class Cursor(DeploymentCursor):
    def __init__(self):
        super().__init__()
        self.template = {"id": HOST, "version": 1, "policy_sha256": "a" * 64,
                         **onboarding._template_policy([], {"interval_seconds": 90})}
        self.copies = {}

    def execute(self, sql, params=()):
        self.rows = []
        self.calls.append((sql, params))
        if sql.startswith("select distinct d.id"):
            self.rows = [{"id": 1, "name": "example.test"}]
        elif sql.startswith("select e.id as entity_id"):
            self.rows = [{**deepcopy(row), "entity_id": entity, "source_section": "domain_posture" if entity == 2 else "directory_accounts"}
                         for (entity, domain), row in sorted(self.directory.items()) if domain == params[0]]
        elif sql.startswith("select * from sli_agent_policy_templates"):
            if params == (self.template["id"], self.template["version"]):
                self.rows = [self.template]
        elif sql.startswith("insert into sli_agent_onboarding_copies"):
            self.copies[params[1]] = params[0]
            self.approvals[params[1]] = params[0]
            self.policy_templates[params[0]] = deepcopy(self.template)
        elif sql.startswith("update sli_agent_group_requests set status=%s"):
            self.requests[params[1]]["status"] = params[0]
        elif sql.startswith("update sli_agent_enrollment_tokens e set token_hash=") and "from sli_agent_onboarding_copies" in sql:
            token = self.tokens[self.copies[params[3]]]
            if token["used_at"] is None and token["revoked_at"] is None:
                token.update(token_hash=params[0], created_at=params[1], expires_at=params[2])
                self.rows = [{"id": token["id"]}]
        else:
            self.calls.pop()
            super().execute(sql, params)


@pytest.fixture
def automatic():
    cur = Cursor()
    key = ec.generate_private_key(ec.SECP256R1())
    binding = {"host_id": HOST, "instance_name": None, "key_fingerprint": fingerprint(key.public_key()), "computer_entity_id": 3}
    body = {"domain_id": 1, "ou_entity_ids": [2], "computer_entity_ids": [3], "max_uses": 1,
            "template_id": HOST, "template_version": 1, "auto_approve": True, "trusted_bindings": [binding]}
    token = groups.create_token(cur, body, actor="session:1")
    submission = {"token": token["token"], "host_id": HOST, "computer_entity_id": 3, "csr_pem": request(key)}
    return cur, token, submission


def test_directory_selects_only_enabled_computers_and_server_ou_boundaries():
    cur = Cursor()
    cur.directory[(4, 1)] = {"version_id": 40, "record": directory_record(dn="CN=Other,OU=Other,DC=example,DC=test")}
    cur.directory[(5, 1)] = {"version_id": 50, "record": directory_record()}
    cur.directory[(5, 1)]["record"]["attributes"]["enabled"] = False
    assert deployment_scope.directory(cur, {})["domains"] == [{"id": 1, "name": "example.test"}]
    whole = deployment_scope.directory(cur, {"domain_id": 1})
    assert [item["id"] for item in whole["computers"]] == [3, 4]
    selected = deployment_scope.directory(cur, {"domain_id": 1, "ou_entity_ids": [2]})
    assert [item["id"] for item in selected["computers"]] == [3]
    assert [item["id"] for item in selected["ous"]] == [2]
    assert not selected["has_more"]
    sql = next(sql for sql, _ in cur.calls if sql.startswith("select e.id"))
    for guard in ("r.status='completed'", "s.status='complete'", "interval '24 hours'", "v.valid_to_utc is null"):
        assert guard in sql


def test_whole_domain_and_selected_hosts_are_supported_without_auto_approval():
    cur = Cursor()
    token = groups.create_token(cur, {"domain_id": 1, "max_uses": 1, "computer_entity_ids": [3]}, actor="session:1")
    assert cur.groups[token["id"]]["ou_entity_ids"] == []
    cur.directory[(3, 1)]["record"] = directory_record(dn="CN=Fixture,CN=Computers,DC=example,DC=test")
    body = {"token": token["token"], "host_id": HOST, "computer_entity_id": 3,
            "csr_pem": request(ec.generate_private_key(ec.SECP256R1()))}
    assert groups.submit(cur, body)["status"] == "pending"
    assert not cur.tokens
    cur.directory[(4, 1)] = {"version_id": 40, "record": directory_record()}
    with pytest.raises(groups.AuditedRejection):
        groups.submit(cur, {**body, "computer_entity_id": 4, "csr_pem": request(ec.generate_private_key(ec.SECP256R1()))})


def test_auto_approval_rotates_lost_reply_and_enrolls_with_a_personal_template(automatic, lifecycle):
    cur, group, body = automatic
    first = groups.submit(cur, body)
    assert first["status"] == "approved" and not cur.agents and not cur.certificates
    second = groups.submit(cur, body)
    assert second["request_id"] == first["request_id"] and second["token"] != first["token"]
    assert len(cur.tokens) == len(cur.copies) == cur.groups[group["id"]]["uses_count"] == 1
    assert all(token["replacement_for"] is None for token in cur.tokens.values())
    assert first["token"] not in repr(cur.calls) and second["token"] not in repr(cur.audits)
    with pytest.raises(AgentError):
        registry.enroll(cur, lifecycle[1], {"token": first["token"], "csr_pem": body["csr_pem"]})
    enrolled = registry.enroll(cur, lifecycle[1], {"token": second["token"], "csr_pem": body["csr_pem"]})
    agent = cur.agents[enrolled["agent_id"]]
    assert agent["collection_policy"]["interval_seconds"] == 90
    assert cur.members[agent["id"]] == group["group_id"]
    personal = PolicyCursor()
    personal.agent = deepcopy(agent)
    policies.update_control(personal, {"agent_id": agent["id"], "expected_revision": 1,
        "collection_policy": {"interval_seconds": 120}}, actor="session:1")
    assert personal.agent["policy_revision"] == 2 and personal.agent["collection_policy"]["interval_seconds"] == 120
    assert cur.template["collection_policy"]["interval_seconds"] == agent["collection_policy"]["interval_seconds"] == 90
    with pytest.raises(groups.AuditedRejection):
        groups.submit(cur, body)
    assert len(cur.certificates) == 1


@pytest.mark.parametrize("change", ["unknown_key", "wrong_host", "disabled", "stale", "outside", "revoked", "expired"])
def test_auto_approval_never_trusts_self_reported_ad_or_bypasses_scope(automatic, change):
    cur, token, body = automatic
    if change == "unknown_key":
        body["csr_pem"] = request(ec.generate_private_key(ec.SECP256R1()))
    elif change == "wrong_host":
        body["host_id"] = "00000000-0000-4000-8000-000000000002"
        body["csr_pem"] = request(ec.generate_private_key(ec.SECP256R1()), body["host_id"])
    elif change == "disabled":
        cur.directory[(3, 1)]["record"]["attributes"]["enabled"] = False
    elif change == "stale":
        cur.directory.pop((3, 1))
    elif change == "outside":
        cur.directory[(3, 1)]["record"] = directory_record(dn="CN=Fixture,OU=Other,DC=example,DC=test")
    elif change == "revoked":
        groups.revoke_token(cur, token["id"], actor="session:1")
    else:
        cur.groups[token["id"]]["expires_at"] = utcnow() - timedelta(seconds=1)
    if change in ("unknown_key", "wrong_host"):
        assert groups.submit(cur, body)["status"] == "pending"
    else:
        with pytest.raises(AgentError):
            groups.submit(cur, body)
    assert not cur.tokens and not cur.copies and not cur.agents and not cur.certificates


def test_stopping_auto_enrollment_withdraws_prepared_token(automatic, lifecycle):
    cur, token, body = automatic
    approved = groups.submit(cur, body)
    groups.revoke_token(cur, token["id"], actor="session:1")
    assert cur.requests[approved["request_id"]]["status"] == "cancelled"
    with pytest.raises(AgentError):
        registry.enroll(cur, lifecycle[1], {"token": approved["token"], "csr_pem": body["csr_pem"]})
    assert not cur.agents and not cur.certificates


def test_auto_retry_rechecks_expiry_after_host_lock_wait(automatic, monkeypatch):
    cur, token, body = automatic
    groups.submit(cur, body)
    expiry = cur.groups[token["id"]]["expires_at"]
    cur.expire_on_host_lock = True
    monkeypatch.setattr(deployment_scope, "utcnow", lambda: expiry if cur.waited else utcnow())
    before = deepcopy(cur.tokens)
    with pytest.raises(groups.AuditedRejection):
        groups.submit(cur, body)
    assert cur.tokens == before


@pytest.mark.parametrize("conflict", [False, True])
def test_manual_approval_uses_the_groups_pinned_template(automatic, conflict):
    cur, token, body = automatic
    cur.groups[token["id"]]["enrollment_policy"]["auto_approve"] = False
    pending = groups.submit(cur, body)
    row = cur.requests[pending["request_id"]]
    if conflict:
        cur.agents[HOST] = {"id": HOST, "host_id": HOST}
    evidence = {"request_id": row["id"], **{key: row[key] for key in ("host_id", "instance_name", "key_fingerprint", "computer_entity_id")}}
    result = group_deployment.approve(cur, {"filter": {"group_id": token["group_id"], "token_id": token["id"]},
        "evidence": [evidence]}, actor="session:1")
    assert result["items"][0]["status"] == ("rejected" if conflict else "approved")
    assert len(cur.copies) == len(cur.tokens) == (0 if conflict else 1)


@pytest.mark.parametrize("change", [{"auto_approve": "true"}, {"auto_approve": True},
    {"computer_entity_ids": [True]}, {"computer_entity_ids": [999]}, {"trusted_bindings": [{}]},
    {"template_id": HOST}, {"template_id": HOST, "template_version": 2}])
def test_invalid_or_unattested_rule_cannot_create_a_token(change):
    cur = Cursor()
    with pytest.raises(AgentError):
        groups.create_token(cur, {"domain_id": 1, "ou_entity_ids": [2], "max_uses": 1, **change}, actor="session:1")
    assert not cur.groups and not cur.tokens
