"""Group scope, batch decisions and issuance withdrawal with cursor fakes."""
from copy import deepcopy
from datetime import timedelta
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents import group_deployment as deployment, group_enrollment as groups, registry
from server.sli.agents.ca import AgentError, utcnow
from tests.unit.test_agent_group_enrollment import GroupCursor, directory_record
from tests.unit.test_agent_registry import HOST, lifecycle as lifecycle, request


class DeploymentCursor(GroupCursor):
    def __init__(self):
        super().__init__()
        self.approvals, self.members = {}, {}
        self.expire_on_host_lock = False
        self.waited = False

    def execute(self, sql, params=()):
        self.rows = []
        self.calls.append((sql, params))
        if sql.startswith("select * from sli_agent_group_tokens where id="):
            row = self.groups.get(params[0])
            if row and (len(params) == 1 or row["group_id"] == params[1]):
                self.rows = [row]
        elif sql.startswith("select * from sli_agent_group_requests"):
            self.rows = [row for key, row in sorted(self.requests.items()) if row["token_id"] == params[0] and key in params[1]]
        elif sql.startswith("select r.id,r.host_id"):
            self.rows = [row for _, row in sorted(self.requests.items()) if row["status"] == "pending"
                and row["token_id"] == params[1] and self.groups[row["token_id"]]["group_id"] == params[0]][:1001]
        elif sql.startswith("insert into sli_agent_group_approvals"):
            assert params[0] not in self.approvals
            self.approvals[params[0]] = params[1]
        elif sql.startswith("update sli_agent_group_requests set status='approved'"):
            self.requests[params[0]]["status"] = "approved"
        elif sql.startswith("select r.token_id"):
            self.rows = [{key: self.requests[req][key] for key in ("token_id", "computer_entity_id", "instance_name")}
                         for req, token in self.approvals.items()
                         if self.tokens[token]["token_hash"] == params[0]]
        elif sql.startswith("select issued.target from sli_agent_audit"):
            self.rows = [{"target": event["target"]} for event in self.audits if event["action"] == "issue"
                for req, token in self.approvals.items() if event["actor"] == "enrollment:" + token
                and (self.requests[req]["computer_entity_id"], self.requests[req]["instance_name"]) == params]
        elif sql.startswith("update sli_agent_enrollment_tokens e set token_hash="):
            token = self.tokens[self.approvals[params[3]]]
            if (token["used_at"] is None and token["revoked_at"] is None
                    and (str(token["host_id"]), token["key_fingerprint"], token["instance_name"]) == params[4:7]
                    and params[7] > utcnow() + timedelta(seconds=60)):
                token.update(token_hash=params[0], created_at=params[1], expires_at=params[2])
                self.rows = [{"id": token["id"]}]
        elif sql.startswith("insert into sli_agent_group_members"):
            for req, token in self.approvals.items():
                if token == params[1]:
                    self.members[params[0]] = self.groups[self.requests[req]["token_id"]]["group_id"]
        elif sql.startswith("update sli_agent_enrollment_tokens e"):
            for req, token in self.approvals.items():
                if self.requests[req]["token_id"] == params[0] and self.tokens[token]["used_at"] is None:
                    self.tokens[token]["revoked_at"] = self.tokens[token]["revoked_at"] or utcnow()
        elif sql.startswith("update sli_agent_group_requests r"):
            for req, token in self.approvals.items():
                if self.requests[req]["token_id"] == params[0] and self.tokens[token]["used_at"] is None:
                    self.requests[req]["status"] = "cancelled"
        elif sql.startswith("update sli_agent_group_requests set status='cancelled'"):
            for row in self.requests.values():
                if row["token_id"] == params[0] and row["status"] == "pending":
                    row["status"] = "cancelled"
        else:
            if self.expire_on_host_lock and sql.startswith("select pg_advisory") and params:
                self.waited = True
                for group in self.groups.values():
                    group["expires_at"] = utcnow() - timedelta(seconds=1)
            self.calls.pop()
            super().execute(sql, params)


@pytest.fixture
def batch():
    cur = DeploymentCursor()
    token = groups.create_token(cur, {"max_uses": 1000, "domain_id": 1, "ou_entity_ids": [2]}, actor="session:1")
    body = {"token": token["token"], "host_id": HOST, "computer_entity_id": 3,
            "csr_pem": request(ec.generate_private_key(ec.SECP256R1()))}
    submission = groups.submit(cur, body)
    row = cur.requests[submission["request_id"]]
    evidence = {"request_id": row["id"], **{key: row[key] for key in
        ("host_id", "instance_name", "key_fingerprint", "computer_entity_id")}}
    approval = {"filter": {"group_id": token["group_id"], "token_id": token["id"]}, "evidence": [evidence]}
    return cur, token, body, approval


def test_tokens_share_an_immutable_group_and_seven_day_ttl(batch):
    cur, first, _, _ = batch
    second = groups.create_token(cur, {"group_id": first["group_id"], "max_uses": 10, "ttl_seconds": 604800}, actor="session:1")
    assert first["group_id"] == second["group_id"]
    assert len(cur.enrollment_groups) == 1
    assert cur.groups[second["id"]]["expires_at"] - cur.groups[second["id"]]["created_at"] == timedelta(days=7)
    for body in ({"group_id": first["group_id"], "domain_id": 2}, {"group_id": HOST}):
        with pytest.raises(AgentError):
            groups.create_token(cur, {"max_uses": 1, **body}, actor="session:1")


def test_pending_then_key_bound_approval_and_idempotent_decision(batch):
    cur, token, _, body = batch
    pending = deployment.list_pending(cur, body["filter"], actor="session:1")
    assert len(pending["items"]) == 1 and not pending["has_more"]
    first = deployment.approve(cur, body, actor="session:1")["items"][0]
    assert first["status"] == "approved" and not cur.agents and not cur.certificates
    assert cur.groups[token["id"]]["uses_count"] == 1
    assert first["token"] not in repr(cur.calls) and first["token"] not in repr(cur.audits)
    repeated = deployment.approve(cur, body, actor="session:1")["items"][0]
    assert repeated["status"] == "already_approved" and "token" not in repeated
    assert len(cur.tokens) == 1
    assert not deployment.list_pending(cur, body["filter"], actor="session:1")["items"]


@pytest.mark.parametrize("change,reason", [("key", "key_identity_unverified"), ("host", "key_identity_unverified"),
    ("instance", "key_identity_unverified"), ("computer", "key_identity_unverified"),
    ("scope", "directory_scope_rejected"), ("disabled", "directory_scope_rejected"),
    ("expired", "batch_unavailable"), ("revoked", "batch_unavailable"),
    ("lock_wait", "batch_unavailable"), ("conflict", "host_conflict_or_expired"),
    ("unknown_request", "request_not_pending")])
def test_denials_remain_pending_and_audited(batch, monkeypatch, change, reason):
    cur, token, _, body = batch
    if change in ("key", "host", "instance", "computer", "unknown_request"):
        field, value = {"key": ("key_fingerprint", "f" * 64), "host": ("host_id", str(UUID(int=2))),
            "instance": ("instance_name", "other"), "computer": ("computer_entity_id", 4),
            "unknown_request": ("request_id", str(UUID(int=3)))}[change]
        body["evidence"][0][field] = value
    elif change == "scope":
        cur.directory[(3, 1)]["record"] = directory_record(dn="CN=Fixture,OU=Other,DC=example,DC=test")
    elif change == "disabled":
        cur.directory[(3, 1)]["record"]["attributes"]["enabled"] = False
    elif change == "expired":
        cur.groups[token["id"]]["expires_at"] = utcnow() - timedelta(seconds=1)
    elif change == "revoked":
        groups.revoke_token(cur, token["id"], actor="session:1")
        reason = "request_not_pending"
    elif change == "lock_wait":
        cur.expire_on_host_lock = True
        expiry = cur.groups[token["id"]]["expires_at"]
        monkeypatch.setattr(deployment, "utcnow", lambda: expiry if cur.waited else utcnow())
    elif change == "conflict":
        cur.agents[HOST] = dict(id=HOST, host_id=HOST)
    result = deployment.approve(cur, body, actor="session:1")["items"][0]
    assert result == {"request_id": body["evidence"][0]["request_id"], "status": "rejected", "reason": reason}
    assert not cur.tokens and not cur.approvals
    assert cur.audits[-2]["details"]["reason"] == reason


@pytest.mark.parametrize("change", ["empty", "duplicate", "oversized", "extra", "boolean", "bad_key", "bad_filter", "wrong_group"])
def test_invalid_batch_contract_is_rejected_before_writes(batch, change):
    cur, _, _, body = batch
    before = deepcopy(cur.audits)
    if change == "empty":
        body["evidence"] = []
    elif change in ("duplicate", "oversized"):
        body["evidence"] *= 2 if change == "duplicate" else 1001
    elif change == "extra":
        body["evidence"][0]["auto_approve"] = True
    elif change == "boolean":
        body["evidence"][0]["computer_entity_id"] = True
    elif change == "bad_key":
        body["evidence"][0]["key_fingerprint"] = "invalid"
    elif change == "bad_filter":
        body["filter"]["status"] = "active"
    else:
        body["filter"]["group_id"] = HOST
    with pytest.raises(AgentError):
        deployment.approve(cur, body, actor="session:1")
    assert not cur.tokens and cur.audits == before


def test_1000_requests_one_action_and_each_decision_audited(batch):
    cur, token, _, body = batch
    prototype = deepcopy(next(iter(cur.requests.values())))
    cur.requests.clear()
    body["evidence"] = []
    for index in range(1, 1001):
        request_id, host = str(UUID(int=index)), str(UUID(int=index + 1000))
        row = {**prototype, "id": request_id, "host_id": host, "key_fingerprint": format(index, "064x")}
        cur.requests[request_id] = row
        body["evidence"].append({"request_id": request_id, **{key: row[key] for key in
            ("host_id", "instance_name", "key_fingerprint", "computer_entity_id")}})
    cur.groups[token["id"]]["uses_count"] = 1000
    result = deployment.approve(cur, body, actor="session:1")
    assert len(result["items"]) == len(cur.tokens) == len(cur.approvals) == 1000
    assert all(item["status"] == "approved" for item in result["items"])
    assert len([item for item in cur.audits if item["action"] == "group_approval"]) == 1000
    assert cur.audits[-1]["details"]["approved"] == 1000
    assert cur.groups[token["id"]]["uses_count"] == 1000
    assert not cur.agents and not cur.certificates


def test_filtered_approval_keeps_other_batches_and_rejected_requests_pending(batch):
    cur, token, _, body = batch
    original = deepcopy(next(iter(cur.requests.values())))
    other = groups.create_token(cur, {"group_id": token["group_id"], "max_uses": 1}, actor="session:1")
    wrong_batch = {**original, "id": str(UUID(int=100)), "token_id": other["id"]}
    mismatch = {**original, "id": str(UUID(int=101)), "host_id": str(UUID(int=102))}
    cur.requests[wrong_batch["id"]] = wrong_batch
    cur.requests[mismatch["id"]] = mismatch
    for row in (wrong_batch, mismatch):
        evidence = {"request_id": row["id"], **{key: row[key] for key in
            ("host_id", "instance_name", "key_fingerprint", "computer_entity_id")}}
        if row is mismatch:
            evidence["key_fingerprint"] = "f" * 64
        body["evidence"].append(evidence)
    result = deployment.approve(cur, body, actor="session:1")
    assert sum(item["status"] == "approved" for item in result["items"]) == 1
    assert sum(item["status"] == "rejected" for item in result["items"]) == 2
    assert cur.requests[wrong_batch["id"]]["status"] == cur.requests[mismatch["id"]]["status"] == "pending"
    assert len(cur.tokens) == len(cur.approvals) == 1


def test_pending_list_is_bounded_and_reports_more(batch):
    cur, _, _, body = batch
    prototype = deepcopy(next(iter(cur.requests.values())))
    cur.requests = {str(UUID(int=index)): {**prototype, "id": str(UUID(int=index))} for index in range(1, 1002)}
    result = deployment.list_pending(cur, body["filter"], actor="session:1")
    assert len(result["items"]) == 1000 and result["has_more"]


def test_approved_key_enrolls_and_membership_is_preserved_after_token_revoke(batch, lifecycle):
    cur, token, submission, body = batch
    authority = lifecycle[1]
    approved = deployment.approve(cur, body, actor="session:1")["items"][0]
    with pytest.raises(AgentError, match="agent_csr_key_mismatch"):
        registry.enroll(cur, authority, {"token": approved["token"], "csr_pem": request(ec.generate_private_key(ec.SECP256R1()))})
    result = registry.enroll(cur, authority, {"token": approved["token"], "csr_pem": submission["csr_pem"]})
    assert cur.members[result["agent_id"]] == token["group_id"]
    groups.revoke_token(cur, token["id"], actor="session:1")
    assert len(cur.agents) == len(cur.certificates) == 1
    assert all(not cert["revoked_at"] for cert in cur.certificates.values())
    assert cur.requests[body["evidence"][0]["request_id"]]["status"] == "approved"


@pytest.mark.parametrize("withdrawal", ["revoke", "expired"])
def test_withdrawal_after_approval_blocks_certificate_issue(batch, lifecycle, withdrawal):
    cur, token, submission, body = batch
    approved = deployment.approve(cur, body, actor="session:1")["items"][0]
    if withdrawal == "revoke":
        groups.revoke_token(cur, token["id"], actor="session:1")
        assert all(item["revoked_at"] for item in cur.tokens.values())
        assert cur.requests[body["evidence"][0]["request_id"]]["status"] == "cancelled"
    else:
        cur.groups[token["id"]]["expires_at"] = utcnow() - timedelta(seconds=1)
    with pytest.raises(AgentError, match="enrollment_token_rejected"):
        registry.enroll(cur, lifecycle[1], {"token": approved["token"], "csr_pem": submission["csr_pem"]})
    assert not cur.agents and not cur.certificates and not cur.members
