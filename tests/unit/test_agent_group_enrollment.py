"""Pending-only admission with cursor fakes; no database or source contact."""
from copy import deepcopy
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents import group_enrollment as groups, registry
from server.sli.agents.ca import AgentError, utcnow
from tests.unit.test_agent_registry import Cursor, HOST, request


def directory_record(*, ou=False, dn=None):
    return {"identity": {"kind": "security_principal" if ou else "ad_computer"},
        "attributes": {"enabled": True, "infrastructure_role": "organizational_unit" if ou else None,
            "distinguished_name": dn or ("OU=Fixture,DC=example,DC=test" if ou else "CN=Fixture,OU=Fixture,DC=example,DC=test")}}


class GroupCursor(Cursor):
    def __init__(self):
        super().__init__()
        self.groups, self.requests = {}, {}
        self.enrollment_groups = {}
        self.directory = {(2, 1): {"version_id": 20, "record": directory_record(ou=True)},
                          (3, 1): {"version_id": 30, "record": directory_record()}}
        self.expire_on_update = False

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        self.rows = []
        if sql.startswith("select v.id as version_id"):
            found = self.directory.get(tuple(params[:2]))
            self.rows = [found] if found else []
        elif sql.startswith("insert into sli_agent_enrollment_groups"):
            group_id, domain, ous = params
            self.enrollment_groups[group_id] = dict(id=group_id, domain_id=domain, ou_entity_ids=ous)
        elif sql.startswith("select * from sli_agent_enrollment_groups"):
            self.rows = [self.enrollment_groups[params[0]]] if params[0] in self.enrollment_groups else []
        elif sql.startswith("insert into sli_agent_group_tokens"):
            token_id, digest, created, expires, maximum, domain, ous, group_id, selected, policy = params
            import json
            self.groups[token_id] = dict(id=token_id, token_hash=digest, created_at=created, expires_at=expires,
                max_uses=maximum, uses_count=0, domain_id=domain, ou_entity_ids=ous, revoked_at=None, group_id=group_id,
                computer_entity_ids=selected, enrollment_policy=json.loads(policy))
        elif sql.startswith("select * from sli_agent_group_tokens"):
            self.rows = [t for t in self.groups.values() if t["token_hash"] == params[0]]
        elif sql.startswith("select id,created_at,expires_at"):
            self.rows = [{k: v for k, v in t.items() if k != "token_hash"} for t in self.groups.values()]
        elif sql.startswith("select id,host_id,computer_entity_id"):
            self.rows = [r for r in self.requests.values() if (r["token_id"], r["key_fingerprint"], r["instance_name"]) == params]
        elif sql.startswith("update sli_agent_group_tokens"):
            token = self.groups.get(params[0])
            if token and "set revoked_at=" in sql:
                token["revoked_at"] = token["revoked_at"] or utcnow()
                self.rows = [dict(id=token["id"])]
            elif token and not self.expire_on_update and not token["revoked_at"] and token["expires_at"] > utcnow() and token["uses_count"] < token["max_uses"]:
                token["uses_count"] += 1
                self.rows = [dict(id=token["id"])]
        elif sql.startswith("insert into sli_agent_group_requests"):
            request_id, token_id, host, instance, key_fp, computer, version = params
            self.requests[request_id] = dict(id=request_id, token_id=token_id, host_id=host, instance_name=instance,
                key_fingerprint=key_fp, computer_entity_id=computer, computer_version_id=version, status="pending")
        elif sql.startswith(("update sli_agent_group_requests r", "update sli_agent_enrollment_tokens e")):
            return
        elif sql.startswith("update sli_agent_group_requests"):
            for row in self.requests.values():
                if row["token_id"] == params[0]:
                    row["status"] = "cancelled"
        else:
            self.calls.pop()
            super().execute(sql, params)


@pytest.fixture
def admission():
    cur = GroupCursor()
    token = groups.create_token(cur, {"max_uses": 1, "domain_id": 1, "ou_entity_ids": [2]}, actor="session:1")
    key = ec.generate_private_key(ec.SECP256R1())
    body = {"token": token["token"], "host_id": HOST, "computer_entity_id": 3, "csr_pem": request(key)}
    return cur, token, body


def test_hash_only_pending_only_and_replay_at_capacity(admission):
    cur, token, body = admission
    first = groups.submit(cur, body)
    assert first == groups.submit(cur, body)
    assert first["status"] == "pending"
    assert cur.groups[token["id"]]["uses_count"] == 1
    assert cur.requests[first["request_id"]]["computer_version_id"] == 30
    assert not cur.agents and not cur.certificates
    assert cur.groups[token["id"]]["token_hash"] == registry.token_hash(token["token"])
    listed = groups.list_tokens(cur, actor="session:1")
    assert "token_hash" not in repr(listed) and token["token"] not in repr(cur.audits)
    assert all(a["actor"] and a["details"]["result"] for a in cur.audits)


def test_capacity_rejects_a_new_key_and_preserves_audit(admission):
    cur, token, body = admission
    groups.submit(cur, body)
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(groups.AuditedRejection, match="group_enrollment_rejected"):
        groups.submit(cur, {**body, "csr_pem": request(other)})
    assert len(cur.requests) == cur.groups[token["id"]]["uses_count"] == 1
    assert cur.audits[-1]["details"] == {"result": "rejected"}
    assert "for update" in next(sql for sql, _ in cur.calls if sql.startswith("select * from sli_agent_group_tokens"))


@pytest.mark.parametrize("state", ["expires_at", "revoked_at", "expire_on_update"])
def test_ttl_revoke_and_expiry_after_lock_wait(admission, state):
    cur, token, body = admission
    if state == "expire_on_update":
        cur.expire_on_update = True
    else:
        cur.groups[token["id"]][state] = utcnow() - timedelta(seconds=1)
    with pytest.raises(groups.AuditedRejection):
        groups.submit(cur, body)
    assert not cur.requests and cur.groups[token["id"]]["uses_count"] == 0
    assert cur.audits[-1]["details"]["result"] == "rejected"


@pytest.mark.parametrize("change", ["missing", "outside_ou", "wrong_domain", "disabled", "user", "self_report", "bad_csr", "wrong_host", "bad_token"])
def test_server_scope_and_csr_fail_closed_without_consuming(admission, change):
    cur, token, body = admission
    if change == "missing":
        del cur.directory[(3, 1)]
    elif change == "outside_ou":
        cur.directory[(3, 1)]["record"] = directory_record(dn="CN=Fixture,OU=Other,DC=example,DC=test")
    elif change == "wrong_domain":
        cur.directory[(3, 2)] = cur.directory.pop((3, 1))
    elif change == "disabled":
        cur.directory[(3, 1)]["record"]["attributes"]["enabled"] = False
    elif change == "user":
        cur.directory[(3, 1)]["record"]["identity"]["kind"] = "ad_user"
    elif change == "self_report":
        body["domain_id"] = 1
        body["ou_dn"] = "OU=Fixture,DC=example,DC=test"
    elif change == "bad_csr":
        body["csr_pem"] = "fixture"
    elif change == "wrong_host":
        body["host_id"] = "00000000-0000-4000-8000-000000000002"
    else:
        body["token"] = "fixture"
    with pytest.raises(groups.AuditedRejection) as exc:
        groups.submit(cur, body)
    assert exc.value.status == 401
    assert not cur.requests and cur.groups[token["id"]]["uses_count"] == 0
    assert "Fixture" not in repr(cur.audits) and "csr" not in repr(cur.audits)


def test_dn_boundaries_do_not_accept_escaped_ou_suffix(admission):
    cur, _, body = admission
    cur.directory[(3, 1)]["record"] = directory_record(dn=r"CN=Fixture\,OU=Fixture,DC=example,DC=test")
    with pytest.raises(groups.AuditedRejection):
        groups.submit(cur, body)


def test_nested_ou_and_named_instance_are_pending(admission):
    cur, _, body = admission
    cur.directory[(3, 1)]["record"] = directory_record(dn=r"CN=Fixture\,Extra,OU=Nested,OU=Fixture,DC=example,DC=test")
    body["instance_name"] = "workstation"
    result = groups.submit(cur, body)
    assert cur.requests[result["request_id"]]["instance_name"] == "workstation"


@pytest.mark.parametrize("override", [{"ttl_seconds": True}, {"ttl_seconds": 59}, {"ttl_seconds": 604801},
    {"max_uses": True}, {"max_uses": 0}, {"max_uses": 10001}, {"domain_id": True},
    {"ou_entity_ids": [True]}, {"ou_entity_ids": [999]}, {"ou_entity_ids": [2] * 129}, {"auto_approve": True}])
def test_create_validation(override):
    cur = GroupCursor()
    with pytest.raises(AgentError):
        groups.create_token(cur, {"max_uses": 1, "domain_id": 1, "ou_entity_ids": [2], **override}, actor="session:1")
    assert not cur.groups


@pytest.mark.parametrize("ttl,maximum", [(60, 1), (604800, 10000)])
def test_create_accepts_boundary_limits_and_deduplicates_server_ous(ttl, maximum):
    cur = GroupCursor()
    token = groups.create_token(cur, {"ttl_seconds": ttl, "max_uses": maximum,
        "domain_id": 1, "ou_entity_ids": [2, 2]}, actor="session:1")
    stored = cur.groups[token["id"]]
    assert stored["expires_at"] - stored["created_at"] == timedelta(seconds=ttl)
    assert stored["max_uses"] == maximum and stored["ou_entity_ids"] == [2]


@pytest.mark.parametrize("malformed", ["", "CN=", "CN=Fixture,", "CN=Fixture\\"])
def test_malformed_server_dn_fails_closed(admission, malformed):
    cur, token, body = admission
    cur.directory[(3, 1)]["record"]["attributes"]["distinguished_name"] = malformed
    with pytest.raises(groups.AuditedRejection):
        groups.submit(cur, body)
    assert cur.groups[token["id"]]["uses_count"] == 0


def test_revocation_cancels_pending_requests_but_keeps_evidence(admission):
    cur, token, body = admission
    result = groups.submit(cur, body)
    assert groups.revoke_token(cur, token["id"], actor="session:1") == {"status": "revoked"}
    assert cur.requests[result["request_id"]]["status"] == "cancelled"
    assert cur.groups[token["id"]]["uses_count"] == 1
    with pytest.raises(groups.AuditedRejection):
        groups.submit(cur, body)
    assert not cur.agents and not cur.certificates


def test_existing_host_cannot_be_replaced_and_replay_cannot_change_claim(admission):
    cur, token, body = admission
    cur.agents[HOST] = {"id": HOST, "host_id": HOST}
    with pytest.raises(groups.AuditedRejection):
        groups.submit(cur, body)
    assert cur.groups[token["id"]]["uses_count"] == 0
    cur.agents.clear()
    groups.submit(cur, body)
    saved = deepcopy(cur.requests)
    with pytest.raises(groups.AuditedRejection):
        groups.submit(cur, {**body, "computer_entity_id": 4})
    assert cur.requests == saved
