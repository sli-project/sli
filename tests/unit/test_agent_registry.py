"""Registry lifecycle with in-memory cursor fakes; no database connections."""
import json
from copy import deepcopy
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from server.sli.agents import registry
from server.sli.agents.ca import AgentError, IssuingCA, fingerprint, parse_csr, utcnow
from server.sli.agents.provision import create_issuer_request, create_root, sign_issuer

HOST = "00000000-0000-4000-8000-000000000001"


def request(key, host=HOST):
    return (x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())


class Cursor:
    def __init__(self):
        self.tokens, self.agents, self.certificates, self.audits = {}, {}, {}, []
        self.calls = []
        self.rows = []
        self.policy_templates = {}

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        self.rows = []
        if "enrolled.host_name as enrolled_name" in sql:
            self.rows = [dict(agent_id=key, enrolled_name=None, registration_host_name=self.agents[key].get("registration_host_name"), assigned_modules=self.agents[key]["assigned_modules"])
                         for key in params[0] if key in self.agents]
            return
        if sql.startswith("select pg_advisory"):
            return
        if sql.startswith("select r.token_id"):
            return
        if sql.startswith("insert into sli_agent_group_members"):
            return
        if sql.startswith("insert into sli_agent_audit"):
            action, actor, target, details = params
            self.audits.append(dict(id=len(self.audits)+1, action=action, actor=actor, target=target, details=json.loads(details), occurred_at=utcnow()))
        elif sql.startswith("insert into sli_agent_policy_history"):
            return
        elif sql.startswith("select t.* from sli_agent_onboarding_copies"):
            template = self.policy_templates.get(params[0])
            self.rows = [template] if template else []
        elif sql.startswith("insert into sli_agent_enrollment_tokens"):
            columns = sql.partition("(")[2].partition(")")[0].split(",")
            token = dict(zip(columns, params, strict=True))
            self.tokens[token["id"]] = dict(replacement_for=None, enrolled_agent_id=None,
                used_at=None, revoked_at=None) | token
        elif sql.startswith("select * from sli_agent_enrollment_tokens"):
            self.rows = [t for t in self.tokens.values() if t["token_hash"] == params[0]]
        elif sql.startswith("select id,host_id,key_fingerprint,created_at"):
            self.rows = [{k: v for k, v in t.items() if k != "token_hash"} for t in self.tokens.values()]
        elif sql.startswith("update sli_agent_enrollment_tokens"):
            token = self.tokens.get(params[-1])
            if token:
                token["used_at" if "set used_at=" in sql else "revoked_at"] = utcnow()
                if "enrolled_agent_id=" in sql:
                    token["enrolled_agent_id"] = params[0]
                self.rows = [dict(id=token["id"])]
        elif sql.startswith("select id from sli_agents where host_id"):
            self.rows = [a for a in self.agents.values() if a["host_id"] == params[0] and
                         (len(params) == 1 or a["instance_name"] == params[1] or a["key_fingerprint"] == params[2])]
        elif sql.startswith("select a.id from sli_agents a"):
            new_id, name, instance, scope = params
            self.rows = [a for a in self.agents.values() if a["id"] != new_id and a["status"] == "active"
                         and (a.get("registration_host_name") or "").lower() == name.lower()
                         and a["instance_name"] == instance
                         and any(entry["action"] == "issue" and entry["target"] == a["id"]
                                 and entry["details"].get("registration_ca_sha256") == scope for entry in self.audits)]
        elif sql.startswith("insert into sli_agents"):
            agent_id, host_id, key_fp, instance, *reported = params
            self.agents[agent_id] = dict(id=agent_id, host_id=host_id, key_fingerprint=key_fp,
                status="active", assigned_modules=[], last_seen=None, created_at=utcnow(),
                registration_host_name=reported[0] if reported else None,
                instance_name=instance, policy_revision=1, applied_policy_revision=0, rights_probe={},
                collection_policy={"state": "active", "interval_seconds": 60, "batch_size": 32,
                                   "rate_limit_per_minute": 120, "spool_max_bytes": 67108864},
                applied_collection_state="unknown", windows_audit={})
            if len(reported) > 1:
                self.agents[agent_id]["collection_policy"] = json.loads(reported[1])
        elif sql.startswith("insert into sli_agent_certificates"):
            agent_id, serial, fp, start, end = params
            self.certificates[serial] = dict(id=len(self.certificates)+1, agent_id=agent_id, serial=serial,
                fingerprint=fp, not_before=start, not_after=end, revoked_at=None)
        elif sql.startswith("select * from sli_agent_certificates"):
            self.rows = [c for c in self.certificates.values() if c["agent_id"] == params[0] and c["serial"] == params[1]]
        elif sql.startswith(("select * from sli_agents where id=", "select id from sli_agents where id=",
                             "select host_id,status,assigned_modules from sli_agents where id=")):
            if params[0] in self.agents:
                self.rows = [self.agents[params[0]]]
        elif sql.startswith("select id,host_id,key_fingerprint,status"):
            columns = sql.split(" from ")[0].removeprefix("select ").split(",")
            self.rows = [{column: agent[column] for column in columns} for agent in self.agents.values()
                         if (agent["id"] == params[0] if params else
                             not (agent["last_seen"] is None and agent["created_at"] <= utcnow() - timedelta(hours=24))
                             and agent["id"] not in getattr(self, "removals", {})
                             and not any(a["action"] == "disable" and a["target"] == agent["id"]
                                         and a["details"].get("reason") == "registration_replaced" for a in self.audits))]
        elif sql.startswith("select details->>'reason' as reason"):
            self.rows = [{"reason": a["details"].get("reason")} for a in reversed(self.audits)
                         if a["target"] == params[0] and a["action"] == "disable"][:1]
        elif sql.startswith("select details->>'registration_host_name' as approved_name"):
            self.rows = [{"approved_name": a["details"].get("registration_host_name")} for a in reversed(self.audits)
                         if a["target"] == params[0] and a["action"] == "token_create"][:1]
        elif sql == "select b.password_detection_domain_id as domain_id,d.fqdn as domain_fqdn from public.sli_agent_module_bindings b left join public.domains d on d.id=b.password_detection_domain_id where b.agent_id=%s and b.module_id='sli.windows.ad-dc'":
            self.rows = []  # No owner-provisioned domain in these legacy fixtures.
        elif sql.startswith("select operation_id,command_id,state,reason,requested_at,reported_at from sli_agent_removals"):
            return
        elif sql.startswith("select serial,not_after,revoked_at"):
            self.rows = [c for c in self.certificates.values() if c["agent_id"] == params[0]]
        elif sql.startswith("select id,action,actor,occurred_at,details from sli_agent_audit"):
            self.rows = sorted([a for a in self.audits if a["target"] == params[0]
                                and a["action"] in ("module_assign", "policy_update", "policy_ack")],
                               key=lambda row: row["id"], reverse=True)[:20]
        elif sql.startswith("update sli_agents"):
            agent = self.agents[params[-1]]
            if "set last_seen=" in sql:
                agent["last_seen"] = utcnow()
            elif "set status=" in sql:
                agent["status"] = "disabled"
            elif "set assigned_modules=" in sql:
                agent["assigned_modules"] = json.loads(params[0])
                if "collection_policy=" in sql:
                    agent.update(collection_policy=json.loads(params[1]), template_id=params[2],
                                 template_version=params[3], template_sha256=params[4])
                else:
                    agent["policy_revision"] = params[1]
            else:
                agent["key_fingerprint"] = params[0]
        elif sql.startswith("update sli_agent_certificates"):
            for cert in self.certificates.values():
                if cert["agent_id"] != params[0]:
                    continue
                if len(params) == 2 and cert["serial"] != params[1]:
                    continue
                if len(params) == 1 and cert["revoked_at"]:
                    continue
                cert["revoked_at"] = cert["revoked_at"] or utcnow()
                self.rows.append(dict(serial=cert["serial"]))
        elif sql.startswith("select id,target as agent_id"):
            self.rows = [dict(id=a["id"], agent_id=a["target"], serial=a["details"]["serial"], revoked_at=a["occurred_at"])
                for a in self.audits if a["action"] == "revoke" and a["id"] > params[0]][:500]
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return deepcopy(self.rows[0]) if self.rows else None

    def fetchall(self):
        return deepcopy(self.rows)


@pytest.fixture
def lifecycle():
    root_key, root = create_root()
    issuer_key, csr = create_issuer_request()
    authority = IssuingCA(root, sign_issuer(root, root_key, csr), issuer_key)
    key = ec.generate_private_key(ec.SECP256R1())
    cur = Cursor()
    token = registry.create_token(cur, {"host_id": HOST, "key_fingerprint": fingerprint(key.public_key())}, actor="session:1")
    return cur, authority, key, token


def enroll(lifecycle):
    cur, authority, key, token = lifecycle
    response = registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(key)})
    cert = x509.load_pem_x509_certificate(response["certificate_pem"].encode())
    return response, cert.public_bytes(serialization.Encoding.DER)


def test_token_hash_only_and_single_use(lifecycle):
    cur, authority, key, token = lifecycle
    stored = cur.tokens[token["id"]]
    assert stored["token_hash"] == registry.token_hash(token["token"])
    assert token["token"] not in repr(cur.calls)
    assert token["token"] not in repr(cur.audits)
    result, der = enroll(lifecycle)
    assert cur.tokens[token["id"]]["used_at"]
    assert cur.tokens[token["id"]]["enrolled_agent_id"] == result["agent_id"]
    assert registry.authenticate(cur, authority, der)["id"] == result["agent_id"]
    assert cur.agents[result["agent_id"]]["last_seen"]
    with pytest.raises(AgentError, match="enrollment_token_rejected"):
        registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(key)})
    assert len(cur.certificates) == 1
    assert [a["action"] for a in cur.audits] == ["token_create", "module_assign", "issue"]


def test_enrollment_copies_pinned_policy_before_token_consumption(lifecycle):
    cur, _, _, token = lifecycle
    cur.policy_templates[token["id"]] = dict(id=HOST, version=2, policy_sha256="a" * 64,
        assigned_modules=[], collection_policy={"manage_windows_audit": True})
    result, der = enroll(lifecycle)
    agent = registry.authenticate(cur, lifecycle[1], der)
    assert agent["collection_policy"] == {"manage_windows_audit": True}
    assert agent["template_id"] == HOST and agent["template_version"] == 2
    assert agent["policy_revision"] == 1 and agent["applied_policy_revision"] == 0
    copy_index = next(i for i, (sql, _) in enumerate(cur.calls) if sql.startswith("update sli_agents set assigned_modules"))
    consume_index = next(i for i, (sql, _) in enumerate(cur.calls) if sql.startswith("update sli_agent_enrollment_tokens"))
    assert copy_index < consume_index
    assert cur.tokens[token["id"]]["used_at"]
    assert [a["action"] for a in cur.audits][:3] == ["token_create", "template_copy", "issue"]
    assert result["agent_id"] == agent["id"]


@pytest.mark.parametrize("replacement", [False, True])
def test_replacement_authority_comes_from_token_not_audit(lifecycle, replacement):
    cur, authority, key, token = lifecycle
    cur.tokens[token["id"]]["replacement_for"] = HOST if replacement else None
    # Opposite audit claim must neither grant nor remove replacement authority.
    cur.audits[0]["details"]["replacement_for"] = None if replacement else HOST
    result = registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(key)})
    agent = cur.agents[result["agent_id"]]
    assert agent["collection_policy"]["state"] == ("drain" if replacement else "active")
    assert bool(agent["assigned_modules"]) is not replacement
    assert cur.tokens[token["id"]]["enrolled_agent_id"] == result["agent_id"]


@pytest.mark.parametrize("state", ["expires_at", "used_at", "revoked_at"])
def test_expired_used_revoked_token(lifecycle, state):
    cur, authority, key, token = lifecycle
    cur.tokens[token["id"]][state] = utcnow() - timedelta(seconds=1)
    with pytest.raises(AgentError, match="enrollment_token_rejected"):
        registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(key)})
    assert not cur.agents and not cur.certificates


def test_token_expiry_checked_after_lock_wait(lifecycle, monkeypatch):
    cur, authority, key, token = lifecycle
    expiry = cur.tokens[token["id"]]["expires_at"]
    moments = iter([expiry - timedelta(seconds=1), expiry])
    monkeypatch.setattr(registry, "utcnow", lambda: next(moments))
    with pytest.raises(AgentError, match="enrollment_token_rejected"):
        registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(key)})
    assert not cur.agents


@pytest.mark.parametrize("value", [None, "", "not-a-token", "x" * 44, "é" * 43])
def test_token_validation(value):
    with pytest.raises(AgentError, match="enrollment_token_rejected"):
        registry.token_hash(value)


@pytest.mark.parametrize("ttl", [True, 0, 59, 3601, "900"])
def test_token_ttl_validation(lifecycle, ttl):
    cur, authority, key, token = lifecycle
    with pytest.raises(AgentError, match="invalid_enrollment_ttl"):
        registry.create_token(cur, {"host_id": HOST, "key_fingerprint": fingerprint(key.public_key()), "ttl_seconds": ttl}, actor="session:1")
    assert len(cur.tokens) == 1


def test_invalid_csr_does_not_consume_token(lifecycle):
    cur, authority, key, token = lifecycle
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(AgentError, match="agent_csr_key_mismatch"):
        registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(other)})
    assert not cur.tokens[token["id"]]["used_at"]
    enroll(lifecycle)


def test_existing_host_and_token_revoke_and_lists(lifecycle):
    cur, authority, key, token = lifecycle
    enrolled, der = enroll(lifecycle)
    second = registry.create_token(cur, {"host_id": HOST, "key_fingerprint": fingerprint(key.public_key())}, actor="session:1")
    with pytest.raises(AgentError, match="agent_host_already_enrolled"):
        registry.enroll(cur, authority, {"token": second["token"], "csr_pem": request(key)})
    registry.revoke_token(cur, second["id"], actor="session:1")
    assert cur.tokens[second["id"]]["revoked_at"]
    items = registry.list_tokens(cur, actor="session:1")["items"]
    assert all("token_hash" not in t and "token" not in t for t in items)
    assert registry.list_agents(cur, actor="session:1")["items"][0]["certificates"][0]["serial"] == enrolled["serial"]
    assert [a["action"] for a in cur.audits][-3:] == ["token_revoke", "token_list", "agent_list"]


def test_renew_key_rotation_and_explicit_revoke(lifecycle):
    cur, authority, key, token = lifecycle
    original, der = enroll(lifecycle)
    rotated = ec.generate_private_key(ec.SECP384R1())
    renewed = registry.renew(cur, authority, der, {"csr_pem": request(rotated)})
    assert renewed["agent_id"] == original["agent_id"]
    assert renewed["serial"] != original["serial"]
    assert cur.agents[original["agent_id"]]["key_fingerprint"] == fingerprint(rotated.public_key())
    registry.authenticate(cur, authority, der)  # Valid overlap until explicit revoke.
    registry.revoke(cur, {"agent_id": original["agent_id"], "serial": original["serial"]}, actor="session:1")
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        registry.renew(cur, authority, der, {"csr_pem": request(key)})
    new_der = x509.load_pem_x509_certificate(renewed["certificate_pem"].encode()).public_bytes(serialization.Encoding.DER)
    registry.authenticate(cur, authority, new_der)
    assert [a["action"] for a in cur.audits] == ["token_create", "module_assign", "issue", "renew", "revoke"]


def test_disable_revokes_all_certs_and_retains_registry(lifecycle):
    cur, authority, key, token = lifecycle
    initial, der = enroll(lifecycle)
    renewed = registry.renew(cur, authority, der, {"csr_pem": request(key)})
    registry.revoke(cur, {"agent_id": initial["agent_id"]}, actor="session:1", disable=True)
    assert len(cur.certificates) == 2
    assert all(c["revoked_at"] for c in cur.certificates.values())
    assert cur.agents[initial["agent_id"]]["status"] == "disabled"
    for pem in (initial["certificate_pem"], renewed["certificate_pem"]):
        der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
        with pytest.raises(AgentError, match="agent_certificate_rejected"):
            registry.authenticate(cur, authority, der)
    assert [a["action"] for a in cur.audits][-3:] == ["revoke", "revoke", "disable"]


@pytest.mark.parametrize("alter", ["unknown_agent", "unknown_serial", "fingerprint", "expired", "disabled"])
def test_auth_registry_failures(lifecycle, alter):
    cur, authority, key, token = lifecycle
    initial, der = enroll(lifecycle)
    if alter == "unknown_agent":
        cur.agents.clear()
    elif alter == "unknown_serial":
        cur.certificates.clear()
    elif alter == "fingerprint":
        cur.certificates[initial["serial"]]["fingerprint"] = "0" * 64
    elif alter == "expired":
        cur.certificates[initial["serial"]]["not_after"] = utcnow()
    else:
        cur.agents[initial["agent_id"]]["status"] = "disabled"
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        registry.authenticate(cur, authority, der)


def test_revocation_feed_uses_publication_order_for_old_certificates(lifecycle):
    cur, authority, key, token = lifecycle
    original, der = enroll(lifecycle)
    renewed = registry.renew(cur, authority, der, {"csr_pem": request(key)})
    registry.revoke(cur, {"agent_id": original["agent_id"], "serial": renewed["serial"]}, actor="session:1")
    page = registry.revocations(cur, 0)
    registry.revoke(cur, {"agent_id": original["agent_id"], "serial": original["serial"]}, actor="session:1")
    next_page = registry.revocations(cur, page["next_cursor"])
    assert [r["serial"] for r in next_page["items"]] == [original["serial"]]
    assert registry.revocations(cur, next_page["next_cursor"])["items"] == []
    assert all("fingerprint" not in item for item in page["items"])
    lock = "select pg_advisory_xact_lock(hashtext('sli-agent-revocations'))"
    assert sum(sql == lock for sql, _ in cur.calls) == 5


def test_mtls_certificate_host_binding_cannot_change_registry_identity(lifecycle):
    cur, authority, key, token = lifecycle
    original, der = enroll(lifecycle)
    other_host = "00000000-0000-4000-8000-000000000003"
    certificate = authority.issue(parse_csr(request(key, other_host), other_host), original["agent_id"], other_host)
    registry._store_cert(cur, certificate, original["agent_id"])
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        registry.authenticate(cur, authority, certificate.public_bytes(serialization.Encoding.DER))
    with pytest.raises(AgentError, match="agent_csr_subject_mismatch"):
        registry.renew(cur, authority, der, {"csr_pem": request(key, other_host)})
    assert cur.agents[original["agent_id"]]["host_id"] == HOST


def test_issuer_failure_preserves_unused_token(lifecycle, monkeypatch):
    cur, authority, key, token = lifecycle
    def unavailable(*args):
        raise AgentError("agent_ca_unavailable", 503)
    monkeypatch.setattr(authority, "issue", unavailable)
    with pytest.raises(AgentError, match="agent_ca_unavailable"):
        registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(key)})
    assert not cur.tokens[token["id"]]["used_at"]
    assert not cur.agents and not cur.certificates
    assert [a["action"] for a in cur.audits] == ["token_create"]


def named_enroll(cur, authority, name):
    key = ec.generate_private_key(ec.SECP256R1())
    token = registry.create_token(cur, {"host_id": HOST, "key_fingerprint": fingerprint(key.public_key()),
                                      "instance_name": name}, actor="session:1")
    response = registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(key),
                                              "instance_name": name})
    der = x509.load_pem_x509_certificate(response["certificate_pem"].encode()).public_bytes(serialization.Encoding.DER)
    return response, der


def test_owner_approved_instances_share_host_and_remain_independent(lifecycle):
    cur, authority, _, _ = lifecycle
    first, first_der = named_enroll(cur, authority, "dc")
    second, second_der = named_enroll(cur, authority, "workstation")
    assert first["agent_id"] != second["agent_id"]
    assert {a["host_id"] for a in cur.agents.values()} == {HOST}
    assert {a["instance_name"] for a in cur.agents.values()} == {"dc", "workstation"}
    assert len({a["key_fingerprint"] for a in cur.agents.values()}) == 2
    cur.agents[first["agent_id"]]["assigned_modules"] = ["sli.windows-eventlog"]
    assert registry.authenticate(cur, authority, first_der)["assigned_modules"] == ["sli.windows-eventlog"]
    second_policy = registry.authenticate(cur, authority, second_der)["assigned_modules"]
    assert len(second_policy) == 1 and second_policy[0]["module_id"] == "sli.workstations"
    assert {a["instance_name"] for a in registry.list_agents(cur, actor="session:1")["items"]} == {"dc", "workstation"}
    registry.revoke(cur, {"agent_id": first["agent_id"]}, actor="session:1", disable=True)
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        registry.authenticate(cur, authority, first_der)
    assert registry.authenticate(cur, authority, second_der)["id"] == second["agent_id"]
    # Disabled identities reserve their instance name, just like the legacy host.
    with pytest.raises(AgentError, match="agent_host_already_enrolled"):
        named_enroll(cur, authority, "dc")
    assert len(cur.agents) == 2


def test_named_token_can_extend_legacy_host_but_not_reuse_key(lifecycle):
    cur, authority, key, _ = lifecycle
    first, _ = enroll(lifecycle)
    second, _ = named_enroll(cur, authority, "workstation")
    assert first["agent_id"] != second["agent_id"]
    token = registry.create_token(cur, {"host_id": HOST, "key_fingerprint": fingerprint(key.public_key()),
                                      "instance_name": "dc"}, actor="session:1")
    with pytest.raises(AgentError, match="agent_host_already_enrolled"):
        registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(key), "instance_name": "dc"})
    assert cur.tokens[token["id"]]["used_at"] is None


def test_unnamed_token_cannot_extend_named_host(lifecycle):
    cur, authority, key, token = lifecycle
    named_enroll(cur, authority, "dc")
    with pytest.raises(AgentError, match="agent_host_already_enrolled"):
        registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(key)})
    assert cur.tokens[token["id"]]["used_at"] is None


def test_named_instances_keep_policy_revisions_and_probe_state_independent(lifecycle):
    cur, authority, _, _ = lifecycle
    first, _ = named_enroll(cur, authority, "dc")
    second, _ = named_enroll(cur, authority, "workstation")
    assigned = registry.assign_module(cur, {"agent_id": first["agent_id"], "module_id": "sli.workstations",
                                           "enabled": True}, actor="session:1")
    assert assigned["policy_revision"] == 3
    cur.agents[first["agent_id"]]["applied_policy_revision"] = 3
    cur.agents[first["agent_id"]]["rights_probe"] = {"last_result": {"status": "allowed"}}
    items = {item["instance_name"]: item for item in registry.list_agents(cur, actor="session:1")["items"]}
    assert items["dc"]["policy_revision"] == items["dc"]["applied_policy_revision"] == 3
    assert items["dc"]["rights_probe"] == {"last_result": {"status": "allowed"}}
    assert items["workstation"]["id"] == second["agent_id"]
    assert items["workstation"]["policy_revision"] == 2
    assert items["workstation"]["applied_policy_revision"] == 0
    assert items["workstation"]["rights_probe"] == {}
    assert items["workstation"]["assigned_modules"][0]["module_id"] == "sli.workstations"
    assert items["dc"]["collection_policy"] == items["workstation"]["collection_policy"]
    assert items["dc"]["applied_collection_state"] == items["workstation"]["applied_collection_state"] == "unknown"


@pytest.mark.parametrize("approved,claimed", [(None, "dc"), ("dc", None), ("dc", "workstation")])
def test_enrollment_cannot_override_owner_instance_approval(lifecycle, approved, claimed):
    cur, authority, key, _ = lifecycle
    token = registry.create_token(cur, {"host_id": HOST, "key_fingerprint": fingerprint(key.public_key()),
                                      "instance_name": approved}, actor="session:1")
    with pytest.raises(AgentError, match="agent_instance_name_mismatch"):
        registry.enroll(cur, authority, {"token": token["token"], "csr_pem": request(key), "instance_name": claimed})
    assert not cur.agents and not cur.certificates
    assert cur.tokens[token["id"]]["used_at"] is None


@pytest.mark.parametrize("name", ["", "DC", "../dc", "a/b", "a\\b", "a" * 49, "dc ", "é", True, 1])
def test_instance_name_validation_before_token_creation(lifecycle, name):
    cur, _, key, _ = lifecycle
    with pytest.raises(AgentError, match="invalid_agent_instance_name"):
        registry.create_token(cur, {"host_id": HOST, "key_fingerprint": fingerprint(key.public_key()),
                                   "instance_name": name}, actor="session:1")
    assert len(cur.tokens) == 1


def test_owner_workstation_assignment_preserves_other_modules_and_audits_hash(lifecycle):
    cur, _, _, _ = lifecycle
    enrolled, _ = enroll(lifecycle)
    agent_id = enrolled["agent_id"]
    dc_assignment = {"module_id": "sli.windows.ad-dc", "enabled": False, "config": {}}
    cur.agents[agent_id]["assigned_modules"] = ["sli.windows-eventlog", dc_assignment, "sli.workstations"]
    body = {"agent_id": agent_id, "module_id": "sli.workstations", "enabled": True,
            "config": {"deny_process_paths": ["c:/fixture/private/*.exe"]}}
    assigned = registry.assign_module(cur, body, actor="session:1")
    assert assigned["assigned_modules"][0] == "sli.windows-eventlog"
    assert assigned["assigned_modules"][1] == dc_assignment
    assert len(assigned["assigned_modules"]) == 3
    assert assigned["assigned_modules"][2]["enabled"] is True
    assert assigned["policy_revision"] == 3
    assert assigned["assigned_modules"][2]["config"]["policy_revision"] == "3"
    audit = cur.audits[-1]
    assert audit["action"] == "module_assign" and audit["actor"] == "session:1"
    assert audit["details"]["module_id"] == "sli.workstations"
    assert len(audit["details"]["policy_sha256"]) == 64
    assert "private" not in repr(audit)
    body["enabled"] = False
    disabled = registry.assign_module(cur, body, actor="session:1")
    assert disabled["assigned_modules"][2]["enabled"] is False
    assert disabled["policy_revision"] == 4
    assert disabled["assigned_modules"][1] == dc_assignment
    assert cur.agents[agent_id]["status"] == "active"


@pytest.mark.parametrize("override", [{"module_id": "fixture.unknown"}, {"enabled": "true"},
    {"config": {"batch_size": 0}}, {"config": {"unexpected": True}}, {"extra": "fixture"}])
def test_assignment_validation_cannot_mutate_or_audit(lifecycle, override):
    cur, _, _, _ = lifecycle
    enrolled, _ = enroll(lifecycle)
    body = {"agent_id": enrolled["agent_id"], "module_id": "sli.workstations", "enabled": True, **override}
    original = deepcopy(cur.agents)
    audit_count = len(cur.audits)
    with pytest.raises(AgentError):
        registry.assign_module(cur, body, actor="session:1")
    assert cur.agents == original and len(cur.audits) == audit_count


def test_assignment_does_not_reactivate_disabled_agent(lifecycle):
    cur, _, _, _ = lifecycle
    enrolled, _ = enroll(lifecycle)
    agent_id = enrolled["agent_id"]
    cur.agents[agent_id]["status"] = "disabled"
    with pytest.raises(AgentError, match="agent_disabled"):
        registry.assign_module(cur, {"agent_id": agent_id, "module_id": "sli.workstations", "enabled": True}, actor="session:1")


def test_assignment_missing_agent_returns_404():
    with pytest.raises(AgentError) as error:
        registry.assign_module(Cursor(), {"agent_id": HOST, "module_id": "sli.workstations", "enabled": True}, actor="session:1")
    assert error.value.status == 404


def test_nps_assignment_preserves_workstation_policy_and_hashes_private_config(lifecycle):
    from tests.unit.test_sli_agent_nps import CONFIG
    cur, _, _, _ = lifecycle
    enrolled, _ = enroll(lifecycle)
    agent_id = enrolled["agent_id"]
    existing = {"module_id": "sli.workstations", "enabled": True, "config": {}}
    cur.agents[agent_id]["assigned_modules"] = [existing]
    body = {"agent_id": agent_id, "module_id": "sli.vpn-nps", "enabled": True, "config": CONFIG}
    result = registry.assign_module(cur, body, actor="session:1")
    assert result["assigned_modules"][0] == existing
    assert result["assigned_modules"][1]["config"]["families"] == {"nps": True}
    assert result["policy_revision"] == 3
    assert result["assigned_modules"][1]["config"]["policy_revision"] == "3"
    assert cur.audits[-1]["details"]["module_id"] == "sli.vpn-nps"
    assert "fixture-endpoint" not in repr(cur.audits[-1])
    assert len(cur.audits[-1]["details"]["policy_sha256"]) == 64


def test_inventory_exposes_only_this_agents_policy_audit(lifecycle):
    cur, _, _, _ = lifecycle
    enrolled, _ = enroll(lifecycle)
    agent_id = enrolled["agent_id"]
    registry.assign_module(cur, {"agent_id": agent_id, "module_id": "sli.workstations", "enabled": True}, actor="session:1")
    registry.audit(cur, "policy_update", "session:2", "00000000-0000-4000-8000-000000000099", revision=9)
    cur.agents[agent_id]["windows_audit"] = {"policy_revision": 2, "families": {"logons": {"state": "missing"}}}
    item = registry.list_agents(cur, actor="session:1")["items"][0]
    assert item["windows_audit"] == cur.agents[agent_id]["windows_audit"]
    assert [row["action"] for row in item["policy_audit"]] == ["module_assign", "module_assign"]
    assert item["policy_audit"][0]["actor"] == "session:1"
    assert item["policy_audit"][1]["actor"].startswith("enrollment:")
    assert item["policy_audit"][0]["occurred_at"]


def test_inventory_can_open_an_exact_agent_and_validates_identifier(lifecycle):
    cur, _, _, _ = lifecycle
    enrolled, _ = enroll(lifecycle)
    agent_id = enrolled["agent_id"]
    result = registry.list_agents(cur, actor="session:1", agent_id=agent_id)
    assert [item["id"] for item in result["items"]] == [agent_id]
    assert any("from sli_agents where id=%s" in sql and params == (agent_id,) for sql, params in cur.calls)
    assert registry.list_agents(cur, actor="session:1", agent_id="00000000-0000-4000-8000-000000000099")["items"] == []
    with pytest.raises(AgentError):
        registry.list_agents(cur, actor="session:1", agent_id="invalid")


@pytest.mark.parametrize('claim,expected', [('pc.example.invalid','pc.example.invalid'), (None,None), ('bad\nname',None), ({'name':'pc'},None)])
def test_enrollment_hostname_is_initial_display_metadata_not_certificate_identity(lifecycle, claim, expected):
    cur, authority, key, token = lifecycle
    result = registry.enroll(cur, authority, {'token':token['token'], 'csr_pem':request(key), 'reported_hostname':claim})
    agent_id = result['agent_id']
    assert cur.agents[agent_id]['registration_host_name'] == expected
    assert cur.agents[agent_id]['host_id'] == HOST
    cert = x509.load_pem_x509_certificate(result['certificate_pem'].encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert list(san) == [x509.UniformResourceIdentifier('urn:sli:agent:'+agent_id), x509.UniformResourceIdentifier('urn:sli:host:'+HOST)]
    agent = registry.list_agents(cur, actor='session:1')['items'][0]
    assert agent['host_name'] == expected
    assert agent['host_name_source'] == ('agent_reported' if expected else 'unknown')
    registry.renew(cur, authority, cert.public_bytes(serialization.Encoding.DER), {'csr_pem':request(key), 'reported_hostname':'changed.example.invalid'})
    assert cur.agents[agent_id]['registration_host_name'] == expected
    assert not any('registration_host_name' in sql.lower() for sql, _ in cur.calls if sql.startswith('update'))


def test_three_registrations_replace_records_and_revoke_every_old_certificate(lifecycle):
    from uuid import uuid4

    cur, ca, _, _ = lifecycle
    results = []
    for name in ("pc.example.invalid", "PC.example.invalid", "pc.example.invalid"):
        host, key = str(uuid4()), ec.generate_private_key(ec.SECP256R1())
        token = registry.create_token(cur, {"host_id": host, "key_fingerprint": fingerprint(key.public_key()), "registration_host_name": name}, actor="session:1")
        results.append(registry.enroll(cur, ca, {"token": token["token"], "csr_pem": request(key, host), "reported_hostname": name}))
    assert [cur.agents[r["agent_id"]]["status"] for r in results] == ["disabled", "disabled", "active"]
    assert all(a["last_seen"] is None for a in cur.agents.values())
    assert [bool(cur.certificates[r["serial"]]["revoked_at"]) for r in results] == [True, True, False]
    assert [a["id"] for a in registry.list_agents(cur, actor="session:1")["items"]] == [results[-1]["agent_id"]]
    for result in results[:2]:
        der = x509.load_pem_x509_certificate(result["certificate_pem"].encode()).public_bytes(serialization.Encoding.DER)
        with pytest.raises(AgentError, match="agent_certificate_rejected"):
            registry.authenticate(cur, ca, der)
        item = registry.list_agents(cur, actor="session:1", agent_id=result["agent_id"])["items"][0]
        assert item["inventory_hidden_reason"] == "registration_replaced"


@pytest.mark.parametrize("difference", ["ca", "instance", "name", "legacy", "absent_name"])
def test_registration_does_not_retire_other_scope_or_unproven_legacy(lifecycle, difference):
    from uuid import uuid4

    cur, ca, key, token = lifecycle
    first = registry.enroll(cur, ca, {"token": token["token"], "csr_pem": request(key), "reported_hostname": "pc.example.invalid"})
    if difference in ("ca", "legacy"):
        issued = next(a for a in cur.audits if a["action"] == "issue")
        issued["details"]["registration_ca_sha256"] = "0" * 64 if difference == "ca" else None
    host, key = str(uuid4()), ec.generate_private_key(ec.SECP256R1())
    instance = "second" if difference == "instance" else None
    name = None if difference == "absent_name" else "other.example.invalid" if difference == "name" else "pc.example.invalid"
    token = registry.create_token(cur, {"host_id": host, "key_fingerprint": fingerprint(key.public_key()), "instance_name": instance, "registration_host_name": name}, actor="session:1")
    registry.enroll(cur, ca, {"token": token["token"], "csr_pem": request(key, host), "instance_name": instance, "reported_hostname": name})
    assert cur.agents[first["agent_id"]]["status"] == "active"
    assert cur.certificates[first["serial"]]["revoked_at"] is None


def test_never_seen_expiry_hides_only_orphans_and_retains_exact_id_readback(lifecycle):
    cur, _, _, _ = lifecycle
    initial, _ = enroll(lifecycle)
    agent = cur.agents[initial["agent_id"]]
    agent["created_at"] = utcnow() - timedelta(hours=23, minutes=59)
    assert registry.list_agents(cur, actor="session:1")["items"]
    agent["created_at"] = utcnow() - timedelta(hours=24)
    assert registry.list_agents(cur, actor="session:1")["items"] == []
    detail = registry.list_agents(cur, actor="session:1", agent_id=initial["agent_id"])["items"][0]
    assert detail["inventory_hidden_reason"] == "never_seen_expired"
    assert detail["created_at"] == agent["created_at"]
    agent["last_seen"] = utcnow() - timedelta(days=2)
    assert registry.list_agents(cur, actor="session:1")["items"][0]["inventory_hidden_reason"] is None


@pytest.mark.parametrize("approved", [None, "other.example.invalid"])
def test_client_name_cannot_authorize_revocation_or_override_approved_name(lifecycle, approved):
    from uuid import uuid4

    cur, ca, key, token = lifecycle
    first = registry.enroll(cur, ca, {"token": token["token"], "csr_pem": request(key), "reported_hostname": "pc.example.invalid"})
    host, key = str(uuid4()), ec.generate_private_key(ec.SECP256R1())
    token = registry.create_token(cur, {"host_id": host, "key_fingerprint": fingerprint(key.public_key()), "registration_host_name": approved}, actor="session:1")
    body = {"token": token["token"], "csr_pem": request(key, host), "reported_hostname": "pc.example.invalid"}
    if approved:
        with pytest.raises(AgentError, match="agent_registration_name_mismatch"):
            registry.enroll(cur, ca, body)
        assert cur.tokens[token["id"]]["used_at"] is None
    else:
        registry.enroll(cur, ca, body)
    assert cur.agents[first["agent_id"]]["status"] == "active"
    assert cur.certificates[first["serial"]]["revoked_at"] is None


@pytest.mark.parametrize("name", ["", "bad\nname", 123, "localhost"])
def test_token_rejects_invalid_approved_registration_name(lifecycle, name):
    cur, _, key, _ = lifecycle
    with pytest.raises(AgentError, match="invalid_agent_registration_name"):
        registry.create_token(cur, {"host_id": HOST, "key_fingerprint": fingerprint(key.public_key()), "registration_host_name": name}, actor="session:1")
