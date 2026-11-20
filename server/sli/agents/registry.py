"""Transactional enrollment. Callers commit before returning secrets/certificates."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import timedelta
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from server.sli.agents.agent_names import reported_hostname
from server.sli.agents.ca import AgentError, fingerprint, parse_csr, utcnow, uuid_text


def audit(cur, action: str, actor: str, target: str, **details):
    import json
    cur.execute("insert into sli_agent_audit(action,actor,target,details) values(%s,%s,%s,%s::jsonb)",
        (action, actor, target, json.dumps(details)))


def token_hash(token) -> str:
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise AgentError("enrollment_token_rejected", 401)
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def instance_name(value):
    if value is not None and (not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,47}", value)):
        raise AgentError("invalid_agent_instance_name")
    return value


def create_token(cur, body: dict, *, actor: str) -> dict:
    host_id = uuid_text(body.get("host_id"))
    replacement_for = uuid_text(body["replacement_for"]) if "replacement_for" in body else None
    if replacement_for:
        cur.execute("select id from sli_agents where id=%s and status='active' for update", (replacement_for,))
        if not cur.fetchone():
            raise AgentError("agent_not_found", 404)
    instance = instance_name(body.get("instance_name"))
    key_fp = body.get("key_fingerprint")
    ttl = body.get("ttl_seconds", 900)
    approved_name = body.get("registration_host_name")
    if approved_name is not None and reported_hostname(approved_name) is None:
        raise AgentError("invalid_agent_registration_name")
    if not isinstance(key_fp, str) or not re.fullmatch(r"[0-9a-f]{64}", key_fp):
        raise AgentError("invalid_key_fingerprint")
    if type(ttl) is not int or not 60 <= ttl <= 3600:
        raise AgentError("invalid_enrollment_ttl")
    raw = secrets.token_urlsafe(32)
    token_id = str(uuid4())
    now = utcnow()
    expires = now + timedelta(seconds=ttl)
    cur.execute("insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at,instance_name,replacement_for) values(%s,%s,%s,%s,%s,%s,%s,%s)",
        (token_id, token_hash(raw), host_id, key_fp, now, expires, instance, replacement_for))
    audit(cur, "token_create", actor, token_id, ttl_seconds=ttl, instance_name=instance,
          **({"replacement_for": replacement_for} if replacement_for else {}),
          **({"registration_host_name": approved_name.lower()} if approved_name else {}))
    return {"id": token_id, "token": raw, "host_id": host_id, "expires_at": expires.isoformat(), "instance_name": instance}


def list_tokens(cur, *, actor: str):
    cur.execute("select id,host_id,key_fingerprint,created_at,expires_at,used_at,revoked_at,instance_name from sli_agent_enrollment_tokens order by created_at desc,id limit 100")
    items = [dict(row) for row in cur.fetchall()]
    audit(cur, "token_list", actor, "tokens")
    return {"items": items}


def revoke_token(cur, value, *, actor: str):
    token_id = uuid_text(value)
    cur.execute("update sli_agent_enrollment_tokens set revoked_at=coalesce(revoked_at,clock_timestamp()) where id=%s returning id", (token_id,))
    if not cur.fetchone():
        raise AgentError("enrollment_token_not_found", 404)
    audit(cur, "token_revoke", actor, token_id)
    return {"status": "revoked"}


def _store_cert(cur, cert, agent_id):
    serial = format(cert.serial_number, "x")
    cur.execute("insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after) values(%s,%s,%s,%s,%s)",
        (agent_id, serial, cert.fingerprint(hashes.SHA256()).hex(), cert.not_valid_before_utc, cert.not_valid_after_utc))
    return serial


def _certificate_response(ca, cert, agent_id):
    return {"agent_id": agent_id, "serial": format(cert.serial_number, "x"),
        "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "ca_chain_pem": ca.chain_pem(), "expires_at": cert.not_valid_after_utc.isoformat()}


def _registration_scope(cur, ca, host_name, instance):
    # Scope comes from the trusted issuing CA, never from a client field. Store
    # it in the immutable issuance audit; legacy rows without proof are not
    # eligible for automatic revocation on an unverified display name alone.
    scope = ca.root.fingerprint(hashes.SHA256()).hex()
    if host_name:
        cur.execute("select pg_advisory_xact_lock(hashtext(%s))",
                    (f"sli-agent-registration:{scope}:{host_name.lower()}:{instance or ''}",))
    return scope


def _replace_registration(cur, agent_id, host_name, instance, scope, *, actor):
    if not host_name:
        return
    cur.execute("""select a.id from sli_agents a
        where a.id<>%s and a.status='active' and lower(a.registration_host_name)=lower(%s)
          and a.instance_name is not distinct from %s
          and exists (select 1 from sli_agent_audit issued where issued.target=a.id::text
            and issued.action='issue' and issued.details->>'registration_ca_sha256'=%s)
        order by a.id for update of a""", (agent_id, host_name, instance, scope))
    for row in cur.fetchall():
        revoke(cur, {"agent_id": str(row["id"])}, actor=actor, disable=True,
               reason="registration_replaced")


def enroll(cur, ca, body: dict):
    digest = token_hash(body.get("token"))
    from server.sli.agents.group_deployment import lock_approval, record_membership
    lock_approval(cur, digest)
    cur.execute("select * from sli_agent_enrollment_tokens where token_hash=%s for update", (digest,))
    token = cur.fetchone()
    if not token or token["used_at"] or token["revoked_at"] or token["expires_at"] <= utcnow():
        raise AgentError("enrollment_token_rejected", 401)
    host_id = str(token["host_id"])
    instance = instance_name(token.get("instance_name"))
    # The request can confirm an approval, never introduce or rename it.
    if instance_name(body.get("instance_name")) != instance:
        raise AgentError("agent_instance_name_mismatch")
    csr = parse_csr(body.get("csr_pem"), host_id)
    if not secrets.compare_digest(fingerprint(csr.public_key()), token["key_fingerprint"]):
        raise AgentError("agent_csr_key_mismatch")
    host_name = reported_hostname(body.get("reported_hostname"))
    # Only the administrator issuing the key-bound token can authorize replacement
    # of a name. A client's display claim and a shared CA grant no such authority.
    cur.execute("select details->>'registration_host_name' as approved_name from sli_agent_audit "
                "where target=%s and action='token_create' order by id desc limit 1", (str(token["id"]),))
    approval = cur.fetchone()
    approved_name = approval["approved_name"] if approval else None
    replacement_for = token["replacement_for"]
    if approved_name and (not host_name or approved_name != host_name.lower()):
        raise AgentError("agent_registration_name_mismatch")
    scope = _registration_scope(cur, ca, host_name, instance)
    role = body.get("machine_role", "workstation")
    if role not in ("workstation", "domain_controller"):
        raise AgentError("invalid_agent_module_config")
    # Serialize independent tokens for the same host without exposing a DB error.
    cur.execute("select pg_advisory_xact_lock(hashtext(%s))", ("sli-agent-host:" + host_id,))
    if instance is None:
        cur.execute("select id from sli_agents where host_id=%s", (host_id,))
    else:
        cur.execute("select id from sli_agents where host_id=%s and (instance_name=%s or key_fingerprint=%s)",
                    (host_id, instance, token["key_fingerprint"]))
    if cur.fetchone():
        raise AgentError("agent_host_already_enrolled", 409)
    if token["expires_at"] <= utcnow():
        raise AgentError("enrollment_token_rejected", 401)
    agent_id = str(uuid4())
    cert = ca.issue(csr, agent_id, host_id)
    from sli_agent.control import collection_policy
    control = collection_policy({"manage_windows_audit": True})
    if replacement_for:
        control["state"] = "drain"
    cur.execute("insert into sli_agents(id,host_id,key_fingerprint,instance_name,registration_host_name,collection_policy) values(%s,%s,%s,%s,%s,%s::jsonb)",
                (agent_id, host_id, token["key_fingerprint"], instance, host_name, json.dumps(control)))
    from server.sli.agents.onboarding import copy_policy
    if not replacement_for and not copy_policy(cur, token["id"], agent_id):
        # A role selects local readers only; it grants no directory/domain scope.
        # Use the normal revisioned assignment path, including the DC binding
        # issuer's staged-history fence. Explicit portable templates win above.
        module = "sli.workstations" if role == "workstation" else "sli.windows.ad-dc"
        config = {}
        if role == "domain_controller":
            name = reported_hostname(body.get("reported_hostname")) or host_id
            name = name if len(name) <= 128 else host_id
            config = {"source_name": name, "connect_address": name}
        assign_module(cur, {"agent_id": agent_id, "module_id": module, "enabled": True, "config": config},
                      actor="enrollment:" + str(token["id"]))
    serial = _store_cert(cur, cert, agent_id)
    actor = "enrollment:" + str(token["id"])
    if approved_name and not replacement_for:
        _replace_registration(cur, agent_id, host_name, instance, scope, actor=actor)
    cur.execute("update sli_agent_enrollment_tokens set used_at=clock_timestamp(),enrolled_agent_id=%s where id=%s", (agent_id, token["id"]))
    record_membership(cur, token["id"], agent_id)
    audit(cur, "issue", actor, agent_id, serial=serial, registration_ca_sha256=scope)
    return _certificate_response(ca, cert, agent_id)


def authenticate(cur, ca, der: bytes, *, removal_only=False, lifecycle=False):
    cert = ca.verify_client(der)
    # Agent -> certificate order is shared with disable and renewal. Transport
    # stays serialized, but does not exclude a snapshot lifecycle reader.
    # Desired-policy/disable/renew writers must retain their FOR UPDATE fence.
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(names) != 1:
        raise AgentError("agent_certificate_rejected", 401)
    try:
        agent_id = uuid_text(names[0].value)
    except AgentError:
        raise AgentError("agent_certificate_rejected", 401) from None
    lock = "for update" if lifecycle else "for no key update"
    cur.execute("select * from sli_agents where id=%s " + lock, (agent_id,))
    agent = cur.fetchone()
    if not agent or (agent["status"] != "active" and not removal_only):
        raise AgentError("agent_certificate_rejected", 401)
    expected = ["urn:sli:agent:" + agent_id, "urn:sli:host:" + str(agent["host_id"])]
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if list(san) != [x509.UniformResourceIdentifier(uri) for uri in expected]:
            raise ValueError()
    except (ValueError, x509.ExtensionNotFound):
        raise AgentError("agent_certificate_rejected", 401) from None
    cur.execute("select * from sli_agent_certificates where agent_id=%s and serial=%s for update", (agent_id, format(cert.serial_number, "x")))
    row = cur.fetchone()
    if not row or (row["revoked_at"] and not removal_only) or row["not_after"] <= utcnow() or not secrets.compare_digest(row["fingerprint"], cert.fingerprint(hashes.SHA256()).hex()):
        raise AgentError("agent_certificate_rejected", 401)
    if removal_only:
        from server.sli.agents.removal import pending
        removal = pending(cur, agent_id)
        # A key already revoked before the command must never regain authority.
        if (agent["status"] != "disabled" or not removal or not row["revoked_at"]
                or row["revoked_at"] < removal["requested_at"]):
            raise AgentError("agent_certificate_rejected", 401)
    cur.execute("update sli_agents set last_seen=clock_timestamp() where id=%s", (agent_id,))
    return dict(agent)


def renew(cur, ca, der: bytes, body: dict):
    agent = authenticate(cur, ca, der, lifecycle=True)
    agent_id = str(agent["id"])
    csr = parse_csr(body.get("csr_pem"), str(agent["host_id"]))
    cert = ca.issue(csr, agent_id, str(agent["host_id"]))
    serial = _store_cert(cur, cert, agent_id)
    cur.execute("update sli_agents set key_fingerprint=%s where id=%s", (fingerprint(csr.public_key()), agent_id))
    audit(cur, "renew", "agent:" + agent_id, agent_id, serial=serial)
    return _certificate_response(ca, cert, agent_id)


def revoke(cur, body: dict, *, actor: str, disable: bool = False, reason=None):
    agent_id = uuid_text(body.get("agent_id"))
    serial = body.get("serial")
    if not disable and (not isinstance(serial, str) or not re.fullmatch(r"[0-9a-f]{1,40}", serial)):
        raise AgentError("invalid_agent_serial")
    cur.execute("select id from sli_agents where id=%s for update", (agent_id,))
    if not cur.fetchone():
        raise AgentError("agent_not_found", 404)
    # Serialize revocation feed IDs through commit, including different agents.
    cur.execute("select pg_advisory_xact_lock(hashtext('sli-agent-revocations'))")
    if disable:
        cur.execute("update sli_agents set status='disabled' where id=%s", (agent_id,))
        cur.execute("update sli_agent_certificates set revoked_at=clock_timestamp() where agent_id=%s and revoked_at is null returning serial", (agent_id,))
    else:
        cur.execute("update sli_agent_certificates set revoked_at=coalesce(revoked_at,clock_timestamp()) where agent_id=%s and serial=%s returning serial", (agent_id, serial))
    revoked = cur.fetchall()
    if not disable and not revoked:
        raise AgentError("agent_certificate_not_found", 404)
    for row in revoked:
        audit(cur, "revoke", actor, agent_id, serial=row["serial"])
    if disable:
        audit(cur, "disable", actor, agent_id, **({"reason": reason} if reason else {}))
    return {"status": "disabled" if disable else "revoked"}


def list_agents(cur, *, actor: str, agent_id=None):
    # Apply visibility before LIMIT so orphan rows cannot crowd out working agents.
    # Exact-ID readback retains registration/removal evidence for administrators.
    clause = " where id=%s" if agent_id is not None else """ where status<>'replaced' and
        not (last_seen is null and created_at <= clock_timestamp() - interval '24 hours')
        and not exists (select 1 from sli_agent_removals r where r.agent_id=sli_agents.id)
        and not exists (select 1 from sli_agent_audit retired where retired.target=sli_agents.id::text
            and retired.action='disable' and retired.details->>'reason'='registration_replaced')"""
    params = (uuid_text(agent_id),) if agent_id is not None else ()
    cur.execute("select id,host_id,key_fingerprint,status,assigned_modules,last_seen,created_at,instance_name,policy_revision,applied_policy_revision,rights_probe,collection_policy,applied_collection_state,windows_audit from sli_agents" + clause + " order by created_at desc,id limit 100", params)
    agents = [dict(row) for row in cur.fetchall()]
    from server.sli.agents.agent_names import read_agent_name_details
    names = read_agent_name_details(cur, [agent["id"] for agent in agents])
    for agent in agents:
        name = names.get(str(agent["id"]), {"name": None, "source": "unknown"})
        agent["host_name"], agent["host_name_source"] = name["name"], name["source"]
        cur.execute("select b.password_detection_domain_id as domain_id,d.fqdn as domain_fqdn "
                    "from public.sli_agent_module_bindings b left join public.domains d on d.id=b.password_detection_domain_id "
                    "where b.agent_id=%s and b.module_id='sli.windows.ad-dc'", (agent["id"],))
        domain = cur.fetchone()
        agent["password_detection_domain"] = {"status": "configured" if domain and domain["domain_id"] is not None else "unconfigured",
            "domain_id": domain["domain_id"] if domain else None, "domain_fqdn": domain["domain_fqdn"] if domain else None}
        agent["rights_probe"] = dict(agent["rights_probe"])
        agent["eventlog_diagnostics"] = agent["rights_probe"].pop("eventlog_diagnostics", None)
        agent["delivery_diagnostics"] = agent["rights_probe"].pop("delivery_diagnostics", None)
        from server.sli.agents.removal import visibility
        agent["removal"] = visibility(cur, agent)
        cur.execute("select details->>'reason' as reason from sli_agent_audit "
                    "where target=%s and action='disable' order by id desc limit 1", (str(agent["id"]),))
        retired = cur.fetchone()
        agent["inventory_hidden_reason"] = (
            "administrator_removed" if agent["removal"] else
            "registration_replaced" if retired and retired["reason"] == "registration_replaced" else
            "never_seen_expired" if agent["last_seen"] is None and agent["created_at"] <= utcnow() - timedelta(hours=24)
            else None)
        cur.execute("select serial,not_after,revoked_at from sli_agent_certificates where agent_id=%s order by id desc limit 100", (agent["id"],))
        agent["certificates"] = [dict(row) for row in cur.fetchall()]
        cur.execute("select id,action,actor,occurred_at,details from sli_agent_audit where target=%s and action in ('module_assign','policy_update','policy_ack') order by id desc limit 20", (str(agent["id"]),))
        agent["policy_audit"] = [dict(row) for row in cur.fetchall()]
    audit(cur, "agent_list", actor, "agents")
    return {"items": agents}


def assign_module(cur, body: dict, *, actor: str):
    from server.sli.agents.policies import assign_module as assign_policy
    return assign_policy(cur, body, actor=actor)


def revocations(cur, after: int):
    if type(after) is not int or not 0 <= after <= 2**63 - 1:
        raise AgentError("invalid_revocation_cursor")
    cur.execute("select pg_advisory_xact_lock(hashtext('sli-agent-revocations'))")
    # IDs cannot paginate mutable revocation timestamps: an old cert can be
    # revoked after a newer one. The append-only audit ID is the feed cursor.
    cur.execute("select id,target as agent_id,details->>'serial' as serial,occurred_at as revoked_at from sli_agent_audit where action='revoke' and id>%s order by id limit 500", (after,))
    items = [dict(row) for row in cur.fetchall()]
    return {"items": items, "next_cursor": items[-1]["id"] if items else after}
