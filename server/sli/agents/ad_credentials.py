"""Scoped write-only registry for AD passwords; no ambient AD identity fallback.

Account checking remains blocked until the authenticated one-shot agent protocol
is connected. Saving a credential must never be reported as a successful bind.
"""
from __future__ import annotations

import json
import re
from uuid import uuid4

from server.sli.agents.ca import AgentError, uuid_text
from server.sli.agents.group_enrollment import AuditedRejection, _positive_id
from server.sli.core import ad_credential_secrets as secrets
from server.sli.sources.ad_source_credentials import AdCredentialStoreError, validate_username

PUBLIC_FIELDS = ("credential_id", "domain_id", "label", "username", "credential_revision", "created_by",
    "created_at", "updated_by", "updated_at", "check_status", "checked_at")


def _audit(cur, actor, domain, action, *, credential=None, revision=None, result="ok"):
    cur.execute("""insert into sli_ad_credential_audit(actor,domain_id,credential_id,credential_revision,action,result)
        values(%s,%s,%s,%s,%s,%s)""", (actor, domain, credential, revision, action, result))


def _deny(cur, actor, domain=None):
    # Do not retain a guessed foreign domain/credential, even in the audit.
    _audit(cur, actor, None, "denied", result="ad_operations_denied")
    raise AuditedRejection("ad_operations_denied", 403)


def _scopes(cur, actor):
    if not re.fullmatch(r"session:[1-9][0-9]*", actor):
        _deny(cur, actor)
    cur.execute("select public.sli_ad_operations_scopes(%s) as scopes", (actor,))
    scopes = cur.fetchone()["scopes"]
    if not scopes:
        _deny(cur, actor)
    return {scope["domain_id"]: scope["ou_entity_ids"] for scope in scopes}


def _key():
    try:
        return secrets.read_master_key()
    except secrets.AdSecretError as exc:
        raise AgentError(str(exc), 409) from None


def _public(row):
    result = {field: row[field] for field in PUBLIC_FIELDS}
    for field in ("credential_id", "created_at", "updated_at", "checked_at"):
        if result[field] is not None:
            result[field] = str(result[field])
    return {**result, "password_status": "saved", "usages": []}


def list_credentials(cur, *, actor):
    scopes = _scopes(cur, actor)
    cur.execute("select id,fqdn from domains where id=any(%s) order by id", (sorted(scopes),))
    domains = [{"id": row["id"], "fqdn": row["fqdn"]} for row in cur.fetchall()]
    # Select metadata only. Password envelopes never enter a list response.
    cur.execute("""select credential_id,domain_id,ou_entity_ids,label,username,credential_revision,
        created_by,created_at,updated_by,updated_at,check_status,checked_at
        from sli_ad_operation_credentials where domain_id=any(%s) order by created_at,credential_id""", (sorted(scopes),))
    items = [_public(row) for row in cur.fetchall() if set(row["ou_entity_ids"]) <= set(scopes[row["domain_id"]])]
    return {"items": items, "domains": domains, "key_status": secrets.key_status(), "write_enabled": False}


def _request(body, fields):
    if type(body) is not dict or set(body) != set(fields):
        raise AgentError("ad_credential_request_invalid")


def _context(row):
    return {key: str(row[key]) if key.endswith("_id") and key != "domain_id" else row[key]
            for key in ("installation_id", "credential_id", "domain_id", "credential_revision")}


def _encrypted(password, context, key):
    try:
        return json.dumps(secrets.encrypt_password(password, context, key))
    except secrets.AdSecretError as exc:
        raise AgentError(str(exc)) from None


def create(cur, body, *, actor):
    _request(body, ("domain_id", "label", "username", "password"))
    domain = _positive_id(body["domain_id"])
    scopes = _scopes(cur, actor)
    if domain not in scopes:
        _deny(cur, actor)
    label = body["label"]
    if type(label) is not str or not 1 <= len(label.strip()) <= 128 or any(ord(c) < 32 for c in label):
        raise AgentError("ad_credential_request_invalid")
    cur.execute("select fqdn from domains where id=%s", (domain,))
    domain_row = cur.fetchone()
    if not domain_row:
        raise AgentError("ad_credential_request_invalid")
    username = body["username"]
    if type(username) is str and "\\" not in username and "@" not in username:
        username += "@" + domain_row["fqdn"]
    try:
        validate_username(username)
    except AdCredentialStoreError:
        raise AgentError("ad_credential_request_invalid") from None
    key = _key()
    cur.execute("select installation_id from sli_ad_credential_installation where singleton=true")
    installation = cur.fetchone()
    if not installation:
        raise AgentError("ad_credential_installation_unavailable", 409)
    credential = str(uuid4())
    context = {"installation_id": str(installation["installation_id"]), "credential_id": credential,
        "domain_id": domain, "credential_revision": 1}
    envelope = _encrypted(body["password"], context, key)
    cur.execute("""insert into sli_ad_operation_credentials(credential_id,installation_id,domain_id,ou_entity_ids,
        label,username,envelope,created_by,updated_by) values(%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
        returning credential_id,domain_id,label,username,credential_revision,created_by,created_at,
        updated_by,updated_at,check_status,checked_at""",
        (credential, context["installation_id"], domain, sorted(set(scopes[domain])), label.strip(), username, envelope, actor, actor))
    result = _public(cur.fetchone())
    _audit(cur, actor, domain, "created", credential=credential, revision=1)
    return result


def _record(cur, credential, *, actor):
    credential = uuid_text(credential)
    scopes = _scopes(cur, actor)
    cur.execute("select * from sli_ad_operation_credentials where credential_id=%s for update", (credential,))
    row = cur.fetchone()
    if (not row or row["domain_id"] not in scopes
            or not set(row["ou_entity_ids"]) <= set(scopes[row["domain_id"]])):
        _deny(cur, actor)
    return row


def replace_password(cur, body, *, actor):
    _request(body, ("credential_id", "credential_revision", "password"))
    row = _record(cur, body["credential_id"], actor=actor)
    if type(body["credential_revision"]) is not int or body["credential_revision"] != row["credential_revision"]:
        raise AgentError("ad_credential_revision_conflict", 409)
    revision = row["credential_revision"] + 1
    context = {**_context(row), "credential_revision": revision}
    envelope = _encrypted(body["password"], context, _key())
    cur.execute("""update sli_ad_operation_credentials set envelope=%s::jsonb,credential_revision=%s,
        updated_by=%s,updated_at=clock_timestamp(),check_status='not_checked',checked_at=null
        where credential_id=%s returning credential_id,domain_id,label,username,credential_revision,
        created_by,created_at,updated_by,updated_at,check_status,checked_at""",
        (envelope, revision, actor, row["credential_id"]))
    result = _public(cur.fetchone())
    _audit(cur, actor, row["domain_id"], "password_replaced", credential=row["credential_id"], revision=revision)
    return result


def delete(cur, body, *, actor):
    _request(body, ("credential_id", "credential_revision"))
    row = _record(cur, body["credential_id"], actor=actor)
    if type(body["credential_revision"]) is not int or body["credential_revision"] != row["credential_revision"]:
        raise AgentError("ad_credential_revision_conflict", 409)
    # No AD check/plan can currently reference these new records. Future
    # consumers must bind the revision and honor deletion, never cache a secret.
    cur.execute("delete from sli_ad_operation_credentials where credential_id=%s", (row["credential_id"],))
    _audit(cur, actor, row["domain_id"], "deleted", credential=row["credential_id"], revision=row["credential_revision"])
    return {"credential_id": str(row["credential_id"]), "status": "deleted", "write_enabled": False}


def check_read_only(cur, body, *, actor):
    _request(body, ("credential_id", "credential_revision"))
    row = _record(cur, body["credential_id"], actor=actor)
    if type(body["credential_revision"]) is not int or body["credential_revision"] != row["credential_revision"]:
        raise AgentError("ad_credential_revision_conflict", 409)
    _key()
    # Deliberately fail closed. The old service/gMSA preflight is not proof of
    # this account's remote LDAP/SYSVOL access and must never be substituted.
    _audit(cur, actor, row["domain_id"], "check_blocked", credential=row["credential_id"],
        revision=row["credential_revision"], result="ad_check_transport_unavailable")
    raise AuditedRejection("ad_check_transport_unavailable", 409)
