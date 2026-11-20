"""Registry and HTTP boundary tests use cursor/handler fakes only."""
import json
import ssl
from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timezone
from http import HTTPStatus
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from server.api import http_server
from server.api.routes import agents
from server.sli.agents import ad_credentials as subject
from server.sli.agents.ca import AgentError
from server.sli.core import ad_credential_secrets as crypto

ACTOR = "session:1"
INSTALLATION = "10000000-0000-4000-8000-000000000001"
PASSWORD = "synthetic-test-password"
BODY = {"domain_id": 1, "label": "synthetic-one", "username": "fixture", "password": PASSWORD}


class Cursor:
    def __init__(self):
        self.scopes = {1: [2, 3]}
        self.credentials, self.audit, self.calls, self.rows = {}, [], [], []

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        self.calls.append((sql, params))
        self.rows = []
        if sql.startswith("select public.sli_ad_operations_scopes"):
            self.rows = [{"scopes": [{"domain_id": key, "ou_entity_ids": value} for key, value in self.scopes.items()]
                if params[0] == ACTOR else []}]
        elif sql.startswith("select id,fqdn from domains"):
            self.rows = [{"id": key, "fqdn": f"fixture-{key}.invalid"} for key in params[0]]
        elif sql.startswith("select fqdn from domains"):
            self.rows = [{"fqdn": "fixture-1.invalid"}]
        elif sql.startswith("select installation_id"):
            self.rows = [{"installation_id": INSTALLATION}]
        elif sql.startswith("insert into sli_ad_operation_credentials"):
            credential, installation, domain, ous, label, username, envelope, actor, _ = params
            now = datetime.now(timezone.utc)
            row = dict(credential_id=credential, installation_id=installation, domain_id=domain, ou_entity_ids=ous,
                label=label, username=username, envelope=json.loads(envelope), credential_revision=1, created_by=actor,
                updated_by=actor, created_at=now, updated_at=now, check_status="not_checked", checked_at=None)
            self.credentials[credential] = row
            self.rows = [deepcopy(row)]
        elif sql.startswith("select * from sli_ad_operation_credentials"):
            if params[0] in self.credentials:
                self.rows = [deepcopy(self.credentials[params[0]])]
        elif sql.startswith("select credential_id,domain_id"):
            self.rows = [deepcopy(row) for row in self.credentials.values() if row["domain_id"] in params[0]]
        elif sql.startswith("update sli_ad_operation_credentials"):
            envelope, revision, actor, credential = params
            self.credentials[credential].update(envelope=json.loads(envelope), credential_revision=revision,
                updated_by=actor, check_status="not_checked", checked_at=None)
            self.rows = [deepcopy(self.credentials[credential])]
        elif sql.startswith("delete from sli_ad_operation_credentials"):
            del self.credentials[params[0]]
        elif sql.startswith("insert into sli_ad_credential_audit"):
            self.audit.append(params)
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        return self.rows


@pytest.fixture
def key(monkeypatch):
    value = b"k" * 32
    monkeypatch.setattr(crypto, "read_master_key", lambda: value)
    return value


def ref(row):
    return {key: row[key] for key in ("credential_id", "credential_revision")}


def test_two_distinct_records_password_is_write_only_in_db_api_sql_and_audit(key):
    cur = Cursor()
    first = subject.create(cur, BODY, actor=ACTOR)
    second = subject.create(cur, {**BODY, "label": "synthetic-two", "username": "second"}, actor=ACTOR)
    assert first["credential_id"] != second["credential_id"]
    result = subject.list_credentials(cur, actor=ACTOR)
    assert len(result["items"]) == 2 and result["write_enabled"] is False
    assert result["items"][0]["password_status"] == "saved"
    assert result["items"][0]["check_status"] == "not_checked"
    assert PASSWORD not in repr((result, cur.calls, cur.audit, cur.credentials))
    assert all("envelope" not in row for row in result["items"])
    assert all("fixture" not in repr(event) for event in cur.audit)
    row = cur.credentials[first["credential_id"]]
    assert crypto.decrypt_password(row["envelope"], subject._context(row), key) == PASSWORD


def test_replacement_uses_new_revision_and_dek_and_deletion_preserves_other_accounts(key):
    cur = Cursor()
    first = subject.create(cur, BODY, actor=ACTOR)
    second = subject.create(cur, {**BODY, "label": "other"}, actor=ACTOR)
    old = deepcopy(cur.credentials[first["credential_id"]])
    replaced = subject.replace_password(cur, {**ref(first), "password": "new-synthetic-password"}, actor=ACTOR)
    assert replaced["credential_revision"] == 2 and replaced["check_status"] == "not_checked"
    row = cur.credentials[first["credential_id"]]
    assert row["envelope"]["wrapped_dek"] != old["envelope"]["wrapped_dek"]
    assert crypto.decrypt_password(row["envelope"], subject._context(row), key) == "new-synthetic-password"
    with pytest.raises(AgentError, match="revision_conflict"):
        subject.delete(cur, ref(first), actor=ACTOR)
    subject.delete(cur, ref(replaced), actor=ACTOR)
    assert list(cur.credentials) == [second["credential_id"]]
    with pytest.raises(AgentError, match="ad_operations_denied"):
        subject.check_read_only(cur, ref(replaced), actor=ACTOR)


@pytest.mark.parametrize("operation", ["list", "create", "replace", "delete", "check"])
def test_no_implicit_owner_other_actor_or_unassigned_domain_access(key, operation):
    cur = Cursor()
    row = subject.create(cur, BODY, actor=ACTOR)
    before = deepcopy(cur.credentials)
    cur.scopes.clear()
    call = {"list": lambda: subject.list_credentials(cur, actor=ACTOR),
        "create": lambda: subject.create(cur, BODY, actor=ACTOR),
        "replace": lambda: subject.replace_password(cur, {**ref(row), "password": PASSWORD}, actor=ACTOR),
        "delete": lambda: subject.delete(cur, ref(row), actor=ACTOR),
        "check": lambda: subject.check_read_only(cur, ref(row), actor=ACTOR)}[operation]
    with pytest.raises(AgentError, match="ad_operations_denied"):
        call()
    assert cur.credentials == before
    assert cur.audit[-1][1] is None and cur.audit[-1][-2:] == ("denied", "ad_operations_denied")
    with pytest.raises(AgentError, match="ad_operations_denied"):
        subject.list_credentials(cur, actor="session:99")


def test_partial_ou_grant_hides_metadata_and_blocks_replacement_and_deletion(key):
    cur = Cursor()
    row = subject.create(cur, BODY, actor=ACTOR)
    cur.scopes[1] = [2]
    assert subject.list_credentials(cur, actor=ACTOR)["items"] == []
    for operation, body in ((subject.replace_password, {**ref(row), "password": PASSWORD}), (subject.delete, ref(row))):
        with pytest.raises(AgentError, match="ad_operations_denied"):
            operation(cur, body, actor=ACTOR)


def test_check_never_uses_legacy_service_identity_or_exposes_password(key):
    cur = Cursor()
    row = subject.create(cur, BODY, actor=ACTOR)
    before = deepcopy(cur.credentials)
    with pytest.raises(AgentError, match="ad_check_transport_unavailable"):
        subject.check_read_only(cur, ref(row), actor=ACTOR)
    assert cur.credentials == before
    assert cur.audit[-1][-2:] == ("check_blocked", "ad_check_transport_unavailable")
    assert PASSWORD not in repr(cur.audit)
    assert not any("command" in sql or "gpo" in sql for sql, _ in cur.calls)


def test_restored_encrypted_rows_without_kek_remain_visible_but_cannot_be_checked(key, monkeypatch):
    original = Cursor()
    saved = subject.create(original, BODY, actor=ACTOR)
    restored = Cursor()
    restored.credentials = deepcopy(original.credentials)
    before = deepcopy(restored.credentials)

    def missing_key():
        raise crypto.AdSecretError("ad_master_key_not_configured")

    monkeypatch.setattr(crypto, "read_master_key", missing_key)
    metadata = subject.list_credentials(restored, actor=ACTOR)
    assert metadata["items"][0]["credential_id"] == saved["credential_id"]
    assert metadata["key_status"] == {"available": False, "error_code": "ad_master_key_not_configured"}
    assert metadata["write_enabled"] is False
    with pytest.raises(AgentError, match="^ad_master_key_not_configured$"):
        subject.check_read_only(restored, ref(saved), actor=ACTOR)
    assert restored.credentials == before and not restored.audit
    assert not any("command" in sql or "gpo" in sql for sql, _ in restored.calls)
    assert PASSWORD not in repr((metadata, restored.calls))


def test_missing_kek_plaintext_and_invalid_input_never_store_password(key, monkeypatch):
    cur = Cursor()
    def missing():
        raise crypto.AdSecretError("ad_master_key_not_configured")
    monkeypatch.setattr(crypto, "read_master_key", missing)
    with pytest.raises(AgentError, match="not_configured"):
        subject.create(cur, BODY, actor=ACTOR)
    assert not cur.credentials
    assert subject.list_credentials(cur, actor=ACTOR)["key_status"]["available"] is False
    for invalid in ({**BODY, "extra": True}, {**BODY, "label": "\n"}, {**BODY, "username": PASSWORD + " invalid"}):
        with pytest.raises(AgentError, match="ad_credential_request_invalid") as error:
            subject.create(cur, invalid, actor=ACTOR)
        assert PASSWORD not in str(error.value)


@pytest.mark.parametrize("method", ["get", "post"])
def test_http_requires_authenticated_session_without_owner_bypass(method, monkeypatch):
    responses, calls = [], []
    monkeypatch.setattr(agents, "_execute", lambda *args, **kwargs: calls.append(args))
    handler = SimpleNamespace(_require_access=lambda *args: True, _authorize_mutation=lambda **kwargs: True,
        _principal={"type": "api_key", "id": 1}, _send_json=lambda *args, **kwargs: responses.append((args, kwargs)))
    assert (agents.try_handle_get(handler, "/api/v1/ad-operation-credentials", {}) if method == "get"
            else agents.try_handle_post(handler, "/api/v1/ad-operation-credentials"))
    assert not calls and responses[0][0][1] == 403


def test_http_mutation_checks_csrf_before_reading_password(monkeypatch):
    calls = []
    handler = SimpleNamespace(_authorize_mutation=lambda **kwargs: False)
    monkeypatch.setattr(agents, "_execute", lambda *args, **kwargs: calls.append(args))
    assert agents.try_handle_post(handler, "/api/v1/ad-operation-credentials")
    assert not calls


@pytest.mark.parametrize("action", ["list", "create", "replace-password", "delete", "check"])
@pytest.mark.parametrize("case", ["granted_viewer", "no_grant", "owner_without_grant", "other_actor",
    "api_key", "anonymous", "cross_origin"])
def test_ad_credential_routes_enforce_session_origin_and_scoped_grants(key, monkeypatch, action, case):
    cur = Cursor()
    row = subject.create(cur, BODY, actor=ACTOR)
    before = deepcopy(cur.credentials)
    cur.audit.clear()
    if case in {"no_grant", "owner_without_grant"}:
        cur.scopes.clear()
    body = BODY if action == "create" else {**ref(row), **({"password": PASSWORD} if action == "replace-password" else {})}
    monkeypatch.setattr(agents, "connect", lambda: nullcontext(SimpleNamespace(
        cursor=lambda: nullcontext(cur), commit=lambda: None,
    )))
    principal = {"type": "api_key" if case == "api_key" else "session", "id": 99 if case == "other_actor" else 1,
        "role": "admin" if case == "owner_without_grant" else "viewer"}
    monkeypatch.setattr(http_server, "principal_from_headers", lambda headers: None if case == "anonymous" else principal)
    monkeypatch.setattr(http_server, "auth_required", lambda: True)
    handler = object.__new__(http_server.RequestHandler)
    handler.server = SimpleNamespace(adlog_tls_enabled=True)
    handler.path = "/api/v1/ad-operation-credentials" + ("/" + action if action not in {"list", "create"} else "")
    handler.command = "GET" if action == "list" else "POST"
    handler.connection = Mock(spec=ssl.SSLSocket)
    handler.headers = {"Host": "localhost", "Origin": "https://foreign.invalid" if case == "cross_origin" else "https://localhost"}
    handler._read_json_body = lambda: body
    handler._access_decision = lambda: {"platform_owner": case == "owner_without_grant", "capabilities": []}
    responses = []
    handler._send_json = lambda payload, status=HTTPStatus.OK, **kwargs: responses.append((payload, status))

    (handler._do_GET if action == "list" else handler._do_POST)()

    allowed = case == "granted_viewer" or (case == "cross_origin" and action == "list")
    expected = (409 if action == "check" else 200) if allowed else (401 if case == "anonymous" else 403)
    assert len(responses) == 1 and responses[0][1] == expected
    assert PASSWORD not in repr((responses, cur.audit))
    if not allowed or action == "check":
        assert cur.credentials == before
    if case in {"no_grant", "owner_without_grant", "other_actor"}:
        assert responses[0][0]["error"] == "ad_operations_denied"
        assert cur.audit[-1][-2:] == ("denied", "ad_operations_denied")
    elif allowed and action == "check":
        assert responses[0][0]["error"] == "ad_check_transport_unavailable"
    elif allowed and action == "create":
        assert len(cur.credentials) == 2
    elif allowed and action == "replace-password":
        assert cur.credentials[row["credential_id"]]["credential_revision"] == 2
    elif allowed and action == "delete":
        assert not cur.credentials
