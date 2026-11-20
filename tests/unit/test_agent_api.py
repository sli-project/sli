"""Owner checks, TLS peer boundary, safe failure and transaction ordering."""
from contextlib import contextmanager, nullcontext
from http import HTTPStatus
from io import BytesIO
import json
from types import SimpleNamespace
from unittest.mock import Mock
import ssl

import pytest

from server.api import http_server
from server.api.routes import agents
from server.sli.agents.ca import AgentError
from server.sli.agents.transport import peer_certificate


class Handler:
    def __init__(self, *, authenticated=True, owner=True, mutation=True, manage=False):
        self.authenticated, self.owner, self.mutation = authenticated, owner, mutation
        self.manage = manage
        self._principal = {"type": "session", "id": 1, "role": "admin"}
        self.connection = object()
        self.headers = {}
        self.body = {}
        self.responses = []

    def _require_access(self, role):
        if not self.authenticated:
            self._send_json({"error": "authentication_required"}, HTTPStatus.UNAUTHORIZED)
        return self.authenticated

    def _access_decision(self):
        return {"platform_owner": self.owner}

    def _require_capability(self, capability):
        assert capability == "access.manage"
        if not self.manage:
            self._send_json({"error": "capability_required"}, HTTPStatus.FORBIDDEN)
        return self.manage

    def _authorize_mutation(self, *, required_role):
        if not self.mutation:
            self._send_json({"error": "cross_origin_request_rejected"}, HTTPStatus.FORBIDDEN)
        return self.mutation

    def _read_json_body(self, **kwargs):
        self.body_options = kwargs
        return self.body

    def _send_json(self, result, status=HTTPStatus.OK, *, headers=None):
        self.responses.append((result, status, headers))


ADMIN_GET = ["/api/v1/admin/agents/sequence-recovery", "/api/v1/admin/agents", "/api/v1/admin/agent-tokens", "/api/v1/admin/agent-packages",
    "/api/v1/admin/agents/file-audit",
    "/api/v1/admin/agent-update-waves",
    "/api/v1/admin/agent-templates", "/api/v1/admin/agent-onboarding",
    "/api/v1/admin/agent-group-tokens"]
ADMIN_POST = ["/api/v1/admin/agents/sequence-recovery", "/api/v1/admin/agent-tokens", "/api/v1/admin/agent-tokens/revoke",
    "/api/v1/admin/agent-deployment-directory",
    "/api/v1/admin/agent-group-requests", "/api/v1/admin/agent-group-requests/approve",
    "/api/v1/admin/agents/file-audit",
    "/api/v1/admin/agent-update-waves", "/api/v1/admin/agent-update-waves/stop",
    "/api/v1/admin/agents/replace",
    "/api/v1/admin/agents/remove",
    "/api/v1/admin/agents/revoke", "/api/v1/admin/agents/disable",
    "/api/v1/admin/agents/modules", "/api/v1/admin/agents/rights-probe", "/api/v1/admin/agents/policy",
    "/api/v1/admin/agent-packages", "/api/v1/admin/agents/update-policy",
    "/api/v1/admin/agent-templates", "/api/v1/admin/agent-onboarding/approve",
    "/api/v1/admin/agent-group-tokens", "/api/v1/admin/agent-group-tokens/revoke"]


def test_admin_guard_inventory_covers_all_declared_routes():
    declared = [(method, path) for method, path in agents.ROUTES if path.startswith("/api/v1/admin/")]
    guarded = [("GET", path) for path in ADMIN_GET] + [("POST", path) for path in ADMIN_POST]
    assert len(declared) == len(set(declared))
    assert len(guarded) == len(set(guarded))
    assert set(declared) == set(guarded)


@pytest.mark.parametrize("method,path", [("GET", p) for p in ADMIN_GET] + [("POST", p) for p in ADMIN_POST])
@pytest.mark.parametrize("authenticated,owner,status", [(False, True, 401), (True, False, 403)])
def test_every_admin_endpoint_requires_authenticated_owner(monkeypatch, method, path, authenticated, owner, status):
    monkeypatch.setattr(agents, "connect", lambda: pytest.fail("unauthorized requests must not connect"))
    handler = Handler(authenticated=authenticated, owner=owner)
    if method == "GET":
        agents.try_handle_get(handler, path, {})
    else:
        agents.try_handle_post(handler, path)
    assert handler.responses[-1][1] == status


def test_fleet_removal_denies_global_management_capability_without_owner_scope(monkeypatch):
    monkeypatch.setattr(agents, "connect", lambda: pytest.fail("foreign scope must not connect"))
    handler = Handler(owner=False, manage=True)
    assert agents.try_handle_post(handler, "/api/v1/admin/agents/remove")
    assert handler.responses[-1][0] == {"error": "platform_owner_required"}
    assert handler.responses[-1][1] == 403


@pytest.mark.parametrize("method,hook_name", [("GET", "audit_status"), ("POST", "enqueue_audit")])
def test_file_audit_admin_routes_forward_scope_and_commit(monkeypatch, method, hook_name):
    events = []
    transaction(monkeypatch, events)
    handler = Handler(owner=False, manage=True)
    target = "00000000-0000-4000-8000-000000000001"
    handler.body = {"agent_id": target, "command": {"action": "check"}}
    def hook(cur, value, *, principal, access):
        assert value == (target if method == "GET" else handler.body)
        assert principal == handler._principal and access == handler._access_decision()
        events.append(hook_name)
        return {"state": "pending"}
    def lookup(plugin, name):
        assert (plugin, name) == ("sli.file-audit", hook_name)
        return hook
    monkeypatch.setattr(agents, "plugin_hook", lookup)
    if method == "GET":
        assert agents.try_handle_get(handler, "/api/v1/admin/agents/file-audit", {"agent_id": [target]})
    else:
        assert agents.try_handle_post(handler, "/api/v1/admin/agents/file-audit")
    assert events == [hook_name, "commit"]
    assert handler.responses == [({"state": "pending"}, HTTPStatus.OK, {"Cache-Control": "no-store"})]


@pytest.mark.parametrize("query", [{}, {"extra": ["1"]}, {"agent_id": []},
    {"agent_id": ["1", "2"]}, {"agent_id": ["1"], "extra": ["2"]}])
def test_file_audit_status_rejects_ambiguous_filters_before_plugin(monkeypatch, query):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "plugin_hook", lambda *args: pytest.fail("invalid filter must not reach plugin"))
    handler = Handler()
    assert agents.try_handle_get(handler, "/api/v1/admin/agents/file-audit", query)
    assert events == ["rollback"]
    assert handler.responses[-1][0] == {"error": "file_audit_request_invalid"}
    assert handler.responses[-1][1] == HTTPStatus.BAD_REQUEST


@pytest.mark.parametrize("rejected", [False, True])
def test_file_audit_report_authenticates_certificate_before_plugin(monkeypatch, rejected):
    events = []
    transaction(monkeypatch, events)
    handler = Handler(authenticated=False)
    handler.body = {"state": "partial"}
    agent = {"id": "00000000-0000-4000-8000-000000000001"}
    monkeypatch.setattr(agents, "peer_certificate", lambda h: events.append("peer") or b"fixture")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    def authenticate(cur, ca, der):
        assert der == b"fixture"
        events.append("authenticate")
        if rejected:
            raise AgentError("agent_certificate_rejected", 401)
        return agent
    def ingest(cur, identity, body):
        assert identity is agent and body == handler.body
        events.append("ingest")
        return {"state": "partial"}
    def lookup(plugin, name):
        assert (plugin, name) == ("sli.file-audit", "ingest_audit")
        events.append("hook")
        return ingest
    monkeypatch.setattr(agents.registry, "authenticate", authenticate)
    monkeypatch.setattr(agents, "plugin_hook", lookup)
    assert agents.try_handle_post(handler, "/api/v1/agent/file-audit-report")
    if rejected:
        assert events == ["peer", "authenticate", "rollback"]
        assert handler.responses[-1][1] == HTTPStatus.UNAUTHORIZED
    else:
        assert events == ["peer", "authenticate", "hook", "ingest", "commit"]
        assert handler.responses == [({"state": "partial"}, HTTPStatus.OK, {"Cache-Control": "no-store"})]


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/v1/admin/agents/file-audit"),
    ("POST", "/api/v1/admin/agents/file-audit"),
    ("POST", "/api/v1/agent/file-audit-report"),
])
def test_file_audit_routes_fail_closed_without_plugin(monkeypatch, method, path):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "plugin_hook", lambda *args: None)
    monkeypatch.setattr(agents, "peer_certificate", lambda h: b"fixture")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    monkeypatch.setattr(agents.registry, "authenticate", lambda *args: {"id": "fixture-agent"})
    handler = Handler()
    if method == "GET":
        assert agents.try_handle_get(handler, path, {"agent_id": ["fixture-agent"]})
    else:
        assert agents.try_handle_post(handler, path)
    assert events == ["rollback"]
    assert handler.responses == [({"error": "file_audit_plugin_unavailable"}, HTTPStatus.CONFLICT,
        {"Cache-Control": "no-store"})]


@pytest.mark.parametrize("path", ["/api/v1/admin/agent-update-waves", "/api/v1/admin/agent-update-waves/stop"])
def test_update_wave_mutation_requires_fleet_owner_scope(monkeypatch, path):
    monkeypatch.setattr(agents, "connect", lambda: pytest.fail("foreign scope must not connect"))
    handler = Handler(owner=False, manage=True)
    assert agents.try_handle_post(handler, path)
    assert handler.responses[-1][0] == {"error": "platform_owner_required"}
    assert handler.responses[-1][1] == 403


@pytest.mark.parametrize("path,operation", [
    ("/api/v1/admin/agent-update-waves", "create"),
    ("/api/v1/admin/agent-update-waves/stop", "stop"),
])
def test_update_wave_mutations_forward_body_and_actor_and_commit(monkeypatch, path, operation):
    events = []
    transaction(monkeypatch, events)
    handler = Handler()
    handler.body = {"fixture": "selection"}
    def perform(cur, body, *, actor):
        assert body == handler.body and actor == "session:1"
        events.append(operation)
        return {"status": "running" if operation == "create" else "stopped"}
    monkeypatch.setattr(agents.update_waves, operation, perform)
    assert agents.try_handle_post(handler, path)
    assert events == [operation, "commit"]
    assert handler.responses[-1][1] == 200
    assert handler.responses[-1][2] == {"Cache-Control": "no-store"}


@pytest.mark.parametrize("query", [{"extra": ["1"]}, {"wave_id": []}, {"wave_id": ["1", "2"]}])
def test_update_wave_list_rejects_ambiguous_filters(monkeypatch, query):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents.update_waves, "list_waves", lambda *a, **k: pytest.fail("invalid filter"))
    handler = Handler()
    assert agents.try_handle_get(handler, "/api/v1/admin/agent-update-waves", query)
    assert events == ["rollback"]
    assert handler.responses[-1][0] == {"error": "agent_update_wave_invalid"}


def test_update_wave_list_forwards_exact_selection_and_audited_actor(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    def read(cur, *, actor, wave_id):
        assert actor == "session:1" and wave_id == "fixture"
        events.append("listed")
        return {"items": []}
    monkeypatch.setattr(agents.update_waves, "list_waves", read)
    handler = Handler()
    assert agents.try_handle_get(handler, "/api/v1/admin/agent-update-waves", {"wave_id": ["fixture"]})
    assert events == ["listed", "commit"]


@pytest.mark.parametrize("path", ["/api/v1/agent/identity", "/api/v1/agent/package", "/api/v1/agent/update-result"])
def test_update_routes_lock_rollout_before_authenticating_agent(monkeypatch, path):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents.update_waves, "lock", lambda cur: events.append("wave_lock"))
    monkeypatch.setattr(agents, "peer_certificate", lambda h: b"fixture")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    def reject(cur, ca, der, **kwargs):
        events.append("authenticate")
        raise AgentError("agent_certificate_rejected", 401)
    monkeypatch.setattr(agents.registry, "authenticate", reject)
    handler = Handler(authenticated=False)
    if path.endswith("update-result"):
        assert agents.try_handle_post(handler, path)
    else:
        assert agents.try_handle_get(handler, path, {"sha256": ["a" * 64]} if path.endswith("package") else {})
    assert events[:2] == ["wave_lock", "authenticate"]
    assert events[-1] == "rollback" and handler.responses[-1][1] == 401


def test_agent_inventory_forwards_exact_target_under_existing_owner_gate(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    calls = []
    monkeypatch.setattr(agents.registry, "list_agents", lambda cur, **kwargs: calls.append(kwargs) or {"items": []})
    target = "00000000-0000-4000-8000-000000000001"
    handler = Handler()
    assert agents.try_handle_get(handler, "/api/v1/admin/agents", {"agent_id": [target]})
    assert calls == [{"actor": "session:1", "agent_id": target}]
    assert handler.responses[-1][0] == {"items": []}
    denied = Handler(owner=False)
    agents.try_handle_get(denied, "/api/v1/admin/agents", {"agent_id": [target]})
    assert len(calls) == 1 and denied.responses[-1][1] == 403


def test_fleet_removal_is_explicit_and_committed_before_response(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    handler = Handler()
    handler.body = {"operation_id": "fixture", "agent_ids": ["fixture-agent"]}
    monkeypatch.setattr(agents.removal, "request", lambda cur, body, actor:
                        events.append((body, actor)) or {"items": []})
    assert agents.try_handle_post(handler, "/api/v1/admin/agents/remove")
    assert events == [(handler.body, "session:1"), "commit"]
    assert handler.responses[-1][0] == {"items": []}


def test_revoked_identity_only_exposes_removal_command(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "peer_certificate", lambda h: b"fixture")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    def authenticate(cur, ca, der, *, removal_only=False):
        if not removal_only:
            raise AgentError("agent_certificate_rejected", 401)
        return {"id": "fixture-agent"}
    monkeypatch.setattr(agents.registry, "authenticate", authenticate)
    monkeypatch.setattr(agents.removal, "command", lambda *a: {"agent_removal": {"action": "uninstall"}})
    monkeypatch.setattr(agents.policies, "check_in", lambda *a: pytest.fail("no policy/data on revoked channel"))
    monkeypatch.setattr(agents.updates, "advertisement", lambda *a: pytest.fail("no packages on revoked channel"))
    handler = Handler(authenticated=False)
    assert agents.try_handle_get(handler, "/api/v1/agent/identity", {})
    assert events == ["commit"] and handler.responses[-1][0] == {"agent_removal": {"action": "uninstall"}}


def test_removal_result_uses_certificate_identity_and_never_body_target(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "peer_certificate", lambda h: b"fixture")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    def authenticate(cur, ca, der, *, removal_only=False):
        assert removal_only and der == b"fixture"
        return {"id": "fixture-own-agent"}
    monkeypatch.setattr(agents.registry, "authenticate", authenticate)
    monkeypatch.setattr(agents.removal, "report", lambda cur, agent, body:
                        events.append((agent, body)) or {"state": "state_cleaned"})
    handler = Handler(authenticated=False)
    handler.body = {"command_id": "fixture-command", "state": "state_cleaned", "reason": None}
    assert agents.try_handle_post(handler, "/api/v1/agent/removal-result")
    assert events == [({"id": "fixture-own-agent"}, handler.body), "commit"]


@pytest.mark.parametrize("path", ["/api/v1/agent/uninstall", "/api/v1/agent/removal-result"])
def test_removal_transport_rejects_unregistered_certificate_before_mutation(monkeypatch, path):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "peer_certificate", lambda h: b"fixture-certificate")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())

    def authenticate(cur, ca, der, *, removal_only=False):
        raise AgentError("agent_certificate_rejected", 401)

    monkeypatch.setattr(agents.registry, "authenticate", authenticate)
    monkeypatch.setattr(agents.removal, "local_uninstall", lambda *args: pytest.fail("rejected agent must not uninstall"))
    monkeypatch.setattr(agents.removal, "report", lambda *args: pytest.fail("rejected agent must not report removal"))
    handler = Handler(authenticated=False, owner=False)
    assert agents.try_handle_post(handler, path)
    assert events == ["rollback"]
    assert handler.responses[-1][0] == {"error": "agent_certificate_rejected"}
    assert handler.responses[-1][1] == 401


@pytest.mark.parametrize("path", ADMIN_POST)
def test_owner_mutations_keep_origin_check(monkeypatch, path):
    monkeypatch.setattr(agents, "connect", lambda: pytest.fail("rejected mutation must not connect"))
    handler = Handler(mutation=False)
    agents.try_handle_post(handler, path)
    assert handler.responses[-1][1] == 403


@pytest.mark.parametrize("path", ["/api/v1/agent/renew", "/api/v1/agent/identity", "/api/v1/agent/enroll",
    "/api/v1/agent/uninstall", "/api/v1/agent/removal-result",
    "/api/v1/agent/package", "/api/v1/agent/update-result", "/api/v1/agent/policy-report",
    "/api/v1/agent/group-enroll"])
def test_cleartext_and_forged_cert_headers_rejected_before_db(monkeypatch, path):
    monkeypatch.setattr(agents, "connect", lambda: pytest.fail("missing TLS must not connect"))
    handler = Handler()
    handler.headers = {"X-Client-Cert": "synthetic", "SSL_CLIENT_VERIFY": "SUCCESS", "SSL_CLIENT_CERT": "synthetic"}
    if path.endswith(("identity", "package")):
        agents.try_handle_get(handler, path, {})
    else:
        agents.try_handle_post(handler, path)
    assert handler.responses[-1][1] == 401


@pytest.mark.parametrize("path,operation", [
    ("/api/v1/admin/agents/modules", "assign_module"),
    ("/api/v1/admin/agents/rights-probe", "request_probe"),
    ("/api/v1/admin/agents/policy", "update_control"),
    ("/api/v1/admin/agents/update-policy", "assign"),
])
@pytest.mark.parametrize("owner,manage", [(True, False), (False, True)])
def test_policy_admin_owner_or_capability_and_committed_response(monkeypatch, path, operation, owner, manage):
    events = []
    transaction(monkeypatch, events)
    target = {"assign_module": agents.registry, "assign": agents.updates}.get(operation, agents.policies)
    monkeypatch.setattr(target, operation, lambda cur, body, actor: events.append((body, actor)) or {"policy_revision": 2})
    handler = Handler(owner=owner, manage=manage)
    handler.body = {"agent_id": "synthetic"}
    assert agents.try_handle_post(handler, path)
    assert events == [({"agent_id": "synthetic"}, "session:1"), "commit"]
    assert handler.responses[-1][0] == {"policy_revision": 2}
    assert handler.responses[-1][2] == {"Cache-Control": "no-store"}


def test_identity_checkin_keeps_collection_policy_and_update_offer(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "peer_certificate", lambda h: b"verified")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    agent = {"id": "synthetic", "host_id": "synthetic-host", "assigned_modules": [],
             "policy_revision": 3, "rights_probe": {}, "collection_policy": {"state": "paused"}}
    monkeypatch.setattr(agents.registry, "authenticate", lambda *a: agent)
    offer = {"sha256": "a" * 64, "version": "1.1.0"}
    def advertisement(cur, identity):
        assert identity is agent
        return offer
    monkeypatch.setattr(agents.updates, "advertisement", advertisement)
    handler = Handler(authenticated=False, owner=False)
    assert agents.try_handle_get(handler, "/api/v1/agent/identity", {})
    result = handler.responses[-1][0]
    assert result["collection_policy"]["state"] == "paused"
    assert result["policy_revision"] == 3 and result["agent_update"] == offer
    assert events == ["commit"]


def test_policy_report_uses_mtls_identity_without_user_session(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "peer_certificate", lambda h: b"verified")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    authenticated_agent = {"id": "synthetic"}
    def authenticate(cur, ca, der):
        assert der == b"verified"
        return authenticated_agent
    monkeypatch.setattr(agents.registry, "authenticate", authenticate)
    monkeypatch.setattr(agents.policies, "report", lambda cur, agent, body: events.append((agent, body)) or {"applied_policy_revision": 2})
    handler = Handler(authenticated=False, owner=False)
    handler.body = {"applied_policy_revision": 2}
    assert agents.try_handle_post(handler, "/api/v1/agent/policy-report")
    assert events == [(authenticated_agent, handler.body), "commit"]
    assert handler.responses[-1][0] == {"applied_policy_revision": 2}


def test_policy_report_rejects_unregistered_certificate_without_applying_policy(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "peer_certificate", lambda h: b"verified")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())

    def authenticate(cur, ca, der):
        raise AgentError("agent_certificate_rejected", 401)

    monkeypatch.setattr(agents.registry, "authenticate", authenticate)
    monkeypatch.setattr(agents.policies, "report", lambda *args: pytest.fail("rejected agent must not report policy"))
    handler = Handler(authenticated=False, owner=False)
    assert agents.try_handle_post(handler, "/api/v1/agent/policy-report")
    assert events == ["rollback"]
    assert handler.responses[-1][0] == {"error": "agent_certificate_rejected"}
    assert handler.responses[-1][1] == 401


def test_audit_report_rejects_cleartext_before_db(monkeypatch):
    monkeypatch.setattr(agents, "connect", lambda: pytest.fail("missing TLS must not connect"))
    handler = Handler()
    handler.headers = {"X-Client-Cert": "synthetic", "SSL_CLIENT_VERIFY": "SUCCESS"}
    assert agents.try_handle_post(handler, "/api/v1/agent/windows-audit-report")
    assert handler.responses[-1][1] == 401


@pytest.mark.parametrize("accepted", [True, False])
def test_audit_report_uses_only_authenticated_agent_and_commits_before_response(monkeypatch, accepted):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "peer_certificate", lambda h: b"verified")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    authenticated_agent = {"id": "synthetic"}
    def authenticate(cur, ca, der):
        assert der == b"verified"
        if not accepted:
            raise AgentError("agent_certificate_rejected", 401)
        return authenticated_agent
    monkeypatch.setattr(agents.registry, "authenticate", authenticate)
    def report(cur, agent, body):
        assert accepted and agent is authenticated_agent
        events.append((agent, body))
        return body
    monkeypatch.setattr(agents.windows_audit, "report", report)
    handler = Handler(authenticated=False, owner=False)
    handler.body = {"windows_audit": {"policy_revision": 2}}
    send = handler._send_json
    def respond(*args, **kwargs):
        events.append("response")
        send(*args, **kwargs)
    handler._send_json = respond
    assert ("POST", "/api/v1/agent/windows-audit-report") in agents.ROUTES
    assert agents.try_handle_post(handler, "/api/v1/agent/windows-audit-report")
    if accepted:
        assert events == [(authenticated_agent, handler.body), "commit", "response"]
        assert handler.responses[-1][0] == handler.body
    else:
        assert events == ["rollback", "response"]
        assert handler.responses[-1][1] == 401


@pytest.mark.parametrize("mode,der,accepted", [(ssl.CERT_NONE, b"cert", False),
    (ssl.CERT_OPTIONAL, None, False), (ssl.CERT_OPTIONAL, b"cert", True),
    (ssl.CERT_REQUIRED, b"cert", True)])
def test_transport_requires_verified_tls_socket(mode, der, accepted):
    socket = Mock(spec=ssl.SSLSocket)
    socket.context = SimpleNamespace(verify_mode=mode)
    socket.getpeercert.return_value = der
    handler = SimpleNamespace(connection=socket)
    if accepted:
        assert peer_certificate(handler) == der
        socket.getpeercert.assert_called_once_with(binary_form=True)
    else:
        with pytest.raises(AgentError, match="agent_mtls_required"):
            peer_certificate(handler)


def transaction(monkeypatch, events, *, commit_error=False):
    class Connection:
        @contextmanager
        def cursor(self):
            yield SimpleNamespace(execute=lambda *args: None)

        def commit(self):
            if commit_error:
                raise RuntimeError("sensitive-bind-value")
            events.append("commit")

    @contextmanager
    def connect():
        try:
            yield Connection()
        except Exception:
            events.append("rollback")
            raise
    monkeypatch.setattr(agents, "connect", connect)


@pytest.mark.parametrize("action", ["credentials", "preview", "confirm", "cancel"])
@pytest.mark.parametrize("case,expected", [
    ("granted_viewer", 200), ("no_grant", 403), ("owner_without_grant", 403),
    ("wrong_permission", 403), ("api_key", 403), ("anonymous", 401), ("cross_origin", 403),
])
def test_gpo_routes_enforce_session_origin_and_scoped_grants(monkeypatch, action, case, expected):
    from tests.unit.test_agent_gpo_plans import ACTOR, CREDENTIAL, SELECTION, Cursor, Registry, confirmation

    monkeypatch.setattr(agents.gpo_plan_credentials, "_registry", lambda: Registry)
    cur = Cursor()
    body = {key: value for key, value in SELECTION.items() if action != "credentials" or key not in CREDENTIAL}
    if action not in {"preview", "credentials"}:
        plan = agents.gpo_plans.preview(cur, SELECTION, actor=ACTOR)
        body = confirmation(plan, cancel=action == "cancel")
    if case in {"no_grant", "owner_without_grant"}:
        cur.grants.clear()
    elif case == "wrong_permission":
        cur.grants[(ACTOR, 1)]["permissions"] = ["preview"] if action == "confirm" else ["apply"]
    # Replace only the database connection; keep dispatch, session/Origin
    # guards, _execute and the scoped service authorization real.
    monkeypatch.setattr(agents, "connect", lambda: nullcontext(SimpleNamespace(
        cursor=lambda: nullcontext(cur), commit=lambda: None,
    )))
    principal = {"type": "api_key" if case == "api_key" else "session", "id": 1,
                 "role": "admin" if case == "owner_without_grant" else "viewer"}
    monkeypatch.setattr(http_server, "principal_from_headers", lambda headers: None if case == "anonymous" else principal)
    monkeypatch.setattr(http_server, "auth_required", lambda: True)
    handler = object.__new__(http_server.RequestHandler)
    handler.server = SimpleNamespace()
    handler.path = "/api/v1/agent-deployment/gpo/" + action
    handler.command = "POST"
    handler.headers = {"Host": "localhost", "Origin": "http://foreign.invalid" if case == "cross_origin" else "http://localhost"}
    handler._read_json_body = lambda: body
    handler._access_decision = lambda: {"platform_owner": case == "owner_without_grant", "capabilities": []}
    responses = []
    handler._send_json = lambda payload, status=HTTPStatus.OK, **kwargs: responses.append((payload, status))

    handler._do_POST()

    assert len(responses) == 1
    assert responses[0][1] == expected
    if expected == 200:
        assert responses[0][0]["write_enabled"] is False
    else:
        assert all(row["status"] == "preview" for row in cur.plans.values())
        if action == "preview":
            assert not cur.plans
        if case in {"no_grant", "owner_without_grant", "wrong_permission"}:
            assert responses[0][0]["error"] == "gpo_deployment_denied"


@pytest.mark.parametrize("action", ["credentials", "preview", "confirm", "cancel"])
@pytest.mark.parametrize("failure", ["session", "origin", "authentication"])
def test_gpo_plan_routes_require_real_session_and_origin(monkeypatch, action, failure):
    monkeypatch.setattr(agents, "connect", lambda: pytest.fail("rejected request must not connect"))
    handler = Handler(authenticated=failure != "authentication", mutation=failure != "origin")
    if failure == "session":
        handler._principal = {"type": "api_key", "id": 1}
    assert agents.try_handle_post(handler, "/api/v1/agent-deployment/gpo/" + action)
    assert handler.responses[-1][1] in {401, 403}


@pytest.mark.parametrize("action", ["preview", "confirm", "cancel"])
def test_gpo_plans_do_not_use_owner_bypass_and_commit_before_response(monkeypatch, action):
    events = []
    transaction(monkeypatch, events)
    handler = Handler(owner=False)
    handler.body = {"synthetic": True}
    def operation(cur, body, *, actor, **kwargs):
        assert actor == "session:1" and body == handler.body
        assert kwargs == ({"cancel": action == "cancel"} if action != "preview" else {})
        events.append("intention")
        return {"write_enabled": False}
    monkeypatch.setattr(agents.gpo_plans, "preview" if action == "preview" else "finish", operation)
    assert agents.try_handle_post(handler, "/api/v1/agent-deployment/gpo/" + action)
    assert events == ["intention", "commit"]
    assert handler.responses[-1][0] == {"write_enabled": False}
    assert handler.responses[-1][2] == {"Cache-Control": "no-store"}


def test_gpo_denial_audit_survives_commit(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    def rejected(*args, **kwargs):
        events.append("denied_audit")
        raise agents.group_enrollment.AuditedRejection("gpo_deployment_denied", 403)
    monkeypatch.setattr(agents.gpo_plans, "preview", rejected)
    handler = Handler(owner=True)
    assert agents.try_handle_post(handler, "/api/v1/agent-deployment/gpo/preview")
    assert events == ["denied_audit", "commit"]
    assert handler.responses[-1][1] == 403


@pytest.mark.parametrize("path,module,operation,query", [
    ("/api/v1/admin/agent-templates", "onboarding", "list_templates", {}),
    ("/api/v1/admin/agent-onboarding", "onboarding", "list_requests", {"token_id": ["fixture-token"]}),
    ("/api/v1/admin/agent-group-tokens", "group_enrollment", "list_tokens", {}),
])
def test_merged_admin_lists_dispatch_and_commit_before_response(monkeypatch, path, module, operation, query):
    events = []
    transaction(monkeypatch, events)

    def read(cur, *args, actor):
        assert actor == "session:1"
        assert args == (("fixture-token",) if operation == "list_requests" else ())
        events.append(operation)
        return {"items": []}

    monkeypatch.setattr(getattr(agents, module), operation, read)
    handler = Handler()
    send = handler._send_json
    handler._send_json = lambda *args, **kwargs: (events.append("response"), send(*args, **kwargs))

    assert agents.try_handle_get(handler, path, query)
    assert events == [operation, "commit", "response"]
    assert handler.responses == [({"items": []}, HTTPStatus.OK, {"Cache-Control": "no-store"})]


@pytest.mark.parametrize("path,operation", [
    ("/api/v1/admin/agent-templates", "save_template"),
    ("/api/v1/admin/agent-onboarding/approve", "approve"),
])
@pytest.mark.parametrize("commit_error", [False, True])
def test_onboarding_response_is_owner_authenticated_and_after_commit(monkeypatch, path, operation, commit_error):
    events = []
    transaction(monkeypatch, events, commit_error=commit_error)
    monkeypatch.setattr(agents.onboarding, operation, lambda cur, body, actor:
        events.append((body, actor)) or {"items": [{"status": "approved", "token": "synthetic-secret"}]})
    handler = Handler()
    handler.body = {"mode": "selected"}
    assert agents.try_handle_post(handler, path)
    assert events[0] == ({"mode": "selected"}, "session:1")
    response, status, headers = handler.responses[-1]
    assert headers == {"Cache-Control": "no-store"}
    if commit_error:
        assert events[-1] == "rollback"
        assert status == 503 and response == {"error": "agent_service_unavailable"}
    else:
        assert events[-1] == "commit"
        assert response["items"][0]["status"] == "approved"


@pytest.mark.parametrize("query", [{}, {"token_id": ["synthetic", "extra"]},
    {"token_id": ["synthetic"], "domain_id": ["1"]}])
def test_onboarding_list_rejects_unscoped_query(monkeypatch, query):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents.onboarding, "list_requests", lambda *args, **kwargs:
        pytest.fail("invalid query cannot list requests"))
    handler = Handler()
    assert agents.try_handle_get(handler, "/api/v1/admin/agent-onboarding", query)
    assert handler.responses[-1][1] == 400


def test_enrollment_response_after_commit_and_no_store(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "require_enrollment_tls", lambda h: None)
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    monkeypatch.setattr(agents.registry, "enroll", lambda c, a, b: events.append("issue") or {"certificate_pem": "synthetic"})
    handler = Handler()
    send = handler._send_json
    handler._send_json = lambda *args, **kwargs: (events.append("response"), send(*args, **kwargs))
    assert agents.try_handle_post(handler, "/api/v1/agent/enroll")
    assert events == ["issue", "commit", "response"]
    assert handler.responses[-1][2] == {"Cache-Control": "no-store"}


def test_authenticated_checkin_preserves_collection_control_for_nps(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "peer_certificate", lambda _handler: b"fixture-certificate")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    row = {"id": "00000000-0000-4000-8000-000000000001", "assigned_modules": [],
           "policy_revision": 2, "rights_probe": {}, "collection_policy": {"state": "paused"}}
    monkeypatch.setattr(agents.registry, "authenticate", lambda *_args: row)
    monkeypatch.setattr(agents.updates, "advertisement", lambda *_args: None)
    handler = Handler()
    assert agents.try_handle_get(handler, "/api/v1/agent/identity", {})
    result, status, _ = handler.responses[-1]
    assert status == 200 and events == ["commit"]
    assert result["collection_policy"]["state"] == "paused"
    assert result["collection_policy"]["batch_size"] == 32
    assert result["policy_revision"] == 2 and result["agent_update"] is None


def test_assignment_uses_owner_actor_and_commits_before_response(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    handler = Handler()
    handler.body = {"agent_id": "fixture", "module_id": "sli.workstations", "enabled": True}

    def assign(cur, body, *, actor):
        assert body is handler.body and actor == "session:1"
        events.append("assignment")
        return {"status": "assigned"}

    monkeypatch.setattr(agents.registry, "assign_module", assign)
    send = handler._send_json
    handler._send_json = lambda *a, **kw: (events.append("response"), send(*a, **kw))
    assert agents.try_handle_post(handler, "/api/v1/admin/agents/modules")
    assert events == ["assignment", "commit", "response"]
    assert handler.responses[-1][2] == {"Cache-Control": "no-store"}


def test_commit_failure_returns_safe_code_and_no_certificate(monkeypatch):
    events = []
    transaction(monkeypatch, events, commit_error=True)
    monkeypatch.setattr(agents.registry, "create_token", lambda *a, **k: {"token": "raw-secret"})
    handler = Handler()
    agents.try_handle_post(handler, "/api/v1/admin/agent-tokens")
    assert events == ["rollback"]
    assert handler.responses[-1][0] == {"error": "agent_service_unavailable"}
    assert handler.responses[-1][1] == 503
    assert "raw-secret" not in repr(handler.responses)
    assert "sensitive-bind-value" not in repr(handler.responses)


@pytest.mark.parametrize("operation,path", [
    ("create_token", "/api/v1/admin/agent-group-tokens"),
    ("revoke_token", "/api/v1/admin/agent-group-tokens/revoke"),
])
def test_group_admin_operation_uses_authenticated_actor_and_commits(monkeypatch, operation, path):
    events = []
    transaction(monkeypatch, events)
    handler = Handler()
    handler.body = {"id": "fixture"}
    def perform(cur, value, *, actor):
        assert actor == "session:1"
        assert value == ("fixture" if operation == "revoke_token" else handler.body)
        events.append(operation)
        return {"status": "fixture"}
    monkeypatch.setattr(agents.group_enrollment, operation, perform)
    assert agents.try_handle_post(handler, path)
    assert events == [operation, "commit"]
    assert handler.responses[-1][2] == {"Cache-Control": "no-store"}


def test_deployment_directory_is_authorized_and_committed_without_ca(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    handler = Handler()
    handler.body = {"domain_id": 1, "ou_entity_ids": [2]}
    def read(cur, body):
        assert body is handler.body
        events.append("directory")
        return {"computers": [], "ous": []}
    monkeypatch.setattr(agents.deployment_scope, "directory", read)
    assert agents.try_handle_post(handler, "/api/v1/admin/agent-deployment-directory")
    assert events == ["directory", "commit"]
    assert handler.responses[-1][2] == {"Cache-Control": "no-store"}


def test_auto_approval_commit_failure_never_returns_the_credential(monkeypatch):
    events = []
    transaction(monkeypatch, events, commit_error=True)
    monkeypatch.setattr(agents, "require_enrollment_tls", lambda h: None)
    monkeypatch.setattr(agents.group_enrollment, "submit", lambda *a: {"status": "approved", "token": "synthetic-secret"})
    handler = Handler(authenticated=False)
    assert agents.try_handle_post(handler, "/api/v1/agent/group-enroll")
    assert events == ["rollback"]
    assert handler.responses[-1][1] == 503 and "synthetic-secret" not in repr(handler.responses)


@pytest.mark.parametrize("operation,path", [("list_pending", "/api/v1/admin/agent-group-requests"),
    ("approve", "/api/v1/admin/agent-group-requests/approve")])
@pytest.mark.parametrize("manage", [False, True])
def test_group_batch_api_uses_authenticated_actor_and_commits(monkeypatch, operation, path, manage):
    events = []
    transaction(monkeypatch, events)
    handler = Handler(owner=not manage, manage=manage)
    handler.body = {"filter": {"group_id": "fixture", "token_id": "fixture"}, "evidence": []}
    def perform(cur, value, *, actor):
        assert actor == "session:1" and value is handler.body
        events.append(operation)
        return {"items": []}
    monkeypatch.setattr(agents.group_deployment, operation, perform)
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: pytest.fail("approval must not issue certificates"))
    assert agents.try_handle_post(handler, path)
    assert events == [operation, "commit"]
    assert handler.responses[-1][0] == {"items": []}
    assert handler.responses[-1][2] == {"Cache-Control": "no-store"}
    assert handler.body_options == ({"max_bytes": 512 * 1024} if operation == "approve" else {})


def test_group_batch_commit_failure_never_returns_approval_secrets(monkeypatch):
    events = []
    transaction(monkeypatch, events, commit_error=True)
    monkeypatch.setattr(agents.group_deployment, "approve", lambda *a, **kw: {"items": [{"token": "synthetic-secret"}]})
    handler = Handler()
    assert agents.try_handle_post(handler, "/api/v1/admin/agent-group-requests/approve")
    assert handler.responses[-1][0] == {"error": "agent_service_unavailable"}
    assert handler.responses[-1][1] == 503
    assert events == ["rollback"]
    assert "synthetic-secret" not in repr(handler.responses)


def test_1000_attestations_fit_authorized_http_body_without_raising_default_limit(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    evidence = [{"request_id": "00000000-0000-4000-8000-000000000001",
        "host_id": "00000000-0000-4000-8000-000000000002", "instance_name": None,
        "key_fingerprint": "a" * 64, "computer_entity_id": 3}] * 1000
    raw = json.dumps({"filter": {}, "evidence": evidence}).encode()
    assert http_server.MAX_JSON_REQUEST_BYTES < len(raw) < 512 * 1024
    handler = Handler()
    handler.headers = {"Content-Length": str(len(raw)), "Content-Type": "application/json"}
    handler.rfile = BytesIO(raw)
    handler.connection = Mock()
    handler.connection.gettimeout.return_value = None
    handler._read_json_body = lambda **kw: http_server.RequestHandler._read_json_body(handler, **kw)
    seen = []
    monkeypatch.setattr(agents.group_deployment, "approve", lambda cur, body, **kw: seen.append(len(body["evidence"])) or {"items": []})
    assert agents.try_handle_post(handler, "/api/v1/admin/agent-group-requests/approve")
    assert seen == [1000] and events == ["commit"]
    handler.rfile = BytesIO(raw)
    with pytest.raises(http_server.RequestInputError, match="request_body_too_large"):
        http_server.RequestHandler._read_json_body(handler)


@pytest.mark.parametrize("rejected,commit_error", [(False, False), (True, False), (True, True)])
def test_group_submission_commits_pending_or_denial_audit_before_response(monkeypatch, rejected, commit_error):
    events = []
    transaction(monkeypatch, events, commit_error=commit_error)
    monkeypatch.setattr(agents, "require_enrollment_tls", lambda h: None)
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: pytest.fail("group token must never access CA"))
    def submit(cur, body):
        events.append("audit")
        if rejected:
            raise agents.group_enrollment.AuditedRejection("group_enrollment_rejected", 401)
        return {"request_id": "fixture", "status": "pending"}
    monkeypatch.setattr(agents.group_enrollment, "submit", submit)
    handler = Handler(authenticated=False, owner=False)
    send = handler._send_json
    handler._send_json = lambda *args, **kwargs: (events.append("response"), send(*args, **kwargs))
    assert agents.try_handle_post(handler, "/api/v1/agent/group-enroll")
    assert events == ["audit", "rollback" if commit_error else "commit", "response"]
    assert handler.responses[-1][1] == (503 if commit_error else 401 if rejected else 200)
    assert "certificate" not in repr(handler.responses)
    assert handler.responses[-1][2] == {"Cache-Control": "no-store"}


def test_group_token_cannot_use_existing_certificate_enrollment(monkeypatch):
    from tests.unit.test_agent_group_enrollment import GroupCursor
    cur = GroupCursor()
    token = agents.group_enrollment.create_token(cur, {"max_uses": 1, "domain_id": 1, "ou_entity_ids": [2]}, actor="session:1")
    authority = Mock()
    with pytest.raises(AgentError, match="enrollment_token_rejected"):
        agents.registry.enroll(cur, authority, {"token": token["token"]})
    authority.issue.assert_not_called()
    assert not cur.agents and not cur.certificates


def test_only_owner_token_endpoint_forwards_instance_approval(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    seen = []
    def create(cur, body, *, actor):
        seen.append((body, actor))
        return {"instance_name": body["instance_name"]}
    monkeypatch.setattr(agents.registry, "create_token", create)
    handler = Handler()
    handler.body = {"instance_name": "dc"}
    agents.try_handle_post(handler, "/api/v1/admin/agent-tokens")
    assert seen == [({"instance_name": "dc"}, "session:1")]
    assert events == ["commit"]
    assert handler.responses[-1][0] == {"instance_name": "dc"}
    denied = Handler(owner=False)
    denied.body = handler.body
    agents.try_handle_post(denied, "/api/v1/admin/agent-tokens")
    assert len(seen) == 1 and denied.responses[-1][1] == 403


def test_revocations_public_without_user_session_and_invalid_cursor(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents.registry, "revocations", lambda cur, after: {"items": [], "next_cursor": after})
    handler = Handler(authenticated=False)
    assert agents.try_handle_get(handler, "/api/v1/agent/revocations", {"after": ["10"]})
    assert handler.responses[-1][0] == {"items": [], "next_cursor": 10}
    for query in ({"after": ["bad"]}, {"after": ["1", "2"]}, {"unexpected": ["1"]}):
        agents.try_handle_get(handler, "/api/v1/agent/revocations", query)
        assert handler.responses[-1][0] == {"error": "invalid_revocation_cursor"}
        assert handler.responses[-1][1] == 400


def test_agent_get_dispatch_before_ambient_session_policy(monkeypatch):
    handler = object.__new__(http_server.RequestHandler)
    handler.path = "/api/v1/agent/identity"
    monkeypatch.setattr(http_server.routes_health, "try_handle_liveness_get", lambda *a: False)
    monkeypatch.setattr(http_server.routes_auth, "try_handle_account_get", lambda *a: False)
    monkeypatch.setattr(http_server.routes_static, "try_handle_login_get", lambda *a: False)
    calls = []
    monkeypatch.setattr(http_server.routes_agents, "try_handle_get", lambda *a: calls.append(a[1]) or True)
    monkeypatch.setattr(http_server, "principal_from_headers", lambda *a: pytest.fail("agent must not use user session"))
    handler._do_GET()
    assert calls == ["/api/v1/agent/identity"]


def test_group_enrollment_dispatch_requires_tls_without_user_session(monkeypatch):
    handler = object.__new__(http_server.RequestHandler)
    handler.path = "/api/v1/agent/group-enroll"
    handler.connection = object()
    handler.headers = {"X-Client-Cert": "synthetic", "SSL_CLIENT_VERIFY": "SUCCESS"}
    handler._require_secure_api_transport = lambda _path: True
    handler._read_json_body = lambda: {}
    handler._authorize_mutation = lambda **_kwargs: pytest.fail("group enrollment must not use user session")
    responses = []
    handler._send_json = lambda result, status=HTTPStatus.OK, **kwargs: responses.append((result, status, kwargs))
    monkeypatch.setattr(http_server, "principal_from_headers", lambda *_args: pytest.fail("group enrollment must not use user session"))
    monkeypatch.setattr(agents, "connect", lambda: pytest.fail("missing TLS must not connect"))

    handler._do_POST()

    assert responses == [({"error": "agent_tls_required"}, HTTPStatus.UNAUTHORIZED,
                          {"headers": {"Cache-Control": "no-store"}})]


def test_existing_tls_listener_loads_optional_agent_trust(monkeypatch, tmp_path):
    for name in ("ADLOG_TLS_CERT", "ADLOG_TLS_KEY"):
        file = tmp_path / name
        file.write_text("synthetic")
        monkeypatch.setenv(name + "_FILE", str(file))
        monkeypatch.delenv(name + "_PATH", raising=False)
    monkeypatch.setenv("SLI_AGENT_MTLS_CA_FILE", "trust.pem")
    context = Mock()
    monkeypatch.setattr(http_server.ssl, "SSLContext", lambda *a: context)
    assert http_server._load_server_tls_context() is context
    context.load_verify_locations.assert_called_once_with(cafile="trust.pem")
    assert context.verify_mode == ssl.CERT_OPTIONAL
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
