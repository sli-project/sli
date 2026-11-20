"""Agent administration uses effective capabilities, not the coarse admin role."""
from http import HTTPStatus

import pytest

from server.api import http_server
from server.api.routes import agents
from server.sli.access.access_control_v4 import route_capability

ADMIN_GET = ("/api/v1/admin/agents", "/api/v1/admin/agent-tokens")
ADMIN_POST = ("/api/v1/admin/agents/modules", "/api/v1/admin/agents/rights-probe",
              "/api/v1/admin/agents/file-audit",
              "/api/v1/admin/agents/policy",
              "/api/v1/admin/agents/disable", "/api/v1/admin/agents/revoke", "/api/v1/admin/agent-tokens")


@pytest.mark.parametrize("method,path", [("GET", path) for path in ADMIN_GET] + [("POST", path) for path in ADMIN_POST])
@pytest.mark.parametrize("authenticated,owner,manage,denied,expected", [
    (False, False, False, False, 401),
    (True, False, False, False, 403),
    (True, True, False, False, 200),
    (True, False, True, False, 200),
    (True, False, True, True, 403),
])
def test_real_handler_effective_agent_admin_access(monkeypatch, method, path, authenticated, owner, manage, denied, expected):
    assert route_capability(path) == "access.manage"
    handler = object.__new__(http_server.RequestHandler)
    handler.headers = {}
    handler._effective_access_cache = {
        "platform_owner": owner, "capabilities": ["access.manage"] if manage else [],
        "capability_policies": [{"capability_key": "access.manage", "effect": "deny", "valid": True,
                                 "scope": {"kind": "all"}}] if denied else [],
    }
    responses, operations = [], []
    handler._send_json = lambda body, status=HTTPStatus.OK, **kwargs: responses.append(status)
    handler._read_json_body = lambda: {"agent_id": "synthetic"}
    handler._authorize_mutation = lambda **kwargs: True
    # Use real _require_access/_require_capability with a fake authenticated
    # principal; no database or real session/access loader is involved.
    monkeypatch.setattr(http_server, "principal_from_headers", lambda headers: {
        "type": "session", "id": 1, "role": "admin"} if authenticated else None)
    monkeypatch.setattr(http_server, "auth_required", lambda: True)
    monkeypatch.setattr(agents, "_execute", lambda *args, **kwargs: operations.append(path))
    if method == "GET":
        assert agents.try_handle_get(handler, path, {})
    else:
        assert agents.try_handle_post(handler, path)
    assert bool(operations) is (expected == 200)
    if expected != 200:
        assert responses == [expected]


def test_policy_report_has_no_ambient_user_capability():
    assert route_capability("/api/v1/agent/policy-report") is None
    assert ("POST", "/api/v1/agent/policy-report") in agents.ROUTES
