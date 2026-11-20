"""Socket-free HTTP reference vectors; no health scan or database is allowed."""
from __future__ import annotations

import io
import json
from http import HTTPStatus
from pathlib import Path
from unittest.mock import patch

import pytest

from server.api import http_server
from server.api.routes import diagnostics


FIXTURE = Path(__file__).resolve().parents[2] / (
    "server-dotnet/tests/Sli.Server.Tests/Compatibility/system-health-http-source.json"
)
PATH = "/reports/system-health.html"
CASES = [
    {"name": "operator", "url": PATH},
    {"name": "admin", "url": PATH, "role": "admin"},
    {"name": "viewer_with_grant", "url": PATH, "role": "viewer"},
    {"name": "unknown_role", "url": PATH, "role": "unknown"},
    {"name": "anonymous", "url": PATH, "authenticated": False},
    {"name": "anonymous_query", "url": PATH + "?q=a%26b&legacy=1", "authenticated": False},
    {"name": "missing_capability", "url": PATH + "?limit=bad", "grant": "missing"},
    {"name": "scoped_capability", "url": PATH, "grant": "scoped"},
    {"name": "explicit_deny", "url": PATH, "grant": "deny"},
    {"name": "legacy_is_not_a_bypass", "url": PATH + "?legacy=1&force=true&limit=bad"},
    {"name": "invalid_inputs_ignored", "url": PATH + "?timezone=No/Such&time_from=bad&limit=bad"},
    {"name": "empty_values", "url": PATH + "?q=&scope=%20&server="},
    {"name": "first_nonempty_value", "url": PATH + "?q=&q=first&q=second&server=one&server=two"},
    {"name": "first_whitespace_value", "url": PATH + "?q=%20&q=second"},
    {"name": "escaped_query", "url": PATH + "?q=%3Cscript%3E%26%22%27&server=dc.example.test&next=https://example.test"},
    {"name": "unicode_query", "url": PATH + "?q=%D1%82%D0%B5%D1%81%D1%82+%2B&scope=all"},
    {"name": "allowlisted_query", "url": PATH + "?event_id=4625&channel=Security&risk=high&status=open&result_class=ok&risk_class=high&event_db_id=7&entity_id=8&time_from=bad&time_to=bad"},
    {"name": "auth_disabled", "url": PATH, "auth_required": False, "authenticated": False},
    {"name": "auth_disabled_capability_denied", "url": PATH, "auth_required": False, "grant": "missing"},
]


def reference(case):
    handler = object.__new__(http_server.RequestHandler)
    handler.path, handler.headers, handler.wfile = case["url"], {}, io.BytesIO()
    handler._require_secure_api_transport = lambda path: True
    grant = case.get("grant", "global")
    policies = []
    if grant in {"scoped", "deny"}:
        policies = [{"capability_key": "operations.view", "effect": "deny" if grant == "deny" else "allow",
                     "valid": True, "scope": {"kind": "all"} if grant == "deny" else {"kind": "domain", "ids": [7]}}]
    handler._access_decision = lambda: {
        "capabilities": ["operations.view"] if grant in {"global", "deny"} else [],
        "capability_policies": policies,
    }
    response = {"status": 200, "location": None, "json": None}
    handler.send_response = lambda status: response.update(status=int(status))
    handler.send_header = lambda key, value: response.update(location=value) if key == "Location" else None
    handler.end_headers = lambda: None
    handler._send_json = lambda body, status=HTTPStatus.OK: response.update(status=int(status), json=body)
    principal = {"type": "session", "id": 1, "role": case.get("role", "operator")} if case.get("authenticated", True) else None
    with (
        patch.object(http_server, "auth_required", return_value=case.get("auth_required", True)),
        patch.object(http_server, "principal_from_headers", return_value=principal),
        patch.object(diagnostics, "get_system_health", side_effect=AssertionError("unreachable health scan")),
        patch.object(diagnostics, "render_system_health_report", side_effect=AssertionError("unreachable HTML renderer")),
    ):
        handler._do_GET()
    assert handler.wfile.getvalue() == b""
    return response


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_system_health_http_matches_frozen_dotnet_fixture(case):
    vectors = json.loads(FIXTURE.read_text(encoding="utf-8"))
    vector = next(vector for vector in vectors if vector["input"]["name"] == case["name"])
    assert vector["input"] == case
    assert reference(case) == vector["expected"]


if __name__ == "__main__":
    FIXTURE.write_text(json.dumps([{"input": case, "expected": reference(case)} for case in CASES],
                                  ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
