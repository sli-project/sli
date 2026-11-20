"""Execute the frozen HTTP handler with synthetic identity/access facts, no sockets or DB."""
from __future__ import annotations

import json
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server.api import http_server


HERE = Path(__file__).resolve().parent


def reference_vectors():
    cases = [
        {"name": "owner", "owner": True},
        *({"name": role, "role": role} for role in ("viewer", "operator", "admin")),
        {"name": "anonymous", "role": None},
        {"name": "unknown_role", "role": "report_reader"},
        {"name": "missing_capability", "grant": False},
        {"name": "explicit_deny", "effect": "deny"},
        {"name": "scoped_allow", "scope": {"kind": "domain", "ids": [1]}},
        {"name": "scoped_deny", "effect": "deny", "scope": {"kind": "domain", "ids": [1]}},
        {"name": "insecure_transport", "secure": False},
        {"name": "auth_disabled", "auth_required": False, "owner": True},
        {"name": "auth_disabled_denied", "auth_required": False, "grant": False},
        *({"name": "query_" + str(i), "query": query} for i, query in enumerate((
            "?refresh=1", "?refresh=true&force=yes", "?refresh=&refresh=1",
            "?view=security&limit=-1", "?view=%3Cscript%3E&unknown=x", "?format=html",
        ))),
    ]
    vectors = []
    for case in cases:
        role = case.get("role", "viewer")
        scope = case.get("scope", {"kind": "all"})
        effect = case.get("effect", "allow")
        grant = case.get("grant", True)
        access = {
            "platform_owner": case.get("owner", False),
            "capabilities": ["workspace.view"] if grant and effect == "allow" and scope == {"kind": "all"} else [],
            "capability_policies": [{"capability_key": "workspace.view", "effect": effect, "scope": scope, "valid": True}] if grant else [],
        }
        handler = object.__new__(http_server.RequestHandler)
        handler.path = "/api/role-views" + case.get("query", "")
        handler.command = "GET"
        handler.headers = {"Accept": "text/html"}
        handler.server = SimpleNamespace(
            request_slots=SimpleNamespace(release=lambda: None),
            adlog_trusted_proxies=("192.0.2.1/32",),
        )
        handler._admit_request = lambda: True
        handler._secure_transport = lambda: case.get("secure", True)
        access_reads = []

        def facts():
            access_reads.append(True)
            return access

        handler._access_decision = facts
        sent = []
        handler._send_json = lambda body, status=HTTPStatus.OK: sent.append((int(status), body))
        errors = []

        def log_error(*args, **kwargs):
            errors.append(str(kwargs["exc"]))
            return "reference-error-id"

        principal = {"type": "session", "id": 1, "role": role} if role else None
        with (
            patch.object(http_server, "auth_required", return_value=case.get("auth_required", True)),
            patch.object(http_server, "principal_from_headers", return_value=principal),
            patch.object(http_server, "log_internal_error", side_effect=log_error),
        ):
            handler.do_GET()
        assert len(sent) == 1
        status, body = sent[0]
        vectors.append({"input": case, "status": status, "body": body,
                        "access_reads": len(access_reads), "errors": errors})
    return vectors


def test_frozen_role_views_http_vectors():
    expected = json.loads((HERE / "role-views-reference.json").read_text(encoding="utf-8"))
    assert reference_vectors() == expected
    for vector in expected:
        if vector["status"] == 500:
            assert vector["errors"] == ["storage_v2_role_views_requires_preloaded_snapshot"]


if __name__ == "__main__":
    (HERE / "role-views-reference.json").write_text(
        json.dumps(reference_vectors(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
