"""Route-equivalence proof for the http_server.py -> server/api/routes/*.py split.

This is a routing test, not a business-logic test: it proves that
`RequestHandler._do_GET`/`_do_POST` still dispatch every path to the same
domain, in the same precedence order, with the same gates, as the single
monolithic file did before tickets 01-07 split it apart. It does not
re-verify what each domain's handlers *do* — that is covered by the
per-domain contract tests each ticket already repointed.

No real socket is used anywhere in this file, matching the existing
contract-test convention (see e.g. tests/migrations/test_sli_v4_contract.py):
`object.__new__(http_server.RequestHandler)` plus targeted monkeypatch.
"""
from __future__ import annotations

from http import HTTPStatus
from types import SimpleNamespace

import pytest

from server.api import http_server
from server.api.routes import access as routes_access
from server.api.routes import ai as routes_ai
from server.api.routes import auth as routes_auth
from server.api.routes import diagnostics as routes_diagnostics
from server.api.routes import entities as routes_entities
from server.api.routes import events as routes_events
from server.api.routes import findings as routes_findings
from server.api.routes import health as routes_health
from server.api.routes import investigations as routes_investigations
from server.api.routes import legacy_reports as routes_legacy_reports
from server.api.routes import objects as routes_objects
from server.api.routes import operations as routes_operations
from server.api.routes import reports as routes_reports
from server.api.routes import runtime as routes_runtime
from server.api.routes import security_monitor as routes_security_monitor
from server.api.routes import semantic as routes_semantic
from server.api.routes import static as routes_static
from server.api.routes import workspace as routes_workspace


def _handler(path: str):
    handler = object.__new__(http_server.RequestHandler)
    handler.path = path
    return handler


@pytest.fixture(autouse=True)
def _no_ambient_auth_requirement(monkeypatch):
    """_do_GET's ambient gate reads auth_required() from the environment
    (ADLOG_AUTH_REQUIRED); force it off so these routing tests don't need to
    fabricate a real session/API-key header on every handler, matching the
    existing convention (see test_detailed_health_requires_operations_capability
    in test_round2_security_reporting.py). Tests that specifically exercise
    an auth denial (e.g. auth's own pre-gate _require_access) are unaffected
    -- that check is independent of this ambient flag."""
    monkeypatch.setattr(http_server, "auth_required", lambda: False)
    monkeypatch.setattr(
        http_server.RequestHandler,
        "_access_decision",
        lambda self: {"platform_owner": True},
    )


# ---------------------------------------------------------------------------
# 1a. GET dispatch coverage: one representative route per domain (18 domains).
# ---------------------------------------------------------------------------

GET_DISPATCH_CASES = [
    ("health", "/api/health/details", routes_health, "try_handle_get"),
    ("static", "/", routes_static, "try_handle_get"),
    ("auth", "/api/auth/users", routes_auth, "try_handle_account_get"),
    ("access", "/api/v1/access/effective", routes_access, "try_handle_get"),
    ("reports", "/api/v1/reports/catalog", routes_reports, "try_handle_get"),
    ("workspace", "/api/v1/workspace", routes_workspace, "try_handle_get"),
    ("events", "/api/v1/events", routes_events, "try_handle_get"),
    ("entities", "/api/v1/entities", routes_entities, "try_handle_get"),
    ("objects", "/api/v1/objects", routes_objects, "try_handle_get"),
    ("investigations", "/api/v1/investigations", routes_investigations, "try_handle_get"),
    ("findings", "/api/findings", routes_findings, "try_handle_get"),
    ("operations", "/api/v1/operations/overview", routes_operations, "try_handle_get"),
    ("runtime", "/api/runtime/status", routes_runtime, "try_handle_get"),
    ("diagnostics", "/api/system/health", routes_diagnostics, "try_handle_get"),
    ("semantic", "/api/v1/semantic/scenarios", routes_semantic, "try_handle_get"),
    ("ai", "/api/ai/runs", routes_ai, "try_handle_get"),
    ("security_monitor", "/api/security/events-monitor", routes_security_monitor, "try_handle_get"),
    ("legacy_reports", "/reports/some-unmapped-report.html", routes_legacy_reports, "try_handle_get"),
]


@pytest.mark.parametrize("label,path,module,attr", GET_DISPATCH_CASES, ids=[c[0] for c in GET_DISPATCH_CASES])
def test_get_dispatches_to_expected_domain(monkeypatch, label, path, module, attr):
    called = []
    monkeypatch.setattr(module, attr, lambda *a, **k: called.append(label) or True)

    handler = _handler(path)
    handler._do_GET()

    assert called == [label]


# ---------------------------------------------------------------------------
# 1b. POST dispatch coverage: one representative mutation route per domain
#     that has one (8 of 18 domains have no POST routes at all).
# ---------------------------------------------------------------------------

POST_DISPATCH_CASES = [
    ("auth", "/api/auth/login", routes_auth, "try_handle_post"),
    ("access", "/api/v1/access/assignments", routes_access, "try_handle_post"),
    ("reports", "/api/v1/reports/definitions", routes_reports, "try_handle_post"),
    ("semantic", "/api/v1/semantic/scenarios/abc/review", routes_semantic, "try_handle_post"),
    ("investigations", "/api/v1/investigations", routes_investigations, "try_handle_post"),
    ("findings", "/api/findings/7/status", routes_findings, "try_handle_post"),
    ("operations", "/api/v1/source-onboarding/preflight", routes_operations, "try_handle_post"),
    ("runtime", "/api/jobs/collect", routes_runtime, "try_handle_post"),
]


@pytest.mark.parametrize("label,path,module,attr", POST_DISPATCH_CASES, ids=[c[0] for c in POST_DISPATCH_CASES])
def test_post_dispatches_to_expected_domain(monkeypatch, label, path, module, attr):
    called = []
    monkeypatch.setattr(module, attr, lambda *a, **k: called.append(label) or True)

    handler = _handler(path)
    handler._do_POST()

    assert called == [label]


# ---------------------------------------------------------------------------
# 2. 401/403 on sensitive routes moved by different tickets — proves the
#    gate is still reached in the right place after the split, not just
#    that *a* response comes back.
# ---------------------------------------------------------------------------

def test_auth_users_get_without_principal_is_401() -> None:
    """Ticket 02: auth's pre-gate try_handle_account_get runs its own
    _require_access("admin") check; no session/API-key header -> 401."""
    handler = _handler("/api/auth/users")
    handler.headers = {}
    sent: list[tuple[dict, HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))

    handler._do_GET()

    assert sent == [({"error": "authentication_required"}, HTTPStatus.UNAUTHORIZED)]


def test_investigation_detail_get_is_403_when_report_not_assigned() -> None:
    """Ticket 05: /api/v1/investigations/<id> is resource-aware (bypasses the
    ambient capability gate) but still gates itself, internally, on report
    assignment via _require_investigation_module. No assigned report -> 403,
    and the case is never actually read."""
    handler = _handler("/api/v1/investigations/1")
    sent: list[tuple[dict, HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    handler._access_decision = lambda: {"capabilities": [], "resource_bound_capabilities": [], "reports": []}

    handler._do_GET()

    assert len(sent) == 1
    payload, status = sent[0]
    assert status == HTTPStatus.FORBIDDEN
    assert payload["error"] == "report_not_assigned"


def test_objects_list_get_is_403_without_capability_via_real_dispatch() -> None:
    """Ticket 03 (closes a ticket-01-review gap): a user with no objects.view
    capability at all must get 403 with required_capability through the real
    dispatch path (try_handle_get -> handler._require_capability), not just
    through a direct call into object_facade_v4. Uses the real
    capability_decision engine (via _access_decision), not a stubbed
    _require_capability, so this proves the production path end to end."""
    handler = _handler("/api/v1/objects")
    sent: list[tuple[dict, HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    handler._access_decision = lambda: {"capabilities": [], "capability_policies": [], "reports": []}

    handler._do_GET()

    assert sent == [(
        {"error": "insufficient_capability", "required_capability": "objects.view"},
        HTTPStatus.FORBIDDEN,
    )]


def test_investigations_list_get_is_404_on_event_scoped_denial_via_real_dispatch(monkeypatch) -> None:
    """Ticket 02 side effect (interfaces.md 'Из тикета 02'): GET
    /api/v1/investigations?event_db_id=... shares _require_investigation_access
    with every other investigations endpoint, so a resource-scoped denial there
    (module check passes, but the event's resource group is outside the
    caller's report grant scope) must answer like a missing resource -- 404
    not_found -- not 403, exercised here through the real dispatch path
    (_do_GET), complementing the case-detail-only coverage already in
    tests/migrations/test_investigation_cases.py."""
    monkeypatch.setattr(routes_investigations, "event_resource_group", lambda _id: [{"kind": "server", "id": 9}])
    monkeypatch.setattr(
        routes_investigations,
        "get_investigations_workspace_data",
        lambda **_k: (_ for _ in ()).throw(
            AssertionError("workspace data must not be read when the scoped check denies")
        ),
    )

    handler = _handler("/api/v1/investigations?event_db_id=99")
    handler._access_decision = lambda: {
        "capabilities": ["investigations.view"],
        "resource_bound_capabilities": [],
        "reports": [{
            "report_key": "investigations.workspace",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{
                "scope": {"kind": "server", "ids": [7]},
                "allowed_actions": ["view"],
                "field_categories": ["security"],
            }],
        }],
    }
    sent: list[tuple[dict, HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))

    handler._do_GET()

    assert sent == [(
        {"error": "not_found", "message": "Investigation resource was not found"},
        HTTPStatus.NOT_FOUND,
    )]


def test_source_onboarding_preflight_has_two_sequential_gates(monkeypatch) -> None:
    """Ticket 06: dispatcher-level _authorize_mutation("operator") +
    _require_capability("operations.view") gate the route; a second,
    stricter _require_access("admin") gates the handler body itself. Make
    the outer gate pass and the inner one fail, and prove the plan is never
    built (both gates are structurally present and run in order)."""
    built: list[str] = []
    monkeypatch.setattr(routes_operations, "plan_dc_onboarding", lambda *a, **k: built.append("plan") or object())

    handler = _handler("/api/v1/source-onboarding/preflight")
    sent: list[tuple[dict, HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    handler._authorize_mutation = lambda **k: True
    handler._require_capability = lambda *a, **k: True
    handler._require_access = lambda role: sent.append(({"error": "insufficient_permissions"}, HTTPStatus.FORBIDDEN)) or False

    handler._do_POST()

    assert built == []
    assert sent[-1] == ({"error": "insufficient_permissions"}, HTTPStatus.FORBIDDEN)


def test_access_assignment_post_is_403_without_capability() -> None:
    """Ticket 02: /api/v1/access/assignments requires
    _authorize_mutation(required_role="admin") AND _require_capability
    ("reports.assign"); denying the capability check must still stop the
    request before any assignment is created."""
    handler = _handler("/api/v1/access/assignments")
    sent: list[tuple[dict, HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    handler._authorize_mutation = lambda **k: True

    def deny(capability, *, resource=None):
        sent.append(({"error": "insufficient_capability", "required_capability": capability}, HTTPStatus.FORBIDDEN))
        return False

    handler._require_capability = deny

    handler._do_POST()

    assert sent == [({"error": "insufficient_capability", "required_capability": "reports.assign"}, HTTPStatus.FORBIDDEN)]


# ---------------------------------------------------------------------------
# 3. 404 exhaustion: an unknown path must actually pass through every
#    domain's try_handle_get (none intercepts it) before falling to the
#    final not_found response.
# ---------------------------------------------------------------------------

_ALL_GET_DOMAIN_ENTRIES = [
    (routes_health, "try_handle_liveness_get"),
    (routes_auth, "try_handle_account_get"),
    (routes_static, "try_handle_login_get"),
    (routes_static, "try_handle_get"),
    (routes_health, "try_handle_get"),
    (routes_access, "try_handle_get"),
    (routes_reports, "try_handle_get"),
    (routes_workspace, "try_handle_get"),
    (routes_events, "try_handle_get"),
    (routes_entities, "try_handle_get"),
    (routes_objects, "try_handle_get"),
    (routes_investigations, "try_handle_get"),
    (routes_findings, "try_handle_get"),
    (routes_operations, "try_handle_get"),
    (routes_runtime, "try_handle_get"),
    (routes_diagnostics, "try_handle_get"),
    (routes_semantic, "try_handle_get"),
    (routes_ai, "try_handle_get"),
    (routes_security_monitor, "try_handle_get"),
    (routes_legacy_reports, "try_handle_get"),
]


def _spy_on_get_domains(monkeypatch) -> list[str]:
    visited: list[str] = []
    for module, attr in _ALL_GET_DOMAIN_ENTRIES:
        original = getattr(module, attr)

        def spy(handler, *rest, _original=original, _key=f"{module.__name__}.{attr}"):
            visited.append(_key)
            return _original(handler, *rest)

        monkeypatch.setattr(module, attr, spy)
    return visited


def test_unknown_path_is_404_without_consulting_any_domain(monkeypatch) -> None:
    """The route registry (ADR 0014, plan 4.3) only calls domains whose ROUTES
    cover the path, so an unknown path reaches no handler at all."""
    visited = _spy_on_get_domains(monkeypatch)
    handler = _handler("/some/totally/unknown/path")
    sent: list[tuple[dict, HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))

    handler._do_GET()

    assert sent == [({"error": "not_found"}, HTTPStatus.NOT_FOUND)]
    assert [key for key in visited if key.endswith(".try_handle_get")] == []


def test_legacy_reports_catch_all_is_consulted_only_for_report_pages(monkeypatch) -> None:
    """routes_legacy_reports' generic startswith("/reports/") fallback must
    never shadow a domain's own, more specific /reports/*.html route."""
    visited = _spy_on_get_domains(monkeypatch)
    handler = _handler("/reports/totally-unknown-page.html")
    handler._send_json = lambda payload, status=HTTPStatus.OK: None
    handler._send_html = lambda *args, **kwargs: None

    handler._do_GET()

    assert [key for key in visited if key.endswith(".try_handle_get")] == ["server.api.routes.legacy_reports.try_handle_get"]


def test_legacy_query_param_is_not_a_bypass_of_the_react_redirect(monkeypatch) -> None:
    """/reports/findings.html has a React parity redirect target. ?legacy=1
    used to be a production escape hatch that reached the legacy page
    directly instead; it no longer is one -- the redirect must still fire,
    and neither the findings domain nor legacy_reports's catch-all should be
    reached (see server.sli.reporting.ui_route_parity.react_route_for_legacy)."""
    called: list[str] = []
    monkeypatch.setattr(routes_findings, "_handle_findings_report", lambda h, q: called.append("findings"))
    monkeypatch.setattr(routes_legacy_reports, "_handle_report", lambda h, p: called.append("legacy_catchall"))

    handler = _handler("/reports/findings.html?legacy=1")
    statuses: list[HTTPStatus] = []
    headers: dict[str, str] = {}
    handler.send_response = lambda status: statuses.append(status)
    handler.send_header = lambda name, value: headers.__setitem__(name, value)
    handler.end_headers = lambda: None

    handler._do_GET()

    assert called == []
    assert statuses == [HTTPStatus.FOUND]
    assert headers["Location"] == "/app/scenarios"


# ---------------------------------------------------------------------------
# 4. Precedence: one test per startswith/endswith conflict named in
#    investigation-routes.md / spec.md §6.
# ---------------------------------------------------------------------------

def test_precedence_reports_export_suffix_over_generic_data_suffix(monkeypatch) -> None:
    called: list[str] = []
    monkeypatch.setattr(routes_reports, "_handle_v4_report_export_api", lambda h, p, q: called.append("export"))
    monkeypatch.setattr(routes_reports, "_handle_v4_report_data_api", lambda h, p, q: called.append("data"))

    handler = object()
    assert routes_reports.try_handle_get(handler, "/api/v1/reports/ad.state/export.csv", {}) is True
    assert called == ["export"]


def test_precedence_jobs_exact_over_job_id_prefix(monkeypatch) -> None:
    called: list[str] = []
    monkeypatch.setattr(routes_runtime, "_handle_get_job", lambda h, p: called.append("get_job"))

    handler = _handler("/api/jobs")
    handler._send_json = lambda *a, **k: called.append("list")

    assert routes_runtime.try_handle_get(handler, "/api/jobs", {}) is True
    assert routes_runtime.try_handle_get(handler, "/api/jobs/42", {}) is True
    assert called == ["list", "get_job"]


def test_precedence_objects_exact_over_type_id_prefix(monkeypatch) -> None:
    called: list[str] = []
    monkeypatch.setattr(routes_objects, "_handle_v4_objects_api", lambda h, q: called.append("list"))
    monkeypatch.setattr(routes_objects, "_handle_v4_object_detail_api", lambda h, p, q: called.append("detail"))

    handler = object()
    assert routes_objects.try_handle_get(handler, "/api/v1/objects", {}) is True
    assert routes_objects.try_handle_get(handler, "/api/v1/objects/asset/42", {}) is True
    assert called == ["list", "detail"]


def test_precedence_investigations_exact_and_cases_over_id_prefix(monkeypatch) -> None:
    called: list[str] = []
    monkeypatch.setattr(routes_investigations, "_handle_v1_investigations_api", lambda h, q: called.append("list"))
    monkeypatch.setattr(routes_investigations, "_handle_v1_investigation_cases_api", lambda h, q: called.append("cases"))
    monkeypatch.setattr(routes_investigations, "_handle_v1_investigation_case_api", lambda h, p, q: called.append("detail"))

    handler = object()
    assert routes_investigations.try_handle_get(handler, "/api/v1/investigations", {}) is True
    assert routes_investigations.try_handle_get(handler, "/api/v1/investigation-cases", {}) is True
    assert routes_investigations.try_handle_get(handler, "/api/v1/investigations/42", {}) is True
    assert called == ["list", "cases", "detail"]


def test_precedence_operations_plugins_exact_over_plugin_id_prefix(monkeypatch) -> None:
    called: list[str] = []
    monkeypatch.setattr(routes_operations, "build_plugin_management_catalog", lambda: called.append("list") or {})
    monkeypatch.setattr(routes_operations, "get_plugin_management", lambda pid: called.append("detail") or {})

    handler = SimpleNamespace()
    handler._send_json = lambda *a, **k: None

    assert routes_operations.try_handle_get(handler, "/api/v1/operations/plugins", {}) is True
    assert routes_operations.try_handle_get(handler, "/api/v1/operations/plugins/sli.remote-access", {}) is True
    assert called == ["list", "detail"]


def test_precedence_events_relations_and_entities_suffix_over_generic_by_id(monkeypatch) -> None:
    called: list[str] = []
    monkeypatch.setattr(routes_events, "_handle_event_relations_api", lambda h, p: called.append("relations"))
    monkeypatch.setattr(routes_events, "_handle_event_entities_api", lambda h, p: called.append("entities"))
    monkeypatch.setattr(routes_events, "_handle_event_by_id_api", lambda h, p: called.append("by_id"))

    handler = object()
    assert routes_events.try_handle_get(handler, "/api/v1/events/42/relations", {}) is True
    assert routes_events.try_handle_get(handler, "/api/v1/events/42/entities", {}) is True
    assert routes_events.try_handle_get(handler, "/api/v1/events/42", {}) is True
    assert called == ["relations", "entities", "by_id"]


def test_precedence_auth_users_password_suffix_over_generic_update(monkeypatch) -> None:
    called: list[str] = []
    monkeypatch.setattr(routes_auth, "_handle_user_create", lambda h: called.append("create"))
    monkeypatch.setattr(routes_auth, "_handle_user_password_reset", lambda h, p: called.append("password"))
    monkeypatch.setattr(routes_auth, "_handle_user_update", lambda h, p: called.append("update"))

    handler = object()
    assert routes_auth.try_handle_post(handler, "/api/auth/users") is True
    assert routes_auth.try_handle_post(handler, "/api/auth/users/42/password") is True
    assert routes_auth.try_handle_post(handler, "/api/auth/users/42") is True
    assert called == ["create", "password", "update"]


def test_precedence_access_report_requests_decision_suffix_over_create(monkeypatch) -> None:
    called: list[str] = []
    monkeypatch.setattr(routes_access, "_handle_report_access_request_create", lambda h: called.append("create"))
    monkeypatch.setattr(routes_access, "_handle_report_access_request_decision", lambda h, p: called.append("decision"))

    handler = SimpleNamespace()
    handler._authorize_mutation = lambda **k: True
    handler._require_capability = lambda *a, **k: True

    assert routes_access.try_handle_post(handler, "/api/v1/access/report-requests") is True
    assert routes_access.try_handle_post(handler, "/api/v1/access/report-requests/7/decision") is True
    assert called == ["create", "decision"]


def test_precedence_domain_html_report_over_legacy_reports_catchall(monkeypatch) -> None:
    """Covers the /reports/* conflict directly against the domain that owns
    the specific page (findings), complementing the full-dispatch version
    above with a same-file-level check within legacy_reports.py itself:
    legacy_reports.try_handle_get must not be reached at all when a domain
    already claimed the path earlier in http_server.py's call sequence."""
    called: list[str] = []
    monkeypatch.setattr(routes_legacy_reports, "_handle_report", lambda h, p: called.append("legacy_catchall"))

    handler = object()
    # legacy_reports.py has no knowledge of other domains -- it only ever
    # sees a path if http_server.py calls it, so exercising it directly on
    # a domain-owned path proves it WOULD swallow it if called out of order.
    assert routes_legacy_reports.try_handle_get(handler, "/reports/findings.html", {}) is True
    assert called == ["legacy_catchall"]


# ---------------------------------------------------------------------------
# 5. Error handling: an unhandled exception from a domain handler still
#    becomes a generic 500 via http_server.py's top-level try/except.
# ---------------------------------------------------------------------------

def test_get_unhandled_domain_exception_becomes_generic_500(monkeypatch) -> None:
    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(routes_events, "try_handle_get", boom)
    monkeypatch.setattr(http_server, "log_internal_error", lambda *a, **k: "INT-TEST-GET")

    handler = _handler("/api/v1/events")
    handler._admit_request = lambda: True
    sent: list[tuple[dict, HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    handler.server = type("S", (), {"request_slots": type("Q", (), {"release": lambda self: None})()})()

    handler.do_GET()

    assert sent == [({"error": "internal_server_error", "internal_error_id": "INT-TEST-GET"}, HTTPStatus.INTERNAL_SERVER_ERROR)]


def test_post_unhandled_domain_exception_becomes_generic_500(monkeypatch) -> None:
    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(routes_runtime, "try_handle_post", boom)
    monkeypatch.setattr(http_server, "log_internal_error", lambda *a, **k: "INT-TEST-POST")

    handler = _handler("/api/jobs/collect")
    handler._admit_request = lambda: True
    sent: list[tuple[dict, HTTPStatus]] = []
    handler._send_json = lambda payload, status=HTTPStatus.OK: sent.append((payload, status))
    handler.server = type("S", (), {"request_slots": type("Q", (), {"release": lambda self: None})()})()

    handler.do_POST()

    assert sent == [({"error": "internal_server_error", "internal_error_id": "INT-TEST-POST"}, HTTPStatus.INTERNAL_SERVER_ERROR)]
