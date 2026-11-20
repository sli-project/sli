"""T089: plugin-owned settings keep the existing storage and access contracts."""
import ast
import json
from copy import deepcopy
from http import HTTPStatus
from pathlib import Path
from types import MethodType, SimpleNamespace
from urllib.parse import urlparse

import pytest
import yaml

from server.api.route_registry import RouteRegistry
from server.api.routes import settings as routes
from server.sli.core import platform_settings
from server.sli.plugin_validation import load_package_settings_schema

ROOT = Path(__file__).resolve().parents[2]


class Handler:
    client_address = ("127.0.0.1", 0)

    def __init__(self, body=None, *, allow=True):
        self._principal = {"username": "fixture-admin", "role": "admin"}
        self.body = body
        self.allow = allow
        self.checks = []
        self.response = None
        self.status = None

    def _send_json(self, value, status=HTTPStatus.OK):
        self.response, self.status = value, status

    def _require_capability(self, capability):
        self.checks.append(("capability", capability))
        return self.allow

    def _authorize_mutation(self, *, required_role):
        self.checks.append(("mutation", required_role))
        return self.allow

    def _read_json_body(self):
        return self.body


@pytest.fixture
def stored(monkeypatch):
    values = {
        "reports.domain_fqdn": "fixture.example.invalid",
        "ad.inactivity_days": "113",
        "ad.service_account_exceptions": '["S-1-5-21-1-2-3-1000"]',
        "workstations.logon_policy": '{"version":2,"policies":[]}',
        "workstations.evidence_retention_days": "123",
    }
    before = deepcopy(values)
    monkeypatch.setattr(platform_settings, "_stored_row", lambda key:
        {"value": values[key], "updated_by": "fixture-admin", "updated_at": None}
        if key in values else None)
    yield values
    assert values == before  # GET is an in-place compatibility read, never a migration write.


@pytest.mark.parametrize("plugin_id", ["sli.ad", "sli.gpo", "sli.workstations", "sli.file-audit", "sli.remote-access", "sli.sigma"])
def test_get_schema_and_values_preserve_legacy_keys(stored, plugin_id):
    h = Handler()
    assert routes.try_handle_get(h, f"/api/plugins/{plugin_id}/settings", {})
    assert h.status == 200
    assert h.checks == [("capability", "access.manage")]
    metadata = load_package_settings_schema(plugin_id)
    assert h.response["schema"] == metadata["settings"]
    assert set(h.response["values"]) == set(metadata["settings"]["properties"])
    if plugin_id == "sli.ad":
        assert h.response["values"]["ad.inactivity_days"] == 113
        assert h.response["values"]["reports.domain_fqdn"] == stored["reports.domain_fqdn"]
        assert h.response["values"]["ad.service_account_exceptions"] == json.loads(stored["ad.service_account_exceptions"])
    if plugin_id == "sli.workstations":
        assert h.response["values"]["workstations.evidence_retention_days"] == 123
        assert h.response["values"]["workstations.logon_policy"] == {"version": 2, "policies": []}
    if plugin_id == "sli.file-audit":
        assert h.response["schema"]["x-core-settings"] == ["security.working_time"]


def test_get_denied_before_read(stored, monkeypatch):
    monkeypatch.setattr(platform_settings, "_stored_row", lambda key: pytest.fail("denied read"))
    h = Handler(allow=False)
    assert routes.try_handle_get(h, "/api/plugins/sli.ad/settings", {})
    assert h.response is None


@pytest.mark.parametrize("plugin_id", ["unknown.plugin", "../sli.ad", "sli.ad/extra"])
def test_unknown_plugin_is_not_read(stored, plugin_id):
    h = Handler()
    assert routes.try_handle_get(h, f"/api/plugins/{plugin_id}/settings", {})
    assert h.status == 404


def test_put_validates_then_reuses_atomic_writer_and_value_free_audit(monkeypatch):
    calls, audits = [], []
    def write(key, value, *, actor, audit):
        calls.append((key, value, actor))
        audit("cursor", {"key": key, "previous": "90", "value": value})
        return {"key": key, "value": value}
    monkeypatch.setattr(routes, "set_setting", write)
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", lambda **kw: audits.append(kw))
    h = Handler({"key": "ad.inactivity_days", "value": 120})
    assert routes.try_handle_put(h, "/api/plugins/sli.ad/settings")
    assert h.status == 200
    assert h.checks == [("mutation", "admin"), ("capability", "access.manage")]
    assert calls == [("ad.inactivity_days", "120", "fixture-admin")]
    assert len(audits) == 1 and audits[0]["cursor"] == "cursor"
    assert audits[0]["details"] == {"plugin_id": "sli.ad", "key": "ad.inactivity_days"}


@pytest.mark.parametrize("body", [
    {}, {"key": "ad.inactivity_days", "value": True},
    {"key": "ad.inactivity_days", "value": "120"},
    {"key": "ad.inactivity_days", "value": 0},
    {"key": "ad.inactivity_days", "value": 3651},
    {"key": "workstations.evidence_retention_days", "value": 120},
    {"key": "security.working_time", "value": {}},
    {"key": "ad.inactivity_days", "value": 120, "extra": "no"},
])
def test_put_rejects_invalid_and_cross_plugin_values_before_write(monkeypatch, body):
    monkeypatch.setattr(routes, "set_setting", lambda *a, **kw: pytest.fail("invalid write"))
    h = Handler(body)
    assert routes.try_handle_put(h, "/api/plugins/sli.ad/settings")
    assert h.status == 400
    assert h.response == {"error": "invalid_plugin_setting_value"}


def test_put_denied_before_body(monkeypatch):
    h = Handler(allow=False)
    h._read_json_body = lambda: pytest.fail("denied body read")
    assert routes.try_handle_put(h, "/api/plugins/sli.ad/settings")
    assert h.checks == [("mutation", "admin")]


def test_put_route_is_registered():
    registry = RouteRegistry((routes,))
    assert registry.candidates("PUT", "/api/plugins/sli.ad/settings") == [routes]
    h = Handler(allow=False)
    assert registry.dispatch_put(h, "/api/plugins/sli.ad/settings")


def test_core_does_not_declare_plugin_setting_specs():
    tree = ast.parse((ROOT / "server/sli/core/platform_settings.py").read_text())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == "SettingSpec"]
    assert len(calls) == 1  # Only the shared working-time setting remains core-owned.


def test_unset_values_are_null_not_persisted(monkeypatch):
    monkeypatch.setattr(platform_settings, "_stored_row", lambda key: None)
    h = Handler()
    assert routes.try_handle_get(h, "/api/plugins/sli.ad/settings", {})
    assert h.response["values"]["reports.domain_fqdn"] is None
    assert h.response["values"]["ad.inactivity_days"] == 90


def test_secret_declaration_fails_closed_before_read(monkeypatch):
    from server.sli.plugins import settings
    metadata = load_package_settings_schema("sli.ad")
    metadata["settings"]["properties"]["ad.inactivity_days"].update({"x-secret": True, "default": "never-return"})
    monkeypatch.setattr(settings, "load_package_settings_schema", lambda _: metadata)
    monkeypatch.setattr(platform_settings, "_stored_row", lambda key: pytest.fail("secret read"))
    h = Handler()
    assert routes.try_handle_get(h, "/api/plugins/sli.ad/settings", {})
    assert h.status == 503
    assert h.response == {"error": "plugin_settings_unavailable"}


def test_put_legacy_validation_errors_do_not_echo_values(monkeypatch):
    def reject(*a, **kw):
        raise ValueError("never-return")
    monkeypatch.setattr(routes, "set_setting", reject)
    h = Handler({"key": "ad.inactivity_days", "value": 120})
    assert routes.try_handle_put(h, "/api/plugins/sli.ad/settings")
    assert h.response == {"error": "invalid_plugin_setting_value"}


def test_settings_namespace_requires_access_manage_without_serving_unknown_routes():
    from server.sli.access.access_control_v4 import route_capability
    assert route_capability("/api/plugins/sli.ad/settings") == "access.manage"
    for path in ("/api/plugins/", "/api/plugins/{}/settings",
                 "/api/plugins/sli.ad/settings-extra", "/api/plugins/sli.ad/other"):
        assert route_capability(path) == "access.manage"
    # Classification is not authorization or registration of another handler.
    for path in ("/api/plugins/", "/api/plugins/sli.ad/settings-extra", "/api/plugins/sli.ad/other"):
        h = Handler()
        assert routes.try_handle_get(h, path, {}) is False
        assert routes.try_handle_put(h, path) is False
        assert h.response is None
    assert route_capability("/api/plugins-extra/sli.ad/settings") is None


def test_old_screen_settings_order_labels_defaults_and_validators_are_preserved():
    keys = list(platform_settings.SETTINGS)
    assert keys == ["reports.domain_fqdn", "ad.snapshot_history_days",
                    "workstations.evidence_retention_days", "ad.password_max_age_days",
                    "ad.inactivity_days", "ad.service_account_exceptions",
                    "windows_auth.distributed_window_hours", "windows_auth.distributed_min_accounts",
                    "windows_auth.distributed_min_sources", "windows_auth.distributed_max_failures_per_account",
                    "security.working_time", "workstations.logon_policy"]
    assert platform_settings.SETTINGS["reports.domain_fqdn"].label == "Домен отчётов"
    assert platform_settings.SETTINGS["ad.inactivity_days"].default == "90"
    assert platform_settings._dns_name(" Fixture.Example.Invalid ") == "fixture.example.invalid"


def _http_method(name, **dependencies):
    """Execute the real ingress method without importing unrelated report plugins."""
    tree = ast.parse((ROOT / "server/api/http_server.py").read_text())
    handler = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "RequestHandler")
    method = next(n for n in handler.body if isinstance(n, ast.FunctionDef) and n.name == name)
    namespace = {"urlparse": urlparse, "HTTPStatus": HTTPStatus,
                 "ROUTE_REGISTRY": RouteRegistry((routes,)), **dependencies}
    exec(compile(ast.Module(body=[method], type_ignores=[]), "http_server.py", "exec"), namespace)
    return namespace[name]


def test_put_ingress_requires_secure_transport_before_dispatch():
    h = Handler()
    h.path = "/api/plugins/sli.ad/settings"
    h._require_secure_api_transport = lambda path: False
    h._read_json_body = lambda: pytest.fail("insecure body read")
    _http_method("_do_PUT")(h)
    assert h.checks == []


def test_put_uses_actual_origin_and_admin_authorization():
    h = Handler({"key": "ad.inactivity_days", "value": 120})
    h.path = "/api/plugins/sli.ad/settings"
    h._require_secure_api_transport = lambda path: True
    h._check_request_origin = lambda: False
    h._authorize_mutation = MethodType(_http_method("_authorize_mutation", auth_required=lambda: True), h)
    h._read_json_body = lambda: pytest.fail("cross-origin body read")
    _http_method("_do_PUT")(h)
    assert h.checks == []
    h._check_request_origin = lambda: True
    h._require_access = lambda role: h.checks.append(("role", role)) or False
    _http_method("_do_PUT")(h)
    assert h.checks == [("role", "admin")]


def test_put_ingress_releases_slot_and_redacts_unexpected_errors():
    h = Handler()
    h.path = "/api/plugins/sli.ad/settings"
    released, logged = [], []
    h.server = SimpleNamespace(request_slots=SimpleNamespace(release=lambda: released.append(True)))
    h._admit_request = lambda: True
    def failed():
        raise RuntimeError("never-return-private-value")
    h._do_PUT = failed
    class InputError(Exception):
        pass
    def log(*args, **kw):
        logged.append(kw)
        return "fixture-error"
    _http_method("do_PUT", RequestInputError=InputError, log_internal_error=log,
                 _safe_request_path=lambda path: path)(h)
    assert released == [True]
    assert h.status == 500
    assert h.response == {"error": "internal_server_error", "internal_error_id": "fixture-error"}
    assert str(logged[0]["exc"]) == "RuntimeError"
    assert logged[0]["exc"].__context__ is None


def test_openapi_documents_actual_get_and_single_key_put_contract():
    spec = yaml.safe_load((ROOT / "docs/api/openapi.yaml").read_text())
    path = spec["paths"]["/api/plugins/{id}/settings"]
    assert ("GET", "/api/plugins/{}/settings") in routes.ROUTES
    assert ("PUT", "/api/plugins/{}/settings") in routes.ROUTES
    assert set(path) == {"get", "put"}
    request = path["put"]["requestBody"]["content"]["application/json"]["schema"]
    assert set(request["required"]) == {"key", "value"}
    assert request["additionalProperties"] is False
    for method in ("get", "put"):
        assert path[method]["parameters"] == [{
            "name": "id", "in": "path", "required": True,
            "schema": {"type": "string", "enum": ["sli.ad", "sli.gpo", "sli.workstations",
                      "sli.file-audit", "sli.remote-access", "sli.sigma"]},
        }]
        assert {"200", "401", "403", "404"} <= path[method]["responses"].keys()
        assert "access.manage" in path[method]["description"]


@pytest.mark.parametrize("locale", ["ru", "en"])
@pytest.mark.parametrize("code", ["plugin_settings_not_found", "plugin_settings_unavailable", "invalid_plugin_setting_value"])
def test_plugin_settings_error_envelopes_are_localized(locale, code):
    from server.sli.core.messages import response_messages
    response = response_messages({"error": code}, locale)
    assert response["message"]["code"] == code
    assert response["message"]["text"] and response["message"]["text"] != code
    frontend = (ROOT / f"frontend/src/i18n/{locale}.ts").read_text()
    assert json.dumps(code) + ": " + json.dumps(response["message"]["text"], ensure_ascii=False) in frontend
