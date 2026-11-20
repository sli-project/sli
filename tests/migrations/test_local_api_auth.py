from __future__ import annotations

from collections import OrderedDict
import threading

import pytest

pytestmark = pytest.mark.core

from server.sli.access import auth


def test_passwords_use_argon2id_and_verify() -> None:
    encoded = auth.PASSWORD_HASHER.hash("correct horse battery staple")
    assert encoded.startswith("$argon2id$")
    assert auth.PASSWORD_HASHER.verify(encoded, "correct horse battery staple")


def test_roles_and_usernames_are_validated() -> None:
    assert auth._valid_username("operator.admin") == "operator.admin"
    assert auth._valid_role("operator") == "operator"
    for value in ("a", "spaces are bad", "../../bad"):
        try:
            auth._valid_username(value)
        except ValueError:
            pass
        else:  # pragma: no cover - clear failure message instead of a bare assert
            raise AssertionError(f"username should be rejected: {value}")


def test_role_permissions_are_ordered() -> None:
    assert auth.allows({"role": "admin"}, "operator")
    assert auth.allows({"role": "operator"}, "viewer")
    assert not auth.allows({"role": "viewer"}, "operator")
    assert not auth.allows(None, "viewer")


def test_product_role_labels_are_explicit() -> None:
    assert auth.ROLE_LABELS == {
        "viewer": "ИБ",
        "operator": "ИТ",
        "admin": "Администратор",
    }


def test_api_key_is_not_plaintext_persisted_form() -> None:
    token = "adl_a_token_that_must_not_be_stored_as_is"
    assert auth._digest(token) != token
    assert auth._digest(token) == auth._digest(token)


def test_browser_reports_are_redirected_to_sign_in_when_session_is_missing() -> None:
    source = __import__("pathlib").Path("server/api/http_server.py").read_text(encoding="utf-8")
    assert 'self.send_header("Location", "/login?" + urlencode({"next": self.path}))' in source
    assert 'if path.startswith("/api/"):' in source


def test_server_restart_preserves_remember_me_sessions() -> None:
    source = __import__("pathlib").Path("server/api/http_server.py").read_text(encoding="utf-8")
    startup_block = source[source.index("def run_server"):]
    assert "revoke_all_sessions()" not in startup_block
    assert "web_sessions_preserved=True" in startup_block


def test_operational_reports_are_server_side_it_only() -> None:
    source = __import__("pathlib").Path("server/api/http_server.py").read_text(encoding="utf-8")
    assert '"/reports/storage-health.html"' in source
    assert '"/reports/collector-health.html"' in source
    assert 'return "operator"' in source


def test_password_reset_and_access_changes_are_audited_without_plaintext() -> None:
    source = __import__("pathlib").Path("server/sli/access/auth.py").read_text(encoding="utf-8")
    assert "def reset_user_password" in source
    assert "user_password_reset" in source
    assert "insert into auth_audit" in source
    assert "password" not in source[source.index("def _audit"):source.index("def create_user")].lower()


def test_login_outcomes_and_last_admin_guard_are_recorded_in_source() -> None:
    auth_source = __import__("pathlib").Path("server/sli/access/auth.py").read_text(encoding="utf-8")
    route_source = __import__("pathlib").Path("server/api/routes/auth.py").read_text(encoding="utf-8")
    assert "select id from auth_users where role='admin' and is_active=true order by id for update" in auth_source
    assert 'action="login", outcome="failed"' in route_source
    assert 'action="login", remote_address=handler.client_address[0]' in route_source


def test_api_keys_have_admin_lifecycle_and_one_time_secret_response() -> None:
    auth_source = __import__("pathlib").Path("server/sli/access/auth.py").read_text(encoding="utf-8")
    route_source = __import__("pathlib").Path("server/api/routes/auth.py").read_text(encoding="utf-8")
    assert "def list_api_keys" in auth_source
    assert "api_key_revoked" in auth_source
    assert '"token": token' in route_source
    assert "This is the one and only response which contains the secret token" in route_source


def test_login_bruteforce_protection_and_browser_security_headers_are_centralized() -> None:
    source = __import__("pathlib").Path("server/api/http_server.py").read_text(encoding="utf-8")
    route_source = __import__("pathlib").Path("server/api/routes/auth.py").read_text(encoding="utf-8")
    assert "def login_allowed" in source
    assert "recent.append(now)" in source
    assert "record_login_failure" not in route_source
    assert "clear_login_failures" not in route_source
    assert '"login_temporarily_locked"' in route_source
    assert '"Retry-After"' in route_source
    assert '"X-Content-Type-Options", "nosniff"' in source
    assert '"X-Frame-Options", "DENY"' in source
    assert "SAMEORIGIN" not in source and "frame-ancestors 'none'" in source
    assert '"Content-Security-Policy"' in source
    assert '"Cache-Control", "no-store, max-age=0"' in source


def test_ui_shell_and_login_do_not_consume_dynamic_rate_buckets() -> None:
    from server.api.http_server import _request_rate_bucket

    for path in (
        "/",
        "/login",
        "/app/",
        "/app/operations",
        "/app/assets/product-main.js",
        "/sli-login.css",
        "/assets/sli-login/sli-logo.svg",
        "/api/health",
    ):
        assert _request_rate_bucket("GET", path) is None
    assert _request_rate_bucket("POST", "/api/auth/login") is None
    assert _request_rate_bucket("GET", "/api/v1/workspace") == "api"
    assert _request_rate_bucket("GET", "/reports/storage-health.html") == "reports"


def test_dynamic_rate_limits_are_isolated_by_bucket() -> None:
    from server.api.http_server import ProtectedHTTPServer

    server = object.__new__(ProtectedHTTPServer)
    server.rate_per_minute = 2
    server.rate_lock = threading.Lock()
    server.client_request_times = OrderedDict()

    assert server.admit_client("192.0.2.9", "api")
    assert server.admit_client("192.0.2.9", "api")
    assert not server.admit_client("192.0.2.9", "api")
    assert server.admit_client("192.0.2.9", "reports")
    assert server.admit_client("192.0.2.10", "api")


def test_investigation_mutation_dispatch_uses_infosec_role(monkeypatch) -> None:
    from server.api import http_server
    from server.api.routes import investigations as routes_investigations

    handler = object.__new__(http_server.RequestHandler)
    handler.path = "/api/v1/investigations"
    required: list[str] = []
    called: list[str] = []
    handler._authorize_mutation = lambda *, required_role="operator": required.append(required_role) or True
    handler._require_capability = lambda capability: capability == "investigations.manage"
    monkeypatch.setattr(routes_investigations, "_handle_v1_investigation_create", lambda h: called.append("create"))

    handler._do_POST()

    assert required == ["viewer"]
    assert called == ["create"]


def test_operational_mutation_dispatch_remains_operator_only(monkeypatch) -> None:
    from server.api import http_server
    from server.api.routes import runtime as routes_runtime

    handler = object.__new__(http_server.RequestHandler)
    handler.path = "/api/jobs/collect"
    required: list[str] = []
    capabilities: list[str] = []
    called: list[str] = []
    handler._authorize_mutation = lambda *, required_role="operator": required.append(required_role) or True
    handler._require_capability = lambda capability: capabilities.append(capability) or True
    monkeypatch.setattr(routes_runtime, "_handle_collect_job", lambda h: called.append("collect"))

    handler._do_POST()

    assert required == ["operator"]
    assert capabilities == ["operations.view"]
    assert called == ["collect"]


def test_auth_runtime_uses_read_only_schema_guard_and_versioned_migration() -> None:
    from pathlib import Path

    auth_source = Path("server/sli/access/auth.py").read_text(encoding="utf-8")
    ensure_block = auth_source[auth_source.index("def ensure_auth_schema"):auth_source.index("def _audit")]
    migration = Path("config/postgres_migrations/014_local_auth_runtime_guard.sql").read_text(encoding="utf-8")

    assert "require_table_columns" in ensure_block
    assert "minimum_schema_version=14" in ensure_block
    assert "create table" not in ensure_block.lower()
    assert "create index" not in ensure_block.lower()
    assert "create table if not exists auth_users" in migration.lower()
    assert "values (14, 'local_auth_runtime_guard')" in migration.lower()


def test_findings_runtime_does_not_execute_schema_ddl() -> None:
    from pathlib import Path

    source = Path("server/sli/semantic/findings_pg_pipeline.py").read_text(encoding="utf-8")
    ensure_block = source[source.index("def ensure_findings_pg_schema"):source.index("def _event_candidate")]

    assert "require_table_columns" in ensure_block
    assert "create table" not in ensure_block.lower()
    assert "alter table" not in ensure_block.lower()
    assert "insert into schema_migrations" not in ensure_block.lower()


def test_successful_authentication_updates_usage_timestamps_with_throttling() -> None:
    from pathlib import Path

    source = Path("server/sli/access/auth.py").read_text(encoding="utf-8")
    read_block = source[source.index("def authenticate_session"):source.index("def principal_from_headers")]

    assert "select u.id" in read_block.lower()
    assert "select id, key_prefix" in read_block.lower()
    assert "update auth_sessions set last_used_at=now()" in read_block.lower()
    assert "update auth_api_keys set last_used_at=now()" in read_block.lower()
    assert "interval '5 minutes'" in read_block.lower()


def test_content_security_policy_uses_nonce_for_executable_inline_content() -> None:
    from pathlib import Path

    source = Path("server/api/http_server.py").read_text(encoding="utf-8")
    assert "script-src 'self' 'unsafe-inline'" not in source
    assert "style-src 'self' 'unsafe-inline'" not in source
    assert "'nonce-{nonce}'" in source
    assert "script-src-attr 'none'" in source
