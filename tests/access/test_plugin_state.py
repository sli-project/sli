from http import HTTPStatus

import pytest
from psycopg import OperationalError
from psycopg.errors import InsufficientPrivilege, RaiseException

from server.api.routes import operations, reports, reports_v2, static
from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    ReportDefinition,
    result,
)
from server.sli.sources import plugin_state as state
from server.source_packs.radius.collection_routes import RadiusCollectionRouteError

ITEM = {
    "plugin_id": "sli.remote-access", "package_version": "0.1.0", "installed": True,
    "configured": True, "enabled": False, "receiving_data": False,
    "component_runtime": "draining", "queue_state": "backlog", "revision": 5,
    "last_data_at_utc": None,
}
ADMIN = {"type": "session", "id": 7, "role": "admin"}
MANAGE = {"capabilities": ["plugins.manage"]}


class Connection:
    def __init__(self, row=ITEM, error=None):
        self.row, self.error = row, error
        self.calls = []
        self.commits = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def cursor(self):
        return self

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        if self.error:
            raise self.error

    def fetchone(self):
        return self.row

    def fetchall(self):
        return [self.row]

    def commit(self):
        self.commits += 1


class Handler:
    def __init__(self, principal=ADMIN, access=None, body=None):
        self._principal = principal
        self.access = MANAGE if access is None else access
        self.body = body if body is not None else {"enabled": False, "expected_revision": 4}
        self.sent = None
        self.body_reads = 0
        self.authorized = True

    def _access_decision(self):
        return self.access

    def _authorize_mutation(self, *, required_role):
        assert required_role == "viewer"
        return self.authorized

    def _require_capability(self, key):
        assert key == "operations.view"
        return self.authorized

    def _read_json_body(self):
        self.body_reads += 1
        return self.body

    def _send_json(self, payload, status=HTTPStatus.OK):
        self.sent = (payload, int(status))


@pytest.fixture
def connection(monkeypatch):
    conn = Connection()
    monkeypatch.setattr(state, "connect", lambda: conn)
    monkeypatch.setattr(state, "remote_access_configured", lambda: True)
    from server.sli.sources import plugin_receipts
    monkeypatch.setattr(plugin_receipts, "query_rows_bounded", lambda *args, **kwargs: [])
    return conn


@pytest.mark.parametrize("principal,access,allowed", [
    (ADMIN, MANAGE, True),
    (ADMIN, {"capabilities": []}, False),
    ({"type": "session", "id": 7, "role": "viewer"}, {"platform_owner": True}, True),
    ({"type": "api_key", "id": 8, "role": "admin"}, MANAGE, True),
    ({"type": "api_key", "id": 8, "role": "operator"}, {"platform_owner": True}, False),
    ({"type": "session", "id": 7, "role": "operator"}, {"capabilities": ["plugins.manage", "access.manage"]}, False),
    ({"type": "session", "id": 7, "role": "viewer"}, {}, False),
    (None, {"platform_owner": True}, False),
])
def test_mutation_requires_authenticated_owner_or_admin(principal, access, allowed):
    assert state.can_manage_plugins(principal, access) is allowed


def test_disable_calls_durable_audited_executor_with_authoritative_actor(connection):
    item = state.set_plugin_enabled("sli.remote-access", {"enabled": False, "expected_revision": 4}, principal=ADMIN, access=MANAGE)
    assert item == ITEM
    assert connection.calls == [("select * from set_plugin_enabled_v1(%s,%s,%s,%s,%s,%s)", ("sli.remote-access", False, 4, "session", 7, True))]
    assert connection.commits == 1


@pytest.mark.parametrize("enabled,revision,runtime", [(True, 1, "running"), (False, 2, "stopped")])
@pytest.mark.parametrize("plugin_id", ["sli.workstations", "sli.gpo"])
def test_owner_changes_registered_plugin_from_drained_state(connection, monkeypatch, enabled, revision, runtime, plugin_id):
    monkeypatch.setattr(state, "remote_access_configured", lambda: pytest.fail("VPN configuration is unrelated"))
    connection.row = {
        **ITEM, "plugin_id": plugin_id, "enabled": enabled,
        "component_runtime": runtime, "queue_state": "drained", "revision": revision + 1,
    }
    owner = {"type": "session", "id": 7, "role": "viewer"}
    handler = Handler(owner, {"platform_owner": True}, {"enabled": enabled, "expected_revision": revision})
    assert operations.try_handle_post(handler, f"/api/v1/plugins/{plugin_id}")
    assert handler.sent == ({"item": connection.row}, 200)
    # Configuration for registry-managed plugins is read inside the guarded SQL transition.
    assert connection.calls == [(
        "select * from set_plugin_enabled_v1(%s,%s,%s,%s,%s,%s)",
        (plugin_id, enabled, revision, "session", 7, None),
    )]
    assert connection.commits == 1


@pytest.mark.parametrize("reason,status", [
    ("plugin_not_found", 404),
    ("plugin_state_request_invalid", 400),
    ("plugin_revision_conflict", 409),
    ("plugin_not_installed", 409),
    ("plugin_not_configured", 409),
    ("plugin_runtime_not_stopped", 409),
    ("plugin_runtime_not_running", 409),
    ("plugin_queue_not_drained", 409),
    ("plugin_active_leases", 409),
    ("plugin_runtime_transition_unsupported", 409),
])
def test_database_refusal_reason_reaches_plugin_api_without_commit(connection, reason, status):
    connection.error = RaiseException(reason)
    handler = Handler(body={"enabled": True, "expected_revision": 1})
    assert operations.try_handle_post(handler, "/api/v1/plugins/sli.workstations")
    assert handler.sent == ({"error": reason}, status)
    assert connection.commits == 0


@pytest.mark.parametrize("reason", [
    "private-marker", "plugin_not_configured\nCONTEXT: private-marker",
])
def test_unknown_database_reason_is_not_exposed_by_api(connection, reason):
    connection.error = RaiseException(reason)
    handler = Handler(body={"enabled": True, "expected_revision": 1})
    assert operations.try_handle_post(handler, "/api/v1/plugins/sli.workstations")
    assert handler.sent == ({"error": "plugin_state_conflict"}, 409)
    assert connection.commits == 0


@pytest.mark.parametrize("reason", [
    "plugin enable precondition failed", "plugin drain precondition failed", "plugin disable precondition failed",
])
def test_legacy_executor_precondition_has_safe_public_reason(connection, reason):
    connection.error = RaiseException(reason)
    handler = Handler()
    assert operations.try_handle_post(handler, "/api/v1/plugins/sli.remote-access")
    assert handler.sent == ({"error": "plugin_runtime_precondition_failed"}, 409)
    assert connection.commits == 0


@pytest.mark.parametrize("body", [
    {"enabled": "false", "expected_revision": 4},
    {"enabled": False, "expected_revision": True},
    {"enabled": False, "expected_revision": 0},
    {"enabled": False},
    {"enabled": False, "expected_revision": 4, "actor_id": 1},
])
def test_invalid_body_never_reaches_database(connection, body):
    with pytest.raises(ValueError, match="plugin_state_request_invalid"):
        state.set_plugin_enabled("sli.remote-access", body, principal=ADMIN, access=MANAGE)
    assert connection.calls == []


def test_unconfigured_enable_and_unknown_plugin_are_rejected(connection, monkeypatch):
    monkeypatch.setattr(state, "remote_access_configured", lambda: False)
    with pytest.raises(state.PluginStateConflict, match="plugin_not_configured"):
        state.set_plugin_enabled("sli.remote-access", {"enabled": True, "expected_revision": 4}, principal=ADMIN, access=MANAGE)
    assert connection.calls == []
    connection.error = RaiseException("plugin_not_found")
    with pytest.raises(LookupError, match="plugin_not_found"):
        state.set_plugin_enabled("sli.gpo", {"enabled": True, "expected_revision": 4}, principal=ADMIN, access=MANAGE)
    assert connection.commits == 0


@pytest.mark.parametrize("error,expected", [(None, state.PluginStateConflict), (RaiseException("private-marker"), state.PluginStateConflict), (InsufficientPrivilege("private-marker"), PermissionError)])
def test_stale_revision_or_revoked_authority_never_commits(connection, error, expected):
    connection.row = None
    connection.error = error
    with pytest.raises(expected) as raised:
        state.set_plugin_enabled("sli.remote-access", {"enabled": False, "expected_revision": 4}, principal=ADMIN, access=MANAGE)
    assert "private-marker" not in str(raised.value)
    assert connection.commits == 0


def test_catalog_keeps_axes_independent_and_excludes_unapproved_fields(connection):
    connection.row = {**ITEM, "private_marker": "must-not-pass"}
    assert state.list_plugin_states() == [{**ITEM, "data_receipts": {"state": "no_receipts", "last_received_at": None, "last_imported_at": None, "last_snapshot_completed_at": None}}]


def test_catalog_is_extensible_to_future_plugins(connection):
    connection.row = {**ITEM, "plugin_id": "sli.gpo"}
    assert state.list_plugin_states()[0]["plugin_id"] == "sli.gpo"


@pytest.mark.parametrize("error", [ValueError("invalid"), TypeError("invalid"), RadiusCollectionRouteError("invalid")])
def test_invalid_configuration_is_reported_as_unconfigured(monkeypatch, error):
    def fail():
        raise error
    monkeypatch.setattr("server.source_packs.radius.collection_routes.load_radius_collection_routes", fail)
    assert state.remote_access_configured() is False


@pytest.mark.parametrize("principal", [None, {"type": "session", "id": 7, "role": "operator"}])
def test_post_denies_delegated_or_unauthenticated_actor_before_body_or_write(monkeypatch, principal):
    handler = Handler(principal, {"capabilities": ["plugins.manage"]})
    monkeypatch.setattr(operations, "set_plugin_enabled", lambda *_a, **_kw: pytest.fail("unauthorized write"))
    assert operations.try_handle_post(handler, "/api/v1/plugins/sli.remote-access")
    assert handler.sent[1] == 403
    assert handler.body_reads == 0


def test_post_obeys_origin_auth_gate_before_body(connection):
    handler = Handler()
    handler.authorized = False
    assert operations.try_handle_post(handler, "/api/v1/plugins/sli.remote-access")
    assert handler.body_reads == 0
    assert connection.calls == []


def test_get_and_post_contract_with_fake_database(connection):
    handler = Handler()
    assert operations.try_handle_get(handler, "/api/v1/plugins", {})
    assert handler.sent == ({"items": state.list_plugin_states(), "can_manage": True, "mutation_api_enabled": True}, 200)
    assert operations.try_handle_post(handler, "/api/v1/plugins/sli.remote-access")
    assert handler.sent == ({"item": ITEM}, 200)


@pytest.mark.parametrize("error,status", [(state.PluginStateConflict("plugin_state_conflict"), 409), (state.PluginStateConflict("private-marker"), 409), (PermissionError(), 403), (ValueError(), 400), (LookupError(), 404), (OperationalError("private-marker"), 503)])
def test_post_maps_errors_without_sensitive_details(monkeypatch, error, status):
    def fail(*_args, **_kwargs):
        raise error
    monkeypatch.setattr(operations, "set_plugin_enabled", fail)
    handler = Handler()
    assert operations.try_handle_post(handler, "/api/v1/plugins/sli.remote-access")
    assert handler.sent[1] == status
    assert "private-marker" not in str(handler.sent)


def test_disabled_report_metadata_does_not_remove_grants_or_rows(connection, monkeypatch):
    definition = ReportDefinition(key="vpn.connections", section="reports/remote-access", title="VPN",
        description="", archetype="inventory-status", access=AccessRule("vpn.audit", scope="delegated"),
        params=(), columns=(Column("id", "ID"),), row_key="id", query=lambda _ctx: result(definition, state="ok", items=[{"id": 1}]))
    monkeypatch.setattr(reports_v2, "get_report", lambda _key: definition)
    access = {"reports": [{"report_key": "vpn.audit", "allowed": True}]}
    handler = Handler(access=access)
    assert reports_v2.try_handle_get(handler, "/api/v2/reports/vpn.connections/data", {})
    payload, status = handler.sent
    assert status == 200
    assert payload["plugin"] == {"plugin_id": "sli.remote-access", "state": "disabled", "read_only": True}
    assert payload["items"] == [{"id": 1}]
    assert access == {"reports": [{"report_key": "vpn.audit", "allowed": True}]}
    handler.access = {"reports": []}
    reports_v2.try_handle_get(handler, "/api/v2/reports/vpn.connections/data", {})
    assert handler.sent == ({"error": "report_access_denied"}, 403)


def test_unavailable_state_retains_report_readability(monkeypatch):
    def unavailable():
        raise OperationalError("private-marker")
    monkeypatch.setattr(state, "list_plugin_states", unavailable)
    assert state.report_plugin_state("vpn.connections")["state"] == "unknown"
    assert state.report_plugin_state("other.report") is None


def test_enabled_report_retains_normal_actions(connection):
    connection.row = {**ITEM, "enabled": True}
    assert state.report_plugin_state("vpn.connections")["read_only"] is False


def test_legacy_report_data_is_marked_without_modifying_rows(connection, monkeypatch):
    monkeypatch.setattr(reports, "execute_v4_report", lambda *_a, **_kw: {"items": [{"id": 1}]})
    handler = Handler()
    reports._handle_v4_report_data_api(handler, "/api/v1/reports/vpn.audit/data", {})
    assert handler.sent[0]["plugin"]["state"] == "disabled"
    assert handler.sent[0]["items"] == [{"id": 1}]


def test_plugin_page_is_a_registered_spa_path():
    assert static._is_spa_path("/plugins")
    assert "plugins" in static.SPA_TOP_LEVEL_ROUTES


@pytest.mark.parametrize("key", ["vpn.accounts", "vpn.connections"])
def test_disabled_v2_report_without_rows_is_not_collected(connection, monkeypatch, key):
    definition = ReportDefinition(key=key, section="reports/remote-access", title="VPN",
        description="", archetype="inventory-status", access=AccessRule("vpn.audit", scope="delegated"),
        params=(), columns=(Column("id", "ID"),), row_key="id",
        query=lambda _ctx: result(definition, state="empty", items=[], coverage={"state": "empty"}))
    monkeypatch.setattr(reports_v2, "get_report", lambda _key: definition)
    handler = Handler(access={"reports": [{"report_key": "vpn.audit", "allowed": True}]})
    assert reports_v2.try_handle_get(handler, f"/api/v2/reports/{key}/data", {})
    payload, status = handler.sent
    assert status == 200
    assert payload["state"] == "unavailable"
    assert payload["reason"] == "not_collected"
    assert payload["coverage"]["state"] == "unavailable"
    assert payload["plugin"]["read_only"] is True


def test_disabled_legacy_empty_report_is_not_collected(connection, monkeypatch):
    monkeypatch.setattr(reports, "execute_v4_report", lambda *_a, **_kw: {"state": "empty", "items": []})
    handler = Handler()
    reports._handle_v4_report_data_api(handler, "/api/v1/reports/vpn.audit/data", {})
    assert handler.sent[0]["state"] == "not_collected"


@pytest.mark.parametrize("status,items", [("denied", []), ("partial", [{"id": 1}]), ("ok", [{"id": 1}])])
def test_disabled_report_preserves_denial_and_retained_data(connection, status, items):
    payload = {"state": status, "items": items}
    state.annotate_plugin_report("vpn.accounts", payload)
    assert payload["state"] == status
    assert payload["items"] == items


def test_enabled_empty_report_keeps_its_state(connection):
    connection.row = {**ITEM, "enabled": True}
    payload = {"state": "empty", "items": []}
    state.annotate_plugin_report("vpn.connections", payload)
    assert payload["state"] == "empty"
