"""Frozen pre-registration AD contracts for subsequent relocation PRs.

The fixture was captured at 08f95ffaa156302707ffe58ab83017a772279f16 before
adding sli.ad to BUNDLED. Never regenerate it from a relocated implementation
to make a parity failure pass.
"""
from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

from ad_report_baseline import baseline_modules
from report_passport_baseline import domain_selection_metadata, extended_metadata
from server.api.routes import operations, runtime, setup
from server.sli.core import database, setup_domain_controllers, setup_status
from server.sli.plugins import registry as plugins
from server.sli.reporting import navigation_registry as navigation
from server.sli.reporting.v2 import registry as reports
from server.sli.reporting.v2.definition import QueryContext

BASELINE = Path(__file__).with_name("fixtures") / "ad_plugin_contract_baseline.json"
NOW = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
TARGET = {
    "hostname": "dc01.example.invalid", "connect_address": "dc01.example.invalid",
    "domain": "example.invalid", "enabled": True, "dns_readback": True,
}


class Handler:
    client_address = ("127.0.0.1", 0)
    _principal: ClassVar[dict] = {"type": "session", "id": 1}

    def __init__(self, body=None, *, allowed=True, capable=True):
        self.body = body or {}
        self.allowed, self.capable = allowed, capable
        self.sent, self.guards = [], []

    def _send_json(self, payload, status=HTTPStatus.OK):
        self.sent.append({"payload": payload, "status": int(status)})

    def _read_json_body(self):
        return self.body

    def _authorize_mutation(self, *, required_role):
        self.guards.append(required_role)
        return self.allowed

    def _require_capability(self, capability):
        self.guards.append(capability)
        return self.capable

    def _require_access(self, role):
        self.guards.append(role)
        return self.allowed


def contract_snapshot(monkeypatch):
    """Use the public registry and routes with synthetic readers, never a DB."""
    manifest = json.loads((navigation.ROOT / "config/plugin_packages/v3/sli.ad.json").read_text("utf-8"))
    keys = {item["report_key"] for item in manifest["reports"]}
    definitions = [definition for definition in reports.registered_reports() if definition.key in keys]
    metadata = {}
    for definition in definitions:
        metadata[definition.key] = {
            "definition": definition.to_json(),
            "access": {
                "report_key": definition.access.report_key,
                "required_fields": sorted(definition.access.required_fields),
                "required_capabilities": sorted(definition.access.required_capabilities),
                "scope": definition.access.scope,
                "export_action": definition.access.export_action,
            },
            "home_order": definition.home_order, "home_view": definition.home_view,
            "metric_categories": {key: sorted(value) for key, value in definition.metric_categories.items()},
            "row_categories": {key: sorted(value) for key, value in definition.row_categories.items()},
            "series_categories": {key: sorted(value) for key, value in definition.series_categories.items()},
        }

    def query(sql, params=(), **kwargs):
        if "from domain_controller_targets t" in sql:
            return [deepcopy(TARGET)]
        if "from collector_channel_runs" in sql or "from ad_snapshot_manifests" in sql:
            return []
        raise AssertionError("unexpected database read")

    monkeypatch.setattr(database, "query_rows", query)
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda *a, **k: pytest.fail("no database connection"))
    monkeypatch.setattr(runtime, "discover_domain_controllers", lambda: [TARGET["hostname"]])
    monkeypatch.setattr("server.sli.core.app_config.load_config", lambda: SimpleNamespace(collector_interval_seconds=600))
    api = {}
    for name, route, path in (
        ("targets", setup, "/api/v1/setup/domain-controllers"),
        ("discovery", runtime, "/api/domain-controllers"),
    ):
        handler = Handler()
        assert route.try_handle_get(handler, path, {})
        api[name] = handler.sent

    audits = []
    monkeypatch.setattr(setup, "record_access_audit_with_cursor", lambda **kw: audits.append({
        "action": kw["action"], "target_type": kw["target_type"],
        "target_key": kw["target_key"], "details": kw["details"],
    }))

    def add(hostname, domain, *, actor, audit):
        if hostname == "duplicate":
            raise setup_domain_controllers.DomainControllerConflictError("domain_controller_already_exists")
        if hostname == "invalid":
            raise ValueError("connect_address_must_be_fqdn")
        if hostname == "missing":
            raise setup_domain_controllers.DomainControllerNotFoundError("domain_not_found")
        item = {**TARGET, "source": "db", "imported_from_file": 0}
        audit(object(), item)
        return item

    def toggle(hostname, enabled, *, actor, audit):
        item = {"hostname": hostname, "enabled": enabled, "previous_enabled": True}
        audit(object(), item)
        return item

    monkeypatch.setattr(setup, "add_target", add)
    monkeypatch.setattr(setup, "set_enabled", toggle)
    for hostname in (TARGET["hostname"], "duplicate", "invalid", "missing"):
        handler = Handler({"hostname": hostname, "domain": TARGET["domain"]})
        assert setup.try_handle_post(handler, setup.CONTROLLERS)
        api["add:" + hostname] = {"sent": handler.sent, "guards": handler.guards}
    handler = Handler({"enabled": False})
    assert setup.try_handle_post(handler, setup.CONTROLLERS_PREFIX + TARGET["hostname"])
    api["disable"] = {"sent": handler.sent, "guards": handler.guards}
    for name, allowed, capable in (("role_denied", False, True), ("capability_denied", True, False)):
        handler = Handler(allowed=allowed, capable=capable)
        assert setup.try_handle_post(handler, setup.CONTROLLERS)
        api[name] = {"sent": handler.sent, "guards": handler.guards}
    api["audits"] = audits

    pack = {"pack_id": "sli.windows.ad-dc", "display_name": "AD DC", "version": "1.0.0", "source_kind": "event", "channels": ["Security"]}
    matrix = {}
    for label, controllers in (("unknown", None), ("unconfigured", {"items": []}),
                               ("disabled", {"items": [{**TARGET, "enabled": False}]}),
                               ("configured", {"items": [TARGET]})):
        for collection in (None, {"collection_enabled": False}, {"collection_enabled": True}):
            for arrival in (None, "2026-10-09T11:59:00+00:00", "2026-10-08T12:00:00+00:00"):
                monkeypatch.setattr(setup_status, "_source_data", lambda *a, arrival=arrival: {TARGET["hostname"]: arrival} if arrival else {})
                key = f"{label}:{collection}:{arrival}"
                matrix[key] = setup_status._source_status(pack, controllers, [], collection, NOW)
    context_pack = {**pack, "pack_id": "sli.windows.ad-context", "source_kind": "context"}
    for domains in ([], [{"fqdn": "example.invalid"}]):
        matrix[f"context:{bool(domains)}"] = setup_status._source_status(context_pack, None, domains, None, NOW)

    # Exercise real report row shaping, ordering, metrics, filters and CSV on a
    # frozen reader input. Follow the definition's active implementation path.
    import importlib
    definition = next(item for item in definitions if item.key == "ad.infrastructure")
    implementation = importlib.import_module("server.sli.reporting.v2.reports.ad_state")
    raw = {
        "state": "available", "coverage": {}, "summary": {"control_counts": {"failed": 1, "passed": 1}},
        "controls": [{"entity_id": 1, "entity_name": "dc01.example.invalid", "entity_type": "domain_controller",
                      "control_id": f"synthetic-{qualification}", "label": "Синтетическая проверка",
                      "qualification": qualification, "actual_value": qualification == "passed",
                      "expected_condition": "Сборщик должен вернуть passed", "authority": "report_rule_v1",
                      "object_context": {"is_global_catalog": True}}
                     for qualification in ("passed", "failed")],
    }
    monkeypatch.setattr(implementation, "get_active_directory_report", lambda **kw: deepcopy(raw))
    report_payloads = {}
    for name, params in (("all", {}), ("filtered", {"qualification": "failed"}), ("empty", {"q": "no-match"})):
        context = QueryContext(access={}, params=params, domain_ids=[1])
        report_payloads[name] = {"result": definition.query(context), "csv": definition.export_csv(context)}

    access = {"capabilities": [], "reports": [{"report_key": item["access_key"], "allowed": True} for item in manifest["reports"]]}
    return {
        "manifest": manifest, "definitions": metadata, "api": api, "source_states": matrix,
        "routes": [list(route) for route in (*setup.ROUTES, *runtime.ROUTES) if "domain-controller" in route[1]],
        "report_payloads": report_payloads,
        "navigation": {str(enabled): navigation.navigation(access, [{"plugin_id": "sli.ad", "enabled": enabled}]) for enabled in (True, False)},
    }


def test_ad_contracts_equal_pre_registration_baseline(monkeypatch):
    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    plugins.registered_plugins.cache_clear()
    reports.registered_reports.cache_clear()
    try:
        candidate = json.loads(json.dumps(contract_snapshot(monkeypatch), ensure_ascii=False))
        expected = json.loads(BASELINE.read_text("utf-8"))
        # Migration 181 intentionally fixes the AD changes category. Keep the
        # frozen relocation baseline intact and allow only this reviewed delta.
        classes = expected["definitions"]["ad.infrastructure"]["definition"]["intent"]["field_classes"]
        assert classes == ["identity_basic", "technical", "security"]
        classes.append("privilege")
        # PR541 adds the full passport. Preserve all pre-registration fields
        # and compare the extension against its independent reviewed capture.
        for metadata in expected["definitions"].values():
            metadata["definition"] = domain_selection_metadata(extended_metadata(metadata["definition"]))
        # PR653 includes known primary/nested privileges. Only this column's
        # label changes; the frozen capture and all other metadata stay exact.
        privilege_column = next(column for column in expected["definitions"]["ad.users.v2"]["definition"]["columns"]
                                if column["key"] == "privilege_basis")
        assert privilege_column["label"] == "Основание прямых привилегий"
        privilege_column["label"] = "Основание привилегий"
        # PR657 intentionally extends only user columns, inline details and
        # field categories. Reconstruct these from frozen code plus its pinned
        # additive delta, never from the candidate report or regenerated JSON.
        with baseline_modules() as load:
            users = load("reports.definitions.users").REPORT
            metadata = domain_selection_metadata(users.to_json())
            expected_users = expected["definitions"]["ad.users.v2"]
            # PR703 adds a checks view. The loader pins its literal metadata
            # independently while retaining the immutable original fixtures.
            # adimpl3's independent literal metadata delta also pins its date,
            # state filters and fifty-row page size. Frozen captures stay intact.
            for key in ("columns", "detail", "views", "params", "limits"):
                expected_users["definition"][key] = metadata[key]
            expected_users["row_categories"] = {key: sorted(value) for key, value in users.row_categories.items()}
            # PR658 changes the computer type choices, inactivity default and
            # optional posture columns. Use frozen code plus its pinned delta;
            # preserve every other field in the pre-registration contract.
            computers = domain_selection_metadata(load("reports.definitions.computers").REPORT.to_json())
            for key in ("columns", "params", "views"):
                expected["definitions"]["ad.computers.v6"]["definition"][key] = computers[key]
        # PR818 adds code envelopes to the two synthetic infrastructure rows.
        # Keep the frozen payload and every original field, CSV and ordering
        # assertion; spell out the additive contract independently of _row.
        for payload in expected["report_payloads"].values():
            for row in payload["result"]["items"]:
                assert row["control_id"] in {"synthetic-passed", "synthetic-failed"}
                assert "presentation_messages" not in row
                row["presentation_messages"] = {
                    "authority_text": {
                        "code": "reports.v2.ad.infrastructure.authority.report_rule_v1",
                        "params": {}, "text": "Правило отчёта v1",
                    },
                    "actual_text": {
                        "code": "reports.boolean.yes" if row["actual_value"] else "reports.boolean.no",
                        "params": {}, "text": "Да" if row["actual_value"] else "Нет",
                    },
                }
                assert row["context"] == [{"code": "is_global_catalog", "label": "Global Catalog", "value": "Да"}]
                row["context"][0]["presentation_messages"] = {
                    "label": {
                        "code": "reports.v2.ad.infrastructure.context_labels.is_global_catalog",
                        "params": {}, "text": "Global Catalog",
                    },
                    "value": {"code": "reports.boolean.yes", "params": {}, "text": "Да"},
                }
        # PR552 registers file-audit in the global enabled-plugin list. Keep
        # the frozen capture intact; every AD contract and visible section
        # must still match, with no file-audit entries under AD-only grants.
        for navigation_payload in expected["navigation"].values():
            assert "sli.file-audit" not in navigation_payload["enabled_plugins"]
            navigation_payload["enabled_plugins"] = sorted([
                *navigation_payload["enabled_plugins"], "sli.file-audit",
            ])
            # PR728 routes both legacy notification reports to one workspace.
            # Pin only these redirects; preserve the frozen fixture and every
            # other navigation, access and AD contract field unchanged.
            navigation_payload["redirects"] = [
                {"from": "/report/notifications.channels", "to": "/notifications", "view": "channels"},
                {"from": "/report/notifications.deliveries", "to": "/notifications", "view": "journal"},
                *navigation_payload["redirects"],
            ]
            # The beta offers Accounting connections. Pin the two VPN aliases
            # affected by the unavailable accounts screen independently of the candidate.
            navigation_payload["redirects"].remove({
                "from": "/report/vpn.accounts", "to": "/report/vpn.connections", "view": "accounts",
            })
            vpn_report = next(redirect for redirect in navigation_payload["redirects"] if redirect["from"] == "/vpn-report")
            assert vpn_report == {"from": "/vpn-report", "to": "/report/vpn.connections", "view": "accounts"}
            vpn_report["view"] = "connections"
        assert candidate == expected
    finally:
        plugins.registered_plugins.cache_clear()
        reports.registered_reports.cache_clear()


@pytest.mark.parametrize("rows", [[], None], ids=["empty-table", "missing-table"])
def test_dc_file_fallback_matches_legacy_payload(monkeypatch, tmp_path, rows):
    from server.sli.sources import dc_discovery

    (tmp_path / "domain_controllers.json").write_text(json.dumps({"domain_controllers": [{
        "hostname": "DC01", "connect_address": "dc01.example.invalid", "owner_confirmed_ip": "192.0.2.1",
    }]}), encoding="utf-8")
    monkeypatch.setattr(dc_discovery, "CONFIG_DIR", tmp_path)

    def query(*args, **kwargs):
        if rows is None:
            raise RuntimeError("synthetic database unavailable")
        return rows

    monkeypatch.setattr(database, "query_rows", query)
    dc_discovery.clear_database_target_cache()
    try:
        handler = Handler()
        assert setup.try_handle_get(handler, "/api/v1/setup/domain-controllers", {})
        assert handler.sent == [{"status": 200, "payload": {"source": "file", "items": [{
            "hostname": "DC01", "connect_address": "dc01.example.invalid", "domain": None,
            "enabled": True, "source": "file", "dns_readback": True,
        }]}}]
        assert "owner_confirmed_ip" not in repr(handler.sent)
        assert "192.0.2.1" not in repr(handler.sent)
        assert dc_discovery.stored_enabled_targets() is None
    finally:
        dc_discovery.clear_database_target_cache()


@pytest.mark.parametrize("failure", ["malformed", "unreadable", "absent"])
def test_dc_file_failure_preserves_empty_response(monkeypatch, tmp_path, failure):
    from server.sli.sources import dc_discovery

    path = tmp_path / "domain_controllers.json"
    if failure != "absent":
        path.write_text("{", encoding="utf-8")
    if failure == "unreadable":
        original = Path.read_text

        def read(path, *args, **kwargs):
            if path == tmp_path / "domain_controllers.json":
                raise OSError("synthetic file unavailable")
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(dc_discovery, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(database, "query_rows", lambda *a, **k: [])
    handler = Handler()
    assert setup.try_handle_get(handler, "/api/v1/setup/domain-controllers", {})
    assert handler.sent == [{"status": 200, "payload": {"source": "none", "items": []}}]


def test_all_disabled_dc_targets_do_not_discover_or_read_file(monkeypatch):
    from server.sli.sources import dc_discovery

    monkeypatch.setattr(dc_discovery, "_load_database_rows", lambda: [{
        "hostname": "DC01", "connect_address": "dc01.example.invalid", "enabled": False,
    }])
    monkeypatch.setattr(dc_discovery, "_targets_from_config_file", lambda: pytest.fail("no file fallback"))
    monkeypatch.setattr(dc_discovery, "_discover_with_directory_services", lambda: pytest.fail("no online discovery"))
    handler = Handler()
    assert runtime.try_handle_get(handler, "/api/domain-controllers", {})
    assert handler.sent == [{"status": 200, "payload": {"items": []}}]


def test_legacy_online_discovery_is_retained_in_ad_plugin(monkeypatch):
    from server.sli.sources import dc_discovery

    monkeypatch.setattr(dc_discovery, "get_configured_domain_controller_targets", list)
    monkeypatch.setattr(dc_discovery, "domain_controller_target_source", lambda: "none")
    monkeypatch.setattr(dc_discovery, "_discover_from_env", list)
    monkeypatch.setattr(dc_discovery, "_discover_with_directory_services", lambda: ["DC02"])
    # The UI API intentionally exposes configured targets only. Legacy
    # discovery remains available to the AD plugin's non-UI consumers.
    assert dc_discovery.discover_domain_controllers() == ["DC02"]


@pytest.mark.parametrize("targets,names", [
    ([], []),
    ([{"hostname": "DC01", "connect_address": "dc01.example.invalid"}], ["DC01"]),
], ids=["unconfigured", "configured"])
def test_controllers_api_uses_configured_targets_without_online_discovery(monkeypatch, targets, names):
    from server.sli.sources import dc_discovery

    monkeypatch.setattr(dc_discovery, "get_configured_domain_controller_targets", lambda: deepcopy(targets))
    monkeypatch.setattr(dc_discovery, "domain_controller_target_source", lambda: "none")
    monkeypatch.setattr(dc_discovery, "_discover_from_env", lambda: pytest.fail("no environment discovery"))
    monkeypatch.setattr(dc_discovery, "_discover_with_directory_services", lambda: pytest.fail("no online discovery"))
    handler = Handler()
    assert runtime.try_handle_get(handler, "/api/domain-controllers", {})
    assert handler.sent == [{"status": 200, "payload": {"items": names}}]


@pytest.mark.parametrize("allowed,capable,guards", [
    (False, True, ["operator"]), (True, False, ["operator", "operations.view"]),
])
def test_onboarding_keeps_outer_guards_before_plugin(monkeypatch, allowed, capable, guards):
    monkeypatch.setattr(operations, "get_configured_domain_controller_targets", lambda: pytest.fail("guard first"))
    handler = Handler(allowed=allowed, capable=capable)
    assert operations.try_handle_post(handler, "/api/v1/source-onboarding/preflight")
    assert handler.guards == guards and handler.sent == []


def test_onboarding_keeps_admin_gate_and_legacy_schema(monkeypatch):
    monkeypatch.setattr(operations, "get_configured_domain_controller_targets", list)
    denied = Handler(allowed=False)
    operations._handle_source_onboarding_preflight(denied)
    assert denied.guards == ["admin"] and denied.sent == []
    handler = Handler({"hostname": "DC01", "connect_address": "dc01.example.invalid", "channels": ["Security"]})
    assert operations.try_handle_post(handler, "/api/v1/source-onboarding/preflight")
    assert handler.guards == ["operator", "operations.view", "admin"]
    assert handler.sent == [{"status": 200, "payload": {
        "api_version": "v1", "kind": "dc_onboarding_preflight", "valid": True,
        "hostname": "DC01", "connect_address": "dc01.example.invalid", "source_pack_id": "sli.windows.ad-dc",
        "channels": ["Security"], "adapter_id": "windows-eventlog-pywin32", "network_actions": [],
        "database_actions": [], "collection_actions": [], "issues": [],
        "next_operator_action": "Review the plan, then explicitly add the controller to the managed configuration.",
    }}]


@pytest.mark.parametrize("body,status,error", [
    ({"enabled": "false"}, 400, "enabled_must_be_boolean"),
    ({"enabled": True}, 404, "domain_controller_not_found"),
])
def test_dc_toggle_keeps_error_response(monkeypatch, body, status, error):
    from server.sli.plugins.ad import setup as ad_setup

    def toggle(*args, **kwargs):
        if status == 400:
            raise ValueError(error)
        raise ad_setup.DomainControllerNotFoundError(error)

    monkeypatch.setattr(ad_setup, "set_enabled", toggle)
    handler = Handler(body)
    assert setup.try_handle_post(handler, "/api/v1/setup/domain-controllers/DC01")
    assert handler.guards == ["admin", "access.manage"]
    assert handler.sent == [{"status": status, "payload": {"error": error}}]


def test_dc_compatibility_paths_share_implementation_and_cache():
    from server.sli.plugins.ad import onboarding, setup as ad_setup, targets
    from server.sli.sources import dc_discovery, source_onboarding

    assert setup_domain_controllers is ad_setup
    assert dc_discovery is targets
    assert source_onboarding is onboarding


class DcCursor:
    """Synthetic rows and SQL trace; no database or external source."""
    def __init__(self, state):
        self.state, self.rows = state, []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        self.state["log"].append((sql, params))
        self.rows = []
        if sql.startswith("select id from domains"):
            self.rows = [{"id": 7}] if params == ("example.invalid",) else []
        elif sql.startswith("select id, lower(fqdn)"):
            self.rows = [{"id": 7, "fqdn": "example.invalid"}, {"id": 8, "fqdn": "child.example.invalid"}]
        elif sql.startswith("select lower(hostname)"):
            self.rows = [{"key": key} for key in self.state["targets"]]
        elif sql.startswith("select hostname, enabled"):
            item = self.state["targets"].get(params[0])
            self.rows = [item] if item else []
        elif sql.startswith("insert into domain_controller_targets"):
            host, address, domain, *rest = params
            self.state["targets"][host.casefold()] = {
                "hostname": host, "connect_address": address, "domain_id": domain, "enabled": True,
                "owner_confirmed_ip": rest[0] if len(rest) == 3 else None,
            }
        elif sql.startswith("update domain_controller_targets"):
            self.state["targets"][params[2]]["enabled"] = params[0]

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class DcConnection:
    def __init__(self, state):
        self.state = state
        self.before = deepcopy(state["targets"])

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        if kind is not None:
            self.state["targets"] = self.before
            self.state["log"].append(("rollback", ()))
        return False

    def cursor(self):
        return DcCursor(self.state)

    def commit(self):
        self.state["log"].append(("commit", ()))


@pytest.fixture
def dc_transaction(monkeypatch):
    from server.sli.sources import dc_discovery

    state = {"targets": {}, "log": []}
    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", lambda: DcConnection(state))
    monkeypatch.setattr(dc_discovery, "domain_controller_target_source", lambda: "file")
    monkeypatch.setattr(dc_discovery, "read_file_targets", lambda: [{
        "hostname": "DC01", "connect_address": "dc01.child.example.invalid", "owner_confirmed_ip": "192.0.2.1",
    }])
    monkeypatch.setattr(dc_discovery, "clear_database_target_cache", lambda: state["log"].append(("invalidate", ())))
    return state


def test_first_dc_add_preserves_file_targets_lock_audit_and_commit(monkeypatch, dc_transaction):
    state = dc_transaction
    audits = []

    def audit(**kwargs):
        audits.append(kwargs)
        state["log"].append(("audit", ()))

    monkeypatch.setattr(setup, "record_access_audit_with_cursor", audit)
    handler = Handler({"hostname": "dc02.example.invalid", "domain": "example.invalid"})
    assert setup.try_handle_post(handler, "/api/v1/setup/domain-controllers")
    assert handler.sent == [{"status": 201, "payload": {"item": {
        "hostname": "dc02", "connect_address": "dc02.example.invalid", "domain": "example.invalid",
        "enabled": True, "source": "db", "dns_readback": False,
    }}}]
    assert state["targets"] == {
        "dc01": {"hostname": "DC01", "connect_address": "dc01.child.example.invalid", "domain_id": 8,
                 "enabled": True, "owner_confirmed_ip": "192.0.2.1"},
        "dc02": {"hostname": "dc02", "connect_address": "dc02.example.invalid", "domain_id": 7,
                 "enabled": True, "owner_confirmed_ip": None},
    }
    assert state["log"][0] == ("select pg_advisory_xact_lock(hashtext('ad_log_setup_domain_controllers'))", ())
    assert [item[0] for item in state["log"]][-3:] == ["audit", "commit", "invalidate"]
    assert audits[0]["cursor"].state is state
    assert audits[0]["action"] == "setup_dc_add" and audits[0]["target_type"] == "domain_controller"
    assert audits[0]["details"] == {
        "connect_address": "dc02.example.invalid", "domain": "example.invalid", "enabled": True,
        "source": "db", "dns_readback": False, "imported_from_file": 1,
    }
    assert "owner_confirmed_ip" not in repr(handler.sent)


@pytest.mark.parametrize("action", ["add", "toggle"])
def test_dc_audit_failure_rolls_back_under_same_transaction(monkeypatch, dc_transaction, action):
    state = dc_transaction
    if action == "toggle":
        state["targets"]["dc02"] = {"hostname": "DC02", "enabled": True}
    before = deepcopy(state["targets"])

    def failed_audit(**kwargs):
        assert kwargs["cursor"].state is state
        raise RuntimeError("synthetic audit unavailable")

    monkeypatch.setattr(setup, "record_access_audit_with_cursor", failed_audit)
    handler = Handler({"hostname": "dc02.example.invalid", "domain": "example.invalid", "enabled": False})
    path = "/api/v1/setup/domain-controllers" + ("/DC02" if action == "toggle" else "")
    with pytest.raises(RuntimeError, match="synthetic audit unavailable"):
        setup.try_handle_post(handler, path)
    assert state["targets"] == before and handler.sent == []
    assert state["log"][-1] == ("rollback", ())
    assert not any(sql in ("commit", "invalidate") for sql, params in state["log"])


def test_first_dc_add_collision_rolls_back_file_import(dc_transaction):
    handler = Handler({"hostname": "dc01.example.invalid", "domain": "example.invalid"})
    assert setup.try_handle_post(handler, "/api/v1/setup/domain-controllers")
    assert handler.sent == [{"status": 409, "payload": {"error": "domain_controller_already_exists"}}]
    assert dc_transaction["targets"] == {}
    assert dc_transaction["log"][-1] == ("rollback", ())


def test_dc_database_failure_propagates_without_success(monkeypatch, dc_transaction):
    def unavailable():
        raise RuntimeError("synthetic database unavailable")

    monkeypatch.setattr("server.sli.core.postgres_runtime_pipeline.connect", unavailable)
    handler = Handler({"hostname": "dc02.example.invalid", "domain": "example.invalid"})
    with pytest.raises(RuntimeError, match="synthetic database unavailable"):
        setup.try_handle_post(handler, "/api/v1/setup/domain-controllers")
    assert handler.sent == [] and dc_transaction["log"] == []


def test_invalid_dc_file_keeps_add_error_before_transaction(monkeypatch, dc_transaction):
    from server.sli.sources import dc_discovery

    def invalid_file():
        raise dc_discovery.DomainControllerConfigurationError("synthetic invalid endpoint")

    monkeypatch.setattr(dc_discovery, "read_file_targets", invalid_file)
    handler = Handler({"hostname": "dc02.example.invalid", "domain": "example.invalid"})
    assert setup.try_handle_post(handler, "/api/v1/setup/domain-controllers")
    assert handler.sent == [{"status": 400, "payload": {"error": "domain_controllers_file_invalid"}}]
    assert dc_transaction["log"] == []


@pytest.mark.parametrize("stored,names,addresses", [
    (None, ["DC01"], {"dc01": ["192.0.2.1"]}),
    ([], [], {}),
    ([{"hostname": "DC02", "owner_confirmed_ip": "192.0.2.2"}], ["DC02"], {"dc02": ["192.0.2.2"]}),
])
def test_core_source_inventory_keeps_db_file_precedence(monkeypatch, tmp_path, stored, names, addresses):
    (tmp_path / "domain_controllers.json").write_text(json.dumps({"domain_controllers": [{
        "hostname": "DC01", "connect_address": "dc01.example.invalid", "owner_confirmed_ip": "192.0.2.1",
    }]}), encoding="utf-8")
    monkeypatch.setattr(database, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(database, "_stored_domain_controller_targets", lambda: stored)
    assert database._configured_domain_controllers() == names
    assert database._configured_source_addresses() == addresses


def test_dc_routes_preserve_capability_map():
    from server.sli.access.access_control_v4 import route_capability

    assert route_capability("/api/v1/setup/domain-controllers") == "access.manage"
    assert route_capability("/api/v1/setup/domain-controllers/DC01") == "access.manage"
    assert route_capability("/api/domain-controllers") == "operations.view"


def test_ad_event_policy_and_validator_equal_pre_relocation_baseline(monkeypatch):
    from tests.unit.ad_event_contract_helpers import (
        assignment_snapshot, initial_read_contract_baseline, normalization_snapshot, packet_contract_snapshot,
    )
    from server.source_packs.normalizers import get_source_normalizer

    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    plugins.registered_plugins.cache_clear()
    try:
        policy = plugins.plugin_hook("sli.ad", "ad_agent_policy")
        validator = plugins.plugin_hook("sli.ad", "ad_agent_rows")
        assert policy is not None and validator is not None
        candidate = packet_contract_snapshot(policy, validator)
        candidate["normalization"] = normalization_snapshot(get_source_normalizer("windows-ad-dc-v1"))
        candidate["assignment"] = assignment_snapshot()
        # Captured at ab25bba39f6ebe34c2e515857552db19c19dfff3 before PR 3.
        # The 24-hour default and signed channel context intentionally extend
        # this contract. Derive those additions from the frozen capture, never
        # refresh the fixture or copy values from the plugin implementation.
        expected = json.loads(BASELINE.with_name("ad_event_contract_baseline.json").read_text("utf-8"))
        expected = initial_read_contract_baseline(expected)
        assert json.loads(json.dumps(candidate, ensure_ascii=False)) == expected
    finally:
        plugins.registered_plugins.cache_clear()


def test_ad_validator_preserves_frozen_legacy_packets(monkeypatch):
    from tests.unit.ad_event_contract_helpers import HOST, Ledger

    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    plugins.registered_plugins.cache_clear()
    try:
        policy = plugins.plugin_hook("sli.ad", "ad_agent_policy")
        validator = plugins.plugin_hook("sli.ad", "ad_agent_rows")
        assert policy is not None and validator is not None
        baseline = json.loads(BASELINE.with_name("ad_event_contract_baseline.json").read_text("utf-8"))
        current_policy = policy(HOST, baseline["policies"]["default"])
        for case, packet in baseline["packets"].items():
            try:
                rows = validator(packet["envelope"], packet["payload"], Ledger().binding(), current_policy)
            except ValueError as exc:
                rows = {"error": str(exc)}
            assert json.loads(json.dumps(rows, ensure_ascii=False)) == packet["validated"], case
    finally:
        plugins.registered_plugins.cache_clear()


def test_ad_normalizer_ownership_and_compatibility_exports():
    from server.sli.plugins.ad import windows_ad_dc as implementation
    from server.source_packs import windows_ad_dc as compatibility
    from server.source_packs.normalizers import get_source_normalizer

    assert plugins.SOURCE_PACK_OWNERS["sli.windows.ad-dc"] == "sli.ad"
    assert plugins.NORMALIZER_OWNERS["windows-ad-dc-v1"] == "sli.ad"
    assert compatibility is implementation
    assert get_source_normalizer("windows-ad-dc-v1") is implementation.normalizer
    assert implementation.normalizer.semantic_projection.__module__ == "server.sli.plugins.ad.windows_ad_dc.semantics"
    import importlib
    for name in ("analysis", "catalog", "entities", "facts", "investigation", "semantics"):
        assert importlib.import_module(f"server.source_packs.windows_ad_dc.{name}") is importlib.import_module(
            f"server.sli.plugins.ad.windows_ad_dc.{name}")


def test_missing_ad_plugin_cannot_resolve_reserved_normalizer(monkeypatch):
    from server.source_packs import normalizers
    from server.sli.plugins.ad.windows_ad_dc import normalizer

    # An entry cached before removal must not bypass the reviewed owner.
    monkeypatch.setattr(normalizers, "_ENTRY_NORMALIZERS", {"windows-ad-dc-v1": normalizer})
    monkeypatch.setattr(plugins, "registered_plugins", lambda: {})
    assert normalizers.get_source_normalizer("windows-ad-dc-v1") is None
