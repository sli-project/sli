"""UI source APIs expose registration data without pilot or host defaults."""

from __future__ import annotations

from copy import deepcopy

import pytest

from server.api.routes import runtime
from server.sli.core import database, platform_settings, setup_status


class Handler:
    def _send_json(self, payload):
        self.payload = payload


@pytest.fixture(autouse=True)
def no_database(monkeypatch):
    monkeypatch.setattr(
        "server.sli.core.postgres_runtime_pipeline.connect",
        lambda *args, **kwargs: pytest.fail("real database access is forbidden"),
    )
    monkeypatch.setattr(database, "_configured_source_addresses", lambda: {})
    monkeypatch.setattr(database, "query_rows_bounded", lambda *args, **kwargs: [])


def test_sources_api_keeps_an_empty_registry_empty(monkeypatch):
    monkeypatch.setattr(database, "query_rows", lambda *args, **kwargs: [])
    handler = Handler()

    assert runtime.try_handle_get(handler, "/api/sources", {})
    assert handler.payload == {"items": []}


@pytest.mark.parametrize("domain", ["first.example.test", "second.example.test"])
def test_sources_api_uses_registered_host_and_domain(monkeypatch, domain):
    source = {
        "hostname": "directory-node", "fqdn": f"directory-node.{domain}",
        "role": "domain_controller", "is_active": True,
        "domain_fqdn": domain, "netbios_name": "SYNTHETIC", "site_name": None,
    }
    monkeypatch.setattr(database, "query_rows", lambda *args, **kwargs: [deepcopy(source)])
    handler = Handler()

    assert runtime.try_handle_get(handler, "/api/sources", {})
    [item] = handler.payload["items"]
    assert {key: item[key] for key in source} == source
    assert "stub" not in item


@pytest.mark.parametrize("targets", [[], [{"hostname": "directory-node", "connect_address": "directory-node.second.example.test"}]])
def test_controllers_api_uses_configured_targets_without_host_discovery(monkeypatch, targets):
    def hook(plugin_id, name):
        assert plugin_id == "sli.ad"
        if name == "discover_domain_controllers":
            return ["host-environment-node"]
        assert name == "get_configured_domain_controller_targets"
        return deepcopy(targets)

    monkeypatch.setattr(runtime, "require_plugin", hook)
    handler = Handler()

    assert runtime.try_handle_get(handler, "/api/domain-controllers", {})
    assert handler.payload == {"items": [item["hostname"] for item in targets]}


@pytest.mark.parametrize("stored,registered,archived", [
    (None, False, False), ("first.example.test", True, False), ("second.example.test", True, False),
    ("first.example.test", False, False), ("second.example.test", False, False),
    ("first.example.test", True, True),
])
def test_setup_readiness_domain_comes_only_from_database(monkeypatch, stored, registered, archived):
    for name in ("ADLOG_REPORT_DOMAIN_FQDN", "SLI_INSTALL_DOMAIN", "USERDNSDOMAIN", "USERDOMAIN"):
        monkeypatch.setenv(name, "environment.example.test")
    def query_rows(sql, params=(), **kwargs):
        if sql == "select is_archived from domains where lower(fqdn) = ?":
            assert params == (stored,)
            return [{"is_archived": archived}] if registered else []
        if sql == "select value, updated_by, updated_at from platform_settings where key = ?":
            assert params == ("reports.domain_fqdn",)
            return [{"value": stored}] if stored else []
        if "from domains d" in sql and "where not d.is_archived" in sql:
            assert params == () and "run.status = 'completed'" in sql
            return []  # No alternative observed non-archive candidate in this fixture.
        pytest.fail("unexpected setup readiness query")

    monkeypatch.setattr(database, "query_rows", query_rows)
    platform_settings.clear_cache()
    try:
        expected = {
            "key": "reports.domain_fqdn", "value": stored if registered and not archived else "",
            "source": "database" if registered and not archived else "not_configured",
        }
        if stored and (not registered or archived):
            expected.update(configured_value=stored, suggested_value=None)
        assert setup_status._report_domain() == expected
    finally:
        platform_settings.clear_cache()
