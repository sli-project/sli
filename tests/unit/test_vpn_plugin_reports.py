"""Physical VPN report ownership and legacy import compatibility."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from server.sli.plugins import registry

PLUGIN = "server.sli.plugins.remote_access.reports"
LEGACY_MODULES = (
    ("server.sli.reporting.v2.reports", "vpn_audit"),
    ("server.sli.reporting.v2.reports", "vpn_connections"),
    ("server.sli.reporting.v2.reports", "nps_policy_denials"),
    ("server.sli.reports", "vpn_connections_reporting"),
    ("server.sli.reports", "vpn_connections_reporting_failed"),
    ("server.sli.reports", "vpn_connections_reporting_timeline"),
    ("server.sli.reports", "vpn_session_reporting"),
    ("server.sli.reports", "vpn_report_composition"),
    ("server.sli.reports", "nps_policy_denials_reporting"),
    ("server.sli.entities", "entity_vpn_reporting"),
)


@pytest.mark.parametrize("legacy,name", LEGACY_MODULES)
def test_legacy_import_is_the_plugin_module(legacy, name):
    current = importlib.import_module(f"{PLUGIN}.{name}")
    assert importlib.import_module(f"{legacy}.{name}") is current
    assert getattr(importlib.import_module(legacy), name) is current
    assert "/plugins/remote_access/reports/" in Path(current.__file__).as_posix()


@pytest.mark.parametrize("legacy,name", LEGACY_MODULES)
def test_legacy_import_follows_reloaded_plugin_module(legacy, name):
    previous = importlib.import_module(f"{PLUGIN}.{name}")
    assert importlib.import_module(f"{legacy}.{name}") is previous

    registry.load_generation("sli.remote-access", None)

    current = importlib.import_module(f"{PLUGIN}.{name}")
    assert current is not previous
    # A from-import must not retain the old module on the parent package.
    assert getattr(__import__(legacy, fromlist=[name]), name) is current
    assert importlib.import_module(f"{legacy}.{name}") is current


@pytest.mark.parametrize("namespace", [PLUGIN, "server.sli.reports"])
@pytest.mark.parametrize("name,helper,kwargs", [
    ("vpn_connections_reporting_failed", "_failed_authorization_collection_coverage",
     {"failed_event_count": 0}),
    ("vpn_connections_reporting_timeline", "_authorization_timeline_collection_coverage",
     {"failed_event_count": 0, "observed_event_count": 0}),
])
def test_split_coverage_from_import_after_reload(namespace, name, helper, kwargs):
    registry.load_generation("sli.remote-access", None)

    # Either compatibility or plugin split module may be the first import.
    module = __import__(f"{namespace}.{name}", fromlist=[helper])
    coverage = getattr(module, helper)
    current = importlib.import_module(f"{PLUGIN}.{name}")
    aggregate = importlib.import_module(f"{PLUGIN}.vpn_connections_reporting")
    assert module is current
    assert coverage is getattr(current, helper) is getattr(aggregate, helper)
    state, details = coverage({}, **kwargs)
    assert state == "not_collected"
    assert details["state"] == "not_collected"
    assert details["source_completeness"] == "not_proven"


@pytest.mark.parametrize("name,archetype,field_classes", [
    ("vpn_audit", "list", {"identity_basic", "technical", "security", "privilege", "hr", "contact"}),
    ("vpn_connections", "timeline", {"identity_basic", "technical", "security", "privilege"}),
])
def test_plugin_and_legacy_reports_preserve_validated_passports(name, archetype, field_classes):
    from server.sli.reporting.v2.registry import validate_report_intents

    current = importlib.import_module(f"{PLUGIN}.{name}")
    legacy = importlib.import_module(f"server.sli.reporting.v2.reports.{name}")
    validate_report_intents((current.REPORT,))
    passport = current.REPORT.to_json()["intent"]
    assert legacy.REPORT is current.REPORT
    assert current.REPORT.query.__module__ == f"{PLUGIN}.{name}"
    assert passport["contract_id"] == "sli.report-intent.v1"
    assert passport["version"] == 1
    assert passport["primary_archetype"] == archetype
    assert set(passport["field_classes"]) == field_classes
    assert "vpn.audit" in passport["rights"]
    assert len(passport["sources"]) == 2


def test_registration_uses_plugin_executors_and_datasets(monkeypatch):
    from server.sli.plugins.remote_access import registration
    from server.sli.plugins.remote_access.reports import accounts_dataset, catalog

    contribution = registry.Contributions()
    registration.register(contribution)
    reports = contribution.hooks["reports"]()
    assert [report.key for report in reports] == ["vpn.accounts", "vpn.connections"]
    assert all(report.query.__module__.startswith(PLUGIN) for report in reports)
    expected = object()
    calls = []

    def fake(*args, **kwargs):
        calls.append((args, kwargs))
        return expected

    for hook, module, name in (
        ("accounts_dataset", accounts_dataset, "read_accounts"),
        ("accounts_summary", accounts_dataset, "_vpn_account_summary"),
        ("connections_catalog", catalog, "_vpn_connections_catalog_item"),
    ):
        monkeypatch.setattr(module, name, fake)
        assert contribution.hooks[hook]("trusted-scope", limit=3) is expected
        assert calls[-1] == (("trusted-scope",), {"limit": 3})


def test_core_account_adapters_delegate_through_registry(monkeypatch):
    # Initial registry loading replaces the bundled plugin namespace.
    # Patch the active generation, rather than an import it will discard.
    registry.registered_plugins.cache_clear()
    registry.registered_plugins()
    from server.sli.reporting import reporting_v4_definitions, reporting_v4_summaries
    from server.sli.plugins.remote_access.reports import accounts_dataset, catalog

    expected = object()
    monkeypatch.setattr(accounts_dataset, "_vpn_account_summary", lambda *_: expected)
    monkeypatch.setattr(catalog, "_vpn_connections_catalog_item", lambda *_, **__: expected)
    assert reporting_v4_summaries._vpn_account_summary("", [], set()) is expected
    assert reporting_v4_definitions._vpn_connections_catalog_item({}, capabilities=set()) is expected


def test_core_account_adapters_cannot_load_an_absent_plugin(monkeypatch):
    from server.sli.reporting import reporting_v4_definitions, reporting_v4_summaries

    monkeypatch.setattr(registry, "discover_plugins", tuple)
    registry.registered_plugins.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="plugin_not_installed"):
            reporting_v4_summaries._vpn_account_summary("", [], set())
        with pytest.raises(RuntimeError, match="plugin_not_installed"):
            reporting_v4_definitions._vpn_connections_catalog_item({}, capabilities=set())
    finally:
        registry.registered_plugins.cache_clear()


def test_absent_plugin_does_not_break_the_legacy_catalogue(monkeypatch):
    from server.sli.reporting import reporting_v4

    monkeypatch.setattr(registry, "discover_plugins", tuple)
    registry.registered_plugins.cache_clear()
    try:
        access = {"capabilities": ["reports.catalog"], "reports": [
            {"report_key": "vpn.audit", "allowed": True},
            {"report_key": "core.fixture", "allowed": True},
        ]}
        catalogue = reporting_v4.report_catalog(None, access=access)
        assert [item["report_key"] for item in catalogue["items"]] == ["core.fixture"]
    finally:
        registry.registered_plugins.cache_clear()
