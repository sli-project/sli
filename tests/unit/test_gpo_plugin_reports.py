"""GPO relocation parity against independent pre-relocation report sources."""
from __future__ import annotations

import ast
import gzip
import importlib
import json
import pkgutil
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType

import pytest

from report_passport_baseline import baseline_tree
from server.api.routes import reports_v2 as routes
from server.sli.plugins import registry as plugins, update_runtime
from server.sli.plugins.gpo import registration, snapshot_projection
from server.sli.plugins.gpo.reports import definition, gpo_v2_reporting as engine
from server.sli.reports import ad_snapshot_change_reporting
from server.sli.reporting.v2 import registry
from server.sli.reporting.v2.definition import QueryContext, ReportDefinition
from server.sli.sources.gpo_v2_source import GPO_HIDDEN_VALUE
from tests.unit.test_ad_plugin_reports import Handler
from tests.unit.test_gpo_effective_access import graph, snapshot as access_snapshot, topology
from tests.unit.test_gpo_sensitive_values import snapshot_with_setting, stored_snapshot

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_name("fixtures") / "gpo_report_sources_baseline.json.gz"
RELOCATIONS = {
    "server.sli.reports.gpo_v2_reporting": "server.sli.plugins.gpo.reports.gpo_v2_reporting",
    "server.sli.reporting.v2.reports.gpo": "server.sli.plugins.gpo.reports.definition",
}


@pytest.fixture(autouse=True)
def isolated_readers(monkeypatch):
    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    monkeypatch.setattr(update_runtime, "_pinned", {})
    plugins.registered_plugins.cache_clear()
    registry.registered_reports.cache_clear()

    def forbidden(*args, **kwargs):
        pytest.fail("GPO report tests must use fakes, never a database")

    for target in ("server.sli.core.postgres_runtime_pipeline.connect", "server.sli.core.database.query_rows",
                   "server.sli.core.database.query_rows_bounded"):
        monkeypatch.setattr(target, forbidden)
    yield
    plugins.registered_plugins.cache_clear()
    registry.registered_reports.cache_clear()


@pytest.fixture
def baseline(monkeypatch):
    sources = json.loads(gzip.decompress(FIXTURE.read_bytes()))["sources"]
    modules = []
    for old, name in zip(RELOCATIONS, ("_gpo_baseline_engine", "_gpo_baseline_definition"), strict=True):
        module = ModuleType(name)
        monkeypatch.setitem(sys.modules, name, module)
        source = sources[old].replace("from server.sli.reports.gpo_v2_reporting import", "from _gpo_baseline_engine import")
        tree = baseline_tree(source, old.rsplit(".", 1)[-1])
        exec(compile(tree, old, "exec"), module.__dict__)
        modules.append(module)
    return modules


@pytest.fixture
def pair():
    def snapshot(name):
        data = json.loads((ROOT / f"tests/fixtures/gpo_v2_reference_{name}.json").read_text("utf-8"))
        data["demo"] = False
        data["demo_notice"] = None
        data["domain"]["dns_name"] = data["domain"]["dns_root"] = "example.test"
        return data

    return {"state": "available", "current": snapshot("current"), "previous": snapshot("previous")}


def install_pair(monkeypatch, module, pair):
    def load(*, domain_ids):
        assert domain_ids == [7]
        return deepcopy(pair)

    monkeypatch.setattr(module, "load_authorized_snapshot_pair", load)


@pytest.mark.parametrize("old,new", RELOCATIONS.items())
def test_compatibility_alias_preserves_module_identity(old, new):
    assert importlib.import_module(old) is importlib.import_module(new)


@pytest.mark.parametrize("old,new", RELOCATIONS.items())
def test_relocation_changes_only_import_paths(old, new):
    sources = json.loads(gzip.decompress(FIXTURE.read_bytes()))["sources"]
    source = ROOT.joinpath(*new.split(".")).with_suffix(".py").read_text("utf-8")
    for original, relocated in RELOCATIONS.items():
        source = source.replace(relocated, original)
    # Keep relocation parity outside PR541's independently frozen passport delta.
    expected = baseline_tree(sources[old], old.rsplit(".", 1)[-1])
    assert ast.dump(ast.parse(source)) == ast.dump(expected)


def test_report_metadata_filters_detail_and_strings_match_baseline(baseline):
    before = baseline[1].REPORT
    assert definition.REPORT.to_json() == before.to_json()
    assert definition.REPORT.access == before.access
    assert definition.REPORT.detail == before.detail
    assert definition.REPORT.intent == before.intent


def test_registration_is_deferred_and_manifest_stays_report_only(monkeypatch):
    monkeypatch.setattr(importlib, "import_module", lambda *_args: pytest.fail("eager report import"))
    contribution = plugins.Contributions()
    registration.register(contribution)
    assert "reports" in contribution.hooks
    assert set(contribution.jobs) == {"gpo-snapshot", "gpo-acquisition"}
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.gpo.json").read_text("utf-8"))
    assert all(manifest[key] == [] for key in ("sources", "agent_modules", "handlers", "schedules", "dependencies"))
    assert manifest["own_permanent_workers"] is False
    assert {row["report_key"] for row in manifest["reports"]} == {"ad.gpo.v2", "ad.gpo.review"}
    assert {row["section_id"] for row in manifest["reports"]} == {"group-policies"}
    assert {route for row in manifest["reports"] for route in row["routes"]} == {"/gpo-report", "/report/ad.gpo.v2"}


def test_plugin_contributes_once_in_the_original_catalog_slot():
    assert plugins.registered_plugins()["sli.gpo"].hooks["reports"]() == (definition.REPORT,)
    assert "gpo" in plugins.PLUGIN_REPORT_MODULES
    found = [report.key for report in registry.registered_reports(validate_intents=True)]
    assert found.count("ad.gpo.v2") == 1
    from server.sli.reporting.v2 import reports as package

    # Reconstruct the old scanner's slots independently of the relocated namespace.
    slots = []
    for info in sorted(pkgutil.iter_modules(package.__path__), key=lambda item: item.name):
        if info.name in {"vpn_audit", "vpn_connections", "nps_policy_denials"}:
            continue
        report = getattr(importlib.import_module(f"{package.__name__}.{info.name}"), "REPORT", None)
        if isinstance(report, ReportDefinition):
            slots.append(report.key)
    assert found[:len(slots)] == slots


def test_missing_gpo_is_not_discovered_through_core_adapter(monkeypatch):
    monkeypatch.setattr(plugins, "BUNDLED", {key: value for key, value in plugins.BUNDLED.items() if key != "sli.gpo"})
    assert registry.get_report("ad.gpo.v2") is None
    assert registry.get_report("security.problems") is not None


def test_gpo_report_runs_without_ad_plugin(monkeypatch, pair):
    monkeypatch.setattr(plugins, "BUNDLED", {key: value for key, value in plugins.BUNDLED.items() if key != "sli.ad"})
    install_pair(monkeypatch, definition, pair)
    report = registry.get_report("ad.gpo.v2")
    assert report is not None
    assert report.query(QueryContext({}, {"view": "all"}, domain_ids=[7], tab="gpos"))["items"]


def test_gpo_drain_hides_only_its_report_and_fences_retained_callbacks(monkeypatch):
    report = registry.get_report("ad.gpo.v2")
    original = update_runtime.fenced
    monkeypatch.setattr(update_runtime, "fenced", lambda plugin_id: plugin_id == "sli.gpo" or original(plugin_id))
    monkeypatch.setattr(registry, "fenced", update_runtime.fenced)
    registry.registered_reports.cache_clear()
    assert registry.get_report("ad.gpo.v2") is None
    assert registry.get_report("ad.infrastructure") is not None
    assert registry.get_report("security.problems") is not None
    with pytest.raises(RuntimeError, match="plugin_update_draining"):
        report.query(QueryContext({}, {}, domain_ids=[7]))


def test_retained_report_callback_rejects_a_different_generation(monkeypatch):
    report = registry.get_report("ad.gpo.v2")
    monkeypatch.setattr(registry, "generation", lambda plugin_id: Path("synthetic-generation"))
    with pytest.raises(RuntimeError, match="plugin_version_changed"):
        report.query(QueryContext({}, {}, domain_ids=[7]))


@pytest.mark.parametrize("tab", ["gpos", "scopes", "settings", "permissions", "wmi", "quality"])
@pytest.mark.parametrize("query", ["", "no-match"])
def test_rows_filters_coverage_details_and_csv_match_baseline(monkeypatch, baseline, pair, tab, query):
    before, after = baseline[1], definition
    for module in (before, after):
        install_pair(monkeypatch, module, pair)
    context = QueryContext({}, {"view": "all", "q": query}, domain_ids=[7], tab=tab, sort="name", direction="desc")
    assert before.REPORT.query(context) == after.REPORT.query(context)
    assert before.REPORT.export_csv(context) == after.REPORT.export_csv(context)


@pytest.mark.parametrize("view", ["attention", "unverified", "assignment", "all", "linked", "unlinked"])
def test_engine_payload_and_filters_match_baseline(baseline, pair, view):
    before, after = baseline[0], engine
    assert before.build_gpo_v2_payload(pair) == after.build_gpo_v2_payload(pair)
    assert before.filter_snapshot_view(pair["current"], view) == after.filter_snapshot_view(pair["current"], view)
    assert snapshot_projection.project_gpo_v2_exact(pair["current"]) == before.project_gpo_v2_exact(pair["current"])


@pytest.mark.parametrize("state", ["not_collected", "denied", "processing", "error", "partial"])
def test_missing_source_states_match_baseline(monkeypatch, baseline, state):
    pair = {"state": state, "current": None, "previous": None}
    for module in (baseline[1], definition):
        install_pair(monkeypatch, module, pair)
    context = QueryContext({}, {}, domain_ids=[7])
    assert baseline[1].REPORT.query(context) == definition.REPORT.query(context)


@pytest.mark.parametrize("tab", ["filtering", "delegation", "linked_scopes"])
@pytest.mark.parametrize("status", ["observed", "partial"])
def test_effective_access_and_linked_scopes_match_baseline(monkeypatch, baseline, tab, status):
    snapshot = access_snapshot()
    snapshot.update(topology())
    snapshot["observed_at"] = "2099-01-01T00:00:00Z"
    snapshot["source_states"]["links"]["status"] = status
    directory = graph()
    directory["source"]["observed_at_utc"] = snapshot["observed_at"]
    pair = {"state": "available", "current": snapshot, "previous": None}
    for module in (baseline[1], definition):
        install_pair(monkeypatch, module, pair)
        monkeypatch.setattr(module, "load_directory_graph", lambda *_args, **_kwargs: deepcopy(directory))
    context = QueryContext({}, {}, domain_ids=[7], tab=tab)
    assert baseline[1].REPORT.query(context) == definition.REPORT.query(context)
    assert baseline[1].REPORT.export_csv(context) == definition.REPORT.export_csv(context)


@pytest.mark.parametrize("state", ["ok", "partial", "not_collected", "unavailable"])
def test_confirmed_history_and_export_match_without_ad_plugin(monkeypatch, baseline, state):
    monkeypatch.setattr(plugins, "BUNDLED", {key: value for key, value in plugins.BUNDLED.items() if key != "sli.ad"})
    monkeypatch.setattr(ad_snapshot_change_reporting, "read_changes", lambda **kwargs: {
        "state": state, "items": [{"object_id": "synthetic-policy", "kind": "attribute_changed",
                                   "before_sha256": "a" * 64, "after_sha256": "b" * 64}],
        "coverage": {"state": state}, "truncated": False,
    })
    context = QueryContext({}, {"period": {"from_utc": "2026-10-01T00:00:00Z", "to_utc": "2026-10-02T00:00:00Z"}},
                           domain_ids=[7], tab="changes")
    report = registry.get_report("ad.gpo.v2")
    assert report.query(context) == baseline[1].REPORT.query(context)

    def export_outcome(report):
        try:
            return report.export_csv(context)
        except ValueError as exc:
            return type(exc).__name__, str(exc)

    assert export_outcome(report) == export_outcome(baseline[1].REPORT)


@pytest.mark.parametrize("suffix", ["", "/data", "/export.csv"])
@pytest.mark.parametrize("fields", [[], ["identity_basic", "technical", "security"],
                                   ["identity_basic", "technical", "security", "privilege"]])
def test_api_metadata_rows_export_and_denials_match_baseline(monkeypatch, baseline, pair, suffix, fields):
    monkeypatch.setattr(routes, "report_plugin_state", lambda key: None)
    monkeypatch.setattr(routes, "annotate_plugin_report", lambda key, payload: payload)
    decision = {"reports": [{"report_key": "ad.gpo.v2", "allowed": True, "allowed_actions": ["view", "export"],
                            "grants": [{"allowed_actions": ["view", "export"], "field_categories": fields,
                                        "scope": {"kind": "domain", "ids": [7]}}]}]}
    responses = []
    for module in (baseline[1], definition):
        install_pair(monkeypatch, module, pair)
        monkeypatch.setattr(routes, "get_report", lambda key: module.REPORT)
        handler = Handler(decision)
        assert routes.try_handle_get(handler, "/api/v2/reports/ad.gpo.v2" + suffix, {"view": ["all"]})
        responses.append(handler.response())
    assert responses[0] == responses[1]


def test_stored_sensitive_values_stay_masked_in_rows_and_csv(monkeypatch, baseline):
    snapshot = snapshot_with_setting({"setting_name": "Password", "value": "synthetic-redaction-marker"})
    stored, _ = stored_snapshot(snapshot)
    pair = {"state": "partial", "current": stored, "previous": None}
    context = QueryContext({}, {"view": "all"}, domain_ids=[7], tab="settings")
    results = []
    for module in (baseline[1], definition):
        install_pair(monkeypatch, module, pair)
        results.append((module.REPORT.query(context), module.REPORT.export_csv(context)))
    assert results[0] == results[1]
    assert GPO_HIDDEN_VALUE in repr(results[1])
    assert "synthetic-redaction-marker" not in repr(results[1])
