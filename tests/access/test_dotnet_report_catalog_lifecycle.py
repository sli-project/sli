"""Differential access-catalog vectors from the frozen Python registry (no DB)."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

from server.sli.access import domain_scope
from server.sli.plugins.registry import Contributions
from server.sli.reporting.v2 import registry
from server.sli.reporting.v2.definition import AccessRule, ReportDefinition

ROOT = Path(__file__).resolve().parents[2]
VECTOR = ROOT / "server-dotnet/tests/Sli.Server.Tests/Access/catalog-lifecycle-source.json"
SOURCE = "ddce909d0ddebe43a670e63c85df369e0bd16f17"


def source_vectors(monkeypatch):
    token = {"value": None, "fenced": False}
    current = {"reports": ()}
    contribution = Contributions(hooks={"reports": lambda: current["reports"]})
    monkeypatch.setattr(registry, "registered_plugins", lambda: {"sli.ad": contribution})
    monkeypatch.setattr(registry, "generation", lambda _: token["value"])
    monkeypatch.setattr(registry, "fenced", lambda _: token["fenced"])
    # Admission is tested separately by the source updater tests. There is no host
    # runtime directory/lock in these synthetic declaration fixtures.
    monkeypatch.setenv("SLI_PLUGIN_RUNTIME_DIR", "")
    monkeypatch.setenv("SLI_PLUGIN_LOCK_DIR", "")
    monkeypatch.setattr(registry.pkgutil, "iter_modules", lambda _: ())
    owners = {"ad.infrastructure": {"owner_id": "sli.ad", "access_key": "ad.state",
              "definition_id": "ad.infrastructure", "required_fields": ["technical"],
              "routes": ["/report/ad.infrastructure"]}}
    # Workstation declarations are deliberately outside the guarded plugin loop.
    from server.sli.plugins.workstations.reports import REPORTS, make_report
    from server.sli.plugins.workstations.overview import make_report as overview
    for definition in (*map(make_report, REPORTS), overview()):
        owners[definition.key] = {"owner_id": "sli.core"}
    monkeypatch.setattr(registry, "load_registry", lambda: ({}, owners))
    rule = AccessRule("ad.state", frozenset({"technical"}))
    base = ReportDefinition("ad.infrastructure", "reports/identity", "Synthetic", "", "table",
                            rule, (), (), lambda _: {"generation": token["value"]}, "id")
    access = {"subject": {"coarse_role": "viewer"}, "capabilities": ["workspace.view"],
              "reports": [{"report_key": "ad.state", "allowed": True, "allowed_actions": ["view"],
                           "grants": [{"scope": {"kind": "all"}, "allowed_actions": ["view"],
                                       "field_categories": ["technical"]}]}]}
    cases = []

    def capture(name):
        definitions = tuple(r for r in registry.registered_reports() if r.key == base.key)
        payload = [{"key": r.key, "report_key": r.access.report_key, "scope": r.access.scope,
                    "required_fields": sorted(r.access.required_fields),
                    "required_capabilities": sorted(r.access.required_capabilities)} for r in definitions]
        cases.append({"name": name, "generation": token["value"], "fenced": token["fenced"],
                      "capabilities": list(access["capabilities"]), "declarations": payload,
                      "permitted_domain_ids": domain_scope._permitted_ids(access)})
        return definitions

    registry.registered_reports.cache_clear()
    try:
        current["reports"] = (base,)
        old = capture("bundled")[0]
        token["value"] = "a" * 64
        current["reports"] = (replace(base, access=replace(rule, required_capabilities=frozenset({"synthetic.view"}))),)
        capture("updated_capability_denied")
        access["capabilities"].append("synthetic.view")
        capture("updated_capability_allowed")
        token["fenced"] = True
        capture("disabled")
        token["fenced"] = False
        capture("enabled")
        current["reports"] = (replace(base, access=replace(rule, required_fields=frozenset({"security"}))),)
        owners[base.key]["required_fields"] = ["security"]
        registry.registered_reports.cache_clear()
        capture("reregistered_fields_denied")
        current["reports"] = ()
        registry.registered_reports.cache_clear()
        capture("removed")
        token["value"] = None
        current["reports"] = (base,)
        owners[base.key]["required_fields"] = ["technical"]
        registry.registered_reports.cache_clear()
        capture("rollback")
        token["value"] = "b" * 64
        try:
            old.query(None)
        except RuntimeError as error:
            race = str(error)
        else:
            raise AssertionError("An old generation callback was admitted")
        token["fenced"] = True
        # Source admission checks update_runtime.fenced independently of registry.fenced.
        monkeypatch.setattr("server.sli.plugins.update_runtime.fenced", lambda _: True)
        try:
            old.query(None)
        except RuntimeError as error:
            drain = str(error)
        else:
            raise AssertionError("A draining callback was admitted")
        paths = ("server/sli/reporting/v2/registry.py", "server/sli/plugins/registry.py",
                 "server/sli/plugins/update_runtime.py")
        return {"source_commit": SOURCE,
                "source_sha256_lf": {p: hashlib.sha256((ROOT / p).read_bytes().replace(b"\r\n", b"\n")).hexdigest() for p in paths},
                "generation_race": race, "drain_callback": drain, "cases": cases}
    finally:
        registry.registered_reports.cache_clear()


def test_dynamic_catalog_matches_dotnet_vectors(monkeypatch):
    assert source_vectors(monkeypatch) == json.loads(VECTOR.read_text("utf-8"))
