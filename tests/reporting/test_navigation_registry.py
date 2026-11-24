from __future__ import annotations

import json
import re
from copy import deepcopy

import pytest

from server.api.routes import reports_v2
from server.sli.reporting import navigation_registry as nav
from server.sli.reporting.v2 import registry


@pytest.fixture
def declarations():
    def read(path):
        return json.loads(path.read_text(encoding="utf-8"))

    return (
        read(nav.ROOT / "config/navigation_v3.json"),
        [read(nav.ROOT / "config/plugin_packages/v3" / (
            "sli.workstations.1.1.0.json" if plugin_id == "sli.workstations" else f"{plugin_id}.json"
        )) for plugin_id in sorted(nav.PLUGIN_IDS)],
        read(nav.ROOT / "config/plugin_architecture_v3.json"),
    )


def access():
    return {"capabilities": ["problem.view", "entity.view"], "reports": [
        {"report_key": key, "allowed": True} for key in
        ("ad.state", "ad.users.v2", "ad.computers.v6", "ad.computer-logons", "ad.gpo.v2", "vpn.audit", "security.queue")
    ]}


def entry_ids(navigation):
    return [entry["id"] for section in navigation["sections"] for group in section["groups"] for entry in group["entries"]]


def test_every_report_has_one_owner_and_preserves_access_keys(declarations):
    _, owners = nav.load_registry()
    all_reports = [report for manifest in declarations[1] for report in manifest["reports"]]
    declared_keys = [*declarations[0]["core_reports"], *(report["report_key"] for report in all_reports)]
    assert len(declared_keys) == len(set(declared_keys))
    definitions = registry.registered_reports()
    assert "security.rule-quality" in {definition.key for definition in definitions}
    for definition in definitions:
        owner = owners[definition.key]
        if owner["owner_id"] == "sli.core":
            assert owner["section_id"] == definition.section
            continue
        assert owner["access_key"] == definition.access.report_key
        assert set(owner["required_fields"]) == set(definition.access.required_fields)
        assert f"/report/{definition.key}" in owner["routes"]
        assert owner["definition_id"] == definition.key
    assert owners["ad.gpo.v2"]["owner_id"] == "sli.gpo"
    assert owners["ad.gpo.v2"]["section_id"] == "group-policies"
    assert owners["ad.users.v2"]["section_id"] == "active-directory"
    assert owners["vpn.connections"]["owner_id"] == owners["vpn.audit"]["owner_id"] == "sli.remote-access"


def test_catalog_exposes_ownership_without_changing_report_sections():
    catalog = registry.catalog(access())
    items = {item["key"]: item for item in catalog["items"]}
    assert items["ad.users.v2"]["owner_id"] == "sli.ad"
    assert items["ad.users.v2"]["navigation_section"] == "active-directory"
    assert items["ad.users.v2"]["section"] == registry.get_report("ad.users.v2").section
    assert items["ad.gpo.v2"]["owner_id"] == "sli.gpo"
    assert items["ad.gpo.v2"]["navigation_section"] == "group-policies"


def test_ad_dc_agent_declaration_stays_in_runtime_manifest(declarations):
    config, manifests, schema = declarations
    runtime = json.loads((nav.ROOT / "config/plugin_packages/sli.ad.agent-v3.json").read_text(encoding="utf-8"))
    declarations_by_id = {item["module_id"]: item for item in runtime["agent_modules"]}
    assert len(declarations_by_id) == len(runtime["agent_modules"])
    assert set(declarations_by_id) == {"sli.windows.ad-dc", "sli.windows.ad-dc-history"}
    for declaration in declarations_by_id.values():
        assert declaration["rights_check_id"] == "windows-dc-eventlog-read"
        assert declaration["policy_schema_ref"] == "sli.ad-dc-policy.v1"
    ad = next(manifest for manifest in manifests if manifest["plugin_id"] == "sli.ad")
    assert ad["agent_modules"] == []
    owners = nav.validate_registry(config, manifests, schema)
    assert owners["ad.users.v2"]["owner_id"] == "sli.ad"

    ad["agent_modules"] = deepcopy(runtime["agent_modules"])
    with pytest.raises(ValueError, match="navigation_manifest_not_in_place"):
        nav.validate_registry(config, manifests, schema)


def test_nps_policy_dataset_is_contributed_by_remote_access(declarations):
    registry_data, manifests, schema = declarations
    remote = next(manifest for manifest in manifests if manifest["plugin_id"] == "sli.remote-access")
    assert any(dataset["dataset_id"] == "vpn.policy-denials" for dataset in remote["datasets"])
    entry = next(entry for section in registry_data["sections"] for group in section["groups"]
                 for entry in group["entries"] if entry["id"] == "vpn-connections")
    assert entry["datasets"] == ["vpn.policy-denials"]
    assert entry["plugin_id"] == "sli.remote-access"
    nav.validate_registry(registry_data, manifests, schema)
    entry["datasets"] = ["foreign.dataset"]
    with pytest.raises(ValueError, match="navigation_dataset_owner_invalid"):
        nav.validate_registry(registry_data, manifests, schema)


def test_legacy_registry_keys_remain_owned():
    _, owners = nav.load_registry()
    keys = set()
    for path in (nav.ROOT / "config/postgres_migrations").glob("*.sql"):
        if "rollback" in path.name:
            continue
        sql = path.read_text(encoding="utf-8")
        keys.update(re.findall(r"insert into report_registry_v4\s*\([^;]+?\)\s*select\s*'([a-z0-9.-]+)'", sql, re.I))
        match = re.search(r"with definitions\(report_key,[^;]+?as \(values(.*?)\)\s*insert into report_registry_v4", sql, re.S | re.I)
        if match:
            keys.update(re.findall(r"\('([a-z0-9.-]+)'", match[1]))
    assert keys
    assert keys <= owners.keys()


@pytest.mark.parametrize("plugin_id,hidden", [
    ("sli.ad", {"ad-report", "users-report", "computers-report", "new-logon-pairs-report"}),
    ("sli.gpo", {"gpo-report"}),
    ("sli.remote-access", {"vpn-connections"}),
])
def test_disable_hides_only_contributions_and_preserves_history(plugin_id, hidden):
    decision = access()
    enabled = registry.catalog(decision)
    disabled = registry.catalog(decision, plugin_states=[{"plugin_id": plugin_id, "enabled": False}])
    assert enabled["items"] == disabled["items"]
    ids = set(entry_ids(disabled["navigation"]))
    assert not ids.intersection(hidden)
    assert {"workspace", "problems"} <= ids
    assert "objects" not in ids
    if plugin_id == "sli.ad":
        assert "gpo-report" in ids
    if plugin_id == "sli.gpo":
        assert "users-report" in ids
    assert registry.get_report("ad.gpo.v2") is not None


def test_navigation_never_widens_existing_grants():
    assert entry_ids(nav.navigation({"reports": [], "capabilities": []})) == ["workspace"]
    denied = {"reports": [{"report_key": "ad.users.v2", "allowed": False}]}
    assert entry_ids(nav.navigation(denied)) == ["workspace"]


@pytest.mark.parametrize("grants,entry_id,view_ids", [
    (["ad.computers.v6"], "computers-report", ["computers"]),
    (["ad.computer-logons"], "computers-report", ["logons"]),
    (["ad.computers.v6", "ad.computer-logons"], "computers-report", ["computers", "logons"]),
    (["vpn.audit"], "vpn-connections", ["connections"]),
    (["vpn.connections"], "vpn-connections", ["connections"]),
])
def test_merged_entries_keep_independent_view_grants(grants, entry_id, view_ids):
    decision = {"reports": [{"report_key": key, "allowed": True} for key in grants]}
    result = nav.navigation(decision)
    entries = [entry for section in result["sections"] for group in section["groups"] for entry in group["entries"]]
    entry = next(entry for entry in entries if entry["id"] == entry_id)
    assert [view["id"] for view in entry["views"]] == view_ids
    assert not {"objects", "logons-report", "vpn-access"}.intersection(entry_ids(result))
    assert result["global_search"] == {"path": "/search", "capabilities": ["objects.view", "entity.view"]}


def test_registry_redirects_keep_old_report_keys_and_access_contracts():
    config, owners = nav.load_registry()
    redirects = {item["from"]: item for item in config["redirects"]}
    assert redirects["/report/ad.computer-logons"] == {
        "from": "/report/ad.computer-logons", "to": "/report/ad.computers.v6", "view": "logons",
    }
    assert redirects["/vpn-report"] == {"from": "/vpn-report", "to": "/report/vpn.connections", "view": "connections"}
    assert "/report/vpn.accounts" not in redirects
    for key in ["ad.computer-logons", "vpn.accounts", "vpn.connections"]:
        assert owners[key]["access_key"] == registry.get_report(key).access.report_key
    assert redirects["/objects"]["to"] == redirects["/entities"]["to"] == config["global_search"]["path"]


@pytest.mark.parametrize("mutation,error", [
    (lambda c: c["redirects"][2].update(view="unknown"), "redirect_invalid"),
    (lambda c: c["redirects"].append(deepcopy(c["redirects"][0])), "duplicate_redirect"),
    (lambda c: c["redirects"][0].update(to="/entities"), "redirect_invalid"),
])
def test_registry_rejects_broken_compatibility_redirects(declarations, mutation, error):
    config, manifests, schema = deepcopy(declarations)
    mutation(config)
    with pytest.raises(ValueError, match=error):
        nav.validate_registry(config, manifests, schema)


@pytest.mark.parametrize("view_grants", [["ad.computers.v6"], ["ad.computer-logons", "ad.computers.v6"]])
def test_registry_rejects_a_view_with_another_reports_access_key(declarations, view_grants):
    config, manifests, schema = deepcopy(declarations)
    entry = next(entry for section in config["sections"] for group in section["groups"]
                 for entry in group["entries"] if entry["id"] == "computers-report")
    entry["views"][1]["reports"] = view_grants
    entry["reports"] = sorted({key for view in entry["views"] for key in view["reports"]})
    with pytest.raises(ValueError, match="entry_reference_invalid"):
        nav.validate_registry(config, manifests, schema)


def test_gpo_has_its_own_section_and_disables_independently():
    enabled = nav.navigation(access())
    sections = {section["id"]: section for section in enabled["sections"]}
    assert sections["group-policies"]["title"] == "shell.section.group-policies"
    assert entry_ids({"sections": [sections["group-policies"]]}) == ["gpo-report"]
    assert "gpo-report" not in entry_ids({"sections": [sections["active-directory"]]})
    disabled = nav.navigation(access(), [{"plugin_id": "sli.gpo", "enabled": False}])
    assert "group-policies" not in {section["id"] for section in disabled["sections"]}
    assert "users-report" in entry_ids(disabled)


def test_config_disables_plugins_independently(monkeypatch):
    config, owners = nav.load_registry()
    config = deepcopy(config)
    config["enabled_plugins"] = ["sli.gpo"]
    monkeypatch.setattr(nav, "load_registry", lambda: (config, owners))
    assert entry_ids(nav.navigation(access())) == ["workspace", "problems", "gpo-report"]


def test_catalog_api_reads_activation_with_a_fake(monkeypatch):
    monkeypatch.setattr(reports_v2, "navigation_plugin_states", lambda: [{"plugin_id": "sli.remote-access", "enabled": False}])

    class Handler:
        def _access_decision(self):
            return access()

        def _send_json(self, payload):
            self.payload = payload

    handler = Handler()
    assert reports_v2.try_handle_get(handler, "/api/v2/reports", {})
    assert "vpn-access" not in entry_ids(handler.payload["navigation"])
    assert "vpn.accounts" in {item["key"] for item in handler.payload["items"]}


def test_activation_observation_is_read_only_and_fails_closed(monkeypatch):
    monkeypatch.setattr(nav, "list_plugin_states", lambda: [{"plugin_id": "sli.remote-access", "enabled": False}])
    assert nav.navigation_plugin_states() == [{"plugin_id": "sli.remote-access", "enabled": False}]
    monkeypatch.setattr(nav, "list_plugin_states", lambda: [])
    assert nav.navigation_plugin_states() == [{"plugin_id": "sli.remote-access", "enabled": False}]

    def unavailable():
        raise RuntimeError("state_unavailable")

    monkeypatch.setattr(nav, "list_plugin_states", unavailable)
    assert nav.navigation_plugin_states() == [{"plugin_id": "sli.remote-access", "enabled": False}]


@pytest.mark.parametrize("mutation,error", [
    (lambda m: m.update(schema_version=2), "value_invalid"),
    (lambda m: m.update(own_permanent_workers=True), "value_invalid"),
    (lambda m: m.update(own_permanent_workers=0), "type_invalid"),
    (lambda m: m.update(workers=[]), "unknown_field"),
    (lambda m: m["core_api"].update(minimum="4.0.0"), "core_api_incompatible"),
    (lambda m: m["reports"].append(deepcopy(m["reports"][0])), "duplicate_report_owner"),
    (lambda m: m["reports"][0].update(dataset_id="unknown.dataset"), "report_reference_invalid"),
    (lambda m: m["reports"][0].update(section_id="admin"), "report_reference_invalid"),
    (lambda m: m["reports"][0].update(history_reader_id="unknown.reader"), "history_reader_invalid"),
    (lambda m: m["reports"][0].update(title_key="unknown.title"), "entry_reference_invalid"),
    (lambda m: m["navigation"].append(deepcopy(m["navigation"][0])), "duplicate_section"),
])
def test_manifest_loader_rejects_invalid_contributions(declarations, mutation, error):
    config, manifests, schema = deepcopy(declarations)
    mutation(manifests[0])
    with pytest.raises(ValueError, match=error):
        nav.validate_registry(config, manifests, schema)


@pytest.mark.parametrize("mutation", [
    lambda entry: entry.pop("plugin_id"),
    lambda entry: entry.update(plugin_id="sli.gpo"),
])
def test_plugin_navigation_cannot_lose_its_owner(declarations, mutation):
    config, manifests, schema = deepcopy(declarations)
    section = next(section for section in config["sections"] if section["id"] == "active-directory")
    mutation(section["groups"][0]["entries"][0])
    with pytest.raises(ValueError, match="entry_reference_invalid"):
        nav.validate_registry(config, manifests, schema)


def test_core_report_section_must_exist(declarations):
    config, manifests, schema = deepcopy(declarations)
    config["sections"] = [section for section in config["sections"] if section["id"] != "investigation"]
    with pytest.raises(ValueError, match="core_section_invalid"):
        nav.validate_registry(config, manifests, schema)


def test_admin_groups_follow_accepted_ia_and_keep_independent_grants():
    result = nav.navigation({"capabilities": ["access.manage", "operations.view", "reports.design"],
                             "reports": [{"report_key": "operations.readiness", "allowed": True}]})
    admin = next(section for section in result["sections"] if section["id"] == "admin")
    assert {group["id"]: [entry["path"] for entry in group["entries"]] for group in admin["groups"]} == {
        "status": ["/admin/status"],
        "base": ["/agents", "/access", "/notifications", "/operations", "/admin/language-time", "/admin/update"],
        "plugins": [
            "/admin/plugins/sli.ad", "/admin/plugins/sli.gpo", "/admin/plugins/sli.workstations",
            "/admin/plugins/sli.file-audit", "/admin/plugins/sli.remote-access", "/admin/plugins/sli.sigma", "/plugins",
        ],
        "advanced": ["/report-studio", "/admin/activity"],
    }
    assert entry_ids(nav.navigation({})) == ["workspace"]
    assert entry_ids(nav.navigation({"capabilities": ["operations.view"]})) == [
        "workspace", "admin-status", "operations", "admin-plugin-ad", "admin-plugin-gpo", "admin-plugin-workstations",
        "admin-plugin-file-audit", "admin-plugin-remote-access", "admin-plugin-sigma", "plugins",
    ]
    for report, destinations in [("notifications.deliveries", ["notifications"]),
                                 ("operations.readiness", ["admin-status"]),
                                 ("decoys.registry", ["admin-status"]),
                                 ("watch.registry", ["admin-status"])]:
        scoped = nav.navigation({"reports": [{"report_key": report, "allowed": True}]})
        assert entry_ids(scoped) == ["workspace", *destinations]
        assert entry_ids(nav.navigation({"reports": [{"report_key": report, "allowed": False}]})) == ["workspace"]
