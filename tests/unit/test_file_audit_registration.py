"""Reviewed package loading, compatibility and exactly one normalizer owner."""
from copy import deepcopy
import importlib
import json
from pathlib import Path

import pytest

from server.sli.plugins import registry, update_runtime
from server.sli.plugins.file_audit import manifest
from server.sli.reporting.v2 import registry as reports
from server.sli.storage.storage_v2_repository_columns import EVENT_FACTS_V2_WRITE_COLUMNS
from server.source_packs import registry as packs
from server.source_packs.normalizers import get_source_normalizer, register_source_normalizer
from sli_agent.file_audit_policy import CONTEXT_EVENT_IDS, EVENT_IDS, OPTIONAL_EVENT_IDS, PROVIDER


@pytest.fixture(autouse=True)
def isolated_registry(monkeypatch):
    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    monkeypatch.setattr(update_runtime, "_pinned", {})
    registry.registered_plugins.cache_clear()
    packs._source_packs.cache_clear()
    packs.resolve_source_pack.cache_clear()
    reports.registered_reports.cache_clear()
    yield
    registry.registered_plugins.cache_clear()
    packs._source_packs.cache_clear()
    packs.resolve_source_pack.cache_clear()
    reports.registered_reports.cache_clear()


def test_reviewed_entry_is_registered_with_no_execution(monkeypatch):
    module = importlib.import_module(registry.BUNDLED["sli.file-audit"])
    with monkeypatch.context() as patch:
        patch.setattr("subprocess.Popen", lambda *_a, **_kw: pytest.fail("started process"))
        patch.setattr("threading.Thread.start", lambda *_a: pytest.fail("started thread"))
        # Guard setup may resolve imports; only registration must forbid them.
        patch.setattr(importlib, "import_module", lambda *_a, **_kw: pytest.fail("eager executor import"))
        contribution = registry.Contributions()
        module.register(contribution)
        assert contribution.hooks["health"]() is True
        assert contribution.jobs == {}
    assert registry.plugin_installed("sli.file-audit")
    assert registry.call_plugin("sli.file-audit", "manifest")["plugin_id"] == "sli.file-audit"
    assert len(registry.call_plugin("sli.file-audit", "report_contracts")) == 8
    assert callable(registry.plugin_hook("sli.file-audit", "file_audit_activity_findings"))
    assert callable(registry.plugin_hook("sli.file-audit", "file_audit_permission_findings"))
    assert reports.get_report("file-audit.actions") is not None
    assert reports.get_report("security.problems") is not None


@pytest.mark.parametrize("event_id", (*EVENT_IDS, *OPTIONAL_EVENT_IDS))
def test_file_events_have_exactly_one_owner(event_id):
    pack = packs.resolve_source_pack("Security", PROVIDER, str(event_id))
    assert pack.pack_id == "sli.windows.file-audit"
    owners = [item.pack_id for item in packs._source_packs() if item.matches("Security", PROVIDER, str(event_id))]
    assert owners == ["sli.windows.file-audit"]
    assert pack.adapters == () and pack.collector is None
    assert get_source_normalizer(pack.normalizer_id).normalizer_id == "windows-file-audit-v1"


@pytest.mark.parametrize("event_id", CONTEXT_EVENT_IDS)
def test_shared_context_stays_owned_by_ad(event_id):
    provider = "Microsoft-Windows-Eventlog" if event_id == 1102 else PROVIDER
    assert packs.resolve_source_pack("Security", provider, str(event_id)).pack_id == "sli.windows.ad-dc"


def test_unknown_provider_or_channel_cannot_claim_file_events():
    assert packs.resolve_source_pack("System", PROVIDER, "4663") is None
    assert packs.resolve_source_pack("Security", "unreviewed-provider", "4663") is None


@pytest.mark.parametrize("present", ["manifest", "entry"])
def test_missing_package_keeps_core_usable_and_ignores_retained_source_manifest(tmp_path, monkeypatch, present):
    entry = registry.BUNDLED["sli.file-audit"]
    path = (tmp_path / "config/plugin_packages/v3/sli.file-audit.json" if present == "manifest"
            else tmp_path / Path(*entry.split(".")).with_suffix(".py"))
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(registry, "ROOT", tmp_path)
    assert not registry.plugin_installed("sli.file-audit")
    assert packs.get_source_pack("sli.windows.file-audit") is None
    assert packs.resolve_source_pack("Security", PROVIDER, "4663") is None
    assert reports.get_report("security.problems") is not None
    assert registry.call_plugin("sli.file-audit", "health")["state"] == "not_installed"


def test_reserved_normalizer_cannot_be_replaced():
    from dataclasses import replace
    normalizer = get_source_normalizer("windows-file-audit-v1")
    with pytest.raises(ValueError, match="reserved by a bundled pack"):
        register_source_normalizer(replace(normalizer, event_facts=lambda **_kw: {}))


def test_normalizer_retains_only_allowlisted_source_facts_and_does_not_infer_actions():
    normalizer = get_source_normalizer("windows-file-audit-v1")
    row = {"channel": "Security", "provider_name": PROVIDER, "event_id": 4663}
    data = {"ObjectName": "C:\\synthetic\\file", "SubjectUserSid": "S-1-1-0", "SubjectLogonId": "0x123",
            "AccessMask": "0x10000", "PrivateMarker": "must-not-be-copied"}
    facts = normalizer.event_facts(row=row, event_data=data)
    assert set(facts) == EVENT_FACTS_V2_WRITE_COLUMNS - {"event_id", "source_facts_sha256"}
    assert facts["object_name"] == data["ObjectName"]
    assert {key for key, value in facts.items() if value is not None} == {"object_name", "file_audit_facts_json"}
    assert json.loads(facts["file_audit_facts_json"]) == {
        "contract_id": "file-audit.facts.v1", "object_name": data["ObjectName"],
        "subject_user_sid": "S-1-1-0", "logon_id": "0x123", "logon_id_numeric": 291,
        "access_mask": 65536, "outcome": "unknown",
    }
    assert normalizer.semantic_projection(event_id=4663, channel="Security", provider=PROVIDER,
                                          event_data=data, source_host="synthetic", correlation_id=None) == {}
    deletion = normalizer.event_facts(row={**row, "event_id": 4660}, event_data={"HandleId": "0x1"})
    assert {key for key, value in deletion.items() if value is not None} == {"file_audit_facts_json"}
    assert json.loads(deletion["file_audit_facts_json"]) == {
        "contract_id": "file-audit.facts.v1", "handle_id": 1, "outcome": "unknown",
    }
    assert normalizer.event_facts(row={**row, "provider_name": "wrong"}, event_data=data) == {}
    oversized = normalizer.event_facts(row=row, event_data={"ObjectName": "x" * 4097})
    assert {key for key, value in oversized.items() if value is not None} == {"file_audit_facts_json"}
    assert json.loads(oversized["file_audit_facts_json"]) == {
        "contract_id": "file-audit.facts.v1", "outcome": "unknown",
    }


@pytest.mark.parametrize("core,agent,error", [("2.0.0", "1.0.0", "core"), ("4.0.0", "1.0.0", "core"),
                                            ("3.0.0", "0.9.0", "agent"), ("3.0.0", "2.0.0", "agent")])
def test_manifest_rejects_incompatible_versions(core, agent, error):
    with pytest.raises(ValueError, match=f"file_audit_{error}_api_incompatible"):
        manifest.load_manifest(core_api=core, agent_api=agent)


@pytest.mark.parametrize("change,error", [
    (lambda value: value.update(plugin_id="sli.unreviewed"), "identity"),
    (lambda value: value.update(plugin_version="1.0.1"), "identity"),
    (lambda value: value["data"].update(schema="sli_plugin_unreviewed"), "identity"),
    (lambda value: value.update(own_permanent_workers=True), "shape"),
    (lambda value: value.update(command="unreviewed"), "shape"),
    (lambda value: value.update(capabilities=[]), "capabilities"),
    (lambda value: value["sources"][0].update(normalizer_id="windows-ad-dc-v1"), "source"),
    (lambda value: value["reports"][0].update(dataset_id="file-audit.unreviewed"), "report_contract"),
    (lambda value: value["reports"].append(deepcopy(value["reports"][0])), "report_contract"),
    (lambda value: value["data"]["migrations"][0].update(version=182), "migration"),
    (lambda value: value["data"]["migrations"][-1].update(version=190), "migration"),
    (lambda value: value["data"]["migrations"][-1].update(version=195), "migration"),
    (lambda value: value["data"]["migrations"][-1].update(core_prerequisites=[194]), "migration"),
    (lambda value: value["data"]["migrations"][-1].update(path="config/postgres_migrations/195_workstation_file_audit.sql"), "migration"),
    (lambda value: value["data"]["migrations"][-1].update(sha256="a" * 64), "migration_checksum"),
    (lambda value: value["data"]["migrations"][-1].update(core_prerequisites=[189]), "migration"),
    (lambda value: value["data"]["migrations"][-1].update(path="config/postgres_migrations/190_file_audit_reports.sql"), "migration"),
    (lambda value: value["data"]["migrations"][0].update(core_prerequisites=[181]), "migration"),
    (lambda value: value["data"]["migrations"][0].update(path="config/postgres_migrations/182_file_audit_contracts.sql"), "migration"),
    (lambda value: value["data"]["migrations"][0].update(path="config/postgres_migrations/181_ad_state_privilege_category.sql"), "migration"),
    (lambda value: value["data"]["migrations"][0].update(sha256="a" * 64), "migration_checksum"),
    (lambda value: value["data"]["migrations"][1].update(version=184), "migration"),
    (lambda value: value["data"]["migrations"][1].update(core_prerequisites=[183]), "migration"),
    (lambda value: value["data"]["migrations"][1].update(path="config/postgres_migrations/184_file_audit_management.sql"), "migration"),
    (lambda value: value["data"]["migrations"][1].update(sha256="a" * 64), "migration_checksum"),
    (lambda value: value["data"]["migrations"][3].update(version=188), "migration"),
    (lambda value: value["data"]["migrations"][3].update(core_prerequisites=[185]), "migration"),
    (lambda value: value["data"]["migrations"][3].update(sha256="a" * 64), "migration_checksum"),
])
def test_manifest_rejects_unreviewed_contracts_and_checksum_drift(change, error):
    value = json.loads((manifest.ROOT / "config/plugin_packages/v3/sli.file-audit.json").read_text("utf-8"))
    change(value)
    with pytest.raises(ValueError, match="manifest_shape_invalid" if error == "shape" else f"file_audit_{error}_invalid"):
        manifest.validate_manifest(value)
