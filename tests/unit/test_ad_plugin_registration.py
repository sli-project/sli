"""Reviewed AD loading, generation admission and namespace isolation."""
from __future__ import annotations

import importlib
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest

from server.sli.plugins import registry, update_runtime
from server.sli.reporting.v2 import registry as reports

PLUGIN_ID = "sli.ad"
ENTRY = "server.sli.plugins.ad.registration"


@contextmanager
def preserved_ad_modules(plugin_id=PLUGIN_ID):
    """Restore collected consumers' module identities after loader tests."""
    package = registry.BUNDLED[plugin_id].rsplit(".", 1)[0]

    def owned(name, module):
        implementation = getattr(module, "__name__", "")
        return (name == package or name.startswith(package + ".")
                or implementation == package or implementation.startswith(package + "."))

    previous = {name: module for name, module in tuple(sys.modules.items()) if owned(name, module)}
    attributes = []
    for name, module in previous.items():
        parent, _, child = name.rpartition(".")
        owner = sys.modules.get(parent)
        if owner is not None and getattr(owner, child, None) is module:
            attributes.append((owner, child, module))
    try:
        yield
    finally:
        for name, module in tuple(sys.modules.items()):
            if owned(name, module):
                parent, _, child = name.rpartition(".")
                owner = sys.modules.get(parent)
                if owner is not None and getattr(owner, child, None) is module:
                    delattr(owner, child)
                sys.modules.pop(name, None)
        sys.modules.update(previous)
        for owner, child, module in attributes:
            setattr(owner, child, module)


@pytest.fixture(autouse=True)
def isolated_registry(monkeypatch):
    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    monkeypatch.setattr(update_runtime, "_pinned", {})
    registry.registered_plugins.cache_clear()
    reports.registered_reports.cache_clear()
    with preserved_ad_modules(), preserved_ad_modules("sli.gpo"):
        yield
    registry.registered_plugins.cache_clear()
    reports.registered_reports.cache_clear()


def test_exactly_one_reviewed_ad_entry_point():
    assert registry.BUNDLED[PLUGIN_ID] == ENTRY
    assert [item for item in registry.discover_plugins() if item[0] == PLUGIN_ID] == [(PLUGIN_ID, ENTRY)]
    assert list(registry.BUNDLED.values()).count(ENTRY) == 1
    contribution = registry.registered_plugins()[PLUGIN_ID]
    assert set(contribution.hooks) == {
        "health", "semantic_capabilities", "list_targets", "add_target", "set_enabled", "import_from_file",
        "stored_enabled_targets", "get_configured_domain_controller_targets", "discover_domain_controllers",
        "configured_server_names", "configured_source_addresses", "plan_dc_onboarding",
        "domain_controllers", "source_configuration", "source_data", "context_interval", "handle_controller_post",
        "ad_agent_policy", "ad_agent_rows", "import_ad_agent_packet", "run_agent_import_once", "normalizer:windows-ad-dc-v1",
        "file_audit_principals",
        "import_snapshot_cycle", "reports", "schedule_jobs", "job_source", "get_runtime_entity_context_evidence",
        "get_ad_account_change_history", "get_ad_account_change_sources",
        "account_change_observation", "apply_observed_account_history", "get_ad_group_membership_history",
        "get_dc_powershell_activity", "handle_dc_powershell_activity_api", "handle_ad_account_change_history_api",
        "handle_ad_account_change_sources_api", "handle_security_event_sources_api", "handle_security_events_api",
        "handle_security_events_export_api", "handle_ad_group_membership_history_api", "security_event_arguments",
    }
    assert set(contribution.jobs) == {
        "ad-snapshot-manifest-coordinator", "ad-snapshot-projection",
        "ad-context-snapshot", "computers-v6-source", "users-report-v2-snapshot",
    }
    assert registry.call_plugin(PLUGIN_ID, "health") is True


def test_registration_and_health_import_no_executors(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("registration must not import an executor or start work")

    module = importlib.import_module(ENTRY)
    with monkeypatch.context() as patch:
        patch.setattr("subprocess.Popen", forbidden)
        patch.setattr("threading.Thread.start", forbidden)
        patch.setattr("multiprocessing.Process.start", forbidden)
        patch.setattr("server.sli.core.postgres_runtime_pipeline.connect", forbidden)
        patch.setattr("server.sli.core.database.query_rows", forbidden)
        # Resolve patch targets before forbidding imports by plugin code.
        patch.setattr(importlib, "import_module", forbidden)
        contribution = registry.Contributions()
        module.register(contribution)
        assert contribution.hooks["health"]() is True
    assert set(contribution.jobs) == {
        "ad-snapshot-manifest-coordinator", "ad-snapshot-projection",
        "ad-context-snapshot", "computers-v6-source", "users-report-v2-snapshot",
    }


def test_file_audit_principals_hook_is_deferred_and_forwards_context(monkeypatch):
    module = importlib.import_module(ENTRY)
    contribution = registry.Contributions()
    provider = ModuleType("server.sli.plugins.ad.file_audit_enrichment")
    imports = []
    cursor = object()
    context = {"domain_id": 1, "sids": ["S-1-5-21-1-2-3-1001"], "at": "2026-01-05T00:00:00Z"}
    expected = {}
    calls = []
    provider.principals = lambda cur, **kwargs: calls.append((cur, kwargs)) or expected

    def load(name):
        assert name == provider.__name__
        imports.append(name)
        return provider

    monkeypatch.setattr(importlib, "import_module", load)
    module.register(contribution)
    assert imports == []

    assert contribution.hooks["file_audit_principals"](cursor, **context) is expected
    assert imports == [provider.__name__]
    assert calls == [(cursor, context)]


def test_manifest_cannot_choose_executable_entry_point(tmp_path, monkeypatch):
    value = json.loads((registry.ROOT / "config/plugin_packages/v3/sli.ad.json").read_text("utf-8"))
    value["entrypoint"] = "unreviewed.registration"
    manifest = tmp_path / "config/plugin_packages/v3/sli.ad.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps(value), encoding="utf-8")
    (tmp_path / "config/plugin_architecture_v3.json").write_bytes(
        (registry.ROOT / "config/plugin_architecture_v3.json").read_bytes())
    executable = tmp_path / Path(*ENTRY.split(".")).with_suffix(".py")
    executable.parent.mkdir(parents=True)
    executable.write_text("", encoding="utf-8")
    monkeypatch.setattr(registry, "ROOT", tmp_path)
    imported = []
    original = importlib.import_module

    def load(name, *args, **kwargs):
        imported.append(name)
        return original(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", load)
    assert registry.discover_plugins() == ((PLUGIN_ID, ENTRY),)
    with pytest.raises(ValueError, match="^executable_or_sensitive_manifest_key:entrypoint$"):
        registry.call_plugin(PLUGIN_ID, "health")
    assert imported == []


@pytest.mark.parametrize("present", ["manifest", "entry"])
def test_missing_package_or_manifest_keeps_core_reports_available(tmp_path, monkeypatch, present):
    path = (tmp_path / "config/plugin_packages/v3/sli.ad.json" if present == "manifest"
            else tmp_path / Path(*ENTRY.split(".")).with_suffix(".py"))
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(registry, "ROOT", tmp_path)
    assert not registry.plugin_installed(PLUGIN_ID)
    assert registry.call_plugin(PLUGIN_ID, "health") == {
        "state": "not_installed", "reason": "plugin_not_installed", "plugin_id": PLUGIN_ID, "items": [],
    }
    assert reports.get_report("security.problems") is not None
    assert reports.get_report("ad.infrastructure") is None


def test_cache_invalidation_retains_bundled_module_identity(monkeypatch):
    module = importlib.import_module(ENTRY)
    first = registry.registered_plugins()[PLUGIN_ID]
    registry.registered_plugins.cache_clear()
    second = registry.registered_plugins()[PLUGIN_ID]
    assert second is not first
    assert second.hooks["health"] is first.hooks["health"] is module._health
    monkeypatch.setattr(registry, "discover_plugins", tuple)
    registry.registered_plugins.cache_clear()
    assert not registry.plugin_installed(PLUGIN_ID)


def test_reload_evicts_module_alias_and_parent_attribute(monkeypatch):
    previous = importlib.import_module(ENTRY)
    owner = ModuleType("synthetic_ad_compat")
    monkeypatch.setitem(sys.modules, owner.__name__, owner)
    monkeypatch.setitem(sys.modules, owner.__name__ + ".registration", previous)
    owner.registration = previous
    registry.load_generation(PLUGIN_ID, None)
    current = importlib.import_module(ENTRY)
    assert current is not previous
    assert owner.__name__ + ".registration" not in sys.modules
    assert not hasattr(owner, "registration")
    assert importlib.import_module("server.sli.plugins.ad").registration is current


def test_loader_isolation_restores_aliases_functions_and_contract_errors():
    from server.ad_context import contracts, repository
    from server.sli.plugins.ad.snapshots import coordinator

    one_shot = coordinator.run_one_shot
    readback = repository.load_projection_manifest
    with preserved_ad_modules(), preserved_ad_modules("sli.gpo"):
        registry.load_generation(PLUGIN_ID, None)
        current = importlib.import_module("server.ad_context.contracts")
        assert current is not contracts
        assert current.AdContextContractError is not contracts.AdContextContractError
        assert importlib.import_module(coordinator.__name__).run_one_shot is not one_shot
        assert importlib.import_module(repository.__name__).load_projection_manifest is not readback

    assert importlib.import_module("server.ad_context.contracts") is contracts
    assert importlib.import_module("server.ad_context.repository") is repository
    assert __import__("server.ad_context", fromlist=["contracts"]).contracts is contracts
    assert __import__("server.ad_context", fromlist=["repository"]).repository is repository
    assert importlib.import_module(coordinator.__name__).run_one_shot is one_shot
    assert importlib.import_module(repository.__name__).load_projection_manifest is readback
    with pytest.raises(contracts.AdContextContractError, match="bounded array"):
        contracts._gpo_settings(None)


@pytest.mark.posix_only
def test_retained_hook_observes_generation_changes_and_drain(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    monkeypatch.setenv("SLI_PLUGIN_RUNTIME_DIR", str(runtime))
    base = runtime / PLUGIN_ID
    # The host updater provides each installed owner's inode; report discovery
    # also admits remote-access while AD drains. Runtime admission is read-only.
    for plugin_id, _ in registry.discover_plugins():
        directory = runtime / plugin_id
        directory.mkdir(parents=True)
        (directory / "admission.lock").write_bytes(b"")
    hook = registry.plugin_hook(PLUGIN_ID, "health")
    assert hook() is True
    generation = "a" * 64
    backend = base / "versions" / generation / "backend"
    backend.mkdir(parents=True)
    (backend / "registration.py").write_text(
        "def register(contribution):\n    contribution.hooks['health'] = lambda: 'synthetic-generation'\n", encoding="utf-8",
    )
    (base / "active.json").write_text(json.dumps({"generation": generation}), encoding="utf-8")
    (base / "draining.json").write_text("{}", encoding="utf-8")
    with pytest.raises(RuntimeError, match="plugin_update_draining"):
        hook()
    assert reports.get_report("security.problems") is not None
    assert reports.get_report("ad.infrastructure") is None
    assert reports.get_report("vpn.connections") is not None
    (base / "draining.json").unlink()
    assert hook() == "synthetic-generation"
    (base / "active.json").unlink()
    assert hook() is True


def test_ad_navigation_manifest_remains_report_only():
    manifest = json.loads((registry.ROOT / "config/plugin_packages/v3/sli.ad.json").read_text("utf-8"))
    assert all(manifest[key] == [] for key in ("sources", "agent_modules", "handlers", "schedules"))
    assert manifest["own_permanent_workers"] is False
    # Existing agent/job registries retain their separate executable contracts.
    for suffix in ("agent", "jobs"):
        declaration = json.loads((registry.ROOT / f"config/plugin_packages/sli.ad.{suffix}-v3.json").read_text("utf-8"))
        assert declaration["plugin_id"] == PLUGIN_ID


@pytest.mark.parametrize("plugin_id", ["sli.ad", "sli.gpo"])
def test_jobs_registration_matches_existing_executable_manifest(plugin_id):
    manifest = json.loads((registry.ROOT / f"config/plugin_packages/{plugin_id}.jobs-v3.json").read_text("utf-8"))
    jobs = registry.registered_plugins()[plugin_id].jobs
    assert set(jobs) == {row["handler_id"] for row in manifest["handlers"]}
    assert all(row["handler_version"] == "1.0.0" for row in manifest["handlers"])
    assert all(callable(stage) and callable(apply) for stage, apply in jobs.values())


def test_gpo_registration_imports_no_snapshot_executor(monkeypatch):
    module = importlib.import_module(registry.BUNDLED["sli.gpo"])
    with monkeypatch.context() as patch:
        patch.setattr(importlib, "import_module", lambda *_args, **_kwargs: pytest.fail("eager executor import"))
        contribution = registry.Contributions()
        module.register(contribution)
    assert set(contribution.jobs) == {"gpo-snapshot", "gpo-acquisition"}


@pytest.mark.parametrize("plugin_id,handler_id", [
    ("sli.ad", "ad-snapshot-manifest-coordinator"), ("sli.gpo", "gpo-snapshot"),
])
@pytest.mark.posix_only
def test_registry_retains_old_job_hash_but_schedules_active_generation(tmp_path, monkeypatch, plugin_id, handler_id):
    from server.sli.core import job_registry
    from server.sli.core.job_queue import digest
    from tests.unit.test_ad_gpo_core_jobs import SnapshotConnection, job

    monkeypatch.setenv("SLI_CORE_JOB_AD_GPO_PILOT", "1")
    spec = job(handler_id)
    runtime = tmp_path / "runtime"
    monkeypatch.setenv("SLI_PLUGIN_RUNTIME_DIR", str(runtime))
    for owner, _ in registry.discover_plugins():
        base = runtime / owner
        base.mkdir(parents=True)
        (base / "admission.lock").write_bytes(b"")
    base = runtime / plugin_id
    token = "a" * 64
    version = base / "versions" / token
    backend = version / "backend"
    backend.mkdir(parents=True)
    manifest = json.loads((registry.ROOT / f"config/plugin_packages/{plugin_id}.jobs-v3.json").read_text("utf-8"))
    manifest["plugin_version"] = "2.0.0"
    (backend / "jobs-v3.json").write_text(json.dumps(manifest), encoding="utf-8")
    (backend / "registration.py").write_text(
        "def register(contribution):\n"
        "    for name in " + repr(tuple(row["handler_id"] for row in manifest["handlers"])) + ":\n"
        "        contribution.jobs[name] = (lambda conn, job: {'marker': 'installed'}, lambda *args: None)\n",
        encoding="utf-8",
    )
    (version / "release.json").write_text("{}", encoding="utf-8")
    (base / "active.json").write_text(json.dumps({"generation": token}), encoding="utf-8")
    handlers = job_registry.pilot_registry()
    assert handlers.resolve(spec)["manifest_sha256"] == spec["manifest_sha256"]
    active = [item for item in handlers.manifests if item["plugin_id"] == plugin_id]
    assert active == [manifest]
    assert digest(active[0]) != spec["manifest_sha256"]
    stage, _ = registry.plugin_job_handlers(plugin_id, handler_id)
    assert stage(None, spec) == {"marker": "installed"}
    bundled = registry.ROOT / f"config/plugin_packages/{plugin_id}.jobs-v3.json"
    update_runtime.pin_job(plugin_id, spec["plugin_version"], spec["manifest_sha256"], bundled)
    assert update_runtime.generation(plugin_id) is None
    assert stage(SnapshotConnection(), spec)["status"] == "success"
    update_runtime.pin_job(plugin_id, "2.0.0", digest(manifest), bundled)
    assert update_runtime.generation(plugin_id) == version
    assert stage(None, spec) == {"marker": "installed"}
    with pytest.raises(ValueError, match="handler_version_unavailable"):
        update_runtime.pin_job(plugin_id, "2.0.0", "f" * 64, bundled)


def test_entity_provider_is_deferred_and_keeps_history_with_acquisition_off(monkeypatch):
    from server.sli.plugins.ad.context import integration

    monkeypatch.delenv("SLI_CORE_JOB_AD_GPO_PILOT", raising=False)
    expected = {"entity_id": 42, "items": [], "returned_count": 0, "bounded": True}
    calls = []
    monkeypatch.setattr(integration, "get_runtime_entity_context_evidence",
                        lambda entity_id, **kwargs: calls.append((entity_id, kwargs)) or expected)
    assert registry.call_plugin("sli.ad", "get_runtime_entity_context_evidence", 42, limit=50) == expected
    assert calls == [(42, {"limit": 50})]


@pytest.mark.parametrize("state", ["absent", "draining", "timeout"])
def test_shared_entity_card_survives_unavailable_optional_provider(state, tmp_path, monkeypatch):
    from server.sli.core.database import QueryTimeoutError
    from server.sli.plugins.ad.context import integration
    from server.sli.reporting import ui_workspace

    monkeypatch.setattr(ui_workspace, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(ui_workspace, "query_rows", lambda *_args, **_kwargs: [{
        "id": 42, "entity_type": "asset", "natural_key": "synthetic", "display_name": "synthetic",
        "first_seen_utc": None, "last_seen_utc": None, "latest_state_status": None,
        "latest_state_summary": None, "latest_state_observed_at_utc": None,
        "latest_state_event_db_id": None,
    }])
    monkeypatch.setattr(ui_workspace, "_get_current_entity_states", lambda **_kwargs: [])
    monkeypatch.setattr(ui_workspace, "_get_entity_evidence_event_rows", lambda **_kwargs: [])
    if state == "absent":
        monkeypatch.setattr(registry, "discover_plugins",
                            lambda: tuple((owner, entry) for owner, entry in registry.BUNDLED.items() if owner != "sli.ad"))
        registry.registered_plugins.cache_clear()
    elif state == "draining":
        base = tmp_path / "sli.ad"
        base.mkdir()
        (base / "draining.json").write_text("{}", encoding="utf-8")
        monkeypatch.setenv("SLI_PLUGIN_RUNTIME_DIR", str(tmp_path))
    else:
        def timeout(*args, **kwargs):
            raise QueryTimeoutError("synthetic timeout", timeout_ms=3000)
        monkeypatch.setattr(integration, "get_runtime_entity_context_evidence", timeout)
    result = ui_workspace.get_entity_workspace_detail_data(entity_id=42, limit=30)
    assert result is not None
    assert result["ad_context"] == {
        "entity_id": 42, "resolution": "temporarily_unavailable", "items": [],
        "returned_count": 0, "bounded": True,
    }
    assert result["ad_context_state"] == "temporarily_unavailable"
    assert result["current_states_state"] == result["events_state"] == "available"
