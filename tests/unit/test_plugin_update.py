"""Signed plugin-only updates with fake runtime/queue and no database."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import stat
from pathlib import Path
from threading import Event, Thread

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.linux import sli_update as update
from scripts.maintenance import release_package as package
from server.sli.plugins import registry, ui_assets, update_runtime
from server.sli.core.job_registry import pilot_registry

PLUGIN = "sli.remote-access"
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def plugin_release(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    # Report discovery admits every installed owner, not only the update target.
    for plugin_id, _ in registry.discover_plugins():
        plugin = runtime / "plugins" / plugin_id
        plugin.mkdir(parents=True)
        (plugin / "admission.lock").touch()
    monkeypatch.setenv("SLI_PLUGIN_RUNTIME_DIR", str(runtime / "plugins"))
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    monkeypatch.delenv("SLI_CORE_JOB_AD_GPO_PILOT", raising=False)
    # This fixture installs only the VPN job generations. Default workstation
    # coexistence and retained pins are covered by test_workstation_projection_jobs.
    monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "0")
    monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_RETENTION", "0")
    registry.registered_plugins.cache_clear()
    baseline = tmp_path / "ui" / PLUGIN
    baseline.mkdir(parents=True)
    asset = b"export const version = '1.0.0';"
    (baseline / "entry.js").write_bytes(asset)
    (baseline / "descriptor.json").write_bytes(package.canonical_json({
        "plugin_id": PLUGIN, "version": "1.0.0", "ui_api": ui_assets.UI_API,
        "routes": [f"/extensions/{PLUGIN}/accounts"], "required_capabilities": [],
        "entry": {"path": "entry.js", "sha256": hashlib.sha256(asset).hexdigest()}}))
    monkeypatch.setenv("SLI_PLUGIN_UI_DIR", str(baseline.parent))
    key = Ed25519PrivateKey.generate()
    private = tmp_path / "offline.key"
    private.write_bytes(key.private_bytes_raw())
    trust = tmp_path / "trust.json"
    trust.write_bytes(package.canonical_json({"schema_version": 1, "keys": [{
        "key_id": "test-only", "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "package_ids": [PLUGIN], "revoked": False}]}))
    core = {"component": "server", "version": "1.0.0", "os": "linux", "architecture": "amd64",
            "image_tag": "sli-running:local", "image_digest": "sha256:" + "a" * 64,
            "compose_project": "sli", "volumes": {},
            "migrations": {"config/postgres_migrations/001_example.sql": "b" * 64},
            "migration_ledger": [{"version": 1, "name": "example", "sha256": "b" * 64}],
            "plugins": {PLUGIN: {"version": "1.0.0", "migrations": {}},
                                           "sli.fixture": {"version": "3.0.0", "enabled": True}}}
    update.atomic_json(runtime / "state/installed.json", core)

    class Host:
        files = []
        calls = []
        fail_health = False
        interrupt = False

        def __init__(self):
            self.plugin_rows = [{"plugin_id": key, "version": value["version"], "installed": True,
                                 "enabled": value.get("enabled", False)} for key, value in core["plugins"].items()]
            self.installed_release = None

        def observe(self):
            return {"migration_ledger_max": 1, "migration_ledger": copy.deepcopy(core["migration_ledger"]),
                    "plugins": copy.deepcopy(self.plugin_rows), "installed_release": copy.deepcopy(self.installed_release),
                    "services": {"api": {key: core[key] for key in ("version", "image_tag", "image_digest")}}}

        def publish_installed(self, previous, candidate, operation):
            from deploy.linux.installed_state import installation_key, inventory
            if self.installed_release:
                assert self.installed_release["inventory"] in (inventory(previous), inventory(candidate))
            self.installed_release = {"installation_key": installation_key(candidate), "operation": operation,
                                      "inventory": inventory(candidate)}
            for row in self.plugin_rows:
                row["version"] = candidate["plugins"][row["plugin_id"]]["version"]

        def plugin_preflight(self, runtime, installed, manifest):
            from deploy.linux.installed_state import validate
            self.calls.append(("preflight", manifest["plugin_id"]))
            assert installed["version"] == "1.0.0"
            validate(installed, self.observe(), runtime)

        def plugin_drain(self, runtime, manifest):
            self.calls.append(("drain", manifest["plugin_id"], tuple(manifest["handlers"])))
            assert update_runtime.fenced(PLUGIN)
            assert not update_runtime.fenced("sli.fixture")
            update_runtime.wait_drained(PLUGIN, 1)

        def plugin_health(self, runtime, manifest):
            self.calls.append(("health", manifest["plugin_id"]))
            if self.interrupt:
                self.interrupt = False
                raise KeyboardInterrupt()
            if self.fail_health:
                self.fail_health = False
                raise RuntimeError("private-error-marker")
            active = update_runtime.generation(PLUGIN)
            contribution = registry.load_generation(PLUGIN, active)
            assert contribution.hooks["health"]() is True
            descriptor, payload = ui_assets.load_package(PLUGIN, allow_draining=True)
            assert descriptor["version"] in payload.decode()

    host = Host()
    host.calls = []
    updater = update.Updater(runtime, trust, host)

    def build(version, previous="1.0.0", change=None, health=True):
        source = tmp_path / ("source-" + version)
        (source / "backend").mkdir(parents=True)
        (source / "ui").mkdir()
        jobs = json.loads((ROOT / "config/plugin_packages/sli.remote-access.jobs-v3.json").read_text("utf-8"))
        jobs["plugin_version"] = version
        (source / "backend/jobs-v3.json").write_bytes(package.canonical_json(jobs))
        (source / "backend/registration.py").write_text(
            "def register(c):\n"
            f"    c.hooks.update(configured=lambda: {version!r}, health=lambda: {health!r})\n"
            f"    c.jobs.update({{name: (lambda *a: {version!r}, lambda *a: None) "
            "for name in ('radius-acquisition', 'radius-session-observation')})\n", encoding="utf-8")
        asset = f"export const version = '{version}';".encode()
        (source / "ui/entry.js").write_bytes(asset)
        descriptor = {"plugin_id": PLUGIN, "version": version, "ui_api": ui_assets.UI_API,
                      "routes": [f"/extensions/{PLUGIN}/accounts"], "required_capabilities": [],
                      "entry": {"path": "entry.js", "sha256": hashlib.sha256(asset).hexdigest()}}
        (source / "ui/descriptor.json").write_bytes(package.canonical_json(descriptor))
        manifest = {"schema_version": 2, "component": "plugin", "package_type": "plugin-update", "package_id": PLUGIN,
                    "version": version, "plugin_id": PLUGIN, "plugin_version": version,
                    "core_api": {"minimum": "1.0.0", "maximum_exclusive": "2.0.0"},
                    "ui_api": {"minimum": "1.0.0", "maximum_exclusive": "2.0.0"},
                    "handlers": [row["handler_id"] for row in jobs["handlers"]],
                    "platform": "linux-amd64", "source_commit": "a" * 40, "build_id": "synthetic-1",
                    "minimum_updater": 1, "deletions": [], "restart_profile": "plugin-only",
                    "from_version": previous, "to_version": version, "image": None, "compose_delta": None, "config_delta": None,
                    "required_free_disk": 1024, "migrations": {},
                    "compatibility": {"core_api": 1, "ui_api": 1, "from_version": previous, "min_version": previous,
                                      "max_version": previous, "os": "linux", "architecture": "amd64"},
                    "files": [{"path": path.relative_to(source).as_posix()} for path in source.rglob("*") if path.is_file()]}
        if change:
            change(manifest)
        output = tmp_path / (version + ".zip")
        package.build_package(source, output, manifest, signing_key=private, key_id="test-only")
        return output

    yield updater, host, build, core
    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    update_runtime._pinned.clear()
    registry.load_generation(PLUGIN, None)
    registry.registered_plugins.cache_clear()


def test_two_vpn_versions_over_one_core_and_retained_queue_pins(plugin_release):
    updater, host, build, core = plugin_release
    for version, previous in (("1.1.0", "1.0.0"), ("1.2.0", "1.1.0")):
        assert updater.apply(build(version, previous)) == "committed"
        assert registry.require_plugin(PLUGIN, "configured") == version
        descriptor, _ = ui_assets.load_package(PLUGIN)
        assert descriptor["version"] == version
        active = update_runtime.generation(PLUGIN)
        assert stat.S_IMODE((active / "backend/registration.py").stat().st_mode) == 0o644
        assert stat.S_IMODE((active / "release.json").stat().st_mode) == 0o644
        installed = package.read_json(updater.installed_path.read_bytes())
        assert {key: value for key, value in installed.items() if key != "plugins"} == {
            key: value for key, value in core.items() if key != "plugins"}
        assert installed["plugins"]["sli.fixture"] == core["plugins"]["sli.fixture"]
        assert not update_runtime.fenced(PLUGIN)
    jobs = pilot_registry()
    assert {key[3] for key in jobs.handlers} == {"1.0.0", "1.1.0", "1.2.0"}
    assert [item["plugin_version"] for item in jobs.manifests] == ["1.2.0"]
    old = next(row for _, row in update_runtime.job_manifests(PLUGIN, ROOT / "config/plugin_packages/sli.remote-access.jobs-v3.json")
               if row["plugin_version"] == "1.1.0")
    from server.sli.core.job_queue import digest
    update_runtime.pin_job(PLUGIN, "1.1.0", digest(old), ROOT / "config/plugin_packages/sli.remote-access.jobs-v3.json")
    stage, _ = registry.plugin_job_handlers(PLUGIN, "radius-acquisition")
    assert stage(None, {}) == "1.1.0"
    assert {call[0] for call in host.calls} == {"preflight", "drain", "health"}
    assert all(call[1] == PLUGIN for call in host.calls)


def test_health_failure_rolls_back_plugin_only(plugin_release):
    updater, host, build, _ = plugin_release
    assert updater.apply(build("1.1.0")) == "committed"
    previous = updater.installed_path.read_bytes()
    host.fail_health = True
    assert updater.apply(build("1.2.0", "1.1.0")) == "rolled_back"
    assert updater.installed_path.read_bytes() == previous
    assert registry.require_plugin(PLUGIN, "configured") == "1.1.0"
    assert ui_assets.load_package(PLUGIN)[0]["version"] == "1.1.0"
    assert "private-error-marker" not in updater.journal_path.read_text()
    assert not update_runtime.fenced(PLUGIN)


def test_u5_plugin_commit_recovers_db_before_cache_interruption(plugin_release, monkeypatch):
    from deploy.linux.installed_state import inventory
    updater, host, build, core = plugin_release
    publish = host.publish_installed
    def crash(*args):
        publish(*args)
        raise KeyboardInterrupt()
    monkeypatch.setattr(host, "publish_installed", crash)
    with pytest.raises(KeyboardInterrupt):
        updater.apply(build("1.1.0"))
    assert package.read_json(updater.installed_path.read_bytes()) == core
    assert host.installed_release["inventory"]["plugins"][PLUGIN]["version"] == "1.1.0"
    status = updater.status()
    active = next(row for row in status["active_plugins"] if row["plugin_id"] == PLUGIN)
    assert active["version"] == active["registry_version"] == "1.1.0"
    assert active["draining"] is True
    assert status["readiness"]["ready"] is False
    monkeypatch.setattr(host, "publish_installed", publish)
    restarted = update.Updater(updater.runtime, updater.trust_store, host)
    assert restarted.resume() == "committed"
    assert host.installed_release["inventory"] == inventory(package.read_json(updater.installed_path.read_bytes()))
    assert restarted.status()["readiness"]["ready"] is True


@pytest.mark.parametrize("bad", ["registry_version", "ledger_hash", "pointer"])
def test_u5_plugin_mismatch_is_rejected_before_drain(plugin_release, bad):
    updater, host, build, _ = plugin_release
    original = updater.installed_path.read_bytes()
    if bad == "registry_version":
        host.plugin_rows[0]["version"] = "9.0.0"
    elif bad == "ledger_hash":
        observe = host.observe
        def changed():
            value = observe()
            value["migration_ledger"][0]["sha256"] = "f" * 64
            return value
        host.observe = changed
    else:
        update.atomic_json(updater.runtime / "plugins" / PLUGIN / "active.json", {"generation": "f" * 64})
    assert updater.apply(build("1.1.0")) == "rejected"
    assert updater.installed_path.read_bytes() == original
    assert not {"drain", "health"} & {row[0] for row in host.calls}


def test_first_update_failure_restores_bundled_plugin_and_ui(plugin_release):
    updater, host, build, _ = plugin_release
    previous = updater.installed_path.read_bytes()
    host.fail_health = True
    assert updater.apply(build("1.1.0")) == "rolled_back"
    assert updater.installed_path.read_bytes() == previous
    assert update_runtime.generation(PLUGIN) is None
    assert ui_assets.load_package(PLUGIN)[0]["version"] == "1.0.0"


def test_native_adapter_nonzero_health_drives_existing_plugin_only_rollback(plugin_release, monkeypatch):
    from types import SimpleNamespace
    from deploy.linux import native_plugin_runtime as native

    updater, host, build, _ = plugin_release
    previous = updater.installed_path.read_bytes()
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        assert update_runtime.fenced(PLUGIN)
        if command[2] == "drain":
            return SimpleNamespace(returncode=0)
        # Candidate process fails; restored bundled generation passes registration health.
        active = update_runtime.generation(PLUGIN)
        return SimpleNamespace(returncode=1 if active is not None else 0)

    monkeypatch.setattr(native.subprocess, "run", run)
    adapter = native.NativePluginRuntime("test-release")
    monkeypatch.setattr(host, "plugin_drain", adapter.plugin_drain)
    monkeypatch.setattr(host, "plugin_health", adapter.plugin_health)
    assert updater.apply(build("1.1.0")) == "rolled_back"
    assert [command[2] for command in commands] == ["drain", "health", "drain", "health"]
    assert commands[-1][-1] == "1.0.0"
    assert updater.installed_path.read_bytes() == previous
    assert update_runtime.generation(PLUGIN) is None
    assert not update_runtime.fenced(PLUGIN)


def test_operator_rollback_and_operation_replay_are_plugin_only(plugin_release):
    updater, _, build, _ = plugin_release
    operation = "a" * 32
    release = build("1.1.0")
    previous = updater.installed_path.read_bytes()
    assert updater.apply(release, operation_id=operation) == "committed"
    assert updater.apply(release, operation_id=operation) == "committed"
    assert updater.resume(rollback=True, operation_id=operation) == "rolled_back"
    assert updater.installed_path.read_bytes() == previous


def test_signature_failure_never_touches_runtime(plugin_release):
    updater, host, build, _ = plugin_release
    output = build("1.1.0")
    body = output.read_bytes()
    output.write_bytes(body.replace(b"export const version", b"EXport const version"))
    with pytest.raises(package.PackageError):
        updater.apply(output)
    assert host.calls == []


def test_ui_is_unavailable_until_candidate_health_succeeds(plugin_release):
    updater, _, _, _ = plugin_release
    update.atomic_json(updater.runtime / "plugins" / PLUGIN / "draining.json", {})
    with pytest.raises(ui_assets.PluginUiError, match="plugin_ui_updating"):
        ui_assets.load_package(PLUGIN)


@pytest.mark.parametrize("validate_intents", [False, True])
def test_core_report_discovery_keeps_running_during_plugin_drain(plugin_release, validate_intents):
    updater, _, _, _ = plugin_release
    from server.sli.reporting.v2 import registry as reports
    reports.registered_reports.cache_clear()
    try:
        previous = reports.registered_reports(validate_intents=validate_intents)
        assert any(row.key.startswith("vpn.") for row in previous)
        core = next(row for row in previous if row.key == "security.problems")
        assert any(row.key == "ad.infrastructure" for row in previous)
        update.atomic_json(updater.runtime / "plugins" / PLUGIN / "draining.json", {})
        assert reports.get_report(core.key) is not None
        assert reports.get_report("ad.infrastructure") is not None
        assert not any(row.key.startswith("vpn.") for row in reports.registered_reports(validate_intents=validate_intents))
    finally:
        reports.registered_reports.cache_clear()


@pytest.mark.parametrize("validate_intents", [False, True])
def test_cached_plugin_report_cannot_execute_after_generation_change(plugin_release, validate_intents):
    updater, _, build, _ = plugin_release
    from server.sli.reporting.v2 import registry as reports
    reports.registered_reports.cache_clear()
    try:
        previous = next(row for row in reports.registered_reports(validate_intents=validate_intents) if row.key == "vpn.connections")
        assert updater.apply(build("1.1.0")) == "committed"
        assert not any(row.key.startswith("vpn.") for row in reports.registered_reports(validate_intents=validate_intents))
        assert reports.get_report("ad.infrastructure") is not None
        with pytest.raises(RuntimeError, match="plugin_version_changed"):
            previous.query(None)
    finally:
        reports.registered_reports.cache_clear()


def test_interrupted_activation_resumes_plugin_rollback(plugin_release):
    updater, host, build, _ = plugin_release
    assert updater.apply(build("1.1.0")) == "committed"
    previous = updater.installed_path.read_bytes()
    host.interrupt = True
    with pytest.raises(KeyboardInterrupt):
        updater.apply(build("1.2.0", "1.1.0"))
    assert update_runtime.fenced(PLUGIN)
    assert updater.resume() == "rolled_back"
    assert updater.installed_path.read_bytes() == previous
    assert updater.resume() == "rolled_back"


def test_dry_run_does_not_activate_or_drain(plugin_release):
    updater, host, build, _ = plugin_release
    result = update.apply_update(build("1.1.0"), trust_store=updater.trust_store, runtime=updater.runtime, host=host, dry_run=True)
    assert result["status"] == "verified" and not result["installed"]
    assert host.calls == [("preflight", PLUGIN)]
    assert update_runtime.generation(PLUGIN) is None


@pytest.mark.parametrize("change,code", [
    (lambda m: m.update(plugin_version="2.0.0"), "update_invalid_plugin_payload"),
    (lambda m: m.update(handlers=["radius-acquisition"] * 2), "update_invalid_plugin_handlers"),
    (lambda m: m["core_api"].update(minimum="2.0.0"), "update_plugin_api_incompatible"),
    (lambda m: m["migrations"].update({"config/postgres_migrations/167_example.sql": "a" * 64}),
     "update_plugin_migration_requires_core_maintenance"),
    (lambda m: m["migrations"].update({"config/postgres_migrations/167_example.sql": "a" * 64,
                                     "config/postgres_migrations/167_duplicate.sql": "b" * 64}),
     "update_duplicate_migration_id"),
])
def test_invalid_contract_rejected_before_runtime(plugin_release, change, code):
    updater, host, build, _ = plugin_release
    with pytest.raises(package.PackageError, match=code):
        updater.apply(build("1.1.0", change=change))
    assert host.calls == []


def test_drain_waits_for_plugin_calls_and_keeps_other_owner_available(plugin_release):
    updater, _, _, _ = plugin_release
    other = updater.runtime / "plugins/sli.fixture"
    other.mkdir()
    (other / "admission.lock").touch()
    started, release = Event(), Event()
    def running():
        with update_runtime.admission(PLUGIN):
            started.set()
            release.wait(2)
    worker = Thread(target=running)
    worker.start()
    assert started.wait(1)
    update.atomic_json(updater.runtime / "plugins" / PLUGIN / "draining.json", {})
    try:
        with pytest.raises(TimeoutError):
            update_runtime.wait_drained(PLUGIN, 0.01)
        with update_runtime.optional_admission(PLUGIN) as available:
            assert not available
        with update_runtime.optional_admission("sli.fixture") as available:
            assert available
    finally:
        release.set()
        worker.join(2)
    update_runtime.wait_drained(PLUGIN, 1)


def test_draining_plugin_does_not_stop_other_queue_claims(plugin_release, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from server.sli.core import job_executor as executor, job_queue
    from server.sli.sources import ad_gpo_jobs
    from server.sli.core import job_registry
    updater, _, _, _ = plugin_release
    update.atomic_json(updater.runtime / "plugins" / PLUGIN / "draining.json", {})
    identities = [{"plugin_id": PLUGIN}, {"plugin_id": "sli.ad"}]
    monkeypatch.setattr(executor, "pilot_enabled", lambda: True)
    monkeypatch.setattr(executor, "pilot_registry", lambda: SimpleNamespace(identities=lambda _: identities))
    monkeypatch.setattr(executor, "STOP", SimpleNamespace(is_set=lambda: False))
    monkeypatch.setattr(executor, "write_heartbeat", lambda *_a, **_k: None)
    cur = SimpleNamespace(execute=lambda *_: pytest.fail("VPN source accessed during drain"))
    conn = SimpleNamespace(cursor=lambda: nullcontext(cur))
    monkeypatch.setattr(executor, "connect", lambda *_: nullcontext(conn))
    monkeypatch.setattr(ad_gpo_jobs, "enabled", lambda: True)
    monkeypatch.setattr(ad_gpo_jobs, "allowed_plugins", lambda: {"sli.ad"})
    monkeypatch.setattr(job_registry, "schedule_jobs", lambda *_: pytest.fail("VPN scheduled during drain"))
    scheduled, claimed = [], []
    monkeypatch.setattr(ad_gpo_jobs, "schedule", lambda *_: scheduled.append("sli.ad"))
    monkeypatch.setattr(job_queue, "claim", lambda _cur, _profile, _executor, items: claimed.append(items))
    assert executor.serve("light", once=True) == 0
    assert scheduled == ["sli.ad"]
    assert claimed == [[{"plugin_id": "sli.ad"}]]
