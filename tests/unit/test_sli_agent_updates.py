"""Real signatures, temporary releases and fake transport/service processes."""
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.maintenance.release_package import build_package, validate_manifest, verify_package, PackageLimits
from sli_agent.config import AgentConfig
from sli_agent.updates import Updates, REQUIRED_FILES, PACKAGE_SNAPSHOT


@pytest.fixture
def agent_package(tmp_path):
    key = Ed25519PrivateKey.generate()
    private = tmp_path / "signing.key"
    private.write_bytes(key.private_bytes_raw())
    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps({"schema_version": 1, "keys": [{"key_id": "test-only",
        "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "package_ids": ["sli.agent"], "revoked": False}]}))
    payload = tmp_path / "input"
    for name in REQUIRED_FILES:
        file = payload / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(b"# synthetic module\n")
    (payload / "sli_agent/runtime.py").write_bytes(b"# synthetic candidate\n")
    (payload / "sli_agent/__init__.py").write_bytes(b"")
    counter = 0

    def create(*, compatibility=None, extra=None, legacy=False, missing=None):
        nonlocal counter
        counter += 1
        files = sorted(REQUIRED_FILES - {missing})
        if extra:
            file = payload / extra
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"# synthetic\n")
            files.append(extra)
        manifest = {"schema_version": 2, "component": "agent", "package_type": "plugin-update",
            "package_id": "sli.agent", "version": "1.1.0", "platform": "windows-amd64",
            "source_commit": "a" * 40, "build_id": "synthetic", "minimum_updater": 1,
            "compatibility": {"core_api": 1, "ui_api": 1, "from_version": "1.0.0",
                "min_version": "1.0.0", "max_version": "1.0.0", "os": "windows", "architecture": "amd64",
                "agent_api": {"min": 1, "max": 1}},
            "from_version": "1.0.0", "to_version": "1.1.0", "migrations": {}, "deletions": [],
            "restart_profile": "none", "image": None, "required_free_disk": 1,
            "compose_delta": None, "config_delta": None, "files": [{"path": f} for f in files]}
        if compatibility:
            manifest["compatibility"].update(compatibility)
            manifest["platform"] = manifest["compatibility"]["os"] + "-" + manifest["compatibility"]["architecture"]
        if legacy:
            del manifest["compatibility"]["agent_api"]
        archive = tmp_path / f"agent-{counter}.zip"
        build_package(payload, archive, manifest, signing_key=private, key_id="test-only")
        return archive, trust
    return create


@pytest.fixture
def installed(tmp_path, monkeypatch):
    from sli_agent import updates
    monkeypatch.setattr(updates, "machine", lambda: {"os": "windows", "architecture": "amd64", "agent_api": 1})
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path / "state",
        update_root=tmp_path / "releases", update_trust_store=tmp_path / "trust.json", service_python=tmp_path / "python.exe")
    root = config.update_root / "versions/1.0.0-initial"
    root.mkdir(parents=True)
    source = Path(__file__).resolve().parents[2]
    for name in REQUIRED_FILES:
        file = root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / name, file)
    config.state_dir.mkdir()
    for file in ("spool/packet.json", "cursors.json", "identity.json"):
        path = config.state_dir / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"preserve durable state")
    manager = Updates(config)
    manager.initialize("1.0.0", "1.0.0-initial")
    return config, manager


def offer(archive):
    return {"sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "version": "1.1.0"}


def transport(archive):
    def download(digest, destination, *, identity):
        assert identity == "synthetic-identity"
        destination.write_bytes(archive.read_bytes())
    return SimpleNamespace(download=download)


def test_signed_agent_inventory_imports_shared_verifier_without_checkout(agent_package, tmp_path):
    archive, trust = agent_package()
    source = Path(__file__).resolve().parents[2]
    release = tmp_path / "release"
    for name in REQUIRED_FILES:
        target = release / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / name, target)
    script = f"""
import sys
from pathlib import Path
sys.path.insert(0, {str(release)!r})
from sli_agent.updates import verify_package
from server.sli import release_package
assert Path(release_package.__file__).resolve().is_relative_to(Path({str(release)!r}))
verified = verify_package(Path({str(archive)!r}), Path({str(trust)!r}))
assert verified.manifest['component'] == 'agent'
print('agent_verifier_verified')
"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script], cwd=tmp_path,
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "agent_verifier_verified"


def test_verify_stage_switch_self_check_and_preserve_state(agent_package, installed):
    archive, _ = agent_package()
    config, updates = installed
    before = {p.relative_to(config.state_dir): p.read_bytes() for p in config.state_dir.rglob("*") if p.is_file()}
    assert updates.offer(offer(archive), transport(archive), "synthetic-identity")
    state = updates.read()
    candidate = updates.release(state["current"])
    assert candidate.parent == updates.release(state["previous"]).parent
    assert (candidate / "sli_agent/runtime.py").read_bytes() == b"# synthetic candidate\n"
    assert (updates.release(state["previous"]) / "sli_agent/runtime.py").read_bytes() == (
        Path(__file__).resolve().parents[2] / "sli_agent/runtime.py").read_bytes()
    assert state["pending"] == offer(archive)["sha256"]
    updates.healthy(state["current"]["directory"])
    assert updates.read()["result"]["status"] == "updated"
    assert updates.read()["pending"] is None
    assert not updates.offer(offer(archive), transport(archive), "synthetic-identity")
    assert {p.relative_to(config.state_dir): p.read_bytes() for p in config.state_dir.rglob("*") if p.is_file()} == before
    reports = []
    updates.report(SimpleNamespace(post=lambda *a, **kw: reports.append((a, kw))), "synthetic-identity")
    assert reports[0][0][0] == "/api/v1/agent/update-result"
    assert reports[0][1]["identity"] == "synthetic-identity"


def test_independent_bootstrap_accepts_signed_snapshot_and_trusted_initial(agent_package, installed):
    archive, _ = agent_package()
    _, updates = installed
    initial = updates.read()["current"]
    assert updates.verified_release(initial) == updates.release(initial)
    assert updates.offer(offer(archive), transport(archive), "synthetic-identity")
    current = updates.read()["current"]
    release = updates.verified_release(current)
    assert (release / PACKAGE_SNAPSHOT).read_bytes() == archive.read_bytes()
    assert updates.rollback("agent_update_timeout")
    assert updates.verified_release(updates.read()["current"]) == updates.release(initial)


def test_initialization_rejects_substituted_initial_verifier_without_publishing_pointer(installed):
    _, updates = installed
    initial = updates.read()["current"]
    (updates.release(initial) / "server/sli/release_package.py").write_bytes(
        b"raise RuntimeError('candidate_executed')\n")
    updates.pointer.unlink()
    with pytest.raises(ValueError, match="agent_update_payload_changed"):
        updates.initialize(initial["version"], initial["directory"])
    assert not updates.pointer.exists()


@pytest.mark.parametrize("failure", ["verifier", "extra_code", "snapshot", "pointer", "initial"])
def test_bootstrap_rejects_modified_release_before_spawn(agent_package, installed, failure):
    from sli_agent.launcher import supervise
    archive, _ = agent_package()
    config, updates = installed
    initial = updates.read()["current"]
    assert updates.offer(offer(archive), transport(archive), "synthetic-identity")
    release = updates.release(updates.read()["current"])
    if failure == "verifier":
        (release / "server/sli/release_package.py").write_bytes(b"raise RuntimeError('candidate_executed')\n")
    elif failure == "extra_code":
        (release / "sli_agent/unlisted.py").write_bytes(b"raise RuntimeError('candidate_executed')\n")
    elif failure == "snapshot":
        (release / PACKAGE_SNAPSHOT).unlink()
    elif failure == "pointer":
        state = updates.read()
        state["current"]["version"] = "9.9.9"
        updates.write(state)
    elif failure == "initial":
        # An attacker cannot evade signatures by selecting an unsigned '-initial'.
        (updates.release(initial) / "server/sli/release_package.py").write_bytes(
            b"raise RuntimeError('candidate_executed')\n")
        state = updates.read()
        state.update(current=initial, previous=None, pending=None)
        updates.write(state)
    launches = []
    class Stop:
        done = False
        def is_set(self):
            return self.done
        def wait(self, seconds):
            self.done = True
    supervise(config, "synthetic-config", Stop(), spawn=lambda *a, **kw: launches.append(a))
    assert launches == []
    if failure != "initial":
        assert updates.read()["current"] == initial
        assert updates.read()["result"]["status"] == "rolled_back"


def test_bootstrap_rejects_package_with_substituted_verifier_and_trust_root(agent_package, installed, tmp_path):
    from server.sli.release_package import extract_payload
    from sli_agent.launcher import supervise
    archive, trust = agent_package(extra="sli_agent/trust.json")
    config, updates = installed
    trusted_policy = trust.read_bytes()
    initial = updates.read()["current"]
    attacker = Ed25519PrivateKey.generate()
    private = tmp_path / "attacker.key"
    private.write_bytes(attacker.private_bytes_raw())
    source = tmp_path / "input"
    substituted_trust = source / "sli_agent/trust.json"
    substituted_trust.write_text(json.dumps({"schema_version": 1, "keys": [{"key_id": "test-only",
        "public_key": base64.b64encode(attacker.public_key().public_bytes_raw()).decode(),
        "package_ids": ["sli.agent"], "revoked": False}]}))
    (source / "server/sli/release_package.py").write_bytes(b"raise RuntimeError('candidate_executed')\n")
    with zipfile.ZipFile(archive) as zipped:
        manifest = json.loads(zipped.read("SLI_RELEASE.json"))
    manifest["files"] = [{"path": item["path"]} for item in manifest["files"]]
    forged = tmp_path / "forged.zip"
    build_package(source, forged, manifest, signing_key=private, key_id="test-only")
    # Simulate a compromised child accepting its own package/root and switching
    # the pointer. The SCM bootstrap must still authenticate with installed trust.
    accepted_by_attacker = verify_package(forged, substituted_trust, component="agent")
    target = {"version": "1.1.0", "directory": "1.1.0-" + accepted_by_attacker.archive_sha256}
    release = updates.root / "versions" / target["directory"]
    release.mkdir()
    extract_payload(accepted_by_attacker, release)
    (release / PACKAGE_SNAPSHOT).write_bytes(accepted_by_attacker.archive_bytes)
    state = updates.read()
    state.update(previous=initial, current=target, pending=accepted_by_attacker.archive_sha256)
    updates.write(state)
    launches = []
    class Stop:
        done = False
        def is_set(self):
            return self.done
        def wait(self, seconds):
            self.done = True
    supervise(config, "synthetic-config", Stop(), spawn=lambda *a, **kw: launches.append(a))
    assert launches == []
    assert trust.read_bytes() == trusted_policy
    assert updates.read()["current"] == initial
    assert updates.read()["result"]["status"] == "rolled_back"


@pytest.mark.parametrize("name", ["sli_agent/launcher.py", "sli_agent/Launcher.py",
                                 "sli_agent/service.py", "sli_agent/msi.py"])
def test_update_packages_cannot_deliver_bootstrap_components(agent_package, installed, name):
    archive, _ = agent_package(extra=name)
    _, updates = installed
    assert not updates.offer(offer(archive), transport(archive), "synthetic-identity")
    assert updates.read()["result"]["reason"] == "agent_update_verification_failed"


@pytest.mark.parametrize("module_name", ["sli_agent.launcher", "sli_agent.updates", "server.sli.release_package"])
def test_bootstrap_code_must_be_installed_outside_candidates(installed, monkeypatch, module_name):
    from sli_agent.launcher import supervise
    config, updates = installed
    monkeypatch.setattr(sys.modules[module_name], "__file__", str(updates.root / "untrusted.py"))
    with pytest.raises(ValueError, match="agent_update_external_bootstrap_required"):
        if module_name == "sli_agent.launcher":
            supervise(config, "synthetic-config", SimpleNamespace(is_set=lambda: True))
        else:
            updates.verified_release(updates.read()["current"])


def test_bootstrap_rechecks_external_trust_after_symlink_retarget(agent_package, installed):
    archive, trust = agent_package()
    _, updates = installed
    assert updates.offer(offer(archive), transport(archive), "synthetic-identity")
    candidate = updates.release(updates.read()["current"])
    internal = candidate / "sli_agent/trust.json"
    internal.write_bytes(trust.read_bytes())
    trust.unlink()
    trust.symlink_to(internal)
    with pytest.raises(ValueError, match="agent_update_external_bootstrap_required"):
        updates.verified_release(updates.read()["current"])


@pytest.mark.parametrize("compatibility", [{"agent_api": {"min": 2, "max": 3}}, {"os": "linux"}])
def test_bootstrap_rechecks_compatibility_if_child_bypasses_staging(agent_package, installed, compatibility):
    from server.sli.release_package import extract_payload
    archive, trust = agent_package(compatibility=compatibility)
    _, updates = installed
    verified = verify_package(archive, trust, component="agent")
    current = {"version": "1.1.0", "directory": "1.1.0-" + verified.archive_sha256}
    candidate = updates.root / "versions" / current["directory"]
    candidate.mkdir()
    extract_payload(verified, candidate)
    (candidate / PACKAGE_SNAPSHOT).write_bytes(verified.archive_bytes)
    with pytest.raises(ValueError, match="agent_update_incompatible"):
        updates.verified_release(current)


@pytest.mark.parametrize("reason", ["agent_update_start_failed", "agent_update_self_check_failed", "agent_update_timeout"])
def test_rollback_is_durable_after_manager_restart(agent_package, installed, reason):
    archive, _ = agent_package()
    config, updates = installed
    updates.offer(offer(archive), transport(archive), "synthetic-identity")
    restarted = Updates(config)
    assert restarted.rollback(reason)
    assert restarted.read()["current"]["version"] == "1.0.0"
    assert restarted.read()["result"]["status"] == "rolled_back"
    assert restarted.read()["result"]["reason"] == reason
    assert not restarted.rollback(reason)
    assert not restarted.offer(offer(archive), transport(archive), "synthetic-identity")
    assert (config.state_dir / "cursors.json").read_bytes() == b"preserve durable state"


@pytest.mark.parametrize("compatibility", [{"agent_api": {"min": 2, "max": 3}}, {"agent_api": None}])
def test_incompatible_api_and_missing_api_fail_before_staging(agent_package, installed, compatibility):
    archive, trust = agent_package(compatibility={"agent_api": {"min": 2, "max": 3}}, legacy=compatibility["agent_api"] is None)
    if compatibility["agent_api"] is None:
        # Legacy contract remains readable, but cannot authorize activation.
        assert verify_package(archive, trust).manifest["component"] == "agent"
    _, updates = installed
    assert not updates.offer(offer(archive), transport(archive), "synthetic-identity")
    assert updates.read()["result"]["reason"] == "agent_update_incompatible_api"
    assert updates.read()["current"]["version"] == "1.0.0"
    assert len(list((updates.root / "versions").iterdir())) == 1


@pytest.mark.parametrize("failure", ["signature", "untrusted", "platform", "version", "payload"])
def test_bad_packages_never_switch_or_stage(agent_package, installed, monkeypatch, failure):
    archive, trust = agent_package(extra="server/forbidden.py" if failure == "payload" else None)
    _, updates = installed
    if failure == "signature":
        with zipfile.ZipFile(archive) as z:
            content = {p: z.read(p) for p in z.namelist()}
        signature = json.loads(content["SLI_SIGNATURE.json"])
        signature["signature"] = base64.b64encode(b"\0" * 64).decode()
        content["SLI_SIGNATURE.json"] = json.dumps(signature).encode()
        with zipfile.ZipFile(archive, "w") as z:
            for name, body in content.items():
                z.writestr(name, body)
    elif failure == "untrusted":
        policy = json.loads(trust.read_text())
        policy["keys"][0]["revoked"] = True
        trust.write_text(json.dumps(policy))
    elif failure == "platform":
        monkeypatch.setattr("sli_agent.updates.machine", lambda: {"os": "linux", "architecture": "arm64", "agent_api": 1})
    elif failure == "version":
        state = updates.read()
        state["current"]["version"] = "0.9.0"
        updates.write(state)
    assert not updates.offer(offer(archive), transport(archive), "synthetic-identity")
    assert updates.read()["pending"] is None
    assert updates.read()["result"]["status"] == "rejected"
    assert len(list((updates.root / "versions").iterdir())) == 1


def test_staging_failure_does_not_activate(agent_package, installed, monkeypatch):
    archive, _ = agent_package()
    _, updates = installed
    def fail(*a):
        raise OSError("synthetic-private-detail")
    monkeypatch.setattr("sli_agent.updates.extract_payload", fail)
    assert not updates.offer(offer(archive), transport(archive), "synthetic-identity")
    assert updates.read()["current"]["version"] == "1.0.0"
    assert updates.read()["result"]["reason"] == "agent_update_stage_failed"
    assert "private-detail" not in json.dumps(updates.read())


@pytest.mark.parametrize("api", [{"min": True, "max": 1}, {"min": 2, "max": 1}, {"min": 0, "max": 1}, {"min": 1}])
def test_agent_api_contract_rejects_invalid_ranges(agent_package, api):
    archive, _ = agent_package()
    with zipfile.ZipFile(archive) as z:
        manifest = json.loads(z.read("SLI_RELEASE.json"))
    manifest["compatibility"]["agent_api"] = api
    with pytest.raises(ValueError):
        validate_manifest(manifest, PackageLimits())


@pytest.mark.parametrize("mode", ["healthy", "exit", "spawn", "timeout"])
def test_launcher_restarts_candidate_and_rolls_back_failures(agent_package, installed, mode):
    from sli_agent.launcher import supervise
    archive, _ = agent_package()
    config, updates = installed
    updates.offer(offer(archive), transport(archive), "synthetic-identity")
    launches = []
    class Stop:
        done = False
        def is_set(self):
            return self.done
        def wait(self, seconds):
            if len(launches) == (1 if mode == "healthy" else 2):
                self.done = True
    stop = Stop()
    class Process:
        dead = False
        def poll(self):
            return 1 if self.dead or mode == "exit" and len(launches) == 1 else None
        def terminate(self):
            self.dead = True
        def wait(self, **kw):
            assert self.dead
    def spawn(args, **kwargs):
        directory = args[-1]
        launches.append(directory)
        assert args[0] == str(config.service_python)
        assert args[1:4] == ["-I", "-B", "-c"]
        assert Path(args[-3]).name == directory
        if mode == "spawn" and len(launches) == 1:
            raise OSError("synthetic-private-detail")
        if mode == "healthy" or len(launches) == 2:
            updates.healthy(directory)
        return Process()
    ticks = iter([0, 121, 122, 123])
    supervise(config, "synthetic-config.json", stop, spawn=spawn, monotonic=lambda: next(ticks))
    state = updates.read()
    assert state["result"]["status"] == ("updated" if mode == "healthy" else "rolled_back")
    if mode != "healthy":
        assert launches[-1] == "1.0.0-initial"


def test_runtime_self_check_requires_enrollment_transport_and_modules(agent_package, installed, monkeypatch):
    from sli_agent import runtime
    from cryptography import x509
    config, updates = installed
    archive, _ = agent_package()
    updates.offer(offer(archive), transport(archive), "synthetic-identity")
    calls = []
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(x509, "load_pem_x509_certificate", lambda *a: SimpleNamespace(
        not_valid_before_utc=now-timedelta(seconds=60), not_valid_after_utc=now+timedelta(seconds=60)))
    identity = SimpleNamespace(agent_id="synthetic", certificate_pem="synthetic")
    monkeypatch.setattr(runtime, "IdentityStore", lambda c: SimpleNamespace(
        prepare=lambda: {"host_id": "synthetic"}, load=lambda: identity))
    monkeypatch.setattr(runtime, "configured_modules", lambda *a: calls.append("modules") or [])
    monkeypatch.setattr(runtime, "Transport", lambda c: SimpleNamespace(get=lambda *a, **kw:
        calls.append("transport") or {"agent_id": identity.agent_id, "assigned_modules": []}))
    monkeypatch.setattr(Updates, "healthy", lambda *a: calls.append("healthy"))
    runtime.run(config, SimpleNamespace(is_set=lambda: True), release_directory=updates.read()["current"]["directory"])
    assert calls == ["modules", "transport", "modules", "healthy"]


@pytest.mark.parametrize("field", ["update_root", "update_trust_store", "service_python"])
def test_update_configuration_requires_both_paths(tmp_path, field):
    with pytest.raises(ValueError, match="agent_config_invalid"):
        AgentConfig("https://core.invalid", tmp_path / "ca", tmp_path / "state", **{field: tmp_path / "updates"})


def test_state_and_trust_cannot_be_inside_release_tree(tmp_path):
    with pytest.raises(ValueError, match="agent_config_invalid"):
        AgentConfig("https://core.invalid", tmp_path / "ca", tmp_path / "releases/state",
            update_root=tmp_path / "releases", update_trust_store=tmp_path / "trust.json", service_python=tmp_path / "python.exe")
    with pytest.raises(ValueError, match="agent_config_invalid"):
        AgentConfig("https://core.invalid", tmp_path / "ca", tmp_path / "state",
            update_root=tmp_path / "releases", update_trust_store=tmp_path / "releases/trust.json", service_python=tmp_path / "python.exe")


@pytest.mark.parametrize("fails", [False, True])
@pytest.mark.parametrize("instance", [None, "dc"])
def test_scm_restart_helper_stops_then_starts_and_rolls_back_start_failure(agent_package, installed, fails, instance):
    from dataclasses import replace
    from sli_agent.config import service_name
    from sli_agent.launcher import restart_windows_service
    archive, _ = agent_package()
    config, updates = installed
    if instance is not None:
        config = replace(config, instance_name=instance, host_id="00000000-0000-4000-8000-000000000001")
        destination = config.release_root / "versions/1.0.0-initial"
        destination.parent.mkdir(parents=True)
        import shutil
        shutil.copytree(updates.release(updates.read()["current"]), destination)
        updates = Updates(config)
        updates.initialize("1.0.0", destination.name)
    updates.offer(offer(archive), transport(archive), "synthetic-identity")
    calls = []
    class Control:
        def StopService(self, name):
            calls.append("stop")
            assert name == service_name(instance)
        def WaitForServiceStatus(self, name, status, timeout):
            calls.append("wait")
            assert name == service_name(instance)
            assert status == 1 and timeout == 30
        def StartService(self, name):
            calls.append("start")
            assert name == service_name(instance)
            if fails and calls.count("start") == 1:
                raise OSError("synthetic-private-detail")
    restart_windows_service(config, control=Control())
    assert calls == (["stop", "wait", "start", "start"] if fails else ["stop", "wait", "start"])
    assert updates.read()["current"]["version"] == ("1.0.0" if fails else "1.1.0")
    if fails:
        assert updates.read()["result"]["reason"] == "agent_update_start_failed"


def test_launcher_requests_scm_restart_after_atomic_switch(installed):
    from sli_agent.launcher import supervise
    config, updates = installed
    candidate = config.update_root / "versions/1.1.0-synthetic"
    candidate.mkdir()
    events = []
    class Stop:
        done = False
        def is_set(self):
            return self.done
        def set(self):
            events.append("stop-wrapper")
            self.done = True
        def wait(self, seconds):
            pass
    class Process:
        dead = False
        def poll(self):
            return 0 if self.dead else None
        def terminate(self):
            events.append("terminate-old")
            self.dead = True
        def wait(self, **kw):
            events.append("old-exited")
    def spawn(*a, **kw):
        state = updates.read()
        state.update(previous=state["current"], current={"version": "1.1.0", "directory": candidate.name}, pending="a" * 64)
        updates.write(state)
        return Process()
    supervise(config, "synthetic-config", Stop(), spawn=spawn, restart_service=lambda: events.append("restart-helper"))
    assert events == ["restart-helper", "stop-wrapper", "terminate-old", "old-exited"]


@pytest.mark.parametrize("instance", [None, "dc"])
def test_installer_grants_only_required_service_restart_rights(monkeypatch, instance):
    import sys
    from sli_agent.config import service_name
    from sli_agent.service import grant_restart_access
    events = []
    acl = SimpleNamespace(AddAccessAllowedAce=lambda revision, rights, sid: events.append((rights, sid)))
    descriptor = SimpleNamespace(GetSecurityDescriptorDacl=lambda: acl,
        SetSecurityDescriptorDacl=lambda *a: None)
    def open_service(manager, name, rights):
        assert manager == "manager" and name == service_name(instance)
        assert rights == 2|4
        return "service"
    service = SimpleNamespace(SC_MANAGER_CONNECT=1, READ_CONTROL=2, WRITE_DAC=4,
        SERVICE_START=8, SERVICE_STOP=16, SERVICE_QUERY_STATUS=32,
        OpenSCManager=lambda *a: "manager", OpenService=open_service,
        QueryServiceObjectSecurity=lambda *a: descriptor,
        SetServiceObjectSecurity=lambda *a: events.append("set-dacl"),
        CloseServiceHandle=lambda h: events.append("close-"+h))
    security = SimpleNamespace(DACL_SECURITY_INFORMATION=1, ACL_REVISION=2, ConvertStringSidToSid=lambda s: "synthetic-sid")
    monkeypatch.setitem(sys.modules, "win32service", service)
    monkeypatch.setitem(sys.modules, "win32security", security)
    grant_restart_access("synthetic-sid", instance)
    assert events == [(8|16|32, "synthetic-sid"), "set-dacl", "close-service", "close-manager"]


@pytest.mark.parametrize("instance", [None, "dc"])
def test_native_restart_control_uses_minimal_rights_and_closes_handles(monkeypatch, instance):
    import sys
    from sli_agent.config import service_name
    from sli_agent.launcher import windows_service_control
    events = []
    def open_manager(machine, database, rights):
        assert rights == 1
        return "manager"
    def open_service(manager, name, rights):
        assert rights == 8|16|32
        assert manager == "manager" and name == service_name(instance)
        return "service"
    native = SimpleNamespace(SC_MANAGER_CONNECT=1, SERVICE_START=8, SERVICE_STOP=16,
        SERVICE_QUERY_STATUS=32, SERVICE_CONTROL_STOP=1,
        OpenSCManager=open_manager, OpenService=open_service,
        ControlService=lambda service, control: events.append("stop"),
        QueryServiceStatus=lambda service: (0, 1), StartService=lambda *a: events.append("start"),
        CloseServiceHandle=lambda handle: events.append("close-"+handle))
    monkeypatch.setitem(sys.modules, "win32service", native)
    with windows_service_control(instance) as control:
        control.StopService(service_name(instance))
        control.WaitForServiceStatus(service_name(instance), 1, 30)
        control.StartService(service_name(instance))
    assert events == ["stop", "start", "close-service", "close-manager"]


@pytest.mark.parametrize("failure", ["enrollment", "expiry", "transport", "modules"])
def test_candidate_self_check_failure_never_marks_healthy(agent_package, installed, monkeypatch, failure):
    from sli_agent import runtime
    from cryptography import x509
    archive, _ = agent_package()
    config, updates = installed
    updates.offer(offer(archive), transport(archive), "synthetic-identity")
    now = datetime.now(timezone.utc)
    identity = SimpleNamespace(agent_id="synthetic", certificate_pem="synthetic")
    monkeypatch.setattr(runtime, "IdentityStore", lambda c: SimpleNamespace(
        prepare=lambda: {"host_id": "synthetic"}, load=lambda: None if failure == "enrollment" else identity))
    monkeypatch.setattr(x509, "load_pem_x509_certificate", lambda *a: SimpleNamespace(
        not_valid_before_utc=now-timedelta(seconds=60),
        not_valid_after_utc=now+timedelta(seconds=-1 if failure == "expiry" else 60)))
    def get(*a, **kw):
        if failure == "transport":
            raise OSError("synthetic-private-detail")
        return {"agent_id": identity.agent_id, "assigned_modules": []}
    monkeypatch.setattr(runtime, "Transport", lambda c: SimpleNamespace(get=get))
    calls = []
    def modules(*a):
        calls.append("modules")
        if failure == "modules" and len(calls) == 2:
            raise ImportError("synthetic-private-detail")
        return []
    monkeypatch.setattr(runtime, "configured_modules", modules)
    monkeypatch.setattr(Updates, "healthy", lambda *a: pytest.fail("failed startup must remain pending"))
    with pytest.raises((OSError, ValueError, ImportError)):
        runtime.run(config, SimpleNamespace(is_set=lambda: True), release_directory=updates.read()["current"]["directory"])
    assert updates.read()["pending"] == offer(archive)["sha256"]


def test_rollback_release_does_not_require_online_self_check(installed, monkeypatch):
    from sli_agent import runtime
    config, updates = installed
    monkeypatch.setattr(runtime, "IdentityStore", lambda c: SimpleNamespace(prepare=lambda: {"host_id": "synthetic"}))
    monkeypatch.setattr(runtime, "Transport", lambda c: SimpleNamespace(get=lambda *a, **kw: pytest.fail("restored release may start offline")))
    runtime.run(config, SimpleNamespace(is_set=lambda: True), release_directory="1.0.0-initial")
    assert updates.read()["pending"] is None


def test_interrupted_stage_is_retained_without_replacing_it(agent_package, installed):
    archive, _ = agent_package()
    _, updates = installed
    partial = updates.root / "versions" / ("1.1.0-" + offer(archive)["sha256"])
    partial.mkdir()
    (partial / "partial.py").write_bytes(b"preserve interrupted stage")
    assert not updates.offer(offer(archive), transport(archive), "synthetic-identity")
    assert updates.read()["result"]["reason"] == "agent_update_stage_failed"
    assert updates.read()["current"]["version"] == "1.0.0"
    assert (partial / "partial.py").read_bytes() == b"preserve interrupted stage"


def test_restart_helper_waits_for_previous_helper_to_release_lock(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from sli_agent import launcher
    attempts = []
    @contextmanager
    def lock(path):
        attempts.append(path)
        if len(attempts) == 1:
            raise OSError("synthetic-lock-busy")
        yield
    monkeypatch.setattr(launcher, "directory_lock", lock)
    monkeypatch.setattr(launcher.time, "sleep", lambda delay: None)
    with launcher.restart_lock(tmp_path):
        assert len(attempts) == 2


def test_transient_download_failure_can_retry_same_signed_archive(agent_package, installed):
    archive, _ = agent_package()
    _, updates = installed
    def offline(*a, **kw):
        raise OSError("synthetic-private-detail")
    assert not updates.offer(offer(archive), SimpleNamespace(download=offline), "synthetic-identity")
    assert updates.read()["result"]["reason"] == "agent_update_download_failed"
    assert updates.read()["attempted"] is None
    assert updates.offer(offer(archive), transport(archive), "synthetic-identity")


def test_two_instances_stage_and_rollback_only_their_own_releases(agent_package, installed):
    from dataclasses import replace
    import shutil
    from sli_agent.protection import directory_lock
    config, legacy = installed
    archive, _ = agent_package()
    initial = legacy.release(legacy.read()["current"])
    managers = []
    for instance in ("dc", "workstation"):
        named = replace(config, instance_name=instance, host_id="00000000-0000-4000-8000-000000000001")
        target = named.release_root / "versions/1.0.0-initial"
        target.parent.mkdir(parents=True)
        shutil.copytree(initial, target)
        manager = Updates(named)
        manager.initialize("1.0.0", target.name)
        managers.append(manager)
    first, second = managers
    before = second.pointer.read_bytes(), legacy.pointer.read_bytes()
    # A sibling's update lock must not block this instance's staging or rollback.
    with directory_lock(second.root / "update-lock"):
        assert first.offer(offer(archive), transport(archive), "synthetic-identity")
        assert first.rollback("agent_update_timeout")
    assert before == (second.pointer.read_bytes(), legacy.pointer.read_bytes())
    assert first.read()["current"]["version"] == "1.0.0"
    assert first.read()["result"]["status"] == "rolled_back"
    assert not (second.root / "downloads").exists()
    assert len(list((first.root / "versions").iterdir())) == 2
    assert len(list((second.root / "versions").iterdir())) == 1
    assert second.offer(offer(archive), transport(archive), "synthetic-identity")
    second.healthy(second.read()["current"]["directory"])
    assert second.read()["result"]["status"] == "updated"
    assert first.read()["current"]["version"] == legacy.read()["current"]["version"] == "1.0.0"


@pytest.mark.parametrize("missing", ["sli_agent/policies.py", "sli_agent/probe.py", "sli_agent/ad_dc.py",
                                    "sli_collect/bookmarked_eventlog.py", "config/source_packs/dc.json",
                                    "config/source_packs/workstations.json", "config/source_packs/radius.json",
                                    "config/event_catalog.json"])
def test_candidate_requires_main_policy_probe_and_dc_dependencies(agent_package, installed, missing):
    archive, _ = agent_package(missing=missing)
    _, updates = installed
    assert not updates.offer(offer(archive), transport(archive), "synthetic-identity")
    assert updates.read()["result"]["reason"] == "agent_update_verification_failed"
    assert updates.read()["current"]["version"] == "1.0.0"
    assert len(list((updates.root / "versions").iterdir())) == 1


def test_agent_api_range_coexists_with_main_compatibility_fields(agent_package, installed):
    archive, trust = agent_package(compatibility={"migration_ledger_max": 166,
        "plugins": {"sli.example": {"min_version": "1.0.0", "max_version": "1.1.0", "enabled": True}}})
    manifest = verify_package(archive, trust, component="agent").manifest
    assert manifest["compatibility"]["agent_api"] == {"min": 1, "max": 1}
    assert manifest["compatibility"]["migration_ledger_max"] == 166
    _, updates = installed
    assert updates.offer(offer(archive), transport(archive), "synthetic-identity")


@pytest.mark.parametrize("instance", [None, "dc"])
def test_detached_restart_helper_forwards_instance(monkeypatch, instance):
    from sli_agent import launcher
    calls = []
    monkeypatch.setattr(launcher, "subprocess", SimpleNamespace(Popen=lambda args, **kw: calls.append((args, kw)),
        DEVNULL=-3, DETACHED_PROCESS=8, CREATE_NO_WINDOW=16))
    launcher.request_service_restart("python.exe", instance)
    assert calls[0][0] == ["python.exe", "-I", "-m", "sli_agent.launcher", *([] if instance is None else ["--instance", instance])]
    assert calls[0][1]["creationflags"] == 8|16


@pytest.mark.parametrize("state", [None, "active", "paused", "drain"])
def test_runtime_acknowledges_policy_and_probe_before_instance_update(tmp_path, monkeypatch, state):
    from sli_agent import policies, runtime
    from sli_agent import updates as update_module
    from sli_agent import probe as probe_module
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path / "state",
        instance_name="dc", host_id="00000000-0000-4000-8000-000000000001",
        update_root=tmp_path / "releases", update_trust_store=tmp_path / "trust.json",
        service_python=tmp_path / "python.exe")
    identity = SimpleNamespace(agent_id="synthetic-agent")
    assignment = {"agent_id": identity.agent_id, "assigned_modules": [], "policy_revision": 7,
                  "rights_probe_request": {"request_id": "synthetic-request"},
                  "agent_update": {"sha256": "a" * 64, "version": "1.1.0"}}
    if state is not None:
        assignment["collection_policy"] = {"state": state}
    events = []
    monkeypatch.setattr(runtime, "IdentityStore", lambda c: SimpleNamespace(
        prepare=lambda: {"host_id": config.host_id}, load=lambda: identity, renew_if_due=lambda *a, **kw: False))
    monkeypatch.setattr(runtime, "configured_modules", lambda *a: [])
    monkeypatch.setattr(policies, "configured_modules", lambda *a: [])
    monkeypatch.setattr(probe_module, "probe", lambda *a, **kw:
        {"contract": "sli.agent-rights-probe.v1", "identity_verified": True, "ready": True})
    def post(path, body, *, identity):
        assert identity.agent_id == assignment["agent_id"]
        events.append((path, body))
    transport = SimpleNamespace(get=lambda *a, **kw: assignment, post=post)
    monkeypatch.setattr(runtime, "Transport", lambda c: transport)
    class Manager:
        def __init__(self, c):
            assert c.release_root == tmp_path / "releases/instances/SLI-Agent-dc"
        def read(self):
            return {"pending": None}
        def report(self, client, peer):
            assert client is transport and peer is identity
            events.append("update-result")
        def offer(self, value, client, peer):
            assert value is assignment["agent_update"] and client is transport and peer is identity
            events.append("stage")
            return True
    monkeypatch.setattr(update_module, "Updates", Manager)
    class Stop:
        done = False
        def is_set(self):
            return self.done
        def wait(self, delay):
            self.done = True
    runtime.run(config, Stop(), release_directory="1.0.0-initial")
    report = {"applied_policy_revision": 7,
              "rights_probe": {"request_id": "synthetic-request", "status": "allowed"}}
    if state is not None:
        report["collection_state"] = "paused" if state == "drain" else state
    assert events == [("/api/v1/agent/policy-report", report), "update-result", "stage"]
    assert not (config.storage_dir / "status.json").exists()


def test_candidate_checks_native_dc_dependencies_before_healthy(agent_package, installed, monkeypatch):
    from sli_agent import runtime
    from cryptography import x509
    import importlib
    archive, _ = agent_package()
    config, updates = installed
    updates.offer(offer(archive), transport(archive), "synthetic-identity")
    now = datetime.now(timezone.utc)
    identity = SimpleNamespace(agent_id="synthetic", certificate_pem="synthetic")
    monkeypatch.setattr(x509, "load_pem_x509_certificate", lambda *a: SimpleNamespace(
        not_valid_before_utc=now-timedelta(seconds=60), not_valid_after_utc=now+timedelta(seconds=60)))
    monkeypatch.setattr(runtime, "IdentityStore", lambda c: SimpleNamespace(
        prepare=lambda: {"host_id": "synthetic"}, load=lambda: identity))
    monkeypatch.setattr(runtime, "configured_modules", lambda *a: [SimpleNamespace(module_id="sli.windows.ad-dc")])
    monkeypatch.setattr(runtime, "Transport", lambda c: SimpleNamespace(
        get=lambda *a, **kw: {"agent_id": identity.agent_id, "assigned_modules": []}))
    def fail_native(name):
        assert name == "win32evtlog"
        raise ImportError("synthetic-native-unavailable")
    monkeypatch.setattr(importlib, "import_module", fail_native)
    monkeypatch.setattr(Updates, "healthy", lambda *a: pytest.fail("missing native DC reader must remain pending"))
    with pytest.raises(ImportError, match="synthetic-native-unavailable"):
        runtime.run(config, SimpleNamespace(is_set=lambda: True), release_directory=updates.read()["current"]["directory"])
    assert updates.read()["pending"] == offer(archive)["sha256"]
