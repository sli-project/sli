"""Updater release activation and console pointer recovery; no DB or Docker."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.linux import sli_update as update
from deploy.linux import updater_component as component
from deploy.linux import updater_launcher as launcher
from scripts.maintenance import release_package as package
from tools.build_update_package import build

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux updater contracts")

AD_CREDENTIAL_FILES = {"server/sli/core/ad_credential_secrets.py"}


@pytest.fixture
def updater_release(tmp_path, monkeypatch):
    source = Path(component.__file__).resolve().parents[2]
    bridge = tmp_path / "bridge"
    for name in package.UPDATER_FILES:
        path = bridge / name
        path.parent.mkdir(parents=True, exist_ok=True)
        body = (source / name).read_bytes()
        if name == "server/sli/release_package.py":
            body = body.replace(b'UPDATER_RELEASE_VERSION = "1.1.0"', b'UPDATER_RELEASE_VERSION = "1.0.1"')
        path.write_bytes(body)
    # This unit fixture adapts only the imported manager identity. The separate
    # stdlib transition suite imports and executes actual isolated B snapshots.
    monkeypatch.setattr(component, "UPDATER_RELEASE_VERSION", "1.0.1")
    real_launcher_check = component.check_launcher
    monkeypatch.setattr(component, "check_launcher",
                        lambda path, digest: real_launcher_check(path, digest, owner_uid=os.getuid()))
    operator = tmp_path / "runtime/tools/updater_launcher.py"
    operator.parent.mkdir(parents=True)
    operator.write_bytes((source / "deploy/linux/updater_launcher.py").read_bytes())
    payload = tmp_path / "payload"
    for name in package.UPDATER_CLOSURE_FILES:
        target = payload / name
        target.parent.mkdir(parents=True, exist_ok=True)
        body = (source / name).read_text("utf-8")
        target.write_text(body, encoding="utf-8")
    private = tmp_path / "offline.key"
    key = Ed25519PrivateKey.generate()
    private.write_bytes(key.private_bytes_raw())
    trust = tmp_path / "trust.json"
    trust.write_bytes(package.canonical_json({"schema_version": 1, "keys": [{
        "key_id": "test-only", "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii"),
        "package_ids": ["sli.updater"], "revoked": False,
    }]}))
    metadata = {"schema_version": 2, "package_type": "plugin-update", "package_id": "sli.updater",
                "component": "updater", "version": "1.1.0", "from_version": "1.0.1", "to_version": "1.1.0",
                "platform": "linux-amd64", "source_commit": "a" * 40, "build_id": "synthetic-1", "minimum_updater": 1,
                "compatibility": {"core_api": 1, "ui_api": 1, "from_version": "1.0.1", "min_version": "1.0.1",
                                  "max_version": "1.0.1", "os": "linux", "architecture": "amd64"},
                "required_free_disk": 1024, "migrations": {}, "deletions": [], "restart_profile": "none",
                "image": None, "compose_delta": None, "config_delta": None,
                "files": [{"path": name} for name in sorted(package.UPDATER_CLOSURE_FILES)]}
    draft = tmp_path / "manifest.json"
    draft.write_bytes(package.canonical_json(metadata))
    output = tmp_path / "updater.zip"
    manifest = build(draft, payload, private, output, key_id="test-only", updater_profile="closure-22")
    calls = []
    manager = component.UpdaterComponent(tmp_path / "runtime", trust, source_root=bridge,
                                        selftest=lambda root, version: calls.append((root, version)))
    return manager, output, calls, manifest


def test_updater_happy_path_verifies_before_execution_and_keeps_running_files(updater_release):
    manager, output, calls, _ = updater_release
    original = manager.inventory(manager.source_root)

    def selftest(root, version):
        assert manager.read_pointer()["current"]["version"] == "1.0.1"
        assert (root / "deploy/linux/sli_update.py").is_file()
        calls.append((root, version))

    manager.selftest = selftest
    assert manager.apply(output) == "committed"
    pointer = manager.read_pointer()
    assert pointer["current"]["version"] == "1.1.0"
    assert pointer["previous"]["version"] == "1.0.1"
    assert len(calls) == 1 and calls[0][1] == "1.1.0"
    assert manager.validate(pointer["previous"]).is_dir()
    assert manager.inventory(manager.source_root) == original
    assert launcher.selected_script(manager.state.parent) == calls[0][0] / "deploy/linux/sli_update.py"
    assert package.read_json(manager.journal.read_bytes())["status"] == "committed"


def test_ad_credential_dependency_remains_digest_protected(updater_release):
    manager, output, _, _ = updater_release
    manager.apply(output)
    current = manager.read_pointer()["current"]
    root = manager.validate(current)
    (root / "server/sli/core/ad_credential_secrets.py").write_bytes(b"changed")
    with pytest.raises(package.PackageError, match="files_changed"):
        manager.validate(current)
    with pytest.raises(ValueError, match="files_changed"):
        launcher.selected_script(manager.state.parent)


@pytest.mark.parametrize("secret_files", [
    set(), launcher.SECRET_FILES, launcher.SECRET_FILES | launcher.NOTIFICATION_FILES,
    launcher.SECRET_FILES | launcher.NOTIFICATION_FILES | AD_CREDENTIAL_FILES,
], ids=["no-secrets", "secrets", "notification-secrets", "ad-credential-secrets"])
@pytest.mark.parametrize("with_backup_helpers", [False, True])
@pytest.mark.parametrize("previous", [False, True])
def test_previous_updater_inventory_remains_available_for_recovery(
    updater_release, secret_files, with_backup_helpers, previous,
):
    manager, _, _, _ = updater_release
    baseline = manager.baseline()
    manager.bootstrap(baseline)
    root = manager.validate(baseline)
    # Historical inventories remain associated with the historical identity.
    baseline["version"] = "1.0.0"
    baseline["directory"] = "1.0.0-" + baseline["directory"].split("-", 1)[1]
    historical = manager.versions / baseline["directory"]
    root.rename(historical)
    root = historical
    helpers = launcher.FILES - launcher.LEGACY_FILES
    assert helpers == {"deploy/linux/backup.py", "deploy/linux/restore_existing.py", "deploy/linux/backup_restore_check.py"}
    removed = ((set() if with_backup_helpers else helpers)
               | ((launcher.SECRET_FILES | launcher.NOTIFICATION_FILES | AD_CREDENTIAL_FILES) - secret_files))
    for name in removed:
        (root / name).unlink()
        del baseline["files"][name]
    assert set(baseline["files"]) == (launcher.FILES if with_backup_helpers else launcher.LEGACY_FILES) | secret_files
    manager.save(manager.pointer, {"format_version": 1, "current": baseline, "previous": baseline})
    assert manager.validate(baseline) == root
    assert launcher.selected_script(manager.state.parent, previous=previous) == root / "deploy/linux/sli_update.py"
    (root / "deploy/linux/update_checkpoint.py").write_bytes(b"modified")
    with pytest.raises(package.PackageError, match="files_changed"):
        manager.validate(baseline)
    with pytest.raises(ValueError, match="files_changed"):
        launcher.selected_script(manager.state.parent, previous=previous)


@pytest.mark.parametrize("kind", ["signature", "payload", "revoked", "scope"])
def test_updater_rejects_untrusted_bytes_before_stage_or_selftest(updater_release, kind):
    manager, output, calls, _ = updater_release
    if kind in {"signature", "payload"}:
        with zipfile.ZipFile(output) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        if kind == "signature":
            value = package.read_json(files[package.SIGNATURE_NAME])
            value["signature"] = base64.b64encode(b"x" * 64).decode("ascii")
            files[package.SIGNATURE_NAME] = package.canonical_json(value)
        else:
            files["payload/deploy/linux/sli_update.py"] += b"# changed"
        with zipfile.ZipFile(output, "w") as archive:
            for name, body in files.items():
                archive.writestr(name, body)
    else:
        trust = package.read_json(manager.trust_store.read_bytes())
        trust["keys"][0].update({"revoked": True} if kind == "revoked" else {"package_ids": ["sli.core"]})
        manager.trust_store.write_bytes(package.canonical_json(trust))
    with pytest.raises(package.PackageError, match="verification_failed"):
        manager.apply(output)
    assert calls == [] and not manager.versions.exists() and not manager.pointer.exists()
    assert not manager.journal.exists()  # pre-lock rejection is side-effect free


def test_selftest_failure_keeps_old_pointer(updater_release):
    manager, output, _, _ = updater_release
    baseline = manager.baseline()
    manager.bootstrap(baseline)
    manager.source_root = manager.validate(baseline)
    original = manager.pointer.read_bytes()

    def fail(*_):
        raise RuntimeError("synthetic-private-error")

    manager.selftest = fail
    with pytest.raises(package.PackageError, match="activation_failed"):
        manager.apply(output)
    assert manager.pointer.read_bytes() == original
    assert "synthetic-private-error" not in manager.journal.read_text("utf-8")
    assert package.read_json(manager.journal.read_bytes())["status"] == "failed"


def test_pointer_rollback_is_offline_and_idempotent(updater_release):
    manager, output, calls, _ = updater_release
    manager.apply(output)
    previous = manager.read_pointer()["previous"]
    manager.trust_store.unlink()
    assert manager.rollback() == "rolled_back"
    assert manager.read_pointer()["current"] == previous
    assert manager.read_pointer()["previous"] is None
    assert calls[-1][1] == "1.0.1"
    assert manager.rollback() == "rolled_back"
    assert len(calls) == 2


def test_recovery_can_launch_previous_if_current_is_damaged(updater_release):
    manager, output, _, _ = updater_release
    manager.apply(output)
    pointer = manager.read_pointer()
    previous_script = launcher.selected_script(manager.state.parent, previous=True)
    (manager.validate(pointer["current"]) / "deploy/linux/sli_update.py").write_text("broken")
    with pytest.raises(ValueError, match="files_changed"):
        launcher.selected_script(manager.state.parent)
    assert launcher.selected_script(manager.state.parent, previous=True) == previous_script
    assert manager.rollback() == "rolled_back"
    assert launcher.selected_script(manager.state.parent) == previous_script


@pytest.mark.parametrize("previous", [False, True])
def test_launcher_retains_legacy_recovery_and_checks_its_files(tmp_path, previous):
    runtime = tmp_path / "runtime"
    directory = "1.0.0-" + "a" * 64
    root = runtime / "updater/versions" / directory
    legacy_files = package.UPDATER_FILES - (launcher.SECRET_FILES | launcher.NOTIFICATION_FILES | AD_CREDENTIAL_FILES)
    assert legacy_files == launcher.FILES
    files = {}
    for name in legacy_files:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"# synthetic legacy updater\n")
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    descriptor = {"component": "updater", "version": "1.0.0", "os": "linux", "architecture": "amd64",
                  "directory": directory, "files": files}
    update.atomic_json(runtime / "state/updater.json", {
        "format_version": 1, "current": descriptor, "previous": descriptor,
    })
    assert launcher.selected_script(runtime, previous=previous) == root / "deploy/linux/sli_update.py"
    (root / "deploy/linux/installation.py").write_bytes(b"changed")
    with pytest.raises(ValueError, match="files_changed"):
        launcher.selected_script(runtime, previous=previous)


@pytest.mark.parametrize("name", ["deploy/linux/installation.py", "deploy/linux/adoption_probe.py",
                                 "deploy/linux/sli_secrets.py", "deploy/linux/secrets-manifest.json",
                                 "server/sli/agents/ca.py", "server/sli/core/notification_secrets.py",
                                 "server/sli/core/secret_files.py"])
@pytest.mark.parametrize("change", ["missing", "extra", "modified", "symlink"])
def test_launcher_validates_installation_dependencies(updater_release, name, change):
    manager, output, _, _ = updater_release
    manager.apply(output)
    pointer = manager.read_pointer()
    root = manager.validate(pointer["current"])
    script = root / "deploy/linux/sli_update.py"
    assert launcher.selected_script(manager.state.parent) == script
    if change == "missing":
        del pointer["current"]["files"][name]
    elif change == "extra":
        pointer["current"]["files"]["deploy/linux/unexpected.py"] = "a" * 64
    elif change == "modified":
        (root / name).write_bytes(b"changed")
    else:
        path = root / name
        target = root / "dependency-copy.py"
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
    manager.save(manager.pointer, pointer)
    reason = "invalid_updater_pointer" if change in {"missing", "extra"} else "files_changed"
    with pytest.raises(ValueError, match=reason):
        launcher.selected_script(manager.state.parent)


@pytest.mark.parametrize("server_version", ["1.0.0", "adopted-1"])
def test_updater_pointer_coexists_with_installed_server_state(updater_release, server_version):
    manager, output, _, _ = updater_release
    installed_path = manager.state / "installed.json"
    update.atomic_json(installed_path, {
        "component": "server", "version": server_version, "os": "linux", "architecture": "amd64",
        "image_tag": "sha256:" + "a" * 64, "image_digest": "sha256:" + "a" * 64,
        "migrations": {}, "compose_project": "sli", "volumes": {"data": "synthetic-data"},
    })
    installed = installed_path.read_bytes()
    manager.selftest = component.run_selftest
    assert manager.apply(output) == "committed"
    pointer = manager.read_pointer()
    assert launcher.selected_script(manager.state.parent) == (
        manager.versions / pointer["current"]["directory"] / "deploy/linux/sli_update.py"
    )
    previous = manager.versions / pointer["previous"]["directory"] / "deploy/linux/sli_update.py"
    assert launcher.selected_script(manager.state.parent, previous=True) == previous
    assert installed_path.read_bytes() == installed
    assert manager.rollback() == "rolled_back"
    assert launcher.selected_script(manager.state.parent) == previous
    assert installed_path.read_bytes() == installed


def test_changed_previous_is_rejected_without_pointer_switch(updater_release):
    manager, output, _, _ = updater_release
    manager.apply(output)
    pointer = manager.read_pointer()
    original = manager.pointer.read_bytes()
    (manager.validate(pointer["previous"]) / "deploy/linux/update_checkpoint.py").write_text("changed")
    with pytest.raises(package.PackageError, match="files_changed"):
        manager.rollback()
    assert manager.pointer.read_bytes() == original


def test_verify_only_does_not_stage_or_execute(updater_release):
    manager, output, calls, _ = updater_release
    assert manager.apply(output, dry_run=True) == "verified"
    assert calls == [] and not manager.pointer.exists() and not manager.versions.exists()
    assert not manager.journal.exists()


def test_only_current_trusted_updater_can_apply_next_release(updater_release):
    manager, output, _, _ = updater_release
    manager.apply(output)
    with pytest.raises(package.PackageError, match="current_updater_required"):
        manager.apply(output)


def test_active_server_operation_blocks_self_update(updater_release):
    manager, output, calls, _ = updater_release
    update.atomic_json(manager.state / "update-journal.json", {"status": "running"})
    with pytest.raises(package.PackageError, match="resume_required"):
        manager.apply(output)
    assert calls == [] and not manager.pointer.exists()


@pytest.mark.parametrize("change", ["extra", "missing", "image", "migrations", "component"])
def test_updater_inventory_and_ownership_are_exact(updater_release, change):
    manifest = json.loads(package.canonical_json(updater_release[3]))
    if change == "extra":
        manifest["files"].append({"path": "trust.json", "size": 1, "sha256": "a" * 64})
    elif change == "missing":
        manifest["files"].pop()
    elif change == "image":
        manifest["image"] = {"path": "image.tar", "digest": "sha256:" + "a" * 64}
    elif change == "migrations":
        manifest["migrations"] = {"config/postgres_migrations/001_example.sql": "a" * 64}
    else:
        manifest["component"] = "server"
    with pytest.raises(package.PackageError):
        package.validate_manifest(manifest, package.PackageLimits())


def test_interrupted_pointer_switch_can_be_rolled_back(updater_release, monkeypatch):
    manager, output, _, _ = updater_release
    save = manager.save

    class PowerLoss(BaseException):
        pass

    def interrupt(path, value):
        save(path, value)
        if path == manager.pointer and value.get("previous"):
            raise PowerLoss()

    monkeypatch.setattr(manager, "save", interrupt)
    with pytest.raises(PowerLoss):
        manager.apply(output)
    assert manager.read_pointer()["current"]["version"] == "1.1.0"
    assert package.read_json(manager.journal.read_bytes())["phase"] == "switch"
    monkeypatch.setattr(manager, "save", save)
    assert manager.rollback() == "rolled_back"
    assert manager.read_pointer()["current"]["version"] == "1.0.1"


def test_interrupted_selftest_recovers_without_switching_pointer(updater_release):
    manager, output, _, _ = updater_release

    class PowerLoss(BaseException):
        pass

    def interrupt(*_):
        raise PowerLoss()

    manager.selftest = interrupt
    with pytest.raises(PowerLoss):
        manager.apply(output)
    original = manager.pointer.read_bytes()
    manager.selftest = lambda *_: None
    assert manager.rollback() == "rolled_back"
    assert manager.pointer.read_bytes() == original
    assert manager.read_pointer()["current"]["version"] == "1.0.1"


def test_interrupted_rollback_finishes_without_toggling_pointer(updater_release, monkeypatch):
    manager, output, _, _ = updater_release
    manager.apply(output)
    save = manager.save

    class PowerLoss(BaseException):
        pass

    def interrupt(path, value):
        save(path, value)
        if path == manager.pointer:
            raise PowerLoss()

    monkeypatch.setattr(manager, "save", interrupt)
    with pytest.raises(PowerLoss):
        manager.rollback()
    monkeypatch.setattr(manager, "save", save)
    assert manager.rollback() == "rolled_back"
    assert manager.read_pointer()["current"]["version"] == "1.0.1"


@pytest.mark.parametrize("exit_code", [0, 1])
def test_selftest_runner_invokes_isolated_candidate_before_switch(tmp_path, monkeypatch, exit_code):
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, exit_code)

    monkeypatch.setattr(component.subprocess, "run", run)
    if exit_code:
        with pytest.raises(package.PackageError, match="selftest_failed"):
            component.run_selftest(tmp_path, "1.1.0")
    else:
        component.run_selftest(tmp_path, "1.1.0")
    args, kwargs = calls[0]
    assert args == [sys.executable, "-I", "-B", str(tmp_path / "deploy/linux/sli_update.py"),
                    "selftest", "--expected-version", "1.1.0"]
    assert kwargs["cwd"] == tmp_path and kwargs["timeout"] == 60


def test_shipped_updater_passes_actual_offline_selftest(updater_release):
    manager, output, _, _ = updater_release
    manager.selftest = component.run_selftest
    assert manager.apply(output) == "committed"
    assert manager.rollback() == "rolled_back"


def test_staged_updater_retains_adoption_dependencies(updater_release, tmp_path):
    manager, output, _, _ = updater_release
    manager.selftest = component.run_selftest
    assert manager.apply(output) == "committed"
    root = manager.validate(manager.read_pointer()["current"])
    # Isolated Python can only import the signed release, never this checkout.
    script = f"""
import sys
from pathlib import Path
sys.path.insert(0, {str(root)!r})
from deploy.linux import installation, sli_update
from server.sli.core import ad_credential_secrets, notification_secrets, secret_files
for module in (installation, ad_credential_secrets, notification_secrets, secret_files):
    assert Path(module.__file__).resolve().is_relative_to(Path({str(root)!r}))
assert Path(installation.__file__).with_name('adoption_probe.py').is_file()
host = object()
def installation_host(*args):
    assert args[-1] == 172800
    return host
def adopt(runtime, actual_host, *, dry_run):
    assert actual_host is host and dry_run
    return {{'status': 'dry_run'}}
installation.InstallationHost = installation_host
installation.adopt = adopt
raise SystemExit(sli_update.main(['adopt', '--compose', 'synthetic-compose.yml',
    '--tls-min-validity-seconds', '172800', '--dry-run', '--json']))
"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script], cwd=tmp_path,
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "dry_run"


def test_updater_cli_and_console_pointer_rollback(updater_release, monkeypatch, capsys):
    manager, output, _, _ = updater_release
    monkeypatch.setattr(component, "UpdaterComponent", lambda *_: manager)
    args = ["--runtime", str(manager.state.parent), "--json"]
    assert update.main(["apply", "--component", "updater", "--package", str(output), *args]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "committed"
    assert update.main(["recover", "--rollback-updater", *args]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "rolled_back"


def test_launcher_executes_selected_version(updater_release, monkeypatch):
    manager, output, _, _ = updater_release
    manager.apply(output)
    calls = []
    monkeypatch.setattr(launcher.os, "execv", lambda executable, args: calls.append((executable, args)))
    launcher.main(["--runtime", str(manager.state.parent), "status", "--json"])
    assert calls == [(sys.executable, [sys.executable, "-I", "-B", str(launcher.selected_script(manager.state.parent)),
                                     "status", "--json", "--runtime", str(manager.state.parent)])]
