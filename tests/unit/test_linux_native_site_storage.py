"""T106a portable native site/host contracts; no services or real secrets."""
import json
import os
import shutil
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import native_clickhouse_endpoint as ch
from deploy.linux import native_host as host
from deploy.linux import native_install as install
from deploy.linux import native_runtime as runtime


@pytest.mark.parametrize("value", ['"true"', "1", "[]", "{}"])
def test_agents_requires_boolean(value):
    with pytest.raises(ValueError, match="^native_site_agents_invalid$"):
        ch.parse_site("agents = " + value)


@pytest.mark.parametrize("value", ['"relative"', '"/"', '"/disk/../backup"',
                                        '"/disk//backup"', '"/disk/backup/"',
                                        '"/var/backups/sli"', '"/srv/sli-db/copies"',
                                        '"/var/lib/sli/copies"', '"/etc/sli/copies"',
                                        '"/disk/backup%"', '"/disk/backup space"', "true"])
def test_backup_root_requires_safe_absolute_path(value):
    with pytest.raises(ValueError, match="^native_site_backup_root_invalid$"):
        ch.parse_site("backup_root = " + value)


def test_optional_site_keys_preserve_legacy_hash_and_are_hashed_when_supplied():
    legacy = {"domain_fqdn": "example.invalid", "bind": "127.0.0.1"}
    assert ch.parse_site("") == legacy
    site = ch.parse_site('agents = true\nbackup_root = "/mnt/copies/sli"')
    assert site == dict(legacy, agents=True, backup_root="/mnt/copies/sli")
    assert install.site_digest(site) != install.site_digest(legacy)
    assert install.site_digest(dict(legacy, agents=False)) != install.site_digest(legacy)


def test_agents_missing_is_checked_before_install_mutation(monkeypatch):
    monkeypatch.setattr(install, "inventory", lambda release: (Path("/release"), {}, "digest"))
    monkeypatch.setattr(install.platform, "freedesktop_os_release", lambda: {"ID": "debian", "VERSION_ID": "13"})
    monkeypatch.setattr(install.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(install, "site_configuration", lambda: ch.parse_site("agents = true"))
    monkeypatch.setattr(install, "SECRETS", Path("/missing-synthetic-secrets"))
    with pytest.raises(RuntimeError, match="^native_agents_secrets_missing$"):
        install.configure("test")


def test_agents_validate_all_four_secrets_and_render_runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(install, "SECRETS", tmp_path)
    for name in install.AGENT_SECRETS:
        (tmp_path / name).write_text("synthetic certificate or key")
    monkeypatch.setattr(install, "trusted", lambda path: path.read_bytes())
    monkeypatch.setattr(install, "secret_metadata_valid", lambda info: True)
    config = install.runtime_settings(ch.parse_site("agents = true"))
    assert json.loads(json.dumps(config))["agents"] is True
    body = runtime.dotnet_unit("test", config)
    for name in install.AGENT_SECRETS:
        assert f"LoadCredential={name}:/etc/sli/secrets/{name}" in body
    (tmp_path / install.AGENT_SECRETS[-1]).unlink()
    with pytest.raises(RuntimeError, match="^native_agents_secrets_missing$"):
        install.runtime_settings(ch.parse_site("agents = true"))


def test_agents_runtime_publishes_json_for_generated_api_unit(tmp_path, monkeypatch):
    writes = {}
    machine = SimpleNamespace(receipt=lambda: None, directory=lambda *args, **kwargs: None,
                              write=lambda path, body, *args, **kwargs: writes.update({path: body}))
    monkeypatch.setattr(host, "administrative_lock", nullcontext)
    monkeypatch.setattr(host, "Host", lambda: machine)
    monkeypatch.setattr(host, "validate_identity", lambda: None)
    monkeypatch.setattr(host, "account", lambda name: object())
    monkeypatch.setattr(host, "group", lambda name: None)
    monkeypatch.setattr(host, "run", lambda argv, **kw: "")
    monkeypatch.setattr(runtime, "CONFIG", tmp_path / "runtime.json")
    monkeypatch.setattr(runtime, "configure_worker_accounts", lambda: None)
    monkeypatch.setattr(install, "validate_agents", lambda site: None)
    monkeypatch.setattr(runtime.subprocess, "run", lambda *args, **kw: None)
    monkeypatch.setattr(runtime, "systemd", lambda service, **kw: {"LoadState": "not-found"})
    runtime.configure(install.runtime_settings(ch.parse_site("agents = true")))
    assert json.loads(writes[str(runtime.CONFIG)])["agents"] is True
    for name in install.AGENT_SECRETS:
        assert f"LoadCredential={name}:" in runtime.dotnet_unit("test", json.loads(writes[str(runtime.CONFIG)]))


def test_agent_secret_permissions_are_not_relaxed():
    assert install.secret_metadata_valid(SimpleNamespace(st_uid=0, st_gid=10001, st_mode=0o100640, st_size=20))
    for change in ({"st_uid": 1}, {"st_gid": 0}, {"st_mode": 0o100644},
                   {"st_mode": 0o040640}, {"st_size": 0}):
        info = dict(st_uid=0, st_gid=10001, st_mode=0o100640, st_size=20)
        assert not install.secret_metadata_valid(SimpleNamespace(**dict(info, **change)))


@pytest.fixture
def storage(tmp_path, monkeypatch):
    machine = host.Host(tmp_path)
    source = machine.path("/mnt/copies/sli")
    source.mkdir(parents=True)
    machine.path(host.MOUNT).mkdir(parents=True)
    monkeypatch.setattr(host.clickhouse, "site_configuration", lambda root=Path("/"): {"backup_root": "/mnt/copies/sli"})
    monkeypatch.setattr(machine, "clickhouse_mode", lambda: "native")
    monkeypatch.setattr(machine, "backup_device", lambda path: 1 if path == machine.path(host.MOUNT) else 2)
    monkeypatch.setattr(machine, "backup_free", lambda path: 100 * 1024**3)
    monkeypatch.setattr(machine, "backup_trusted", lambda path: None)
    mounted = []
    monkeypatch.setattr(machine, "backup_mounted", lambda source, target: bool(mounted))
    writes, calls = {}, []
    monkeypatch.setattr(machine, "write", lambda name, body, *args, **kwargs: writes.update({name: body}))
    monkeypatch.setattr(machine, "directory", lambda name, *args, **kwargs: machine.path(name).mkdir(parents=True, exist_ok=True))
    def run(argv, **kw):
        calls.append(argv)
        if argv == ["systemctl", "start", "var-backups-sli.mount"]:
            mounted.append(True)
        if argv[0] == "findmnt":
            return json.dumps({"filesystems": [{"target": "/var/backups/sli", "fsroot": "/sli", "maj:min": "8:2"},
                                               {"target": "/mnt/copies/sli", "fsroot": "/sli", "maj:min": "8:2"}]})
        return ""
    monkeypatch.setattr(host, "run", run)
    return machine, source, writes, calls


def test_backup_root_same_device_refused_without_writes(storage, monkeypatch):
    machine, _, writes, calls = storage
    monkeypatch.setattr(machine, "backup_device", lambda path: 1)
    with pytest.raises(host.HostError, match="^native_backup_root_same_device$"):
        machine.configure_backup_root()
    assert not writes and not calls


def test_backup_root_low_space_refused(storage, monkeypatch):
    machine, _, writes, calls = storage
    monkeypatch.setattr(machine, "backup_free", lambda path: 0)
    with pytest.raises(host.HostError, match="^native_backup_root_insufficient_space$"):
        machine.configure_backup_root()
    assert not writes and not calls


def test_backup_root_missing_refused(storage):
    machine, source, writes, calls = storage
    source.rmdir()
    with pytest.raises(host.HostError, match="^native_backup_root_invalid$"):
        machine.configure_backup_root()
    assert not writes and not calls


def test_backup_root_estimate_scales_with_existing_database(storage, monkeypatch):
    machine, _, writes, calls = storage
    (machine.path(host.MOUNT) / "synthetic-data").write_bytes(b"x" * 1024)
    monkeypatch.setattr(machine, "backup_free", lambda path: 1024**3 + 1023)
    with pytest.raises(host.HostError, match="native_backup_root_insufficient_space"):
        machine.configure_backup_root()
    assert not writes and not calls


def test_backup_root_estimate_includes_application_files(storage, monkeypatch):
    machine, _, writes, calls = storage
    files = machine.path("/var/lib/sli/evidence")
    files.mkdir(parents=True)
    (files / "synthetic-evidence").write_bytes(b"x" * 1024)
    monkeypatch.setattr(machine, "backup_free", lambda path: 1024**3 + 2047)
    with pytest.raises(host.HostError, match="native_backup_root_insufficient_space"):
        machine.configure_backup_root()
    assert not writes and not calls


def test_existing_backup_directory_is_not_hidden(storage):
    machine, _, writes, calls = storage
    target = machine.path("/var/backups/sli")
    target.mkdir(parents=True)
    (target / "existing-set").write_bytes(b"preserved")
    with pytest.raises(host.HostError, match="native_backup_root_target_not_empty"):
        machine.configure_backup_root()
    assert not writes and not calls
    assert (target / "existing-set").read_bytes() == b"preserved"


def test_wrong_mount_identity_is_refused(storage, monkeypatch):
    machine, _, _, _ = storage
    monkeypatch.setattr(machine, "backup_mounted", lambda source, target: False)
    with pytest.raises(host.HostError, match="native_backup_root_mount_mismatch"):
        machine.configure_backup_root()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink validation; Linux CI")
def test_backup_root_symlink_is_refused(storage):
    machine, source, writes, calls = storage
    saved = source.with_name("original")
    source.rename(saved)
    source.symlink_to(saved, target_is_directory=True)
    with pytest.raises(host.HostError, match="native_backup_root_untrusted"):
        machine.configure_backup_root()
    assert not writes and not calls


def test_backup_mount_loss_blocks_capture_before_copy(storage, monkeypatch):
    from deploy.linux import backup, native_backup
    machine, _, _, _ = storage
    monkeypatch.setattr(host, "Host", lambda: machine)
    monkeypatch.setattr(machine, "receipt", lambda: None)
    monkeypatch.setattr(host, "administrative_lock", nullcontext)
    monkeypatch.setattr(backup, "write_json", lambda *args: None)
    with pytest.raises(host.HostError, match="native_backup_root_mount_mismatch"):
        native_backup.capture_locked(machine.root / "not-created", writers_fenced=True)
    assert not (machine.root / "not-created").exists()


def test_backup_mount_identity_refuses_a_different_directory(tmp_path):
    machine = host.Host(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    assert machine.backup_mounted(source, source)
    other = tmp_path / "other"
    other.mkdir()
    assert not machine.backup_mounted(source, other)


@pytest.mark.skipif(os.name == "nt", reason="Linux private mount namespace; no host mounts")
def test_bind_mount_routes_backup_bytes_in_private_namespace(tmp_path):
    if not shutil.which("unshare") or not shutil.which("mount"):
        pytest.skip("Linux mount tools unavailable")
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    target.mkdir()
    script = (
        "from pathlib import Path; import subprocess,sys; "
        "source,target=map(Path,sys.argv[1:]); "
        "subprocess.run(['mount','--bind',str(source),str(target)],check=True); "
        "(target/'native').mkdir(mode=0o700); "
        "(target/'native'/'synthetic-set').write_bytes(b'synthetic backup'); "
        "assert (source/'native'/'synthetic-set').read_bytes()==b'synthetic backup'; "
        "assert source.samefile(target)"
    )
    result = subprocess.run(["unshare", "--mount", sys.executable, "-c", script, str(source), str(target)],
                            capture_output=True, text=True, timeout=30,
                            env={"PATH": os.environ["PATH"], "LC_ALL": "C"})
    if result.returncode and "Operation not permitted" in result.stderr:
        pytest.skip("Private mount namespace requires Linux CAP_SYS_ADMIN")
    assert result.returncode == 0, result.stderr


def test_backup_root_mount_is_required_by_all_services_and_timer(storage):
    machine, _, writes, calls = storage
    machine.configure_backup_root()
    unit = writes["/etc/systemd/system/var-backups-sli.mount"]
    assert "What=/mnt/copies/sli\nWhere=/var/backups/sli\nType=none\nOptions=bind" in unit
    assert "RequiresMountsFor=/mnt/copies/sli" in unit
    assert calls.index(["systemctl", "daemon-reload"]) < calls.index(["systemctl", "start", "var-backups-sli.mount"])
    for unit in machine.backup_dependent_units():
        body = writes[f"/etc/systemd/system/{unit}.d/80-sli-backup-mount.conf"]
        assert "BindsTo=var-backups-sli.mount" in body and "After=var-backups-sli.mount" in body
    from deploy.linux import native_backup
    config = dict(install.runtime_settings(ch.parse_site("")), profiles=["light", "heavy", "long"])
    expected = set(host.units()) | set(native_backup.units()) | set(runtime.dotnet_units("test", config)) | {
        name for name in runtime.units(install.runtime_settings(ch.parse_site(""))) if not name.endswith(".slice")}
    assert machine.backup_dependent_units() == expected - {"sli-backup-settings.service"}


def test_legacy_backup_root_does_not_write_mount(tmp_path, monkeypatch):
    monkeypatch.setattr(ch, "site_configuration", lambda root: {})
    assert host.Host(tmp_path).configure_backup_root() is None


def test_new_diagnostics_are_finite(monkeypatch, capsys):
    monkeypatch.setattr(install.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(install, "inventory", lambda release: (_ for _ in ()).throw(RuntimeError("native_agents_secrets_missing")))
    assert install.main(["configure", "test"]) == 1
    assert 'Agent certificates are missing' in capsys.readouterr().err
    monkeypatch.setattr(install, "inventory", lambda release: (_ for _ in ()).throw(RuntimeError("private diagnostic")))
    assert install.main(["configure", "test"]) == 1
    message = capsys.readouterr().err
    assert 'journalctl -t sli-setup' in message and 'private diagnostic' not in message


@pytest.fixture
def reconfiguration(tmp_path, monkeypatch):
    from deploy.linux import native_backup, native_upgrade
    state = tmp_path / "state"
    state.mkdir()
    config_path = tmp_path / "runtime.json"
    old = dict(install.runtime_settings(ch.parse_site("")), profiles=["light", "heavy"], ad_credentials=True)
    config_path.write_text(json.dumps(old))
    site = ch.parse_site("agents = true")
    receipt = {"schema_version": 1, "status": "configured", "release": "test",
               "site_sha256": install.site_digest(ch.parse_site(""))}
    (state / "package-install.json").write_text(json.dumps(receipt))
    calls = []
    monkeypatch.setattr(install, "STATE", state)
    monkeypatch.setattr(runtime, "CONFIG", config_path)
    monkeypatch.setattr(install, "site_configuration", lambda: dict(site))
    monkeypatch.setattr(install, "validate_agents", lambda settings: calls.append("secrets-checked"))
    monkeypatch.setattr(install, "trusted", lambda path: path.read_bytes())
    monkeypatch.setattr(runtime, "document", lambda path: json.loads(path.read_text()))
    monkeypatch.setattr(install, "atomic", lambda path, value: path.write_text(json.dumps(value)))
    monkeypatch.setattr(install, "replace_managed", lambda path, allowed, body: path.write_bytes(body.encode()))
    monkeypatch.setattr(install, "inventory", lambda release: (tmp_path / release, {}, "digest"))
    monkeypatch.setattr(native_upgrade, "preflight", lambda: (tmp_path / "test", None))
    monkeypatch.setattr(native_upgrade, "operation_lock", lambda path: nullcontext())
    monkeypatch.setattr(native_backup, "ROOT", tmp_path)
    monkeypatch.setattr(host, "administrative_lock", nullcontext)
    monkeypatch.setattr(runtime, "no_transaction", lambda **kwargs: None)
    monkeypatch.setattr(runtime, "stop_writers", lambda: calls.append("writers-stopped"))
    monkeypatch.setattr(install, "command", lambda argv, **kwargs: calls.append(argv))
    monkeypatch.setattr(install, "backup_schedule", lambda: "disabled")
    monkeypatch.setattr(install, "wait_api", lambda config: calls.append("api-checked"))
    monkeypatch.setattr(install, "wait_health", lambda: calls.append("health-checked"))
    return SimpleNamespace(state=state, old=old, site=site, calls=calls, config=config_path)


def test_reconfigure_agents_preserves_profiles_and_updates_receipt(reconfiguration):
    ctx = reconfiguration
    install.reconfigure_agents("test")
    actual = json.loads(ctx.config.read_text())
    assert actual == dict(ctx.old, agents=True)
    assert "LoadCredential=agent_issuer_key:" in runtime.dotnet_unit("test", json.loads(ctx.config.read_text()))
    assert ctx.calls.index("secrets-checked") < ctx.calls.index("writers-stopped") < ctx.calls.index("api-checked")
    assert not any(call[:2] in [["systemctl", "enable"], ["systemctl", "start"]]
                   and "sli-backup.timer" in call for call in ctx.calls if isinstance(call, list))
    assert json.loads((ctx.state / "package-install.json").read_text())["site_sha256"] == install.site_digest(ctx.site)
    assert json.loads((ctx.state / "agents-reconfigure.json").read_text())["status"] == "configured"
    ctx.site["agents"] = False
    install.reconfigure_agents("test")
    assert json.loads(ctx.config.read_text())["agents"] is False
    assert "LoadCredential=agent_issuer_key:" not in runtime.dotnet_unit("test", json.loads(ctx.config.read_text()))


def test_reconfigure_rejects_unrelated_site_change_before_stopping(reconfiguration):
    ctx = reconfiguration
    ctx.site["backup_root"] = "/mnt/copies/sli"
    with pytest.raises(RuntimeError, match="^native_agents_reconfigure_site_mismatch$"):
        install.reconfigure_agents("test")
    assert "writers-stopped" not in ctx.calls
    assert json.loads(ctx.config.read_text()) == ctx.old


def test_reconfigure_interruption_is_resumable(reconfiguration, monkeypatch):
    ctx = reconfiguration
    def interrupted(path, allowed, body):
        path.write_bytes(body.encode())
        raise KeyboardInterrupt
    monkeypatch.setattr(install, "replace_managed", interrupted)
    with pytest.raises(KeyboardInterrupt):
        install.reconfigure_agents("test")
    assert json.loads((ctx.state / "agents-reconfigure.json").read_text())["status"] == "applying"
    monkeypatch.setattr(install, "replace_managed", lambda path, allowed, body: path.write_bytes(body.encode()))
    install.reconfigure_agents("test")
    assert json.loads(ctx.config.read_text())["agents"] is True


def test_reconfigure_failure_keeps_autostart_disabled_and_can_retry(reconfiguration, monkeypatch):
    ctx = reconfiguration
    def fail():
        raise RuntimeError("synthetic health failure")
    monkeypatch.setattr(install, "wait_health", fail)
    with pytest.raises(RuntimeError, match="synthetic health failure"):
        install.reconfigure_agents("test")
    assert ["systemctl", "enable", "--now", "sli.target", "sli-backup.timer"] not in ctx.calls
    assert ctx.calls[-1] == "writers-stopped"
    monkeypatch.setattr(install, "wait_health", lambda: None)
    install.reconfigure_agents("test")
    assert json.loads((ctx.state / "agents-reconfigure.json").read_text())["status"] == "configured"


def test_reconfigure_missing_agents_secret_does_not_stop_writers(reconfiguration, monkeypatch):
    ctx = reconfiguration
    def missing(site):
        raise RuntimeError("native_agents_secrets_missing")
    monkeypatch.setattr(install, "validate_agents", missing)
    with pytest.raises(RuntimeError, match="native_agents_secrets_missing"):
        install.reconfigure_agents("test")
    assert "writers-stopped" not in ctx.calls
    assert not (ctx.state / "agents-reconfigure.json").exists()


def test_reconfiguration_gate_rejects_partial_publication(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "STATE", tmp_path)
    monkeypatch.setattr(runtime, "TRANSACTIONS", tmp_path / "transactions")
    runtime.TRANSACTIONS.mkdir()
    monkeypatch.setattr(runtime, "document", lambda path: json.loads(path.read_text()))
    (tmp_path / "agents-reconfigure.json").write_text(json.dumps({"status": "applying"}))
    with pytest.raises(runtime.RuntimeErrorCode, match="native_agents_reconfigure_pending"):
        runtime.no_transaction()


def test_upgrade_recovery_keeps_accepted_agents_configuration(reconfiguration, tmp_path, monkeypatch):
    from deploy.linux import native_upgrade
    ctx = reconfiguration
    install.reconfigure_agents("test")
    accepted_api = runtime.dotnet_unit("test", runtime.configuration())
    saved = tmp_path / "saved/units"
    saved.mkdir(parents=True)
    old_api = runtime.dotnet_unit("test", ctx.old)
    (saved / "sli-dotnet-api.service").write_text(old_api)
    native_upgrade.restore_agents_unit(saved.parent)
    assert runtime.dotnet_unit("test", runtime.configuration()) == accepted_api
    assert (saved / "sli-dotnet-api.service").read_text() == old_api
