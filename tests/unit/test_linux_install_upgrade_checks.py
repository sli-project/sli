"""Beta package acceptance on a private filesystem and a stateful service double."""

from contextlib import contextmanager, nullcontext, redirect_stderr
from fnmatch import fnmatchcase
from io import StringIO
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from deploy.linux import native_dotnet_generator as generator
from deploy.linux import backup, native_backup as native, native_install as install
from deploy.linux import native_host as host, native_runtime as runtime
from deploy.linux import native_upgrade as upgrade, restore_existing, update_checkpoint
from deploy.linux import native_pg_inventory, native_pg_migrate
from tests.unit.test_linux_native_backup import recovery_set
from tests.unit.test_linux_native_pg_migrate import postgres as postgres, s5_release as s5_release
from tests.unit.test_linux_native_pg_migrate import private_postgres
from scripts.maintenance import existing_postgres_bootstrap as bootstrap


def atomic_json(path, value):
    """Windows double for POSIX directory fsync, retaining atomic file writes."""
    temporary = path.with_name(path.name + ".new")
    with temporary.open("w") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


@pytest.fixture
def runtime_host(tmp_path, monkeypatch):
    """Only OS account/DB operations are doubled; rendering and retirement are real."""
    guarded_write = host.Host(tmp_path).write
    config = tmp_path / "etc/sli/runtime.json"
    monkeypatch.setattr(runtime, "CONFIG", config)
    if os.name == "nt":
        # NTFS chmod cannot model POSIX write bits. Match the trusted 0644
        # service files created below; production trust checks remain enabled.
        lstat = Path.lstat

        def unit_stat(path, *args, **kwargs):
            info = lstat(path, *args, **kwargs)
            if path.parent == tmp_path / "etc/systemd/system" and path.name.startswith("sli-clickhouse-"):
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o644)
            return info

        monkeypatch.setattr(Path, "lstat", unit_stat)

    def local(name):
        path = Path(name)
        if path.is_relative_to(tmp_path):
            return path
        return tmp_path / str(name).lstrip("/")

    def write(name, body, mode=0o644):
        path = local(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        path.chmod(mode)

    states = {"sli-postgresql.service": {"enabled": True, "active": True}}
    commands = []

    def command(argv, **kwargs):
        commands.append(argv)
        if argv[0] in {"usermod", "systemd-tmpfiles"}:
            return ""
        assert argv[0] == "systemctl", argv
        action = argv[1]
        if action == "list-unit-files":
            return "\n".join(name + (" enabled" if state["enabled"] else " disabled")
                             for name, state in states.items() if name in argv[2:])
        if action == "list-units":
            return "\n".join(name + " loaded active running SLI" for name, state in states.items()
                             if name in argv[2:] and state["active"])
        if action == "reset-failed":
            for name, state in states.items():
                if not argv[2:] or any(fnmatchcase(name, pattern) for pattern in argv[2:]):
                    state.pop("failed", None)
            return ""
        if action in {"disable", "stop"}:
            for name in argv[2:]:
                if name.startswith("--"):
                    continue
                state = states[name]
                if action == "disable":
                    state["enabled"] = False
                if action == "stop" or "--now" in argv:
                    state["active"] = False
            return ""
        if action in {"enable", "start"}:
            for name in argv[2:]:
                if name.startswith("--"):
                    continue
                state = states.setdefault(name, {"enabled": False, "active": False})
                if action == "enable":
                    state["enabled"] = True
                if action == "start" or "--now" in argv:
                    state["active"] = True
                if name == "sli-dotnet.target":
                    for service in runtime.selected(runtime.configuration()):
                        states[runtime.dotnet_unit_name(service)] = {"active": True, "enabled": False}
            return ""
        assert action == "daemon-reload", argv
        return ""

    machine = SimpleNamespace(
        receipt=lambda: None,
        directory=lambda name, *a, **kw: local(name).mkdir(parents=True, exist_ok=True),
        write=write,
    )
    monkeypatch.setattr(host, "Host", lambda: machine)
    monkeypatch.setattr(host, "administrative_lock", nullcontext)
    monkeypatch.setattr(host, "validate_identity", lambda: None)
    monkeypatch.setattr(host, "group", lambda name: SimpleNamespace(gr_mem=[], gr_gid=12345))
    monkeypatch.setattr(host, "pwd", SimpleNamespace(getpwall=lambda: []))
    monkeypatch.setattr(host, "account", lambda name: True)
    def run(argv, **kwargs):
        output = command(argv, **kwargs)
        no_match = argv[:2] == ["systemctl", "list-unit-files"] and not output
        return subprocess.CompletedProcess(argv, int(no_match), output, "")

    monkeypatch.setattr(host, "subprocess", SimpleNamespace(run=run))
    monkeypatch.setattr(runtime, "configure_worker_accounts", lambda: None)
    monkeypatch.setattr(runtime.clickhouse, "site_configuration", dict)
    monkeypatch.setattr(runtime, "stop_services", lambda *a, **kw: None)
    monkeypatch.setattr(runtime, "systemd", lambda *a, **kw: {"LoadState": "not-found"})
    # Redirect the fixed OS paths, keeping the retirement algorithm unchanged.
    retire = host.retire_clickhouse
    monkeypatch.setattr(host, "retire_clickhouse", lambda: retire(tmp_path))
    release_unit = runtime.release_rendered_unit

    def release_rendered_unit(path, body, *, saved_directory="units"):
        return release_unit(local(path), body, state=tmp_path / "state", recovery=tmp_path / "recovery",
                            saved_directory=saved_directory)

    monkeypatch.setattr(runtime, "release_rendered_unit", release_rendered_unit)
    monkeypatch.setattr(runtime, "trusted", lambda path: path.read_bytes())
    return SimpleNamespace(root=tmp_path, states=states, commands=commands, write=write, command=command,
                           machine=machine, guarded_write=guarded_write)


def test_beta_configuration_creates_dotnet_services_without_database_containers(runtime_host):
    system = runtime_host
    runtime.configure({"schema_version": 1, "profiles": ["light"], "radius_pilot": False,
                       "agents": True, "bind": "192.0.2.10", "https_port": 443,
                       "health_url": "https://192.0.2.10:443/api/health/ready"})
    destination = system.root / "generated"
    destination.mkdir()
    generator.generate(runtime, "beta", destination)
    units = {path.name: path.read_text() for path in destination.iterdir()}
    assert "sli-dotnet-api.service" in units
    assert "sli-dotnet-post-collection.service" in units
    assert "sli-dotnet-ad-snapshot-manifest-coordinator.service" in units
    assert "sli-dotnet-semantic.service" in units
    assert "sli-dotnet-notification-delivery.service" in units
    assert "sli-dotnet-executor-light.service" in units
    assert "sli-dotnet-storage-lifecycle.service" in units
    assert all("/opt/sli/dotnet/beta/Sli.Server" in body for name, body in units.items()
               if name.endswith(".service"))
    assert not any("clickhouse" in name or "docker" in name for name in units)
    assert not any("docker.service" in body or "sli-clickhouse-" in body for body in units.values())
    assert system.states["sli-postgresql.service"] == {"enabled": True, "active": True}


def test_runtime_upgrade_retires_both_clickhouse_services_and_preserves_all_data(runtime_host):
    system = runtime_host
    for name in ("sli-backup.service", "unrelated.service"):
        system.states[name] = {"enabled": False, "active": False, "failed": True}
    retained = {}
    for name in ("history", "warm"):
        unit = "sli-clickhouse-" + name + ".service"
        system.states[unit] = {"enabled": True, "active": True}
        system.write("/etc/systemd/system/" + unit, "[Service]\nExecStart=/synthetic-only\n")
        retained[f"srv/sli-db/clickhouse/{name}/data/part.bin"] = ("part-" + name).encode()
    retained.update({"srv/sli-db/pgdata/18/main/base/page": b"postgres-page",
                     "var/lib/sli/raw_files/packet": b"agent-packet",
                     "var/lib/sli/evidence/report": b"report-file"})
    for name, content in retained.items():
        path = system.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    config = {"schema_version": 1, "profiles": ["light"], "radius_pilot": False,
              "health_url": "https://192.0.2.10:443/api/health/ready"}
    for _ in range(2):
        runtime.configure(config)
        assert all((system.root / name).read_bytes() == content for name, content in retained.items())
        assert not system.states["sli-backup.service"].get("failed", False)
        assert system.states["unrelated.service"]["failed"]
        assert system.states["sli-postgresql.service"] == {"enabled": True, "active": True}
        for name in ("history", "warm"):
            unit = "sli-clickhouse-" + name + ".service"
            assert system.states[unit] == {"enabled": False, "active": False}
            assert not (system.root / "etc/systemd/system" / unit).exists()
    assert json.loads(runtime.CONFIG.read_text())["profiles"] == ["light"]


@pytest.mark.parametrize("foreign_edit", [False, True])
def test_notification_upgrade_accepts_retained_layout(runtime_host, monkeypatch, capsys, foreign_edit):
    system = runtime_host
    site_path = system.root / "etc/sli/site.toml"
    site_text = 'bind = "0.0.0.0"\nserver_name = "sli.example.test"\nhttps_port = 443\n'
    site = runtime.clickhouse.parse_site(site_text)
    system.write("/etc/sli/site.toml", site_text)
    config = install.runtime_settings(site)
    config.pop("public_url")  # The accepted release did not persist the notification origin.
    runtime_path = "/etc/sli/runtime.json"
    previous_body = json.dumps(config, sort_keys=True) + "\n"
    system.write(runtime_path, previous_body)
    previous_bytes = runtime.CONFIG.read_bytes()
    old_unit = runtime.dotnet_unit("beta1-f6f433e7ada0", config, "notification-setup")
    old_unit = "\n".join(line for line in old_unit.split("\n") if not line.startswith("ExecStartPre="))
    old_unit = old_unit.replace('Environment="SLI_PUBLIC_URL=' + runtime.clickhouse.public_url(config),
                                'Environment="SLI_PUBLIC_URL=' + config["health_url"].split("/api/")[0])
    unit_name = "sli-dotnet-notification-setup.service"
    system.write("/run/systemd/generator/" + unit_name, old_unit)
    for name, body in host.units().items():
        system.write("/etc/systemd/system/" + name, body)
    for name, body in runtime.units(config).items():
        system.write("/usr/lib/systemd/system/" + name, body)
    unrelated = "[Service]\nExecStart=/synthetic-routing\n"
    system.write("/etc/systemd/system/telegram-via-vpn.service", unrelated)
    foreign_path = "/usr/lib/systemd/system/sli-ready.service"
    foreign_body = "[Service]\nExecStart=/synthetic-operator-edit\n"
    if foreign_edit:
        system.write(foreign_path, foreign_body)

    # Exercise the real refusal for changed bytes, with service accounts and
    # file publication doubled by the private-host fixture.
    def checked_write(name, body, mode):
        if name == str(runtime.CONFIG):
            name = runtime_path
        path = system.root / name.lstrip("/")
        if path.exists() and path.read_text(encoding="utf-8") != body:
            system.guarded_write(name, body, mode)
        system.write(name, body, mode)

    monkeypatch.setattr(system.machine, "write", checked_write)
    monkeypatch.setattr(host, "ensure_directory", lambda path: None)
    monkeypatch.setattr(runtime.clickhouse, "site_configuration", lambda: site)
    original_exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda path: original_exists(site_path if path == Path("/etc/sli/site.toml")
                                                                     else path))
    monkeypatch.setattr(install, "site_configuration", lambda: site)
    monkeypatch.setattr(install, "trusted", lambda path: path.read_bytes())
    candidate = system.root / "beta1-3a6828ff4db8"
    source = candidate / "deploy/linux/native_runtime.py"
    source.parent.mkdir(parents=True)
    shutil.copyfile(runtime.__file__, source)

    def run_candidate(argv, **kwargs):
        if argv[0] != "/synthetic/python":
            system.command(argv, **kwargs)
            return subprocess.CompletedProcess(argv, 0, stderr=b"")
        output = StringIO()
        with monkeypatch.context() as child, redirect_stderr(output):
            child.setattr(sys, "argv", ["-c", *argv[5:]])
            child.setattr(sys, "path", sys.path.copy())
            try:
                exec(argv[4], {})
            except SystemExit as error:
                return subprocess.CompletedProcess(argv, error.code, stderr=output.getvalue().encode())
        return subprocess.CompletedProcess(argv, 0, stderr=b"")

    monkeypatch.setattr(install.subprocess, "run", run_candidate)
    monkeypatch.delenv(install.operations().PROGRESS_FD, raising=False)
    manifest = {"python": "/synthetic/python"}
    if foreign_edit:
        with pytest.raises(RuntimeError, match="native_install_command_failed"):
            upgrade.configure_candidate(candidate, manifest)
        journal = capsys.readouterr().err
        assert "native_existing_configuration_conflict: " + foreign_path in journal
        assert "synthetic-operator-edit" not in journal
        assert (system.root / foreign_path.lstrip("/")).read_text() == foreign_body
        return

    upgrade.configure_candidate(candidate, manifest)
    assert runtime.CONFIG.read_bytes() == previous_bytes
    assert (system.root / "etc/systemd/system/telegram-via-vpn.service").read_text() == unrelated
    destination = system.root / "generated-candidate"
    destination.mkdir()
    generator.generate(runtime, candidate.name, destination)
    unit = (destination / unit_name).read_text()
    assert 'Environment="SLI_PUBLIC_URL=https://sli.example.test"' in unit
    assert f"ExecStartPre=/opt/sli/dotnet/{candidate.name}/Sli.Server notification-setup --repair-public-urls" in unit
    volatile_units = system.root / "run/systemd/system"
    monkeypatch.setattr(upgrade, "VOLATILE_UNITS", volatile_units)
    monkeypatch.setattr(upgrade, "ensure_directory", lambda path: path.mkdir(parents=True, exist_ok=True))
    upgrade.testing_units("a" * 32)
    drop_in = volatile_units / (unit_name + ".d") / "90-sli-upgrade.conf"
    assert drop_in.read_text() == "[Service]\nEnvironment=SLI_NATIVE_UPGRADE_TESTING=1\n"
    upgrade.configure_candidate(candidate, manifest)
    upgrade.testing_units()
    assert not drop_in.exists()


@pytest.mark.parametrize("migration_failure", [False, True])
def test_apt_candidate_migrates_and_reconfigures_without_manual_steps(runtime_host, s5_release, postgres, monkeypatch,
                                                                   migration_failure):
    """The package's configure-package entry point owns migration and retirement."""
    system = runtime_host
    config = {"schema_version": 1, "profiles": ["light"], "radius_pilot": False,
              "bind": "192.0.2.10", "https_port": 443,
              "health_url": "https://192.0.2.10:443/api/health/ready"}
    system.write(str(runtime.CONFIG), json.dumps(config))
    retained = {}
    for name in ("history", "warm"):
        unit = "sli-clickhouse-" + name + ".service"
        system.states[unit] = {"enabled": True, "active": True}
        system.write("/etc/systemd/system/" + unit, "[Service]\nExecStart=/synthetic-only\n")
        path = system.root / f"srv/sli-db/clickhouse/{name}/data/part.bin"
        path.parent.mkdir(parents=True)
        path.write_bytes(("retained-" + name).encode())
        retained[path] = path.read_bytes()
    packet = system.root / "var/lib/sli/raw_files/packet"
    packet.parent.mkdir(parents=True)
    packet.write_bytes(b"original-agent-packet")
    state = system.root / "state"
    state.mkdir()
    (state / "package-install.json").write_text(json.dumps({"release": "old", "status": "configured"}))
    old = system.root / "old"
    old.mkdir()
    candidate = s5_release
    if migration_failure:
        third = candidate / "config/postgres_migrations/344_synthetic_readback.sql"
        third.write_text("begin;\n" + third.read_text() + "\nselect * from public.synthetic_missing_table;\ncommit;", newline="\n")
        (candidate / "deploy/linux/native_pg_ledger.json").write_text(json.dumps(native_pg_inventory.build_manifest(candidate)))
    ledger_query = "select json_agg(m order by version) from public.schema_migrations m;"
    previous_ledger = postgres(ledger_query).stdout
    shutil.copyfile(Path(runtime.__file__), candidate / "deploy/linux/native_runtime.py")
    for root, version in ((old, "1.0-1~deb13"), (candidate, "2.0-1~deb13")):
        (root / "native-package.json").write_text(json.dumps({"schema_version": 1, "release": root.name, "version": version}))
    manifest = {"python": "/synthetic/python", "python_sha256": "a" * 64, "postgres_version": "18.test",
                "roles": ["synthetic"], "plugins": {"synthetic": 1},
                "migration_ledger": native_pg_inventory.expected_ledger(candidate)}
    previous = {**manifest, "migration_ledger": [row for row in manifest["migration_ledger"] if row["version"] < 342]}
    recovery = system.root / "recovery"
    recovery.mkdir()
    (recovery / "units").mkdir()
    (recovery / "recovery.json").write_text("{}")
    transaction = system.root / "transactions" / ("a" * 32)
    checkpoint = transaction / "checkpoints/20261116T010000.000000Z"
    checkpoint.mkdir(parents=True)
    (checkpoint / "manifest.json").write_text('{"consistency_point":{"writers_fenced":true}}')
    monkeypatch.setattr(install, "trusted", lambda path: path.read_bytes())
    checkpoint_digest = upgrade.digest(checkpoint / "manifest.json")
    (checkpoint.parent / "integrity-verified.json").write_text(json.dumps({
        "backup_id": checkpoint.name, "manifest_sha256": checkpoint_digest, "terminal": True,
        "status": "integrity_verified", "checkpoint_verification": "integrity",
    }))
    (transaction / "journal.json").write_text(json.dumps({
        "schema_version": 1, "transaction": transaction.name, "status": "checkpoint_verified", "step": "after",
        "previous": old.name, "candidate": candidate.name, "target_version": "2.0-1~deb13",
        "created_at_utc": "2026-11-16T01:00:00+00:00", "checkpoint_verification": "integrity",
        "checkpoint": checkpoint.name, "checkpoint_sha256": checkpoint_digest,
        "recovery_sha256": upgrade.digest(recovery / "recovery.json"),
    }))
    monkeypatch.setattr(upgrade, "TRANSACTIONS", transaction.parent)
    monkeypatch.setattr(upgrade, "UNITS", system.root / "usr/lib/systemd/system")
    monkeypatch.setattr(upgrade, "RUNTIME_HELPER", system.root / "usr/lib/sli/native_runtime.py")
    monkeypatch.setattr(native, "DATA", system.root / "var/lib/sli")
    monkeypatch.setattr(native, "CONFIG", system.root / "etc/sli")
    monkeypatch.setattr(native, "STATE", state)
    monkeypatch.setattr(install, "STATE", state)
    monkeypatch.setattr(install, "RELEASES", system.root)
    monkeypatch.setattr(upgrade, "systemd_available", lambda: False)
    monkeypatch.setattr(upgrade, "operation_lock", lambda root: nullcontext())
    monkeypatch.setattr(install, "setup_deadline", nullcontext)
    monkeypatch.setattr(install, "ensure_directory", lambda path, *a, **kw: path.mkdir(parents=True, exist_ok=True))
    if os.name == "nt":
        monkeypatch.setattr(install, "atomic", atomic_json)
    monkeypatch.setattr(install, "inventory", lambda name: (old, previous, "old-digest") if name == old.name
                        else (candidate, manifest, "candidate-digest"))
    monkeypatch.setattr(upgrade, "verify_recovery", lambda name: (recovery, {}))
    current = [old]
    restored = []

    def switch(root, inventory, digest, previous_receipt_path=None):
        if migration_failure:
            assert root == old and restored, "Only the checkpoint's previous release may start after SQL failure"
            assert previous_receipt_path == recovery / "installed.json"
        else:
            assert previous_receipt_path is None
        current[0] = root
        install.atomic(state / "installed.json", {**inventory, "release": str(root), "manifest_sha256": digest})

    monkeypatch.setattr(upgrade, "switch", switch)  # OS symlink replacement is covered by POSIX tests.
    monkeypatch.setattr(upgrade, "fence", lambda: None)
    monkeypatch.setattr(upgrade, "testing_units", lambda *a: None)
    monkeypatch.setattr(install, "preserve_recovery", lambda *a: None)
    monkeypatch.setattr(install, "site_configuration", dict)
    health_checks = []
    monkeypatch.setattr(install, "wait_api", lambda config: health_checks.append(current[0]))
    monkeypatch.setattr(install, "wait_health", lambda: None)
    monkeypatch.setattr(runtime, "systemd", lambda service, **kw: {"LoadState": "not-found"} if kw.get("dotnet") is False
                        else {"ActiveState": "active" if system.states.get(runtime.dotnet_unit_name(service), {}).get("active")
                              else "inactive", "MainPID": "42"})
    run = upgrade.subprocess.run
    monkeypatch.setattr(upgrade.subprocess, "run", lambda argv, **kw: SimpleNamespace(returncode=1)
                        if argv[:2] == ["systemctl", "is-failed"] else run(argv, **kw))
    migrations = []

    def run_sql(body):
        migrations.append(True)
        result = postgres(body)
        if migration_failure:
            assert result.returncode != 0 and "synthetic_missing_table" in result.stderr
            raise RuntimeError("native_pg_migration_failed")
        assert result.returncode == 0, result.stderr

    monkeypatch.setattr(native_pg_migrate, "run_sql", run_sql)

    def command(argv, **kwargs):
        if argv[0] == manifest["python"]:
            assert argv[1:4] == ["-I", "-B", "-c"] and argv[-2] == str(candidate)
            runtime.configure(json.loads(argv[-1]))
            return ""
        return system.command(argv, **kwargs)

    monkeypatch.setattr(install, "command", command)
    if migration_failure:
        def restore_checkpoint(journal):
            # No migration, object or data change may survive even before the
            # coordinator's conservative checkpoint recovery runs.
            assert postgres(ledger_query).stdout == previous_ledger
            assert postgres("select step,body from public.upgrade_probe;").stdout.strip() == "340|preserve-customer-data"
            assert postgres("select to_regprocedure('expire_short_storage_partitions342(timestamptz,timestamptz,timestamptz)');").stdout.strip() == ""
            restored.append(journal.value["previous"])

        monkeypatch.setattr(upgrade, "restore_checkpoint", restore_checkpoint)
        monkeypatch.setattr(upgrade, "restore_helpers", lambda *a: None)
        monkeypatch.setattr(upgrade, "restore_agents_unit", lambda *a: None)
        monkeypatch.setattr(upgrade, "configure_candidate", lambda *a: pytest.fail("new binaries must not be configured"))
        monkeypatch.setattr(upgrade, "start_checked", lambda: health_checks.append(current[0]))
        with pytest.raises(RuntimeError, match="^native_pg_migration_failed$"):
            upgrade.configure_package(candidate.name, "2.0-1~deb13")
        journal = upgrade.Journal(transaction).value
        assert journal["status"] == "rolled_back" and journal["services_restored"] is True
        assert journal["failure_reason_code"] == "native_pg_migration_failed"
        assert postgres(ledger_query).stdout == previous_ledger
        assert restored == [old.name] and migrations == [True]
        assert health_checks and all(root == old for root in health_checks)
        assert json.loads((state / "package-install.json").read_text())["release"] == old.name
        before = list(health_checks)
        with pytest.raises(RuntimeError, match="reconciliation_required"):
            upgrade.configure_package(candidate.name, "2.0-1~deb13")
        assert health_checks == before
        return
    for _ in range(2):
        upgrade.configure_package(candidate.name, "2.0-1~deb13")
        journal = upgrade.Journal(transaction).value
        assert journal["status"] == "committed" and journal["services_restored"] is True
        assert current[0] == candidate
        assert json.loads((state / "package-install.json").read_text())["release"] == candidate.name
        assert packet.read_bytes() == b"original-agent-packet"
        assert all(path.read_bytes() == content for path, content in retained.items())
        assert all(system.states[f"sli-clickhouse-{name}.service"] == {"enabled": False, "active": False}
                   for name in ("history", "warm"))
        assert postgres("select body from public.upgrade_probe where step=340;").stdout.strip() == "preserve-customer-data"
    assert migrations == [True]
    assert health_checks and all(root == candidate for root in health_checks)
    actual = postgres("select json_agg(m order by version) from public.schema_migrations m;").stdout.strip()
    assert json.loads(actual) == manifest["migration_ledger"]


@pytest.mark.parametrize("tampered", [False, True])
def test_s5_restore(tmp_path, monkeypatch, tampered):
    """Use native_backup's actual manifest/hash reader and the actual file restore.

    Database tools and POSIX snapshot/ownership calls are OS doubles. No daemon,
    host credential or installed directory is opened by this test.
    """
    data = tmp_path / "d"
    state = data / "state"
    config = tmp_path / "etc/sli"
    pg_config = tmp_path / "etc/postgresql/18/sli"
    transaction = data / "transactions" / ("a" * 32)
    for path in (state, config / "secrets", pg_config, transaction):
        path.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(install, "trusted", lambda path: path.read_bytes())
    checkpoint = recovery_set(transaction / "checkpoints", "20261116T010000.000000Z", legacy_clickhouse=False)
    manifest = json.loads((checkpoint / "manifest.json").read_text())
    manifest["consistency_point"] = {"writers_fenced": True}
    (checkpoint / "companion/secrets").mkdir()
    (checkpoint / "companion/postgresql").mkdir()
    # The only secret in this private tree is a generated test credential.
    credential = secrets.token_urlsafe(32)
    for path in (config / "secrets/runtime_password", checkpoint / "companion/secrets/runtime_password"):
        path.write_text(credential)
    manifest["content_checksums"] = backup.content_inventory(checkpoint)
    (checkpoint / "manifest.json").write_text(json.dumps(manifest))
    (transaction / "file-metadata.json").write_text("{}")
    (transaction / "checkpoints/integrity-verified.json").write_text(json.dumps({
        "backup_id": checkpoint.name, "manifest_sha256": upgrade.digest(checkpoint / "manifest.json"),
        "terminal": True, "status": "integrity_verified", "checkpoint_verification": "integrity",
    }))
    (transaction / "journal.json").write_text(json.dumps({
        "schema_version": 1, "transaction": transaction.name, "status": "recovering", "step": "before",
        "checkpoint": checkpoint.name, "checkpoint_verification": "integrity",
        "checkpoint_sha256": upgrade.digest(checkpoint / "manifest.json"),
        "file_metadata_sha256": upgrade.digest(transaction / "file-metadata.json"),
    }))
    (state / "installed.json").write_text("candidate-state")
    (data / "evidence").mkdir()
    (data / "evidence/item").write_bytes(b"candidate-file")
    (data / "candidate-only").write_bytes(b"candidate-only")
    pg_page = tmp_path / "srv/sli-db/pgdata/18/main/page"
    pg_page.parent.mkdir(parents=True)
    pg_page.write_bytes(b"candidate-database")
    retained = {}
    for name in ("history", "warm"):
        path = tmp_path / f"srv/sli-db/clickhouse/{name}/data/part.bin"
        path.parent.mkdir(parents=True)
        path.write_bytes(("retained-" + name).encode())
        retained[path] = path.read_bytes()
    for name, value in {"DATA": data, "STATE": state, "CONFIG": config}.items():
        monkeypatch.setattr(native, name, value)
    monkeypatch.setattr(upgrade, "POSTGRES_CONFIG", pg_config)
    monkeypatch.setattr(install, "ensure_directory", lambda path, *a, **kw: path.mkdir(parents=True, exist_ok=True))
    if os.name == "nt":
        # Windows has no directory fsync; keep real atomic file replacement.
        monkeypatch.setattr(install, "atomic", atomic_json)
        monkeypatch.setattr(upgrade, "sync_tree", lambda path: None)
    monkeypatch.setattr(upgrade, "fence", lambda: None)
    monkeypatch.setattr(upgrade, "wait_restore_databases", lambda: None)
    commands = []
    monkeypatch.setattr(install, "command", lambda argv, **kw: commands.append(argv))

    @contextmanager
    def snapshot(root, identifier, **kwargs):
        # Emulate descriptor-based POSIX snapshotting on a private tree only.
        private = tmp_path / "private-snapshot"
        shutil.copytree(root / identifier, private)
        try:
            yield private, None
        finally:
            shutil.rmtree(private)

    monkeypatch.setattr(update_checkpoint, "snapshot", snapshot)

    def restore_database(source, private, observed, components, *, replace_existing):
        assert components == ("postgres",) and replace_existing is True
        assert set(observed["components"]) == {"postgres", "files"}
        pg_page.write_bytes((source / "postgres/toc.dat").read_bytes())

    monkeypatch.setattr(restore_existing, "restore_components", restore_database)
    journal = upgrade.Journal(transaction)
    if tampered:
        (checkpoint / "data" / checkpoint.name / "postgres/toc.dat").write_bytes(b"tampered")
        with pytest.raises(RuntimeError, match="native_backup_hash_mismatch"):
            upgrade.restore_checkpoint(journal)
        assert pg_page.read_bytes() == b"candidate-database"
        assert (data / "evidence/item").read_bytes() == b"candidate-file"
        assert not journal.value.get("checkpoint_restored")
        assert not commands
    else:
        upgrade.restore_checkpoint(journal)
        assert pg_page.read_bytes() == b"synthetic"
        assert (data / "evidence/item").read_bytes() == b"synthetic"
        assert not (data / "candidate-only").exists()
        assert json.loads((state / "installed.json").read_text()) == {"migration_ledger": []}
        assert (config / "secrets/runtime_password").read_text() == credential
        assert journal.value["checkpoint_restored"] is True
        assert ["systemctl", "start", "sli-postgresql.service"] in commands
        assert not any("clickhouse" in str(command) for command in commands)
    assert all(path.read_bytes() == content for path, content in retained.items())
    assert (transaction / "journal.json").exists()


def test_s5_restore_real_postgres_before_payload_retention(tmp_path, monkeypatch, postgres):
    """A pre-351 directory backup recovers real rows, roles and partition data.

    Both clusters are private. Only Windows substitutes POSIX process priority,
    flock, statvfs and directory-descriptor copying; all PostgreSQL tools, SQL,
    backup publication, hash validation and component restore run unchanged.
    """
    root = Path(__file__).resolve().parents[2]
    tools = postgres.tools
    monkeypatch.setenv("PATH", str(tools) + os.pathsep + os.environ.get("PATH", ""))
    # Use the shared directory-backup engine without native host provisioning
    # or ClickHouse. It is also the engine used by native_backup.capture_locked.
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "docker")
    monkeypatch.setattr(backup, "clickhouse_targets", lambda: ())
    backups = tmp_path / "backups"
    backups.mkdir()
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(backups))
    monkeypatch.setenv("SLI_PG_HOST", "127.0.0.1")
    monkeypatch.setenv("SLI_PG_PORT", str(postgres.port))
    monkeypatch.setenv("SLI_PG_ADMIN_USER", "postgres")
    for key in ("SLI_PG_ADMIN_PASSWORD", "SLI_PG_ADMIN_PASSFILE", "PGPASSWORD", "PGPASSFILE", "PGSERVICE"):
        monkeypatch.delenv(key, raising=False)
    password = tmp_path / "generated-password"
    password.write_text(secrets.token_urlsafe(32), encoding="utf-8")
    monkeypatch.setenv("SLI_PG_ADMIN_PASSWORD_FILE", str(password))

    if os.name == "nt":
        launch = subprocess.Popen

        def windows_process(argv, **kwargs):
            if argv[:8] == ["ionice", "-c", "2", "-n", "7", "nice", "-n", "10"]:
                argv = argv[8:]
            if "env" in kwargs:
                kwargs["env"] = {**kwargs["env"], "SystemRoot": os.environ["SystemRoot"]}
            return launch(argv, **kwargs)

        @contextmanager
        def windows_snapshot(directory, identifier, **kwargs):
            private = tmp_path / "snapshot"
            shutil.copytree(directory / identifier, private)
            try:
                yield private, backup.content_inventory(private)
            finally:
                shutil.rmtree(private)

        monkeypatch.setattr(subprocess, "Popen", windows_process)
        monkeypatch.setattr(backup, "backup_lock", lambda *a, **kw: nullcontext())
        monkeypatch.setattr(backup.backup_policy, "filesystem",
                            lambda path: backup.backup_policy.existing_parent(path).stat().st_dev)
        monkeypatch.setattr(update_checkpoint, "snapshot", windows_snapshot)

    def source(body):
        return postgres("\\connect sli\n" + body)

    def execute(query, body):
        result = query(body)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    execute(postgres, "create role adlog_user login; create role sli_migration login; "
            "create database sli owner sli_migration;")
    migrations = tuple(item for item in bootstrap.forward_migration_inventory(root / "config/postgres_migrations")
                       if item.version <= 349)
    baseline = bootstrap.load_baseline(root / "config/postgres_baseline", migrations)
    rendered = bootstrap.render_baseline_schema(baseline, "example.test", tmp_path / "baseline.sql")
    execute(source, baseline.roles_path.read_text(encoding="utf-8"))
    execute(source, rendered.read_text(encoding="utf-8"))
    execute(source, "insert into auth_users(username,password_hash,role) "
            "values('platform-owner','synthetic-unusable-hash','admin');")
    for item in migrations:
        if item.version > baseline.version:
            execute(source, item.path.read_text(encoding="utf-8"))
    assert execute(source, "select max(version) from schema_migrations;") == "349"
    execute(source, """
        insert into sli_agents(id,host_id,key_fingerprint,status)
            values('10000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000002',repeat('a',64),'active');
        insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
            select '10000000-0000-4000-8000-000000000001','sli.windows.ad-dc',n,
                ('00000000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,repeat('a',64),
                '{"agent_id":"10000000-0000-4000-8000-000000000001","module_id":"sli.windows.ad-dc",
                  "source_instance_id":"synthetic","generation":"1","policy_revision":"1"}',
                '{"status":"committed"}','2026-11-01T01:02:03Z' from generate_series(1,2) n;
        insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at,imported_at)
            select packet_id,envelope,
                '{"contract":"sli.collection-packet.v1","header":{"channel":"Security"},
                  "context":{"ad_dc":{"read_error":"synthetic"}}}',
                '[{"record_id":17,"event_id":4625,"computer":"dc.example.test","message":"Тест восстановления"}]',
                received_at,case when sequence=1 then received_at end from sli_agent_receipts;
        select public.create_event_storage_partitions('2026-11-01','2026-11-01');
        insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
            select n,'2026-11-01T01:02:03Z',4625,(select id from domains where fqdn='example.test'),
                'synthetic-user','synthetic-target','192.0.2.17','dc.example.test',
                '{"$channel":"Security","$provider":"synthetic","$principals":{"SubjectUserName":"synthetic-user"}}',
                '{"status":"failure"}','{"reason":"synthetic"}' from generate_series(1001,1002) n;
        insert into findings(fingerprint,rule_code,title,severity)
            values('synthetic-restore','synthetic_restore','Синтетическая проблема','medium');
        insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,
            actor,target,source,computer,method,outcome,fields,source_sha256,evidence_role,note,event_record_id)
            select f.id,h.event_id,h.time_created_utc,h.event_kind,h.domain_id,h.actor,h.target,h.source,
                h.computer,h.method,h.outcome,h.fields,sha256('synthetic-event'::bytea),'primary','synthetic',17
            from findings f cross join event_hot h where f.fingerprint='synthetic-restore' and h.event_id=1001;
        """)
    tables = ("sli_agent_packet_inbox", "sli_agent_receipts", "sli_agent_stream_receipts", "findings",
              "finding_event_copies337", "finding_event_details337", "event_hot", "schema_migrations")

    def rows(query):
        return {table: json.loads(execute(query, f"select jsonb_agg(doc order by doc::text) from "
                                         f"(select to_jsonb(t) doc from public.{table} t) records;"))
                for table in tables}

    before = rows(source)
    assert all(before.values()), "every recovery selection must contain actual rows"
    with backup.backup_lock(backups):
        checkpoint = backup.capture_backup(backups, 7, ("postgres",), writers_fenced=True)
    manifest = json.loads((checkpoint / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["migration_ledger_max_version"] == 349
    assert manifest["content_checksums"] == backup.content_inventory(checkpoint)

    execute(source, (root / "config/postgres_migrations/351_inbox_payload_retention.sql").read_text(encoding="utf-8"))
    execute(source, "set role adlog_storage_lifecycle_delete; update sli_agent_packet_inbox "
            "set packet=null,event_rows=null where imported_at is not null; reset role;")
    assert execute(source, "select count(*) from sli_agent_packet_inbox where packet is null and event_rows is null;") == "1"
    rollback = source((root / "config/postgres_migrations/351_inbox_payload_retention.rollback.sql").read_text(encoding="utf-8"))
    assert rollback.returncode != 0 and "inbox_payload_retention351_rollback_payloads_expired" in rollback.stderr

    with private_postgres(tmp_path / "restored") as restored:
        execute(restored, "create database sli;")
        monkeypatch.setenv("SLI_PG_PORT", str(restored.port))

        def destination(body):
            return restored("\\connect sli\n" + body)

        assert restore_existing.main([str(checkpoint), "--component", "postgres"]) == 0
        assert rows(destination) == before
        assert execute(destination, "select relowner::regrole from pg_class where oid='public.event_hot'::regclass;") == "adlog_storage_owner"
        assert execute(destination, "select has_table_privilege('adlog_user','public.finding_event_copies337','SELECT');") == "t"
        # Replacement is destructive: a corrupt set must fail before touching
        # even a row written after a successful restore, without a DB double.
        execute(destination, "insert into findings(fingerprint,rule_code,title,severity) "
                "values('after-restore','synthetic_restore','После восстановления','low');")
        untampered = rows(destination)
        toc = checkpoint / "postgres/toc.dat"
        toc.write_bytes(toc.read_bytes() + b"tampered")
        with pytest.raises(ValueError, match="^linux_restore_invalid_manifest$"):
            restore_existing.restore_backup(checkpoint, ("postgres",), replace_existing=True)
        assert rows(destination) == untampered
    # Source and destination were different clusters; recovery did not repair
    # the source in place or silently migrate the recovered schema to 351.
    assert execute(source, "select max(version) from schema_migrations;") == "351"
    assert execute(source, "select count(*) from sli_agent_packet_inbox where packet is null;") == "1"
