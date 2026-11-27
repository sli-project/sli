"""EXTCH integration contracts on fakes, including Windows/CPython 3.10.

No real Docker, systemd, PostgreSQL, package build or network is contacted.
Linux ownership/mount/cgroup acceptance remains a Debian CI/VM gate.
"""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import io
import json
import os
import re
import socket
import sys
from pathlib import Path, PurePosixPath
import tarfile
from types import SimpleNamespace
import xml.etree.ElementTree as ET
import zipfile

import pytest

from deploy.linux import backup, native_backup, native_clickhouse_transition
from deploy.linux import native_clickhouse_endpoint as ch
from deploy.linux import native_host as host, native_install, native_package, native_runtime, native_upgrade


@pytest.mark.parametrize('data_gib,accepted', [(100, True), (0, False)])
def test_native_capture_admission_requires_capture_space_and_live_reserve(tmp_path, monkeypatch, data_gib, accepted):
    from deploy.linux import backup_policy as policy

    root, data = tmp_path / 'backups', tmp_path / 'data'
    root.mkdir()
    data.mkdir()
    estimate = policy.space_estimate(10 * policy.GIB, backup_bytes=5 * policy.GIB)
    point = {'database_size_bytes': 10 * policy.GIB}
    connection = SimpleNamespace(execute=lambda sql: SimpleNamespace(fetchone=lambda: [point]))
    monkeypatch.setattr(backup, 'native_mode', lambda: True)
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(Path('/unused')))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a: nullcontext(connection))
    monkeypatch.setattr(backup, 'pg_capacity_paths', lambda value: {'data': str(data)})
    monkeypatch.setattr(host.Host, 'backup_space_estimate', lambda self, path, **kwargs: estimate)
    monkeypatch.setattr(native_backup, 'ROOT', root)
    monkeypatch.setattr(native_backup, 'capture_volume_admission', policy.volume_admission)
    monkeypatch.setattr(policy, 'filesystem', lambda path: 'ssd' if Path(path) == data else 'hdd')
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda path: SimpleNamespace(
        free=(data_gib if Path(path) == data else 7) * policy.GIB))
    if accepted:
        backup.capture_admission(root)
    else:
        with pytest.raises(backup.BackupError, match='insufficient_data_disk_space'):
            backup.capture_admission(root)
    assert not list(root.iterdir()) and not list(data.iterdir())


@pytest.mark.parametrize("selected", ["native", "docker"])
def test_host_configure_uses_postgres_without_retired_provider(tmp_path, monkeypatch, selected):
    calls, files = [], {}
    monkeypatch.setattr(ch, "configured_mode", lambda root=Path("/"): selected)
    monkeypatch.setattr(host, "validate_identity", lambda: None)
    monkeypatch.setattr(host, "check_ports", lambda: None)
    monkeypatch.setattr(host, "check_docker", lambda root=Path("/"): calls.append("docker-admission"))
    def run(argv, **kwargs):
        calls.append(argv)
        if argv[0].endswith("postgres"): return "postgres (PostgreSQL) 18.6"
        if argv[-1] == "--version": return "ClickHouse server version " + ch.endpoint("history", selected).version
        if argv[0] == "pg_lsclusters": return "18 sli 5432 down postgres /srv/sli-db/pgdata/18/main log"
        return ""
    monkeypatch.setattr(host, "run", run)
    machine = host.Host(tmp_path)
    monkeypatch.setattr(machine, "receipt", lambda: {"clickhouse_mode": selected})
    monkeypatch.setattr(machine, "passwords", lambda: None)
    monkeypatch.setattr(machine, "directory", lambda *a, **k: None)
    monkeypatch.setattr(machine, "write", lambda path, body, *a, **k: files.update({path: body}))
    path = tmp_path / "etc/postgresql/18/sli/postgresql.conf"
    path.parent.mkdir(parents=True)
    path.write_text("# existing synthetic cluster\n")
    machine.configure()
    assert ch.endpoint("history", selected).version_command() not in calls
    assert "docker-admission" not in calls
    for unit, body in host.units(selected).items():
        assert files["/etc/systemd/system/" + unit] == body
    assert not any(isinstance(c, list) and ("start" in c or "enable" in c) for c in calls)


@pytest.mark.parametrize("selected", ["native", "docker"])
def test_ready_checks_postgres_pin_without_retired_provider(tmp_path, monkeypatch, selected):
    from deploy.linux import installed_state
    manifest = {"schema_version": 1, "postgres_version": "18.6",
                "clickhouse_version": ch.endpoint("history", selected).version,
                "migration_ledger": [{"version": 1}], "roles": [["test"]], "plugins": {"test": {}}}
    installed = manifest | {"release": str(tmp_path), "manifest_sha256": "accepted"}
    monkeypatch.setattr(ch, "configured_mode", lambda root=Path("/"): selected)
    monkeypatch.setattr(host, "administrative_lock", nullcontext)
    monkeypatch.setattr(host.Host, "receipt", lambda self: None)
    monkeypatch.setattr(host, "validate_identity", lambda: None)
    monkeypatch.setattr(native_runtime, "no_transaction", lambda: None)
    monkeypatch.setattr(native_runtime, "release", lambda: (tmp_path, manifest, "accepted"))
    monkeypatch.setattr(native_runtime, "document", lambda path: installed)
    monkeypatch.setattr(installed_state, "native_ledger_matches", lambda *a: None)
    from deploy.linux import native_pg_inventory
    monkeypatch.setattr(native_pg_inventory, "verify_ledger", lambda *a, **k: None)
    versions = ["18.6"]
    monkeypatch.setattr(native_runtime, "observe_when_available", lambda *a: (versions[0], [], [{"version": 1}]))
    assert native_runtime.ready()
    versions[0] = "different"
    with pytest.raises(native_runtime.RuntimeErrorCode, match="version_mismatch"):
        native_runtime.ready()


def test_upgrade_ignores_retired_provider_and_keeps_postgres_identity():
    previous = dict(python="p", python_sha256="a", postgres_version="18.6", clickhouse_version="25.8.33.6",
                    migration_ledger=[1], roles=[1], plugins={"test": 1}, clickhouse_mode="docker")
    native_upgrade.compatible(previous, dict(previous))
    native_upgrade.compatible(previous, previous | {"clickhouse_mode": "native"})
    with pytest.raises(RuntimeError, match="incompatible_inventory"):
        native_upgrade.compatible(previous, previous | {"postgres_version": "different"})
    assert native_runtime.DATABASES == ("sli-postgresql.service",)


@pytest.mark.parametrize("selected", ["native", "docker"])
@pytest.mark.parametrize("allowed", [False, True])
def test_fresh_lifecycle_waits_for_postgres_before_migration_and_readiness(tmp_path, monkeypatch, selected, allowed):
    state = tmp_path / "state"
    state.mkdir()
    release = tmp_path / "release"
    release.mkdir()
    calls = []
    manifest = {"schema_version": 1, "python": "/fake/python", "postgres_version": "18.6",
                "clickhouse_version": ch.endpoint("history", selected).version}
    monkeypatch.setattr(ch, "configured_mode", lambda root=Path("/"): selected)
    monkeypatch.setattr(native_install, "STATE", state)
    monkeypatch.setattr(native_install, "CURRENT", tmp_path / "unselected")
    monkeypatch.setattr(native_install, "SITE", tmp_path / "absent-site.toml")
    expected_site = {"domain_fqdn": "example.invalid", "bind": "127.0.0.1"}
    if allowed:
        native_install.SITE.write_text('docker_allowed_containers = ["amnezia-gateway-client"]\n')
        monkeypatch.setattr(native_install, "trusted", lambda path: path.read_bytes())
        expected_site["docker_allowed_containers"] = ["amnezia-gateway-client"]
    monkeypatch.setattr(native_install, "inventory", lambda name: (release, manifest, "digest"))
    monkeypatch.setattr(native_install.platform, "freedesktop_os_release", lambda: {"ID": "debian", "VERSION_ID": "13"}, raising=False)
    monkeypatch.setattr(native_install.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(native_install, "atomic", lambda path, value: path.write_text(json.dumps(value)))
    monkeypatch.setattr(native_install, "command", lambda argv, **kw: calls.append(argv))
    monkeypatch.setattr(native_install, "select", lambda root: calls.append("select"))
    monkeypatch.setattr(native_install, "wait_api", lambda config: calls.append("api-ready"))
    monkeypatch.setattr(native_install, "wait_health", lambda: calls.append("healthy"))
    monkeypatch.setattr(native_install, "preserve_recovery", lambda *a: calls.append("recovery"))
    monkeypatch.setattr(host, "Host", lambda: SimpleNamespace(receipt=lambda: None, configure=lambda: calls.append("host"),
                                                             postgres_system_identifier=lambda: '123456789'))
    monkeypatch.setattr(host, "administrative_lock", nullcontext)
    monkeypatch.setattr(host, "validate_identity", lambda: None)
    monkeypatch.setattr(host, "MOUNT", str(tmp_path / "empty-data"))
    monkeypatch.setattr(native_runtime, "no_transaction", lambda: None)
    monkeypatch.setattr(native_runtime, "wait_databases", lambda: calls.append("engines-ready"))
    monkeypatch.setattr(native_runtime, "configure", lambda config: None)
    monkeypatch.setattr(native_runtime, "configuration", lambda: {})
    monkeypatch.setattr(native_runtime, "selected", lambda config: ["api"])
    monkeypatch.setattr(native_runtime, "systemd", lambda name: {"ActiveState": "active", "MainPID": "42"})
    monkeypatch.setattr(native_backup, "configure", lambda: None)
    native_install.configure("test")
    receipt = json.loads((state / "package-install.json").read_text())
    assert receipt["site_sha256"] == hashlib.sha256(json.dumps(expected_site, sort_keys=True).encode()).hexdigest()
    migrate = next(c for c in calls if isinstance(c, list) and "migrate" in c)
    assert calls.index("engines-ready") < calls.index(migrate)
    assert calls.index(migrate) < calls.index(["systemctl", "start", "sli-ready.service"])
    assert calls.index("healthy") < calls.index(["systemctl", "enable", "sli.target"])


@pytest.fixture
def mode(monkeypatch):
    monkeypatch.setattr(ch, "configured_mode", lambda root=Path("/"): "docker")


def test_mode_is_persisted_and_explicit_switch_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(ch, "trusted_text", lambda path: path.read_text())
    cpu = tmp_path / "proc/cpuinfo"
    cpu.parent.mkdir()
    cpu.write_text("flags : sse avx\n")
    assert ch.configured_mode(tmp_path) == "docker"
    receipt = tmp_path / "var/lib/sli/state/host-prepared.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_text(json.dumps({"clickhouse_mode": "docker"}))
    cpu.write_text("flags : avx2\n")
    assert ch.configured_mode(tmp_path) == "docker"
    site = tmp_path / "etc/sli/site.toml"
    site.parent.mkdir(parents=True)
    site.write_text('clickhouse_mode = "native"\n')
    with pytest.raises(ValueError, match="mode_change_requires_migration"):
        ch.configured_mode(tmp_path)


@pytest.mark.parametrize("selected", ["native", "docker"])
def test_host_units_exclude_retired_provider_but_legacy_configs_keep_endpoints(selected):
    units = host.units(selected)
    for name in ch.INSTANCES:
        endpoint = ch.endpoint(name, selected)
        assert endpoint.unit not in units
        config = ET.fromstring(host.ch_config(name, selected))
        assert config.findtext("http_port") == str(endpoint.http)
        assert config.findtext("tcp_port") == str(endpoint.tcp)
        assert config.findtext("storage_configuration/disks/backups/path") == endpoint.backup_server + "/"


@pytest.mark.parametrize("selected", ["native", "docker"])
def test_credential_renderer_does_not_read_root_only_mode_state(tmp_path, monkeypatch, selected):
    value = "synthetic-only"
    monkeypatch.setattr(host, "credential", lambda name: value)
    monkeypatch.setattr(ch, "configured_mode", lambda *a: pytest.fail("unprivileged renderer must not read private receipt"))
    monkeypatch.setattr(host, "Path", lambda path: tmp_path / "users.xml")
    monkeypatch.setattr(host.os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), raising=False)
    monkeypatch.setattr(host.os, "chown", lambda *a: None, raising=False)
    monkeypatch.setattr(host, "pwd", SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=123, pw_gid=456)))
    host.render_ch("history", selected)
    body = (tmp_path / "users.xml").read_text()
    assert value not in body
    assert ET.fromstring(body).findtext("users/sli_history/password_sha256_hex") == hashlib.sha256(value.encode()).hexdigest()
    assert "sli-clickhouse-history.service" not in host.units(selected)


def test_all_application_and_probe_units_hide_the_docker_socket():
    config = {"profiles": ["light"], "radius_pilot": False, "bind": "127.0.0.1",
              "health_url": "https://127.0.0.1:8443/api/health/ready"}
    units = {**native_runtime.units(config), **native_runtime.dotnet_units("test", config)}
    for name in [*(native_runtime.dotnet_unit_name(n) for n in native_runtime.selected(config)),
                 "sli-ready.service", "sli-health.service"]:
        assert ch.SOCKET_SANDBOX in units[name]
        assert "SupplementaryGroups=docker" not in units[name]


def managed_container(name="history"):
    return {"Name": "/sli-clickhouse-" + name, "Image": ch.endpoint(name, "docker").image_id,
            "State": {"Running": True}, "Mounts": [],
            "Config": {"User": "123:456", "Labels": {"org.sli.clickhouse.instance": name}},
            "HostConfig": {"NetworkMode": "bridge", "RestartPolicy": {"Name": "no"},
                           "ReadonlyRootfs": True, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
                           "PortBindings": {"8123/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8123"}]}}}


@pytest.mark.parametrize("violation", [None, "name", "compose", "image", "host_network", "public_port", "socket", "root"])
@pytest.mark.parametrize("allowed", [[], ["amnezia-gateway-client"]])
def test_only_two_managed_pinned_containers_are_allowed(violation, allowed):
    rows = [managed_container(), managed_container("warm")]
    row = rows[0]
    if violation == "name": row["Name"] = "/postgres"
    if violation == "compose": row["Config"]["Labels"]["com.docker.compose.project"] = "other"
    if violation == "image": row["Image"] = "sha256:" + "0" * 64
    if violation == "host_network": row["HostConfig"]["NetworkMode"] = "host"
    if violation == "public_port": row["HostConfig"]["PortBindings"]["8123/tcp"][0]["HostIp"] = "0.0.0.0"
    if violation == "socket": row["Mounts"] = [{"Destination": "/run/docker.sock"}]
    if violation == "root": row["Config"]["User"] = "0:0"
    def run(argv):
        return "a\nb\n" if "ls" in argv else json.dumps(rows)
    if violation:
        with pytest.raises(ValueError, match="foreign_container"):
            ch.check_containers(run, allowed_containers=allowed)
    else:
        ch.check_containers(run, allowed_containers=allowed)


def test_stopped_unit_cannot_hide_a_live_container():
    def run(argv):
        return "sli-clickhouse-history\n" if "ls" in argv else json.dumps([managed_container()])
    with pytest.raises(ValueError, match="container_still_running"):
        ch.require_stopped(run, "sli-clickhouse-history")


def test_cleanup_stops_a_lost_attach_container_and_never_removes_foreign_data():
    row = managed_container()
    calls = []
    present = [True]
    def run(argv):
        calls.append(argv)
        if "ls" in argv: return "sli-clickhouse-history\n" if present[0] else ""
        if "inspect" in argv: return json.dumps([row])
        if "stop" in argv: row["State"]["Running"] = False
        if "rm" in argv: present[0] = False
        return ""
    ch.cleanup_container(run, "sli-clickhouse-history", "history")
    assert any("stop" in c for c in calls) and any("rm" in c for c in calls)
    assert not present[0]
    present[0] = True
    row["Image"] = "sha256:" + "0" * 64
    calls.clear()
    with pytest.raises(ValueError, match="foreign_container"):
        ch.cleanup_container(run, "sli-clickhouse-history", "history")
    assert not any("stop" in c or "rm" in c for c in calls)


def test_foreign_docker_group_membership_rejected_before_container_commands(monkeypatch):
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        assert argv[0] == "dpkg-query"
        return "26.1.5+dfsg1-9+deb13u1"
    monkeypatch.setattr(host, "run", run)
    monkeypatch.setattr(host, "group", lambda name: SimpleNamespace(gr_gid=999, gr_mem=["sli-api"]))
    with pytest.raises(host.HostError, match="socket_exposed"):
        host.check_docker()
    assert len(calls) == 2


@pytest.fixture
def image_archive(tmp_path, monkeypatch):
    path = tmp_path / "image.tar"
    config = json.dumps({"os": "linux", "architecture": "amd64"}).encode()
    identifier = "sha256:" + hashlib.sha256(config).hexdigest()
    manifest = [{"Config": "config.json", "Layers": ["layer.tar"], "RepoTags": ["clickhouse/clickhouse-server:25.8"]}]
    with tarfile.open(path, "w") as archive:
        for name, data in {"manifest.json": json.dumps(manifest).encode(), "config.json": config, "layer.tar": b"fake layer"}.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    pins = deepcopy(ch.pins())
    pins["docker"]["image"].update(id=identifier, archive_sha256=ch.file_sha256(path))
    monkeypatch.setattr(ch, "pins", lambda: pins)
    return path, identifier, pins


def test_image_load_is_offline_and_verifies_id(image_archive):
    path, identifier, _ = image_archive
    calls = []
    def run(argv):
        calls.append(argv)
        return json.dumps([{"Id": identifier, "Os": "linux", "Architecture": "amd64"}]) if "inspect" in argv else ""
    ch.load_image(path, run)
    assert calls[0] == ["/usr/bin/docker", "load", "--input", str(path)]
    assert not any("pull" in argv for argv in calls)
    assert calls[-1][-1] == "clickhouse/clickhouse-server:25.8.33.6"


def test_image_tampering_fails_before_docker(image_archive):
    path, _, _ = image_archive
    with path.open("ab") as stream: stream.write(b"tamper")
    with pytest.raises(ValueError, match="archive_mismatch"):
        ch.load_image(path, lambda argv: pytest.fail("must not call Docker"))


@pytest.mark.parametrize("selected", ["native", "docker"])
def test_backup_host_to_server_mapping_is_separate_from_endpoint(selected, tmp_path, monkeypatch):
    archive = tmp_path / selected
    archive.mkdir()
    target = backup.ClickHouse("history", "127.0.0.1", "sli_history", "unused", archive_root=archive,
        disk_root=archive, server_root=PurePosixPath("/var/lib/clickhouse/backups") if selected == "docker" else None)
    monkeypatch.setattr(backup.ClickHouse, "query", lambda self, sql: [{"path": str(self.server_root or self.disk_root) + "/"}])
    assert target.backup_disk_path(archive / "history.zip") == "history.zip"
    assert target.backup_disk_path(archive / ".restore-test/history.zip") == ".restore-test/history.zip"
    monkeypatch.setattr(backup.ClickHouse, "query", lambda self, sql: [{"path": "/unexpected/"}])
    with pytest.raises(RuntimeError, match="disk_path_mismatch"):
        target.backup_disk_path(archive / "history.zip")


def test_docker_backup_settings_keep_native_deployment(mode):
    settings = native_backup.settings()
    assert settings["SLI_DEPLOYMENT_MODE"] == "native"
    assert not any("CLICKHOUSE" in key for key in settings)
    assert settings["SLI_PG_ADMIN_PASSWORD_FILE"].endswith("/postgres_password")


@pytest.mark.parametrize("selected", ["native", "docker"])
@pytest.mark.parametrize("coordinator", [None, "sli-upgrade-drill-123.service"])
@pytest.mark.parametrize("failure", [None, "unit"])
def test_isolated_databases_use_only_disposable_paths_and_stop_every_engine(tmp_path, monkeypatch, selected, coordinator, failure):
    from deploy.linux import operation_wait
    calls = []
    meminfo = tmp_path / 'meminfo'
    meminfo.write_text(f'MemTotal: {15 * 1024**2} kB\nMemAvailable: {12 * 1024**2} kB\n')
    monkeypatch.setattr(native_backup, 'MEMINFO', meminfo, raising=False)
    monkeypatch.setattr(operation_wait, 'coordinator_unit', lambda: coordinator)
    monkeypatch.setattr(native_backup, 'systemd_budget', lambda path: 2500)
    monkeypatch.setattr(native_backup, 'DATA', tmp_path)
    monkeypatch.setattr(native_backup.shutil, 'disk_usage', lambda _: SimpleNamespace(total=500 * 1024**3))
    work = tmp_path / ("a" * 16)
    work.mkdir()
    monkeypatch.setattr(ch, "configured_mode", lambda root=Path("/"): selected)
    monkeypatch.setattr(ch, "database_directory", lambda: "/var/lib/sli-db")
    fake_pwd = SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=123, pw_gid=456))
    settings = native_backup.settings
    monkeypatch.setattr(native_backup, "settings", lambda: settings() | {"SLI_BACKUP_ROOT": str(tmp_path / "published")})
    monkeypatch.setitem(sys.modules, "pwd", fake_pwd)
    monkeypatch.setattr(host, "pwd", fake_pwd)
    monkeypatch.setattr(native_backup.os, "chown", lambda *a: None, raising=False)
    monkeypatch.setattr(host, "check_docker", lambda: calls.append("docker-admission"))
    monkeypatch.setattr(socket, "socket", lambda: nullcontext(SimpleNamespace(bind=lambda address: calls.append(address))))
    monkeypatch.setattr(backup, "pg_passfile", lambda: nullcontext(Path("unused")))
    monkeypatch.setattr(backup, "pg_connect", lambda *a, **k: nullcontext(SimpleNamespace(execute=lambda q: None)))
    monkeypatch.setattr(backup.ClickHouse, "query", lambda *a: [{"ready": 1}])
    cleanup = []
    def cleanup_container(run, container, name):
        cleanup.append((container, name))
        if failure == 'container' and name == 'history':
            raise RuntimeError('injected')
    monkeypatch.setattr(ch, "cleanup_container", cleanup_container)
    def command(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["systemctl", "show"]:
            if failure == 'unit':
                return b"ActiveState=active\nMainPID=42\nControlGroup=\n"
            return b"ActiveState=inactive\nMainPID=0\nControlGroup=\n"
        return b""
    monkeypatch.setattr(native_backup, "command", command)
    failed = failure == 'unit'
    outcome = {'databases_stopped': False}
    expected = pytest.raises(RuntimeError, match='native_drill_cleanup_failed') if failed else nullcontext()
    with expected, native_backup.isolated_databases(work, cleanup=outcome) as env:
        assert env["SLI_PG_PORT"] == "55432"
        assert not any("CLICKHOUSE" in key for key in env)
        assert not (work / 'history').exists() and not (work / 'warm').exists()
    starts = [c for c in calls if isinstance(c, list) and c[0] == "systemd-run"]
    assert len(starts) == 1
    budgets = [3 * 1024**3]
    assert all('--property=MemoryMax=' + str(budget) in command
               for command, budget in zip(starts, budgets, strict=True))
    assert 'shared_buffers=393216kB' in starts[0]
    assert 'maintenance_work_mem=786432kB' in starts[0]
    assert 'max_parallel_maintenance_workers=0' in starts[0]
    if coordinator:
        assert all('--property=BindsTo=sli-upgrade-drill-123.service' in c for c in starts)
        assert all('--property=After=sli-upgrade-drill-123.service' in c for c in starts)
        assert all('--property=RuntimeMaxSec=infinity' in c for c in starts)
    else:
        assert all('--property=RuntimeMaxSec=43200' in c for c in starts)
        assert all(not any(arg.startswith('--property=BindsTo=') for arg in c) for c in starts)
    assert all("--property=InaccessiblePaths=/srv/sli-db /var/lib/sli-db /etc/sli/secrets" in c for c in starts)
    assert '/usr/lib/postgresql/18/bin/postgres' in starts[0]
    assert not cleanup and "docker-admission" not in calls
    assert len([c for c in calls if isinstance(c, list) and c[:2] == ["systemctl", "stop"]]) == 1
    assert outcome['databases_stopped'] is not failed


@pytest.mark.parametrize("format_version", [3, 4])
@pytest.mark.parametrize("selected", ["native", "docker"])
def test_legacy_archives_restore_through_endpoint_without_changing_source(tmp_path, monkeypatch, selected, format_version):
    from deploy.linux import restore_existing, backup_restore_check
    source = tmp_path / "source"
    source.mkdir()
    root = tmp_path / "published"
    root.mkdir()
    staging = tmp_path / "staging"
    staging.mkdir()
    stats = {"events": {"row_count": 2, "max_values": {}}}
    manifest = {"format_version": format_version, "components": {}}
    targets = []
    for name in ch.INSTANCES:
        with zipfile.ZipFile(source / (name + ".zip"), "w") as archive:
            archive.writestr("synthetic.bin", b"unchanged rows")
        host_root = staging / name
        host_root.mkdir()
        targets.append(backup.ClickHouse(name, "127.0.0.1", "sli_history" if name == "history" else "default", "fake",
            port=ch.endpoint(name, selected).http, archive_root=host_root, disk_root=host_root,
            server_root=PurePosixPath("/var/lib/clickhouse/backups") if selected == "docker" else None))
        manifest["components"][name] = {"archive": name + ".zip", "databases": ["fixture"],
                                        "table_names": {"fixture": list(stats)}, "live_tables": {"fixture": stats}}
    (source / "manifest.json").write_text(json.dumps(manifest))
    before = {p.name: p.read_bytes() for p in source.iterdir()}
    calls = []
    def query(self, sql):
        calls.append((self.name, sql))
        if "SELECT free_space" in sql: return [{"free_space": 100 * 1024**3}]
        if "SELECT path FROM system.disks" in sql: return [{"path": str(self.server_root or self.disk_root) + "/"}]
        if "system.databases" in sql: return []
        if sql.startswith("RESTORE"):
            relative = re.search(r"Disk\('backups', '([^']+)'\)", sql)[1]
            archive = self.archive_root / relative
            assert archive.is_file() and zipfile.ZipFile(archive).read("synthetic.bin") == b"unchanged rows"
            return [{"status": "RESTORED"}]
        pytest.fail("unexpected SQL")
    monkeypatch.setattr(backup, "clickhouse_targets", lambda: tuple(targets))
    monkeypatch.setattr(backup.ClickHouse, "query", query)
    monkeypatch.setattr(backup.ClickHouse, "statistics", lambda self, db: stats)
    monkeypatch.setattr(backup_restore_check, "archive_statistics", lambda *a, **kw: {"fixture": stats})
    restore_existing.restore_components(source, root, manifest, ("history", "warm"))
    assert {p.name: p.read_bytes() for p in source.iterdir()} == before
    assert len([sql for _, sql in calls if sql.startswith("RESTORE")]) == 2
    assert all(not list(t.archive_root.iterdir()) for t in targets)


def test_docker_transition_has_no_version_hop_and_native_is_unchanged():
    plan = native_clickhouse_transition.plan_transition(clickhouse_mode="docker")
    assert plan.versions == (ch.endpoint("history", "docker").version,) and plan.steps == ()
    assert native_clickhouse_transition.verify_path(plan, [])["status"] == "not_required"
    assert len(native_clickhouse_transition.plan_transition().versions) == 2


def test_site_toml_accepts_docker_and_rejects_invalid_modes(tmp_path, monkeypatch):
    path = tmp_path / "site.toml"
    monkeypatch.setattr(native_install, "SITE", path)
    monkeypatch.setattr(native_install, "trusted", lambda path: path.read_bytes())
    path.write_text('clickhouse_mode = "docker"\n')
    assert native_install.site_configuration()["clickhouse_mode"] == "docker"
    path.write_text('clickhouse_mode = "auto"\n')
    with pytest.raises(ValueError, match="mode_invalid"):
        native_install.site_configuration()


@pytest.mark.parametrize("selected", ["native", "docker"])
def test_packages_exclude_clickhouse_and_docker_for_either_legacy_provider(tmp_path, monkeypatch, selected, image_archive):
    source = tmp_path / "source"
    source.mkdir()
    manifest = {"schema_version": 1, "python": "/opt/sli/runtimes/test/bin/python3.14",
        "python_sha256": "a" * 64, "migration_ledger": [{"version": 1}], "roles": [["test", False]],
        "plugins": {"test": {"version": "1"}}, "clickhouse_version": ch.endpoint("history", selected).version}
    (source / "native-runtime.json").write_text(json.dumps(manifest))
    captured = {}
    def build(argv, **kwargs):
        root = Path(argv[3])
        captured[root.name] = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    monkeypatch.setattr(native_package.subprocess, "run", build)
    from deploy.linux import native_plugins
    monkeypatch.setattr(native_plugins, "release_inventory", lambda root, plugins: plugins)
    published = tmp_path / "published"
    published.mkdir()
    (published / "Sli.Server").write_text("synthetic-apphost")
    (published / "Sli.Server.runtimeconfig.json").write_text("{}")
    native_package.build(source, tmp_path / "out", "test", "1.0-1~deb13", "1.0-1~deb13",
                         clickhouse_mode=selected, image_archive=image_archive[0] if selected == "docker" else None,
                         dotnet_published=published)
    public = captured["sli"]["DEBIAN/control"].decode()
    host_control = captured["sli-host"]["DEBIAN/control"].decode()
    assert "clickhouse-server" not in public + host_control
    assert "docker.io" not in public + host_control and "docker-cli" not in public + host_control
    assert "sli-clickhouse-image" not in captured
    assert not any("image.tar" in path or 'sli-clickhouse-' in path
                   for package in captured.values() for path in package)
