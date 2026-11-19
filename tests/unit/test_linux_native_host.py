"""Native host boundaries with synthetic files and commands; no live database."""

import json
import os
import stat
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import native_host as host

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX accounts, credentials and mount preparation; Linux CI")


DB_UUID = "11111111-2222-3333-4444-555555555555"


@pytest.fixture(autouse=True)
def bootstrap_marker(tmp_path, monkeypatch):
    monkeypatch.setattr(host, "BOOTSTRAP_MARKER", tmp_path / "bootstrap.json")
    monkeypatch.setattr(host.clickhouse, "configured_mode", lambda root=Path("/"): "native")


@pytest.fixture
def machine(tmp_path, monkeypatch):
    calls = []
    diversions = {}
    monkeypatch.setattr(host, "ROOT_UID", os.geteuid())
    monkeypatch.setattr(host.os, "chown", lambda *args: None)
    monkeypatch.setattr(host.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=os.geteuid()))
    monkeypatch.setattr(host.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=os.getegid()))
    monkeypatch.setattr(host, "validate_identity", lambda: None)
    monkeypatch.setattr(host, "account", lambda name: None)
    monkeypatch.setattr(host, "group", lambda name: None)
    monkeypatch.setattr(host, "check_ports", lambda: None)
    # The synthetic host starts at tmp_path; the runner's /tmp is not /var/lib.
    original_lstat = Path.lstat

    def metadata(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        if path in tmp_path.parents:
            return SimpleNamespace(st_uid=host.ROOT_UID, st_mode=info.st_mode & ~0o022)
        return info

    monkeypatch.setattr(Path, "lstat", metadata)

    def run(argv, **options):
        calls.append((argv, options))
        if argv[0] == "dpkg-divert":
            source = argv[-1]
            if "--listpackage" in argv:
                return "LOCAL" if source in diversions else ""
            if "--truename" in argv:
                return diversions.get(source, source)
            diversions[source] = argv[-2]
            return ""
        if argv == ["/usr/lib/postgresql/18/bin/postgres", "--version"]:
            return "postgres (PostgreSQL) 18.6"
        if argv == ["/usr/bin/clickhouse-server", "--version"]:
            return "ClickHouse server version " + host.clickhouse.endpoint("history", "native").version
        if argv[0] == "findmnt":
            return json.dumps({"filesystems": [{"target": host.MOUNT, "fstype": "ext4", "uuid": DB_UUID, "options": "rw"}]})
        if argv[0] == "pg_createcluster":
            path = tmp_path / "etc/postgresql/18/sli/postgresql.conf"
            path.parent.mkdir(parents=True)
            path.write_text("# synthetic vendor configuration\n")
        return ""

    monkeypatch.setattr(host, "run", run)
    machine = host.Host(tmp_path)
    monkeypatch.setattr(machine, "backup_free", lambda path: 64 * 1024**3)
    original_trust = machine.backup_trusted
    monkeypatch.setattr(machine, "backup_trusted", lambda path: None if path == machine.path(host.MOUNT) else original_trust(path))
    machine.calls = calls
    machine.diversions = diversions
    return machine


def test_prepare_accepts_postgresql_common_directories(machine, monkeypatch):
    paths = {machine.path(name) for name in ("/etc/postgresql", "/var/lib/postgresql")}
    for path in paths:
        path.mkdir(parents=True)
        path.chmod(0o755)
    config = machine.path("/etc/postgresql-common/createcluster.conf")
    config.parent.mkdir(parents=True)
    config.write_text("# Debian default\n")
    config.chmod(0o644)
    original_lstat = Path.lstat

    def metadata(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        if path in paths:
            return SimpleNamespace(st_uid=123, st_mode=stat.S_IFDIR | 0o755)
        return info

    monkeypatch.setattr(Path, "lstat", metadata)
    monkeypatch.setattr(host, "account", lambda name: SimpleNamespace(pw_uid=123) if name == "postgres" else None)
    machine.prepare(DB_UUID)
    assert machine.receipt()["uuid"] == DB_UUID
    assert machine.path(host.STATE + "/createcluster.conf.before").read_text() == "# Debian default\n"


def test_prepare_is_repeatable_preserves_site_config_and_never_starts(machine):
    config = machine.path("/etc/postgresql-common/createcluster.conf")
    config.parent.mkdir(parents=True)
    config.write_text("# synthetic site setting\nssl = on\n")
    machine.prepare(DB_UUID)
    before = {str(p): p.read_bytes() for p in machine.root.rglob("*") if p.is_file()}
    machine.prepare(DB_UUID)
    after = {str(p): p.read_bytes() for p in machine.root.rglob("*") if p.is_file()}
    assert before == after
    assert machine.receipt()["uuid"] == DB_UUID
    assert machine.path(host.STATE + "/createcluster.conf.before").read_text() == "# synthetic site setting\nssl = on\n"
    assert not (machine.root / "etc/systemd/system/clickhouse-server.service").exists()
    assert all(argv[0] in {"findmnt", "groupadd", "useradd", "dpkg-divert"} for argv, _ in machine.calls)
    assert machine.diversions == {}
    assert not any("--add" in argv for argv, _ in machine.calls)
    assert not machine.path("/usr/sbin/policy-rc.d").exists()


@pytest.mark.parametrize("conflict", ["missing", "foreign", "unredirected", "destination"])
def test_vendor_start_diversions_fail_closed(machine, conflict):
    machine.prepare(DB_UUID)
    machine.vendor_diversions(install=True)
    source = host.VENDOR_START_FILES[0]
    if conflict == "missing":
        machine.diversions.clear()
    elif conflict == "foreign":
        machine.diversions[source] = source + ".foreign"
    elif conflict == "unredirected":
        path = machine.root / source.lstrip("/")
        path.parent.mkdir(parents=True)
        path.touch()
    else:
        machine.diversions.clear()
        path = machine.root / (source + ".sli-vendor").lstrip("/")
        path.parent.mkdir(parents=True)
        path.touch()
        with pytest.raises(host.HostError, match="diversion_conflict"):
            machine.vendor_diversions(install=True)
        return
    with pytest.raises(host.HostError, match="diversion_invalid"):
        machine.vendor_diversions()


@pytest.mark.parametrize("field,value", [("uuid", "wrong"), ("target", "/"), ("fstype", "xfs")])
def test_wrong_mount_fails_before_any_writes(machine, monkeypatch, field, value):
    row = {"target": host.MOUNT, "fstype": "ext4", "uuid": DB_UUID, field: value}
    monkeypatch.setattr(host, "run", lambda *a, **kw: json.dumps({"filesystems": [row]}))
    with pytest.raises(RuntimeError, match="mount_mismatch"):
        machine.prepare(DB_UUID)
    assert list(machine.root.iterdir()) == []


def test_missing_mount_and_uuid_injection_refused(machine, monkeypatch):
    monkeypatch.setattr(host, "run", lambda *a, **kw: pytest.fail("must not run a command"))
    with pytest.raises(host.HostError, match="uuid_invalid"):
        machine.prepare("--synthetic-option")
    monkeypatch.setattr(host, "run", lambda *a, **kw: '{"filesystems": []}')
    with pytest.raises(RuntimeError, match="mount_mismatch"):
        machine.prepare(DB_UUID)


@pytest.mark.parametrize("directory", ["/etc/postgresql", "/var/lib/clickhouse", "/srv/sli-db/pgdata"])
def test_foreign_database_refused(machine, directory):
    path = machine.path(directory)
    path.mkdir(parents=True)
    (path / "synthetic-existing").touch()
    with pytest.raises(RuntimeError, match="existing_database"):
        machine.prepare(DB_UUID)
    assert not machine.path(host.STATE + "/host-prepared.json").exists()


def test_busy_port_refused_before_writes(machine, monkeypatch):
    def busy():
        raise host.HostError("native_database_port_busy")
    monkeypatch.setattr(host, "check_ports", busy)
    with pytest.raises(host.HostError, match="port_busy"):
        machine.prepare(DB_UUID)
    assert list(machine.root.iterdir()) == []


def test_symlink_and_modified_receipt_guard_refused(machine):
    (machine.root / "etc").symlink_to(machine.root, target_is_directory=True)
    with pytest.raises(host.HostError, match="symlink"):
        machine.path("/etc/sli/secrets")
    (machine.root / "etc").unlink()
    machine.prepare(DB_UUID)
    machine.path("/etc/postgresql-common/createcluster.conf").write_text("create_main_cluster = true\n")
    with pytest.raises(host.HostError, match="cluster_guard_missing"):
        machine.receipt()


def test_partial_prepare_can_resume_without_changing_original(machine, monkeypatch):
    config = machine.path("/etc/postgresql-common/createcluster.conf")
    config.parent.mkdir(parents=True)
    config.write_text("# synthetic original\ncreate_main_cluster = true\n")
    before = config.read_text()
    receipt = host.STATE + "/host-prepared.json"
    original = machine.write

    def interrupt(path, *args):
        if path == receipt:
            raise host.HostError("interrupted")
        original(path, *args)

    monkeypatch.setattr(machine, "write", interrupt)
    with pytest.raises(host.HostError, match="interrupted"):
        machine.prepare(DB_UUID)
    assert not machine.path(receipt).exists()
    prepared = config.read_text()
    assert prepared != before
    monkeypatch.setattr(machine, "write", original)
    machine.prepare(DB_UUID)
    assert machine.receipt()["uuid"] == DB_UUID
    assert machine.path(host.STATE + "/createcluster.conf.before").read_text() == before
    assert config.read_text() == prepared


def test_configure_requires_receipt_and_keeps_databases_stopped(machine, monkeypatch):
    with pytest.raises(FileNotFoundError):
        machine.configure()
    monkeypatch.setattr(machine, "passwords", lambda: None)
    machine.prepare(DB_UUID)
    machine.configure()
    for name, body in host.units().items():
        assert machine.path("/etc/systemd/system/" + name).read_text() == body
    commands = [argv for argv, _ in machine.calls]
    create = next(argv for argv in commands if argv[0] == "pg_createcluster")
    assert "--start-conf=manual" in create
    assert "--encoding=UTF8" in create and "--locale=C.UTF-8" in create
    assert "--start" not in create
    assert ["systemctl", "daemon-reload"] in commands
    assert not any("start" in argv or "enable" in argv or "apt" in argv for argv in commands)


@pytest.mark.parametrize("cluster", ["18 main 5432 down postgres /other log", "17 sli 5432 down postgres /other log",
                                     "18 sli 5432 online postgres /srv/sli-db/pgdata/18/main log"])
def test_configure_rejects_unexpected_clusters(machine, monkeypatch, cluster):
    machine.prepare(DB_UUID)
    original = host.run
    monkeypatch.setattr(host, "run", lambda argv, **kw: cluster if argv[0] == "pg_lsclusters" else original(argv, **kw))
    with pytest.raises(host.HostError, match="unexpected_postgres_cluster"):
        machine.configure()
    assert not machine.path("/etc/sli/clickhouse/history/config.xml").exists()


def test_units_have_mount_guard_isolated_credentials_and_no_automatic_third_ch():
    units = host.units()
    assert "sli-postgresql.service" in units and "sli-bootstrap-pg.service" in units
    assert not any("clickhouse" in name for name in units)
    for name, body in units.items():
        assert "check-mount" in body
        assert "SupplementaryGroups" not in body
        if name.startswith("sli-clickhouse") or name == "sli-postgresql.service":
            assert "BindsTo=srv-sli\\x2ddb.mount" in body
            assert "RequiresMountsFor=/srv/sli-db" in body
    assert all('history_password' not in body and 'warm_password' not in body for body in units.values())


def test_ch_configs_are_disjoint_loopback_and_backup_paths_match_n07():
    paths = []
    for name, (http, tcp, _, _) in host.INSTANCES.items():
        tree = ET.fromstring(host.ch_config(name))
        assert tree.findtext("listen_host") == "127.0.0.1"
        assert tree.findtext("http_port") == str(http)
        assert tree.findtext("tcp_port") == str(tcp)
        assert tree.find("interserver_http_port") is None
        paths.append(tree.findtext("path"))
        staging = f"/var/backups/sli/staging/{name}/"
        assert tree.findtext("storage_configuration/disks/backups/path") == staging
        assert tree.findtext("backups/allowed_path") == staging
        assert tree.findtext("users_config") == f"/run/sli-ch-{name}/users.xml"
    assert paths[0] != paths[1]


@pytest.fixture
def credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    path = tmp_path / "history_password"
    path.write_text("synthetic-only\n")
    path.chmod(0o400)
    return path


def test_systemd_0400_credential_read_without_common_group(credentials):
    assert host.credential("history_password") == "synthetic-only"


@pytest.mark.parametrize("conflict", [None, "writable_mount", "wrong_group", "wrong_owner", "outside_mount"])
def test_systemd_root_owned_acl_credential(tmp_path, monkeypatch, conflict):
    directory = tmp_path / "sli-clickhouse-history.service"
    directory.mkdir()
    (directory / "history_password").write_text("synthetic-only\n")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(directory))
    monkeypatch.setattr(host, "CREDENTIALS_ROOT", tmp_path if conflict != "outside_mount" else tmp_path / "other")
    monkeypatch.setattr(host.os, "fstat", lambda fd: SimpleNamespace(
        st_mode=0o100440, st_uid=123 if conflict == "wrong_owner" else 0,
        st_gid=10001 if conflict == "wrong_group" else 0, st_size=15))
    monkeypatch.setattr(host.os, "statvfs", lambda path: SimpleNamespace(
        f_flag=0 if conflict == "writable_mount" else os.ST_RDONLY))
    if conflict:
        with pytest.raises(host.HostError, match="credential_invalid"):
            host.credential("history_password")
    else:
        assert host.credential("history_password") == "synthetic-only"


@pytest.mark.parametrize("kind", ["symlink", "broad", "empty", "newline", "large", "directory"])
def test_invalid_credential_refused(credentials, kind):
    credentials.chmod(0o600)
    if kind == "symlink":
        target = credentials.with_name("other")
        credentials.rename(target)
        credentials.symlink_to(target)
    elif kind == "broad":
        credentials.chmod(0o640)
    elif kind == "directory":
        credentials.unlink()
        credentials.mkdir()
    else:
        credentials.write_text({"empty": "", "newline": "a\nb", "large": "x" * 4097}[kind])
    with pytest.raises((host.HostError, OSError)):
        host.credential("history_password")


def test_subprocess_failure_does_not_expose_output(monkeypatch, capsys):
    monkeypatch.setattr(host.subprocess, "run", lambda *a, **kw: SimpleNamespace(
        returncode=1, stdout="synthetic-private-material", stderr="synthetic-private-material"))
    with pytest.raises(host.HostError, match="^native_command_failed$"):
        host.run(["synthetic-command"])
    assert "synthetic-private-material" not in str(capsys.readouterr())


def test_pg_bootstrap_uses_only_stdin_for_passwords(monkeypatch):
    calls = []
    monkeypatch.setattr(host, "credential", lambda name: "synthetic'only")
    monkeypatch.setattr(host, "run", lambda argv, **kw: calls.append((argv, kw)) or ("0\n" if "-XAt" in argv else ""))
    host.bootstrap_pg()
    assert all("synthetic" not in str(argv) for argv, _ in calls)
    sql = calls[1][1]["input"]
    assert "PASSWORD %L'" in sql and "'synthetic''only'" in sql
    assert "log_statement='none'" in sql
    assert "NOINHERIT" in sql and "NOBYPASSRLS" in sql
    assert "CREATE DATABASE sli OWNER sli_migration" in calls[2][1]["input"]
    assert "native_role_conflict" in sql
    assert "native_database_owner_conflict" in calls[2][1]["input"]


def test_pg_bootstrap_refuses_existing_identities_before_reading_secrets(monkeypatch):
    monkeypatch.setattr(host, "run", lambda *a, **kw: "2\n")
    monkeypatch.setattr(host, "credential", lambda *a: pytest.fail("must not read"))
    with pytest.raises(host.HostError, match="existing_postgres_identities"):
        host.bootstrap_pg()


def test_pg_bootstrap_can_resume_with_same_credentials_but_refuses_rotation(monkeypatch):
    calls = []
    count = "0\n"
    monkeypatch.setattr(host, "credential", lambda name: "synthetic-only")
    monkeypatch.setattr(host, "run", lambda argv, **kw: calls.append((argv, kw)) or (count if "-XAt" in argv else ""))
    host.bootstrap_pg()
    intent = host.BOOTSTRAP_MARKER.read_bytes()
    assert b"synthetic-only" not in intent
    count = "2\n"  # Interrupted after the role transaction, before CREATE DATABASE.
    host.bootstrap_pg()
    assert host.BOOTSTRAP_MARKER.read_bytes() == intent
    assert "WHERE NOT EXISTS" in calls[5][1]["input"]
    monkeypatch.setattr(host, "credential", lambda name: "synthetic-changed")
    calls.clear()
    with pytest.raises(host.HostError, match="intent_invalid"):
        host.bootstrap_pg()
    assert len(calls) == 1


@pytest.mark.parametrize("conflict", ["foreign_group", "wrong_gid", "member", "primary_member", "root_user", "login_user"])
def test_account_and_secret_group_conflicts_refused(monkeypatch, conflict):
    shared = SimpleNamespace(gr_name="sli-secrets", gr_gid=10001, gr_mem=[])
    named = SimpleNamespace(gr_name="sli-secrets", gr_gid=10001, gr_mem=[])
    if conflict == "foreign_group":
        shared.gr_name = "synthetic-foreign"
    if conflict == "wrong_gid":
        named.gr_gid = 10002
    if conflict == "member":
        shared.gr_mem = ["synthetic-member"]
    monkeypatch.setattr(host, "group", lambda name: shared if name == 10001 else named)
    monkeypatch.setattr(host.pwd, "getpwall", lambda: [SimpleNamespace(pw_gid=10001)] if conflict == "primary_member" else [])
    entry = SimpleNamespace(pw_uid=0 if conflict == "root_user" else 101, pw_gid=101,
                            pw_shell="/bin/sh" if conflict == "login_user" else "/usr/sbin/nologin", pw_dir="/nonexistent")
    monkeypatch.setattr(host, "account", lambda name: entry)
    monkeypatch.setattr(host.grp, "getgrall", list)
    with pytest.raises(host.HostError, match="conflict"):
        host.validate_identity()


def test_password_generation_uses_inventory_and_does_not_rotate(machine, monkeypatch):
    from deploy.linux import sli_secrets

    # Fake root/group metadata only; generated files stay in the temporary tree.
    writes = []
    existing = machine.path("/etc/sli/secrets/postgres_password")
    existing.parent.mkdir(parents=True)
    existing.write_text("synthetic-existing")
    original_stat = Path.stat

    def metadata(path, *args, **kw):
        info = original_stat(path, *args, **kw)
        if path == existing:
            return SimpleNamespace(st_mode=0o100640, st_uid=host.ROOT_UID, st_gid=10001, st_size=info.st_size)
        return info

    monkeypatch.setattr(Path, "stat", metadata)
    monkeypatch.setattr(machine, "write", lambda name, body, **kw: writes.append((name, body, kw)))
    machine.passwords()
    manifest = json.loads(Path(host.__file__).with_name("secrets-manifest.json").read_text())
    expected = {name for name, spec in manifest["secrets"].items() if spec["kind"] == "password" and spec["group"] == "core"}
    assert {Path(name).name for name, _, _ in writes} == expected - {"postgres_password", "history_password", "warm_password"}
    assert existing.read_text() == "synthetic-existing"
    assert all(options == {"group_name": "sli-secrets"} and len(body.strip()) >= 48 for _, body, options in writes)
    for name, body, _ in writes:
        sli_secrets._validate(Path(name).name, manifest["secrets"][Path(name).name], body.encode("ascii"))


def test_invalid_existing_password_refuses_before_generation(machine, monkeypatch):
    path = machine.path("/etc/sli/secrets/postgres_password")
    path.parent.mkdir(parents=True)
    path.write_text("synthetic-only")
    path.chmod(0o666)
    monkeypatch.setattr(machine, "write", lambda *a, **kw: pytest.fail("must not generate"))
    with pytest.raises(host.HostError, match="secret_invalid"):
        machine.passwords()


@pytest.mark.parametrize("body", ["synthetic-only\n", "synthetic-only\r\n", "synthetic-\u00e9"])
def test_existing_password_must_match_canonical_format(machine, monkeypatch, body):
    path = machine.path("/etc/sli/secrets/postgres_password")
    path.parent.mkdir(parents=True)
    path.write_text(body, encoding="utf-8")
    original_stat = Path.stat

    def metadata(item, *args, **kwargs):
        info = original_stat(item, *args, **kwargs)
        if item == path:
            return SimpleNamespace(st_mode=0o100640, st_uid=host.ROOT_UID, st_gid=10001, st_size=info.st_size)
        return info

    monkeypatch.setattr(Path, "stat", metadata)
    monkeypatch.setattr(machine, "write", lambda *a, **kw: pytest.fail("must not generate or rotate"))
    with pytest.raises(host.HostError, match="secret_invalid"):
        machine.passwords()


def test_unsupported_postgres_version_fails_before_cluster_or_secrets(machine, monkeypatch):
    machine.prepare(DB_UUID)
    original = host.run
    monkeypatch.setattr(host, "run", lambda argv, **kw: "postgres (PostgreSQL) 17.9" if argv[0] == "/usr/lib/postgresql/18/bin/postgres" else original(argv, **kw))
    monkeypatch.setattr(machine, "passwords", lambda: pytest.fail("must not generate"))
    with pytest.raises(host.HostError, match="version_mismatch"):
        machine.configure()


def test_ch_render_contains_hash_only_and_unit_owned_status(credentials, monkeypatch):
    import hashlib
    import io

    body = io.StringIO()
    class Output:
        def __enter__(self):
            return body
        def __exit__(self, *args):
            pass
    original = os.open
    opened = []
    def fake_open(path, flags, *args):
        if str(path).startswith("/run/sli-ch-"):
            opened.append((path, flags, args))
            return 12345
        return original(path, flags, *args)
    monkeypatch.setattr(host.os, "open", fake_open)
    monkeypatch.setattr(host.os, "fdopen", lambda *a: Output())
    host.render_ch("history")
    tree = ET.fromstring(body.getvalue())
    assert "synthetic-only" not in body.getvalue()
    assert tree.findtext("users/sli_history/password_sha256_hex") == hashlib.sha256(b"synthetic-only").hexdigest()
    assert opened[0][0] == Path("/run/sli-ch-history/users.xml")
    assert opened[0][1] & os.O_NOFOLLOW


def test_prepare_configure_permissions_ignore_restrictive_umask(machine):
    import stat

    existing = machine.root / 'etc'
    existing.mkdir(mode=0o711)
    existing.chmod(0o711)  # Establish the pre-existing mode independently of the outer umask.
    previous = os.umask(0o077)
    try:
        machine.prepare(DB_UUID)
        machine.configure()
    finally:
        os.umask(previous)
    expected = {'usr/lib/sli': 0o755, 'var/lib/sli': 0o755,
                'var/lib/sli/state': 0o700, 'var/lib/sli/recovery': 0o700,
                'var/lib/sli/transactions': 0o700, 'etc/sli/secrets': 0o750,
                'etc/postgresql-common': 0o755, 'etc/systemd/system': 0o755,
                'usr/lib/sli/native_host.py': 0o644, 'usr/lib/sli/native_preinstall.py': 0o644}
    for name, mode in expected.items():
        assert stat.S_IMODE((machine.root / name).stat().st_mode) == mode, name
    assert stat.S_IMODE(existing.stat().st_mode) == 0o711


def test_unprivileged_user_can_read_installed_helper_under_umask_077(tmp_path, monkeypatch):
    import subprocess
    import sys

    if os.geteuid() != 0:
        pytest.skip('Dropping to a service UID requires Linux root; other mode tests run unprivileged')
    # This models the installed filesystem root. A pytest directory inherited
    # from umask 077 must not deny traversal before the installed tree is tested.
    tmp_path.chmod(0o755)
    monkeypatch.setattr(host.grp, 'getgrnam', lambda name: SimpleNamespace(gr_gid=0))
    previous = os.umask(0o077)
    try:
        host.Host(tmp_path).write('/usr/lib/sli/native_host.py', '# readable helper\n', 0o644)
    finally:
        os.umask(previous)
    for name in ('usr', 'usr/lib', 'usr/lib/sli', 'usr/lib/sli/native_host.py'):
        info = (tmp_path / name).stat()
        assert (info.st_uid, info.st_gid) == (0, 0)
        assert stat.S_IMODE(info.st_mode) == (0o644 if name.endswith('.py') else 0o755)
    # Set cwd while privileged so pytest's private outer parents do not affect
    # the installed tree's permission check. The child drops all group access.
    code = ('import os; os.setgroups([]); os.setgid(65534); os.setuid(65534); '
            'assert open("usr/lib/sli/native_host.py").read() == "# readable helper\\n"')
    subprocess.run([sys.executable, '-I', '-c', code], cwd=tmp_path, check=True)
