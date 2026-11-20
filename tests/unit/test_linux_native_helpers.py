"""Native helper adapters and unchanged Docker backup readers, without live DBs."""
# ruff: noqa: F811 -- imported pytest fixtures are intentionally named as parameters

import json
import re
import stat
import sys
import zipfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup, migrate, native_plugins
from deploy.linux import backup_restore_check as drill
from deploy.linux import restore_existing as restore
from tests.unit.linux_operation_process import completed
from tests.unit.linux_backup_volumes import (
    volume_layout,  # noqa: F401 -- shared fixture
)
from tests.unit.test_linux_backup_capacity import (
    private_postgres,  # noqa: F401 -- shared fixture
)
from tests.unit.test_linux_helper_runtime_root import (
    runtime_tree,  # noqa: F401 -- synthetic trusted helper-root fixture
)
from tests.unit.test_restore_existing_native import (
    native_file_permissions,  # noqa: F401 -- shared fixture
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only native helpers")


@pytest.fixture
def native(tmp_path, monkeypatch, runtime_tree):
    from deploy.linux import operation_wait
    monkeypatch.setattr(operation_wait, 'history_path', lambda backup_root=None: tmp_path / 'backups/.status/summary.json')
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    path = tmp_path / "backups"
    path.mkdir(mode=0o700)
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(path))
    runtime_tree.mkdir(mode=0o700, parents=True)
    return backup.backup_root()


def test_docker_defaults_and_native_defaults(monkeypatch):
    monkeypatch.delenv("SLI_DEPLOYMENT_MODE", raising=False)
    assert backup.postgres_target().connection() == {"host": "postgres", "port": 5432, "user": "postgres"}
    assert backup.backup_root() == Path("/backups")
    assert [(t.host, t.port, t.archive_root) for t in backup.clickhouse_targets()] == [
        ("clickhouse", 8123, None), ("warm-tier", 8123, None)]
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    assert backup.postgres_target().host == "127.0.0.1"
    assert backup.backup_root() == Path("/var/backups/sli")
    assert backup.helper_temporary_root() == Path("/run/sli/helpers")
    assert backup.clickhouse_targets() == ()


@pytest.mark.parametrize("setting,value", [("SLI_DEPLOYMENT_MODE", "other"), ("SLI_PG_PORT", "bad"),
                                         ("SLI_PG_PORT", "0"), ("SLI_PG_PORT", "65536"),
                                         ("SLI_PG_HOST", "remote.invalid"), ("SLI_PG_ADMIN_USER", "bad\nvalue")])
def test_invalid_pg_settings_fail_before_connection(native, monkeypatch, setting, value):
    monkeypatch.setenv(setting, value)
    monkeypatch.setattr(backup.psycopg, "connect", lambda **kw: pytest.fail("must not connect"))
    with pytest.raises(ValueError, match="^linux_backup_invalid_settings$"):
        backup.pg_connect(Path("unused"))


def test_native_pg_tools_connection_and_private_passfile_share_endpoint(native, tmp_path, monkeypatch):
    monkeypatch.setenv("SLI_PG_HOST", "::1")
    monkeypatch.setenv("SLI_PG_PORT", "5543")
    monkeypatch.setenv("SLI_PG_ADMIN_USER", "synthetic_admin")
    monkeypatch.setattr(backup, "read_secret", lambda _: r"synthetic:pass\word")
    calls = []

    def connect(**options):
        calls.append(options)
        assert options["host"] == "::1" and options["port"] == 5543
        assert options["user"] == "synthetic_admin"
        assert "password" not in options
        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def execute(self, *args):
                return SimpleNamespace(fetchone=lambda: (4096,))
        return Connection()

    def run(command, **options):
        assert {"--host=::1", "--port=5543", "--username=synthetic_admin"} <= set(command)
        assert "PGPASSWORD" not in options["env"]
        assert r"synthetic:pass\word" not in str(command) + str(options)
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(backup.psycopg, "connect", connect)
    monkeypatch.setattr(backup.subprocess, "run", run)
    monkeypatch.setattr(backup.subprocess, 'Popen', lambda *a, **kw: completed(run(*a, **kw)))
    with backup.pg_passfile(database="sli") as passfile:
        assert passfile.is_relative_to(backup.helper_temporary_root())
        assert stat.S_IMODE(passfile.stat().st_mode) == 0o600
        assert passfile.read_text() == r"\:\:1:5543:sli:synthetic_admin:synthetic\:pass\\word" + "\n"
        backup.pg_connect(passfile)
        migrate.run_sql([tmp_path / "synthetic.sql"], passfile=passfile)
        restore.run_restore(tmp_path, passfile=passfile, jobs=2, replace_existing=False)
        restore.analyze_postgres(passfile, 2)
    assert not passfile.exists()
    assert [call[0] for call in calls if isinstance(call, list)] == ["psql", "pg_restore", "vacuumdb"]


@pytest.mark.parametrize("unsafe", [None, "permissions", "symlink", "directory"])
def test_supplied_pgpass_is_not_rewritten_or_removed(native, tmp_path, monkeypatch, unsafe):
    path = tmp_path / "pgpass"
    body = b"127.0.0.1:5432:*:postgres:synthetic-only\n"
    path.write_bytes(body)
    path.chmod(0o600)
    selected = path
    if unsafe == "permissions":
        path.chmod(0o640)
    elif unsafe == "symlink":
        selected = tmp_path / "link"
        selected.symlink_to(path)
    elif unsafe == "directory":
        selected = native
    monkeypatch.setenv("SLI_PG_ADMIN_PASSFILE", str(selected))
    monkeypatch.setattr(backup, "read_secret", lambda _: pytest.fail("must not read another secret"))
    if unsafe:
        with pytest.raises(ValueError, match="invalid_secret"), backup.pg_passfile():
            pytest.fail("unsafe passfile accepted")
    else:
        with backup.pg_passfile() as observed:
            assert observed == path
    assert path.read_bytes() == body


@pytest.mark.parametrize("name,hostname", [("history", "clickhouse"), ("warm", "warm-tier")])
def test_docker_http_uses_configured_port(monkeypatch, name, hostname):
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "docker")
    prefix = f"ADLOG_{name.upper()}_CLICKHOUSE"
    monkeypatch.setenv(prefix + "_PORT", "18124")
    calls = []
    response = SimpleNamespace(status=200, read=lambda _: b'{"data":[]}')
    connection = SimpleNamespace(request=lambda *a, **kw: None, getresponse=lambda: response, close=lambda: None)
    monkeypatch.setattr(backup.http.client, "HTTPConnection", lambda host, port, **kw:
                        calls.append((host, port)) or connection)
    monkeypatch.setattr(backup, "read_secret", lambda _: "synthetic-only")
    target = next(t for t in backup.clickhouse_targets() if t.name == name)
    assert target.query("SELECT 1") == []
    assert calls == [(hostname, 18124)]


@pytest.mark.parametrize("setting,value", [("HOST", "invalid/host"), ("PORT", "65536")])
def test_docker_clickhouse_rejects_invalid_endpoint(monkeypatch, setting, value):
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "docker")
    monkeypatch.setenv("ADLOG_WARM_CLICKHOUSE_" + setting, value)
    with pytest.raises(ValueError, match="^linux_backup_invalid_settings$"):
        backup.clickhouse_targets()


def test_native_ignores_retired_clickhouse_endpoint_and_archive_settings(native, monkeypatch):
    monkeypatch.setenv("ADLOG_WARM_CLICKHOUSE_PORT", "65536")
    monkeypatch.setenv("SLI_HISTORY_CLICKHOUSE_BACKUP_DISK_ROOT", str(native))
    monkeypatch.setenv("SLI_WARM_CLICKHOUSE_BACKUP_ROOT", str(native))
    assert backup.clickhouse_targets() == ()
    assert not list(native.iterdir())


@pytest.fixture
def legacy_archive(tmp_path):
    directory = tmp_path / "archive"
    directory.mkdir()
    return backup.ClickHouse("history", "clickhouse", "synthetic", "SYNTHETIC_PASSWORD",
                             archive_root=directory, disk_root=directory)


@pytest.mark.parametrize("bad", ["live_root", "outside", "symlink"])
def test_legacy_archive_mapping_rejects_mismatch_before_backup(native, tmp_path, monkeypatch, legacy_archive, bad):
    queries = []
    monkeypatch.setattr(backup.ClickHouse, "query", lambda self, q:
                        queries.append(q) or [{"path": str(tmp_path / "wrong")}])
    archive = legacy_archive.archive_root / "history.zip"
    if bad == "outside":
        archive = tmp_path / "history.zip"
    elif bad == "symlink":
        archive.symlink_to(tmp_path / "history.zip")
    with pytest.raises(RuntimeError, match="disk_path_mismatch"):
        legacy_archive.backup_disk_path(archive)
    assert queries == (["SELECT path FROM system.disks WHERE name='backups'"] if bad == "live_root" else [])


def fake_databases(monkeypatch, root, volume_layout):
    calls = []
    counts = dict.fromkeys(backup.KEY_TABLES, 3)
    stats = {"events": {"row_count": 3, "max_values": {"event_db_id": "7"}}}

    def dump(destination):
        calls.append(("postgres", "dump"))
        destination.mkdir()
        (destination / "toc.dat").write_bytes(b"synthetic-dump")
        (destination.parent / "roles.sql").write_text("CREATE ROLE synthetic_role;\n")
        return {"size_bytes": 14, "duration_seconds": 0, "server_version": "18.6",
                "migration_ledger_max_version": 3, "row_counts": counts, "roles_file": "roles.sql"}

    def query(self, statement):
        calls.append((self.name, statement))
        if "SELECT path FROM system.disks" in statement:
            return [{"path": str(self.disk_root or "/var/lib/clickhouse/backups")}]
        if "free_space" in statement:
            return [{"free_space": 100 * 1024**3, "path": "/var/lib/clickhouse/restore-check/"}]
        if 'sum(bytes_on_disk)' in statement and 'system.parts' in statement:
            return [{'size_bytes': 17}]
        if "SELECT version" in statement:
            return [{"version": "25.8"}]
        if statement.startswith("BACKUP"):
            disk_path = re.search(r"Disk\('backups', '([^']+)'\)", statement)[1]
            archive = self.disk_root / disk_path if self.disk_root else root / disk_path.removeprefix("scheduled/")
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("synthetic.bin", b"synthetic-history")
            return [{"status": "BACKUP_CREATED"}]
        if statement.startswith("RESTORE"):
            disk_path = re.search(r"Disk\('backups', '([^']+)'\)", statement)[1]
            archive = self.disk_root / disk_path if self.disk_root else root / disk_path.removeprefix("scheduled/")
            assert archive.is_file()
            assert self.name + ".zip" in disk_path
            with zipfile.ZipFile(archive) as handle:
                assert handle.read("synthetic.bin") == b"synthetic-history"
            return [{"status": "RESTORED"}]
        if "system.databases" in statement:
            return [] if "WHERE name IN" in statement else [{"name": "fixture"}]
        if statement.startswith("DROP"):
            return []
        pytest.fail("unexpected fake query")

    def execute(statement):
        from tests.unit.test_linux_backup_capacity import point

        if statement == backup.PG_CAPACITY_SQL:
            return SimpleNamespace(fetchone=lambda: (point(),))
        if statement == 'SELECT pg_database_size(current_database())':
            return SimpleNamespace(fetchone=lambda: (point()['database_size_bytes'],))
        if "SELECT rolname" in str(statement):
            return SimpleNamespace(fetchall=lambda: [("synthetic_role",)])
        if "SELECT EXISTS" in str(statement):
            return SimpleNamespace(fetchone=lambda: (False,))
        return SimpleNamespace(fetchone=lambda: (3,))

    connection = SimpleNamespace(execute=execute)
    monkeypatch.setattr(backup, "dump_postgres", dump)
    monkeypatch.setattr(backup.ClickHouse, "query", query)
    monkeypatch.setattr(backup.ClickHouse, "statistics", lambda self, db: stats)
    monkeypatch.setattr(backup, "read_secret", lambda _: "synthetic-only")
    monkeypatch.setattr(backup, "pg_connect", lambda *a, **kw: nullcontext(connection))
    monkeypatch.setattr(backup, "row_counts", lambda _: counts)
    monkeypatch.setattr(backup, "pg_tool", lambda command, _, *, watch=None: calls.append(("postgres", command)))
    monkeypatch.setattr(migrate, "run_sql", lambda *a, **kw: None)
    from deploy.linux import backup_policy
    from tests.unit.test_linux_backup_capacity import GIB, point

    work = backup_policy.work_root(root)
    volume_layout.update({root.resolve(): 'backup-device', work.resolve(): 'backup-device'})
    volume_layout.update({Path(path).resolve(): 'data-device' for path in backup.pg_capacity_paths(point()).values()})
    monkeypatch.setattr(backup_policy.shutil, 'disk_usage', lambda path: SimpleNamespace(free=100 * GIB))
    return calls


@pytest.mark.parametrize("with_files", [False, True])
def test_legacy_backup_reads_in_native_mode_without_manifest_rewrite(native, tmp_path, monkeypatch,
                                                                   volume_layout, with_files, request):
    files = tmp_path / "files"
    files.mkdir()
    (files / "synthetic.bin").write_bytes(b"synthetic-files")
    monkeypatch.setenv("SLI_BACKUP_FILES_ROOT", str(files))
    calls = fake_databases(monkeypatch, native, volume_layout)
    # Create the actual old layout with the Docker writer, then use the native reader.
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "docker")
    legacy_components = backup.COMPONENTS if with_files else backup.COMPONENTS[:-1]
    source = backup.run_backup(native, retention=1, components=legacy_components)
    before = {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    manifest = json.loads(before[Path("manifest.json")])
    assert manifest["format_version"] == (4 if with_files else 3)
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    destination = tmp_path / "restored"
    destination.mkdir()
    if with_files:
        request.getfixturevalue("native_file_permissions")
    calls.clear()
    with pytest.raises(ValueError, match="^linux_restore_invalid_components$"):
        restore.restore_backup(source, legacy_components, files_root=destination if with_files else None)
    assert not calls
    assert not list(destination.iterdir())
    current_components = ("postgres", "files") if with_files else ("postgres",)
    restore.restore_backup(source, current_components, files_root=destination if with_files else None)
    assert {p.relative_to(source): p.read_bytes() for p in source.rglob("*") if p.is_file()} == before
    assert any(name == "postgres" and isinstance(q, list) and q[0] == "pg_restore" for name, q in calls)
    assert {name for name, _ in calls} == {"postgres"}
    if with_files:
        assert (destination / "synthetic.bin").read_bytes() == b"synthetic-files"
    assert not list(native.glob("sli-checkpoint-*"))


def test_native_capture_and_isolated_drill_use_separate_staging(native, monkeypatch, private_postgres, volume_layout):
    from tests.unit.test_linux_backup_capacity import prepare_capacity

    monkeypatch.setenv("SLI_PG_PORT", "5543")
    monkeypatch.setenv("SLI_PG_ADMIN_USER", "synthetic_admin")
    private_postgres.ledger = 3
    calls = fake_databases(monkeypatch, native, volume_layout)
    source = backup.run_backup(native, retention=1)
    assert set(json.loads((source / "manifest.json").read_text())["components"]) == {"postgres"}
    assert not list(source.glob("*.zip"))
    # This exercises shared helpers against native endpoints, not the native
    # service's isolated_databases lifecycle (covered in test_linux_native_backup).
    # The live endpoint is read-only; the private cluster requires capacity proof.
    admin = prepare_capacity(native, source, monkeypatch)
    monkeypatch.setattr(backup, "pg_connect", lambda *a, **kw: nullcontext(admin))
    before = backup.content_inventory(source, exclude_manifest=False)
    result = drill.restore_check(native)
    assert result["status"] == "verified"
    commands = [command for name, command in calls if name == "postgres" and isinstance(command, list)]
    restored = next(command for command in commands if command[0] == "pg_restore")
    assert {"--port=5432", "--username=sli_check"} <= set(restored)
    assert any(arg.startswith("--host=") and "/pg-" in arg for arg in restored)
    assert "--host=127.0.0.1" not in restored
    assert not any(query.startswith(('CREATE', 'DROP')) for query in admin.queries)
    assert stat.S_IMODE(source.stat().st_mode) == 0o700
    assert backup.content_inventory(source, exclude_manifest=False) == before
    assert calls[0] == ("postgres", "dump")
    assert {name for name, _ in calls} == {"postgres"}


def test_corrupt_legacy_manifest_is_rejected_before_restore(native, monkeypatch, volume_layout):
    calls = fake_databases(monkeypatch, native, volume_layout)
    source = backup.run_backup(native, components=("postgres",))
    (source / "postgres/toc.dat").write_bytes(b"tampered")
    calls.clear()
    with pytest.raises(ValueError, match="invalid_manifest"):
        restore.restore_backup(source, ("postgres",))
    assert not calls


@pytest.mark.parametrize("operation", ["migrate", "import"])
def test_native_migrate_and_import_accept_existing_admin_passfile(native, tmp_path, monkeypatch, operation):
    passfile = tmp_path / "admin.pgpass"
    passfile.write_text("127.0.0.1:5543:sli:synthetic_admin:synthetic-only\n")
    passfile.chmod(0o600)
    monkeypatch.setenv("SLI_PG_ADMIN_PASSFILE", str(passfile))
    monkeypatch.setenv("SLI_PG_PORT", "5543")
    monkeypatch.setenv("SLI_PG_ADMIN_USER", "synthetic_admin")
    monkeypatch.setenv("SLI_PLATFORM_OWNER_PASSWORD_FILE", str(tmp_path / "owner"))
    monkeypatch.delenv("SLI_PG_ADMIN_PASSWORD_FILE", raising=False)
    roles = tmp_path / "roles.sql"
    roles.write_text("CREATE ROLE synthetic_role;\n")
    dump = tmp_path / "dump"
    dump.mkdir()
    (dump / "toc.dat").write_bytes(b"synthetic")
    calls = []
    connection = SimpleNamespace(execute=lambda sql, *a, **kw: SimpleNamespace(
        fetchone=lambda: (4096,) if 'pg_database_size' in sql else ("schema_migrations",)),
                                 transaction=nullcontext)

    def connect(**options):
        assert options["host"] == "127.0.0.1" and options["port"] == 5543
        assert options["user"] == "synthetic_admin" and options["passfile"] == str(passfile)
        calls.append("connect")
        return nullcontext(connection)

    def secret(setting):
        assert setting == "SLI_PLATFORM_OWNER_PASSWORD"
        return "synthetic-only"

    def run_sql(paths, **options):
        assert options["passfile"] == passfile
        calls.append("sql")

    monkeypatch.setattr(migrate.psycopg, "connect", connect)
    monkeypatch.setattr(migrate, "forward_migration_inventory", lambda _: [])
    monkeypatch.setattr(migrate, "load_baseline", lambda *a: SimpleNamespace(version=0, roles_path=roles))
    monkeypatch.setattr(migrate, "base_schema_markers", lambda _: [])
    monkeypatch.setattr(migrate, "attest_ledger", lambda *a, **kw: None)
    monkeypatch.setattr(migrate, "apply_pending", lambda *a, **kw: None)
    def bootstrap_plugins(conn):
        assert conn is connection
        calls.append("plugins")

    monkeypatch.setattr(native_plugins, "bootstrap", bootstrap_plugins)
    monkeypatch.setattr(migrate, "create_platform_owner", lambda *a: None)
    monkeypatch.setattr(migrate, "configure_worker_logins", lambda *a: None)
    monkeypatch.setattr(migrate, "configure_permanent_history", lambda: None)
    monkeypatch.setattr(migrate, "configure_workstation_history", lambda: None)
    monkeypatch.setattr(migrate, "secret_value", secret)
    monkeypatch.setattr(restore, "secret_value", secret)
    monkeypatch.setattr(migrate, "run_sql", run_sql)
    monkeypatch.setattr(restore, "require_empty_database", lambda *a, **kw: None)
    monkeypatch.setattr(restore, "restore_roles", lambda *a: None)
    monkeypatch.setattr(restore, "reconcile_owner", lambda *a, **kw: None)
    monkeypatch.setattr(backup, "pg_tool", lambda command, _, *, watch: calls.append(command[0]))
    monkeypatch.setattr(restore, "run_restore", lambda *a, **kw: calls.append("pg_restore"))
    if operation == "migrate":
        migrate.migrate()
        assert calls == ["connect", "plugins", "sql"]
    else:
        restore.restore_existing(dump, roles_file=roles)
        assert "pg_restore" in calls and "vacuumdb" in calls
    assert passfile.is_file()
    assert not list(backup.helper_temporary_root().iterdir())


@pytest.mark.parametrize("volume,reason", [
    ("backup-device", "insufficient_backup_disk_space"),
    ("data-device", "insufficient_data_disk_space"),
])
def test_native_capture_checks_disk_space_before_postgres_dump(native, monkeypatch, volume_layout, volume, reason):
    from deploy.linux import backup_policy
    from tests.unit.test_linux_backup_capacity import GIB

    calls = fake_databases(monkeypatch, native, volume_layout)
    monkeypatch.setattr(backup_policy.shutil, "disk_usage", lambda path: SimpleNamespace(
        free=0 if backup_policy.filesystem(path) == volume else 100 * GIB))
    with pytest.raises(backup.BackupError, match=f"^{reason}$"):
        backup.run_backup(native)
    assert not calls
    assert not list(native.glob(".*.partial"))
    assert not list(native.glob("*/manifest.json"))


@pytest.mark.parametrize("components", [("history",), ("postgres", "warm")])
def test_native_capture_rejects_retired_components_before_creating_backup(native, monkeypatch, volume_layout, components):
    calls = fake_databases(monkeypatch, native, volume_layout)
    before = list(native.iterdir())
    with pytest.raises(ValueError, match="^linux_backup_invalid_components$"):
        backup.run_backup(native, components=components)
    assert not calls
    assert list(native.iterdir()) == before


@pytest.mark.parametrize("action", ["backup", "restore"])
def test_failed_legacy_archive_operation_cleans_staging_and_preserves_source(
    native, monkeypatch, volume_layout, legacy_archive, action,
):
    fake_databases(monkeypatch, native, volume_layout)
    source = native / "synthetic-backup"
    source.mkdir()
    component = legacy_archive.backup(source)
    before = backup.content_inventory(source, exclude_manifest=False)
    query = backup.ClickHouse.query
    monkeypatch.setattr(drill, "archive_statistics", lambda *a: {"fixture": legacy_archive.statistics("fixture")})

    def fail(self, statement):
        if statement.startswith("BACKUP" if action == "backup" else "RESTORE"):
            assert list(legacy_archive.archive_root.glob(".restore-*"))
            raise RuntimeError("synthetic_failure")
        return query(self, statement)

    monkeypatch.setattr(backup.ClickHouse, "query", fail)
    with pytest.raises(RuntimeError, match="synthetic_failure"):
        if action == "backup":
            legacy_archive.backup(source)
        else:
            restore.restore_clickhouse(source, native, legacy_archive, component, replace_existing=False)
    assert backup.content_inventory(source, exclude_manifest=False) == before
    assert not list(legacy_archive.archive_root.iterdir())


def test_native_capture_refuses_live_data_backup_volume(native, monkeypatch, volume_layout):
    from deploy.linux import backup_policy
    from tests.unit.test_linux_backup_capacity import point

    calls = fake_databases(monkeypatch, native, volume_layout)
    work = backup_policy.work_root(native)
    volume_layout[Path(point()['data_directory']).resolve()] = 'backup-device'
    with pytest.raises(backup.BackupError, match='^restore_volume_mismatch$'):
        backup.run_backup(native)
    assert not any(query == 'dump' or (isinstance(query, str) and query.startswith('BACKUP'))
                   for _, query in calls)
    assert not list(native.glob('.*.partial')) and not work.exists()


@pytest.mark.parametrize('misplaced', ['work', 'clickhouse'])
def test_native_capture_leaves_foreign_drill_workspace_unadmitted(native, monkeypatch, volume_layout, misplaced):
    from deploy.linux import backup_policy
    from tests.unit.test_linux_backup_capacity import GIB, point

    calls = fake_databases(monkeypatch, native, volume_layout)
    work = backup_policy.work_root(native)
    volume_layout[(work if misplaced == 'work' else work / 'clickhouse').resolve()] = 'data-device'
    source = backup.run_backup(native)
    assert (source / 'postgres/toc.dat').read_bytes() == b'synthetic-dump'
    assert not list(source.glob('*.zip'))
    assert calls == [('postgres', 'dump')]
    assert not work.exists()
    before = backup.content_inventory(source, exclude_manifest=False)

    # Capture does not use this workspace. A separately requested full drill
    # still requires the real volume admission, with fresh cluster-bound proof.
    capacity = point()
    filesystems = {role: {'device': backup_policy.filesystem(Path(path).resolve()), 'free_bytes': 100 * GIB}
                   for role, path in backup.pg_capacity_paths(capacity).items()}
    backup.write_json(native / '.postgres-capacity.json', backup.pg_capacity_receipt(
        capacity, filesystems, observed_at=backup.utc_now().isoformat()))
    admission = drill.postgres_admission(native, capacity, {'database_size_bytes': capacity['database_size_bytes']})
    assert admission['status'] == 'skipped' and admission['reason'] == 'restore_volume_mismatch'
    assert backup.content_inventory(source, exclude_manifest=False) == before
    assert not work.exists()


def test_native_cli_defaults_to_seven_daily_backups(native, monkeypatch):
    monkeypatch.delenv('SLI_BACKUP_RETENTION', raising=False)
    path = native / "20261019T010000.000000Z"
    calls = []

    def capture(root, retention, **kwargs):
        calls.append(("backup", retention))
        return path

    monkeypatch.setattr(backup, "run_backup", capture)
    monkeypatch.setattr(drill, "light_check", lambda root, *, selected: calls.append(("integrity", root, selected)))
    monkeypatch.setattr(backup, "refresh_heartbeat", lambda root: calls.append(("heartbeat", root)))
    assert backup.main(["--once"]) == 0
    assert calls == [("backup", 7), ("integrity", native, path), ("heartbeat", native)]
