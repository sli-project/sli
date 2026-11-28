"""Private helper roots without systemd or live databases.

Windows runs real directory/file operations with POSIX metadata emulated;
Linux root runs exercise actual ownership and modes.
"""
import os
import stat
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup, migrate, native_backup, native_plugins, native_upgrade


@pytest.fixture
def runtime_tree(tmp_path, monkeypatch):
    root = tmp_path / "run/sli/helpers"
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    monkeypatch.setenv("SLI_HELPER_RUNTIME_ROOT", str(root))
    modes = {}
    original_lstat, original_mkdir, original_chmod = Path.lstat, os.mkdir, Path.chmod

    def mkdir(path, mode=0o777, **options):
        original_mkdir(path, mode=mode, **options)
        # Windows has no POSIX umask; emulate the normal Linux 0022 here.
        modes[Path(path)] = mode & ~0o022

    def chmod(path, mode, **options):
        original_chmod(path, mode, **options)
        modes[path] = mode

    def lstat(path, **options):
        info = original_lstat(path, **options)
        values = list(info)
        # Only synthetic test paths: no access to host secrets or services.
        if os.name == "nt" or getattr(os, "geteuid", lambda: -1)() != 0:
            values[4:6] = [0, 0]
            if stat.S_ISDIR(info.st_mode):
                values[0] = stat.S_IFDIR | modes.get(path, 0o755)
            elif path in modes:
                values[0] = stat.S_IFMT(info.st_mode) | modes[path]
        # tmp_path ancestors can include a shared /tmp on Linux CI.
        if path in tmp_path.parents:
            values[4:6] = [0, 0]
            values[0] = stat.S_IFDIR | 0o755
        return os.stat_result(values)

    monkeypatch.setattr(os, "mkdir", mkdir)
    monkeypatch.setattr(Path, "chmod", chmod)
    monkeypatch.setattr(Path, "lstat", lstat)
    if os.name == "nt" or getattr(os, "geteuid", lambda: -1)() != 0:
        monkeypatch.setattr(os, "chown", lambda *a: None, raising=False)
    return root


@pytest.mark.parametrize("existing", [False, True])
def test_migrate_creates_private_helper_root_without_systemd(runtime_tree, monkeypatch, existing):
    root = runtime_tree
    if existing:
        root.mkdir(mode=0o700, parents=True)
    monkeypatch.setenv("SLI_PG_ADMIN_PASSWORD_FILE", "synthetic-only")
    monkeypatch.setenv("SLI_PLATFORM_OWNER_PASSWORD_FILE", "synthetic-only")
    monkeypatch.delenv("SLI_PG_ADMIN_PASSFILE", raising=False)
    monkeypatch.delenv("SLI_PG_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(migrate, "secret_value", lambda _: "synthetic-only")
    monkeypatch.setattr(migrate, "forward_migration_inventory", lambda _: [])
    monkeypatch.setattr(migrate, "base_schema_markers", lambda _: [])
    connection = SimpleNamespace(
        execute=lambda *a: SimpleNamespace(fetchone=lambda: (None,)), transaction=nullcontext)
    observed = []

    def connect(**options):
        passfile = Path(options["passfile"])
        assert passfile.is_relative_to(root)
        assert stat.S_IMODE(passfile.lstat().st_mode) == 0o600
        assert passfile.read_text().endswith(":synthetic-only\n")
        assert stat.S_IMODE(passfile.parent.lstat().st_mode) == 0o700
        info = root.lstat()
        assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700)
        observed.append(passfile)
        return nullcontext(connection)

    def render(baseline, domain, destination, **options):
        assert destination.parent.is_relative_to(root)
        assert stat.S_IMODE(destination.parent.lstat().st_mode) == 0o700
        destination.write_text("-- synthetic baseline\n")
        return destination

    monkeypatch.setattr(migrate.psycopg, "connect", connect)
    monkeypatch.setattr(migrate, "render_baseline_schema", render)
    monkeypatch.setattr(native_plugins, "bootstrap", lambda *a: None)
    for name in ("attest_ledger", "apply_pending", "create_platform_owner", "run_sql", "configure_worker_logins",
                 "configure_permanent_history"):
        monkeypatch.setattr(migrate, name, lambda *a, **kw: None)
    # A fresh database must render the baseline inside the private helper root.
    monkeypatch.setattr(migrate, "load_baseline", lambda *a: SimpleNamespace(version=0, roles_path=root / "roles.sql"))
    migrate.migrate()
    assert len(observed) == 1 and not observed[0].exists()
    assert root.is_dir() and not list(root.iterdir())
    assert stat.S_IMODE(root.parent.lstat().st_mode) == 0o755


@pytest.mark.parametrize("defect", ["owner", "mode", "symlink", "file", "parent_owner", "parent_mode", "parent_symlink"])
def test_helper_root_refuses_untrusted_existing_paths(runtime_tree, monkeypatch, defect):
    root = runtime_tree
    root.mkdir(mode=0o700, parents=True)
    path = root.parent if defect.startswith("parent_") else root
    original_lstat = Path.lstat

    def untrusted(candidate, **options):
        info = original_lstat(candidate, **options)
        if candidate != path:
            return info
        values = list(info)
        if defect.endswith("owner"):
            values[4] = 12345
        elif defect.endswith("mode"):
            values[0] = stat.S_IFDIR | (0o777 if defect.startswith("parent_") else 0o750)
        else:
            values[0] = (stat.S_IFLNK if defect.endswith("symlink") else stat.S_IFREG) | 0o700
        return os.stat_result(values)

    monkeypatch.setattr(Path, "lstat", untrusted)
    with pytest.raises(ValueError, match="^linux_backup_invalid_settings$"), backup.helper_temporary_directory(prefix="sli-migrate-"):
        pytest.fail("untrusted root accepted")
    assert not list(root.iterdir())


@pytest.mark.parametrize("prefix", ["sli-restore-", "sli-restore-roles-", "sli-backup-secret-"])
def test_drill_creates_private_helpers_below_traversable_work(runtime_tree, prefix):
    root = runtime_tree
    root.parent.mkdir(mode=0o711, parents=True)
    with backup.helper_temporary_directory(prefix=prefix) as temporary:
        path = Path(temporary)
        assert path.parent == root
        assert stat.S_IMODE(path.lstat().st_mode) == 0o700
        assert stat.S_IMODE(root.lstat().st_mode) == 0o700
    assert stat.S_IMODE(root.parent.lstat().st_mode) == 0o711
    assert not list(root.iterdir())


def test_upgrade_pgpass_creates_missing_runtime_root(runtime_tree, monkeypatch):
    monkeypatch.setattr(native_backup, "settings", lambda: dict(os.environ))
    monkeypatch.delenv("SLI_PG_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("SLI_PG_ADMIN_PASSFILE", raising=False)
    monkeypatch.setattr(backup, "read_secret", lambda _: "synthetic-only")
    monkeypatch.setattr(backup, "clickhouse_targets", lambda: ())
    observed = []

    def connect(passfile, database, *, autocommit):
        assert database == "postgres" and passfile.is_relative_to(runtime_tree)
        assert autocommit
        assert stat.S_IMODE(passfile.lstat().st_mode) == 0o600
        assert passfile.is_file()
        observed.append(passfile)
        return nullcontext(SimpleNamespace(execute=lambda *args: SimpleNamespace(fetchall=list)))

    monkeypatch.setattr(backup, "pg_connect", connect)
    native_upgrade.database_quiet()
    assert len(observed) == 1 and not observed[0].exists()
    assert runtime_tree.is_dir() and not list(runtime_tree.iterdir())


def test_helper_root_rechecks_directory_created_by_another_process(runtime_tree, monkeypatch):
    root = runtime_tree
    original_mkdir = Path.mkdir

    def raced_mkdir(path, mode=0o777, **options):
        if path == root:
            original_mkdir(path, mode=0o755)
            raise FileExistsError(path)
        return original_mkdir(path, mode=mode, **options)

    monkeypatch.setattr(Path, "mkdir", raced_mkdir)
    with pytest.raises(ValueError, match="^linux_backup_invalid_settings$"), backup.helper_temporary_directory(prefix="sli-backup-secret-"):
        pytest.fail("unsafe concurrent directory accepted")
    assert stat.S_IMODE(root.lstat().st_mode) == 0o755
    assert not list(root.iterdir())


def test_default_helper_root_leaves_shared_systemd_namespace_traversable(monkeypatch):
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    monkeypatch.delenv("SLI_HELPER_RUNTIME_ROOT", raising=False)
    monkeypatch.setattr(backup, "canonical_directory", Path)
    assert backup.helper_temporary_root() == Path("/run/sli/helpers")


def test_docker_does_not_create_native_helper_root(runtime_tree, monkeypatch):
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "docker")
    with backup.helper_temporary_directory(prefix="sli-backup-secret-") as temporary:
        assert Path(temporary).is_dir()
        assert not runtime_tree.exists()
