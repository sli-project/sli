"""Restore PostgreSQL dumps or selected backup components with fixed diagnostics."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import replace
from pathlib import Path

import psycopg

from deploy.linux import backup, migrate, operation_wait
from server.sli.core.secret_files import secret_value


ROLE_CREATE = re.compile(r'^CREATE ROLE ("(?:[^"]|"")*"|[a-z_][a-z_0-9]*);$', re.MULTILINE)


def restore_roles(source: Path, connection, passfile: Path, temporary: Path) -> None:
    """Replay a trusted pg_dumpall --roles-only --no-role-passwords export.

    Existing role passwords survive; the migration step rebinds service logins
    to the destination secret files. Never print role names or SQL diagnostics.
    """
    body = source.read_text(encoding="utf-8")
    if re.search(r'\bPASSWORD\s+(?:\'|NULL\b)', body, re.IGNORECASE):
        raise ValueError("linux_restore_role_passwords_forbidden")
    matches = list(ROLE_CREATE.finditer(body))
    if not matches:
        raise ValueError("linux_restore_invalid_roles")
    existing = {row[0] for row in connection.execute("SELECT rolname FROM pg_roles").fetchall()}

    def name(match):
        value = match[1]
        return value[1:-1].replace('""', '"') if value.startswith('"') else value

    rendered = ROLE_CREATE.sub(lambda match: "" if name(match) in existing else match[0], body)
    path = temporary / "restore-roles.sql"
    path.write_text(rendered, encoding="utf-8")
    path.chmod(0o600)
    migrate.run_sql([path], passfile=passfile, atomic=True)
    observed = {row[0] for row in connection.execute("SELECT rolname FROM pg_roles").fetchall()}
    if not {name(match) for match in matches} <= observed:
        raise RuntimeError("linux_restore_roles_readback_failed")


def analyze_postgres(passfile: Path, jobs: int) -> None:
    with backup.pg_connect(passfile) as connection:
        size = connection.execute('SELECT pg_database_size(current_database())').fetchone()[0]
    watch = operation_wait.Watch('postgres_analyze', minimum=backup.TIMEOUT, size=size,
                                 history=operation_wait.history_path())
    backup.pg_tool(["vacuumdb", "--no-password", *backup.postgres_target().arguments(),
                    "--dbname=sli", "--analyze-in-stages", f"--jobs={jobs}"], passfile, watch=watch)
    print("linux_restore_analyze_verified", flush=True)


def reconcile_owner(connection, *, sync: bool = False) -> None:
    """Check the restored credential; changing it requires explicit opt-in."""
    from argon2.exceptions import InvalidHashError, VerificationError
    from server.sli.access.auth import PASSWORD_HASHER

    password = secret_value("SLI_PLATFORM_OWNER_PASSWORD")
    row = connection.execute(
        "SELECT id, password_hash, is_active FROM public.auth_users WHERE lower(username)=%s",
        ("platform-owner",),
    ).fetchone()
    if not row or not row[2]:
        raise RuntimeError("linux_restore_owner_unavailable")
    try:
        valid = PASSWORD_HASHER.verify(row[1], password)
    except (VerificationError, InvalidHashError):
        valid = False
    if valid:
        return
    if not sync:
        raise RuntimeError("linux_restore_owner_credentials_mismatch")
    if not 12 <= len(password) <= 4096:
        raise ValueError("linux_restore_owner_password_invalid")
    with connection.transaction():
        connection.execute("UPDATE public.auth_users SET password_hash=%s, updated_at=now() WHERE id=%s",
                           (PASSWORD_HASHER.hash(password), row[0]))
        connection.execute("UPDATE public.auth_sessions SET revoked_at=now() "
                           "WHERE user_id=%s AND revoked_at IS NULL", (row[0],))
        connection.execute("INSERT INTO public.auth_audit(actor_type, actor_id, action, outcome) "
                           "VALUES ('system', %s, 'restore_owner_password_sync', 'ok')", (row[0],))
    print("linux_restore_owner_password_synchronized", flush=True)


def require_empty_database(connection, *, replace_existing: bool = False) -> None:
    row = connection.execute("""
        SELECT EXISTS (
            SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND n.nspname NOT LIKE 'pg_%'
            UNION ALL
            SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND n.nspname NOT LIKE 'pg_%'
            UNION ALL
            SELECT 1 FROM pg_namespace
            WHERE nspname NOT IN ('public', 'pg_catalog', 'information_schema')
              AND nspname NOT LIKE 'pg_%'
        )
    """).fetchone()
    if not row or (row[0] and not replace_existing):
        raise RuntimeError("linux_restore_requires_empty_database")


def run_restore(dump: Path, *, passfile: Path, jobs: int, replace_existing: bool) -> None:
    command = ["pg_restore", "--no-password", "--exit-on-error", "--format=directory",
               *backup.postgres_target().arguments(), "--dbname=sli", f"--jobs={jobs}"]
    # Ownership and ACLs are deliberately preserved (no --no-owner/--no-acl).
    if replace_existing:
        command.extend(["--clean", "--if-exists"])
    command.append(str(dump))
    watch = operation_wait.Watch('postgres_restore', minimum=0, native=True,
                                 size=max(1, operation_wait.file_bytes(dump)),
                                 work_path=backup.helper_temporary_root() or Path(tempfile.gettempdir()),
                                 history=operation_wait.history_path())
    try:
        backup.pg_tool(command, passfile, watch=watch)
    except backup.BackupError:
        raise RuntimeError("linux_restore_sql_failed") from None


def restore_existing(dump: Path, *, jobs: int = 4, replace_existing: bool = False,
                     roles_file: Path | None = None, sync_owner_password: bool = False,
                     check_agent_trust: bool = False, progress=None) -> None:
    progress = progress or (lambda stage: None)
    progress("preflight")
    if not dump.is_dir() or not (dump / "toc.dat").is_file() or not 1 <= jobs <= 64:
        raise ValueError("linux_restore_invalid_input")
    if "SLI_PG_ADMIN_PASSWORD_FILE" not in os.environ and "SLI_PG_ADMIN_PASSFILE" not in os.environ:
        raise ValueError("missing restore secret file")
    inventory = migrate.forward_migration_inventory(migrate.ROOT / "config/postgres_migrations")
    baseline = migrate.load_baseline(migrate.ROOT / "config/postgres_baseline", inventory)
    if check_agent_trust:
        from deploy.linux.sli_secrets import check_agent_bundle
        check_agent_bundle()
    roles_file = roles_file or dump.parent / "roles.sql"
    if not roles_file.is_file():
        raise ValueError("linux_restore_roles_file_required")
    with (backup.helper_temporary_directory(prefix="sli-restore-") as temporary,
          backup.pg_passfile(database="sli", reader=lambda: secret_value("SLI_PG_ADMIN_PASSWORD")) as passfile):
        with psycopg.connect(**backup.postgres_target().connection(), dbname="sli", passfile=str(passfile),
                             connect_timeout=5, autocommit=True) as connection:
            connection.execute("select pg_advisory_lock(hashtext('sli_linux_stand_migrate'))")
            require_empty_database(connection, replace_existing=replace_existing)
            # Init already owns the runtime/migration logins. A retry may also
            # have created baseline roles; never alter the checksummed source.
            roles = baseline.roles_path.read_text(encoding="utf-8")
            roles = re.sub(
                r"CREATE ROLE ([a-z_][a-z_0-9]*);",
                lambda match: (
                    "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='"
                    + match[1] + "') THEN CREATE ROLE " + match[1] + "; END IF; END $$;"
                ), roles,
            )
            roles_path = Path(temporary) / "roles.sql"
            roles_path.write_text(roles, encoding="utf-8")
            progress("roles")
            migrate.run_sql([roles_path], passfile=passfile, atomic=True)
            restore_roles(roles_file, connection, passfile, Path(temporary))
            progress("postgres_restore")
            run_restore(dump, passfile=passfile, jobs=jobs, replace_existing=replace_existing)
        # Use the regular ledger/grant/login path before report statistics.
        progress("migrations")
        migrate.migrate()
        progress("owner_password")
        with backup.pg_connect(passfile, autocommit=True) as connection:
            reconcile_owner(connection, sync=sync_owner_password)
        progress("analyze")
        analyze_postgres(passfile, jobs)
    # The normal migration path verifies the restored ledger, applies newer
    # migrations, then runtime_grants.sql and the file-backed worker logins.
    print("linux_restore_verified")


def restore_postgres(path: Path, manifest: dict, *, replace_existing: bool) -> None:
    """Restore the captured state without applying candidate migrations."""
    counts = manifest["components"]["postgres"]["row_counts"]
    ledger = manifest["migration_ledger_max_version"]
    if not isinstance(counts, dict) or type(ledger) is not int or not (path / "postgres/toc.dat").is_file():
        raise ValueError("linux_restore_invalid_postgres")
    with backup.pg_passfile() as passfile:
        roles_file = path / manifest["components"]["postgres"].get("roles_file", "roles.sql")
        if roles_file != path / "roles.sql":
            raise ValueError("linux_restore_invalid_roles")
        if manifest["components"]["postgres"].get("roles_file") and not roles_file.is_file():
            raise ValueError("linux_restore_roles_file_required")
        # Replacement can resume after DROP DATABASE committed but before
        # CREATE DATABASE. Empty-target checks still use sli for fresh restores.
        database = "postgres" if replace_existing else "sli"
        with backup.pg_connect(passfile, database, autocommit=True) as connection:
            if replace_existing and connection.execute("SELECT 1 FROM pg_database WHERE datname='sli'").fetchone() is None:
                # Role replay uses psql against sli. An empty placeholder makes
                # it retryable before the normal owned database is recreated.
                connection.execute("CREATE DATABASE sli TEMPLATE template0")
            require_empty_database(connection, replace_existing=replace_existing)
            if roles_file.is_file():
                with backup.helper_temporary_directory(prefix="sli-restore-roles-") as temporary:
                    restore_roles(roles_file, connection, passfile, Path(temporary))
        with backup.pg_connect(passfile, "postgres", autocommit=True) as connection:
            connection.execute("DROP DATABASE IF EXISTS sli WITH (FORCE)")
            connection.execute("CREATE DATABASE sli OWNER sli_migration TEMPLATE template0")
        watch = operation_wait.Watch('postgres_restore', minimum=backup.TIMEOUT,
                                     size=manifest['components']['postgres'].get('database_size_bytes', 0),
                                     history=operation_wait.history_path())
        backup.pg_tool(["pg_restore", "--no-password", "--exit-on-error", "--format=directory",
                        *backup.postgres_target().arguments(), "--dbname=sli", "--jobs=2",
                        str(path / "postgres")], passfile, watch=watch)
        analyze_postgres(passfile, 2)
        with backup.pg_connect(passfile) as connection:
            if (backup.row_counts(connection) != counts
                    or connection.execute("SELECT max(version) FROM public.schema_migrations").fetchone()[0] != ledger):
                raise RuntimeError("linux_restore_postgres_readback_failed")


def clickhouse_databases(target: backup.ClickHouse, component: dict) -> list[str]:
    names = component["databases"]
    if (not isinstance(names, list) or not names or len(set(names)) != len(names)
            or any(not isinstance(name, str) or not name or name in
                   {"system", "information_schema", "INFORMATION_SCHEMA"}
                   or name.startswith("sli_backup_") for name in names)
            or component.get("archive") != target.name + ".zip"):
        raise ValueError("linux_restore_invalid_clickhouse")
    return names


def restore_clickhouse(path: Path, root: Path, target: backup.ClickHouse, component: dict,
                       *, replace_existing: bool) -> None:
    """Expose only the verified private archive to ClickHouse's backup disk."""
    from deploy.linux.backup_restore_check import (
        RESTORE_TIMEOUT, archive_statistics,
    )

    names = clickhouse_databases(target, component)
    with zipfile.ZipFile(path / (target.name + ".zip")) as archive:
        required = backup.backup_policy.space_estimate(
            expanded_ch_bytes=sum(item.file_size for item in archive.infolist()))['clickhouse_bytes']
    target = replace(target, timeout=RESTORE_TIMEOUT, deadline=None, operation_size=required)
    disks = target.query("SELECT free_space FROM system.disks WHERE name='default'")
    if len(disks) != 1 or int(disks[0]["free_space"]) < required:
        if len(disks) == 1:
            backup.backup_policy.report_refusal({'reason': 'insufficient_backup_disk_space',
                                                'volume': 'clickhouse:' + target.name + '/default',
                                                'required_bytes': required,
                                                'free_bytes': int(disks[0]['free_space'])})
        raise RuntimeError("linux_restore_clickhouse_insufficient_space")
    existing = target.query("SELECT name FROM system.databases WHERE name IN ("
                            + ", ".join(backup.ch_literal(name) for name in names) + ")")
    if existing and not replace_existing:
        # Official images create empty default/configured databases on startup.
        # RESTORE can use them directly; views and dictionaries still count as
        # occupied, even when they contain no physical rows.
        databases = ", ".join(backup.ch_literal(name) for name in names)
        occupied = target.query("SELECT 1 AS occupied FROM system.tables WHERE database IN ("
                                + databases + ") UNION ALL SELECT 1 AS occupied FROM system.dictionaries "
                                "WHERE database IN (" + databases + ") LIMIT 1")
        if occupied:
            raise RuntimeError("linux_restore_requires_empty_clickhouse")
    with target.readable_archive(path / (target.name + ".zip"), root, private=True) as disk_path:
        expected = archive_statistics(target, names, disk_path)
        if component.get("table_names") != {name: list(tables) for name, tables in expected.items()}:
            raise RuntimeError("linux_restore_clickhouse_inventory_failed")
        if replace_existing:
            for name in names:
                target.query("DROP DATABASE IF EXISTS " + backup.ch_identifier(name)
                             + " SYNC SETTINGS max_table_size_to_drop=0, max_partition_size_to_drop=0")
        objects = ", ".join("DATABASE " + backup.ch_identifier(name) for name in names)
        rows = target.query(f"RESTORE {objects} FROM Disk('backups', {backup.ch_literal(disk_path)}) "
                            "SETTINGS max_threads=2, max_memory_usage=536870912, storage_policy='default'")
        if not rows or rows[0].get("status") != "RESTORED":
            raise RuntimeError("linux_restore_clickhouse_incomplete")
        if any(target.statistics(name) != expected[name] for name in names):
            raise RuntimeError("linux_restore_clickhouse_readback_failed")


def native_files_destination(destination):
    mode = os.environ.get("SLI_DEPLOYMENT_MODE")
    return mode == "native" or (not mode and destination == Path("/var/lib/sli")
                                and Path("/etc/sli/runtime.json").is_file())


def preserved_directories(destination):
    from deploy.linux.native_runtime import PRESERVED_DATA_DIRECTORIES

    return PRESERVED_DATA_DIRECTORIES | ({"plugins"} if native_files_destination(destination) else set())


def files_inventory(path, preserved):
    """Inventory only the replaceable data; never descend into host state."""
    result = {}
    for child in path.iterdir():
        if child.name in preserved:
            if child.is_symlink() or not child.is_dir():
                raise ValueError("linux_restore_invalid_host_directory")
            continue
        if child.is_dir() and not child.is_symlink():
            result.update({child.name + "/" + name: info for name, info in
                           backup.content_inventory(child, exclude_manifest=False,
                                                    check=operation_wait.InventoryProgress()).items()})
        else:
            # Preserve the common inventory's link/hardlink/special-file checks.
            if child.is_symlink() or not child.is_file() or child.stat().st_nlink != 1:
                raise ValueError("linux_backup_invalid_files")
            if child.name == "ad_credentials_master_key":
                raise ValueError("linux_backup_excluded_secret")
            with child.open("rb") as stream:
                progress = operation_wait.InventoryProgress()
                digest = operation_wait.hash_stream(stream, progress)
                progress.advance(1)
                result[child.name] = {"sha256": digest,
                                      "size": child.stat().st_size}
    return result


def validate_files_destination(path: Path, destination: Path, *, replace_existing: bool) -> None:
    if (destination.absolute() != destination.resolve() or not destination.is_dir()
            or destination == Path(destination.anchor)):
        raise ValueError("linux_restore_invalid_files_destination")
    # Reject unexpected links/special files before removing any existing content.
    preserved = preserved_directories(destination)
    files_inventory(destination, preserved)
    if any(child.name not in preserved for child in destination.iterdir()) and not replace_existing:
        raise RuntimeError("linux_restore_requires_empty_files")
    source = path / "files"
    if not source.is_dir() or destination.is_relative_to(path) or path.is_relative_to(destination):
        raise ValueError("linux_restore_invalid_files_destination")


def restore_files(path: Path, destination: Path, *, replace_existing: bool) -> None:
    destination = destination.absolute()
    validate_files_destination(path, destination, replace_existing=replace_existing)
    source = path / "files"
    preserved = preserved_directories(destination)
    # Validate all source data before deleting anything, including excluded
    # source trees. Excluded bytes are never copied onto this host.
    backup.content_inventory(source, exclude_manifest=False, check=operation_wait.InventoryProgress())
    expected = files_inventory(source, preserved)
    native = native_files_destination(destination)
    if native:
        from deploy.linux.native_runtime import data_group_id, restore_data_permissions
        gid = data_group_id()  # Fail before deletion if host preparation is missing.
    for child in destination.iterdir():
        if child.name in preserved:
            continue
        if child.is_dir():
            operation_wait.remove_tree(child)
        else:
            child.unlink()
            operation_wait.made_progress()
    for child in source.iterdir():
        if child.name in preserved:
            continue
        if child.is_dir():
            operation_wait.copy_tree(child, destination / child.name)
        else:
            operation_wait.copy2(child, destination / child.name)
    if files_inventory(destination, preserved) != expected:
        raise RuntimeError("linux_restore_files_readback_failed")
    if native:
        restore_data_permissions(destination, gid)


def restore_components(path: Path, root: Path, manifest: dict, components: tuple[str, ...],
                       *, replace_existing: bool = False, files_root: Path | None = None) -> None:
    if (not components or len(set(components)) != len(components)
            or not set(components) <= set(backup.COMPONENTS)
            or not set(components) <= set(manifest["components"])):
        raise ValueError("linux_restore_invalid_components")
    targets = backup.clickhouse_targets()
    available = {"postgres", "files", *(target.name for target in targets)}
    if not set(components) <= available:
        raise ValueError("linux_restore_invalid_components")
    if "files" in components and (files_root is None or not (path / "files").is_dir()):
        raise ValueError("linux_restore_missing_files_root")
    if "files" in components and (files_root.absolute().is_relative_to(root.absolute())
                                 or root.absolute().is_relative_to(files_root.absolute())):
        raise ValueError("linux_restore_invalid_files_destination")
    if "files" in components:
        files_root = files_root.absolute()
        validate_files_destination(path, files_root, replace_existing=replace_existing)
    for target in targets:
        if target.name in components:
            clickhouse_databases(target, manifest["components"][target.name])
            if not (path / (target.name + ".zip")).is_file():
                raise ValueError("linux_restore_invalid_clickhouse")
    if "postgres" in components:
        restore_postgres(path, manifest, replace_existing=replace_existing)
    for target in targets:
        if target.name in components:
            restore_clickhouse(path, root, target, manifest["components"][target.name],
                               replace_existing=replace_existing)
    if "files" in components:
        restore_files(path, files_root, replace_existing=replace_existing)


def restore_backup(path: Path, components: tuple[str, ...], *, replace_existing: bool = False,
                   files_root: Path | None = None) -> None:
    from deploy.linux.update_checkpoint import snapshot

    root = backup.backup_root()
    identifier = path.absolute().relative_to(root).as_posix()
    with backup.backup_lock(root), snapshot(root, identifier, temporary_root=root,
                                          progress=operation_wait.made_progress) as (private, inventory):
        manifest = json.loads((private / "manifest.json").read_bytes())
        if (manifest.get("status") != "success" or manifest.get("backup_id") != path.name
                or manifest.get("content_checksums") != inventory):
            raise ValueError("linux_restore_invalid_manifest")
        restore_components(private, root, manifest, components,
                           replace_existing=replace_existing, files_root=files_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--replace-existing", action="store_true")
    parser.add_argument("--component", action="append", choices=backup.COMPONENTS)
    parser.add_argument("--files-root", type=Path)
    parser.add_argument("--roles-file", type=Path)
    parser.add_argument("--sync-owner-password", action="store_true")
    parser.add_argument("--check-agent-trust", action="store_true")
    parser.add_argument("--result-file", type=Path,
                        help="Atomic progress and terminal result in a protected writable directory")
    args = parser.parse_args(argv)
    stage = "preflight"

    def record(current, status="running", error_code=None):
        nonlocal stage
        stage = current
        document = {"status": status, "stage": stage, "updated_at_utc": backup.utc_now().isoformat()}
        if error_code is not None:
            document['error_code'] = error_code
        if args.result_file:
            backup.write_json(args.result_file, document)
        print("linux_restore_stage " + stage + " " + status, flush=True)

    try:
        record("preflight")
        if args.component:
            if args.roles_file or args.sync_owner_password or args.check_agent_trust:
                raise ValueError("linux_restore_options_require_database_import")
            record("components_restore")
            restore_backup(args.dump, tuple(args.component), replace_existing=args.replace_existing,
                           files_root=args.files_root)
            print("linux_restore_verified")
        else:
            restore_existing(args.dump, jobs=args.jobs, replace_existing=args.replace_existing,
                             roles_file=args.roles_file, sync_owner_password=args.sync_owner_password,
                             check_agent_trust=args.check_agent_trust, progress=record)
        record("complete", "success")
    except Exception as error:  # noqa: BLE001 - never disclose connection/SQL/dump errors
        known = {'linux_restore_owner_credentials_mismatch', 'linux_restore_owner_unavailable',
                 'linux_restore_role_passwords_forbidden', 'linux_restore_roles_file_required',
                 'linux_restore_roles_readback_failed', 'linux_restore_requires_empty_database'}
        reason = str(error) if type(error) in {RuntimeError, ValueError} and str(error) in known else 'linux_restore_failed'
        try:
            record(stage, "failed", reason)
        except OSError:
            pass
        print("linux_restore_failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
