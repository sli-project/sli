"""Scheduled, atomic backups; diagnostics contain fixed codes only."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

import psycopg
from psycopg import sql

from deploy.linux import backup_policy, operation_wait

KEY_TABLES = (
    "schema_migrations", "event_hot", "event_cold_facts", "event_cold_daily",
    "storage_v2_event_identity_allocations", "ad_snapshot_change_history",
    "finding_event_copies337", "entities_v2",
)
BACKUP_NAME = re.compile(r"^\d{8}T\d{6}\.\d{6}Z$")
TIMEOUT = 21600
COMPONENTS = ("postgres", "history", "warm", "files")
REUSE_SECONDS = 30 * 60
CH_BACKUP_LIMITS = ("max_threads=2, os_thread_priority=10, "
                    "max_local_read_bandwidth=16777216, max_local_write_bandwidth=16777216")
ERROR_CODES = frozenset({
    "native_site_operation_stall_invalid",
    "linux_backup_inline_secret_forbidden", "linux_backup_invalid_secret",
    "linux_backup_invalid_retention", "linux_backup_invalid_components", "linux_backup_invalid_settings",
    "linux_backup_components_require_once", "linux_backup_invalid_files", "linux_backup_overlapping_files_root",
    "linux_backup_pg_tool_failed", "linux_backup_dump_missing", "linux_backup_clickhouse_deadline_exceeded",
    "linux_backup_clickhouse_failed", "linux_backup_clickhouse_response_limit", "linux_backup_clickhouse_invalid_metrics",
    "linux_backup_clickhouse_disk_path_mismatch", "linux_backup_clickhouse_no_databases",
    "linux_backup_clickhouse_incomplete", "linux_backup_consistency_window_exceeded",
    "insufficient_backup_disk_space", "insufficient_data_disk_space", "restore_volume_mismatch",
    "postgres_capacity_unavailable", "postgres_size_estimate_unavailable",
    "linux_backup_restore_cleanup_required", "linux_backup_restore_sandbox_failed",
    "linux_backup_restore_socket_path_too_long",
})
CH_WATERMARK_IDS = {"id", "event_id", "event_db_id", "first_event_db_id", "last_event_db_id",
                    "logon_source_id", "logoff_source_id", "revision"}


# Keep this read-only probe identical to the trusted host updater's probe. The
# backup image has no Docker socket, PGDATA mount or server-side OS function.
PG_CAPACITY_SQL = """SELECT json_build_object(
 'cluster_id', (SELECT system_identifier::text FROM pg_control_system()),
 'postmaster_start', pg_postmaster_start_time()::text,
 'data_directory', current_setting('data_directory'),
 'database_size_bytes', pg_database_size(current_database()),
 'tablespaces', (SELECT json_agg(json_build_object('oid', oid::bigint,
 'location', pg_tablespace_location(oid)) ORDER BY oid) FROM pg_tablespace))"""


def pg_capacity_paths(point: dict) -> dict:
    data = point["data_directory"]
    if not isinstance(data, str) or not data.startswith("/") or "\x00" in data:
        raise ValueError("linux_backup_invalid_capacity")
    paths = {"data": data, "wal": data.rstrip("/") + "/pg_wal",
             "default": data.rstrip("/") + "/base", "global": data.rstrip("/") + "/global"}
    spaces = point["tablespaces"]
    if not isinstance(spaces, list) or not 2 <= len(spaces) <= 128:
        raise ValueError("linux_backup_invalid_capacity")
    seen = set()
    for space in spaces:
        oid, location = space["oid"], space["location"]
        if type(oid) is not int or oid <= 0 or oid in seen or not isinstance(location, str):
            raise ValueError("linux_backup_invalid_capacity")
        seen.add(oid)
        if oid in {1663, 1664}:
            if location:
                raise ValueError("linux_backup_invalid_capacity")
        elif location.startswith("/") and "\x00" not in location:
            paths[f"tablespace:{oid}"] = location
        else:
            raise ValueError("linux_backup_invalid_capacity")
    if not {1663, 1664} <= seen:
        raise ValueError("linux_backup_invalid_capacity")
    return paths


def pg_capacity_binding(point: dict) -> dict:
    paths = pg_capacity_paths(point)
    cluster, started = point["cluster_id"], point["postmaster_start"]
    if not isinstance(cluster, str) or not re.fullmatch(r"[0-9]{1,20}", cluster):
        raise ValueError("linux_backup_invalid_capacity")
    if not isinstance(started, str) or datetime.fromisoformat(started).tzinfo is None:
        raise ValueError("linux_backup_invalid_capacity")
    topology = json.dumps(paths, sort_keys=True, separators=(",", ":")).encode()
    return {"cluster_id": cluster, "postmaster_start": started,
            "topology_sha256": hashlib.sha256(topology).hexdigest()}


def pg_capacity_receipt(point: dict, filesystems: dict, *, observed_at: str) -> dict:
    binding = pg_capacity_binding(point)
    if set(filesystems) != set(pg_capacity_paths(point)):
        raise ValueError("linux_backup_invalid_capacity")
    for item in filesystems.values():
        if (not isinstance(item, dict) or set(item) != {"device", "free_bytes"}
                or not isinstance(item["device"], str) or not re.fullmatch(r"[a-zA-Z0-9:_-]{1,128}", item["device"])
                or type(item["free_bytes"]) is not int or not 0 <= item["free_bytes"] < 2**63):
            raise ValueError("linux_backup_invalid_capacity")
    if datetime.fromisoformat(observed_at).tzinfo is None:
        raise ValueError("linux_backup_invalid_capacity")
    return {"format_version": 1, **binding, "observed_at_utc": observed_at, "filesystems": filesystems}


def publish_pg_capacity(root: Path, document: dict) -> None:
    # Fixed destination only. Atomic replace means readers never accept half a
    # sample. It carries no SQL, paths, credentials or cleanup authority.
    receipt = pg_capacity_receipt(document["point"], document["filesystems"],
                                  observed_at=document["observed_at_utc"])
    write_json(root / ".postgres-capacity.json", receipt)


def native_mode() -> bool:
    mode = os.environ.get("SLI_DEPLOYMENT_MODE", "docker")
    if mode not in {"docker", "native"}:
        raise ValueError("linux_backup_invalid_settings")
    return mode == "native"


def configured_port(setting: str, default: int) -> int:
    try:
        value = int(os.environ.get(setting, str(default)))
    except ValueError:
        raise ValueError("linux_backup_invalid_settings") from None
    if not 1 <= value <= 65535:
        raise ValueError("linux_backup_invalid_settings")
    return value


def canonical_directory(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or path != path.resolve() or path == Path(path.anchor):
        raise ValueError("linux_backup_invalid_settings")
    return path


def backup_root() -> Path:
    default = "/var/backups/sli" if native_mode() else "/backups"
    return canonical_directory(os.environ.get("SLI_BACKUP_ROOT", default))


def helper_temporary_root() -> Path | None:
    if native_mode():
        # /run/sli is also the traversable parent of per-service systemd roots.
        return canonical_directory(os.environ.get("SLI_HELPER_RUNTIME_ROOT", "/run/sli/helpers"))
    return None


def _validate_helper_root(root: Path) -> None:
    for path in (root, *root.parents):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or (path == root and stat.S_IMODE(info.st_mode) != 0o700)):
            raise ValueError("linux_backup_invalid_settings")


def helper_temporary_directory(*, prefix: str):
    root = helper_temporary_root()
    if root is not None:
        from deploy.linux.native_preinstall import ensure_directory

        # Setup/APT/build callers do not have a systemd RuntimeDirectory.
        # Validate before creation; never repair permissions on existing paths.
        _validate_helper_root(root)
        ensure_directory(root, 0o700)
        _validate_helper_root(root)
    return tempfile.TemporaryDirectory(prefix=prefix, **({"dir": root} if root is not None else {}))


def pgpass_escape(value: str) -> str:
    if any(char in value for char in "\r\n\x00"):
        raise ValueError("linux_backup_invalid_settings")
    return value.replace("\\", "\\\\").replace(":", "\\:")


@dataclass(frozen=True)
class Postgres:
    host: str
    port: int
    user: str

    def arguments(self) -> list[str]:
        return [f"--host={self.host}", f"--port={self.port}", f"--username={self.user}"]

    def connection(self) -> dict:
        return {"host": self.host, "port": self.port, "user": self.user}


def postgres_target() -> Postgres:
    host = os.environ.get("SLI_PG_HOST", "127.0.0.1" if native_mode() else "postgres")
    user = os.environ.get("SLI_PG_ADMIN_USER", "postgres")
    if (not re.fullmatch(r"[a-zA-Z0-9_.:-]+", host) or not user or user == "*"
            or any(char in user for char in "\r\n\x00")
            or (native_mode() and host not in {"127.0.0.1", "::1", "localhost"})):
        raise ValueError("linux_backup_invalid_settings")
    return Postgres(host, configured_port("SLI_PG_PORT", 5432), user)


def ch_identifier(value: str) -> str:
    return "`" + value.replace("\\", "\\\\").replace("`", "\\`") + "`"


def ch_literal(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class BackupError(RuntimeError):
    def __init__(self, code: str, **numbers: int):
        super().__init__(code)
        self.numbers = numbers


def failure_diagnostic(error: Exception, step: str) -> dict:
    """Allow fixed codes and machine error numbers, never exception text or server bodies."""
    if hasattr(error, "backup_diagnostic"):
        return error.backup_diagnostic
    if isinstance(error, operation_wait.OperationTimeout):
        return {"error_code": error.code, **error.detail}
    code = str(error) if type(error) in {RuntimeError, ValueError, BackupError} else ""
    if code not in ERROR_CODES:
        code = ("linux_backup_timeout" if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else
                "linux_backup_os_error" if isinstance(error, OSError) else
                "linux_backup_database_error" if isinstance(error, psycopg.Error) else
                "linux_backup_unexpected_error")
    result = {"error_code": code, "step": step}
    if isinstance(error, OSError) and isinstance(error.errno, int):
        result["errno"] = error.errno
    if isinstance(error, psycopg.Error) and re.fullmatch(r"[0-9A-Z]{5}", error.sqlstate or ""):
        result["sqlstate"] = error.sqlstate
    if isinstance(error, BackupError):
        for key in ("returncode", "http_status", "clickhouse_code"):
            if type(error.numbers.get(key)) is int:
                result[key] = error.numbers[key]
    if isinstance(error, BackupError):
        result.update(getattr(error, "pg_diagnostic", {}))
    return result


@contextmanager
def backup_step(step: str):
    try:
        yield
    except Exception as error:
        error.backup_diagnostic = failure_diagnostic(error, step)
        raise


def report_failure(error: Exception, step: str) -> None:
    print("linux_backup_failed", file=sys.stderr, flush=True)
    diagnostic = failure_diagnostic(error, step)
    print("linux_backup_diagnostic " + " ".join(f"{key}={value}" for key, value in diagnostic.items()),
          file=sys.stderr, flush=True)


def read_secret(setting: str) -> str:
    """File-only credentials, including protection against inherited inline values."""
    if setting in os.environ:
        raise ValueError("linux_backup_inline_secret_forbidden")
    value = Path(os.environ[setting + "_FILE"]).read_text(encoding="utf-8").rstrip("\r\n")
    if not value or any(char in value for char in "\r\n\0"):
        raise ValueError("linux_backup_invalid_secret")
    return value


@contextmanager
def backup_lock(root: Path, *, name: str = ".backup.lock", check=None):
    """Serialize backup/pruning and restore drills sharing this bind directory."""
    import fcntl  # Linux-only; imported here so the module (and its tests) load on Windows CI.

    with (root / name).open("a") as handle:
        if check is None:
            fcntl.flock(handle, fcntl.LOCK_EX)
        else:
            while True:
                check()
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(min(0.05, check()))
        yield


def write_json(path: Path, document: dict) -> None:
    # Heartbeats and --once can publish simultaneously; never share a temp name.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix="." + path.name + ".", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def successful_backups(root: Path) -> list[Path]:
    result = []
    for path in root.iterdir():
        if path.is_symlink() or not path.is_dir() or not BACKUP_NAME.fullmatch(path.name):
            continue
        try:
            manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
            if (manifest["status"] == "success" and manifest["backup_id"] == path.name
                    and ((path / "postgres/toc.dat").is_file()
                         or (manifest.get("format_version") == 4
                             and isinstance(manifest.get("components"), dict)))):
                result.append(path)
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return sorted(result, key=lambda path: path.name)


def prune(root: Path, retention: int, new_backup: Path) -> None:
    """Only a published success permits deletion; always keep the newest success."""
    if retention < 1:
        raise ValueError("linux_backup_invalid_retention")
    backups = successful_backups(root)
    if new_backup not in backups:
        return
    # A narrow capture must never retire a full recovery set.
    selected = set(json.loads((new_backup / "manifest.json").read_bytes()).get("components", {}))
    backups = [path for path in backups if
               set(json.loads((path / "manifest.json").read_bytes()).get("components", {})) == selected]
    # A later completed set means both servers have finished their serialized
    # BACKUP operations. Leave newer partials and unrecognized paths untouched.
    for path in root.iterdir():
        if path.is_symlink() or not path.is_dir():
            continue
        if path.name.startswith(".") and path.name.endswith(".partial"):
            stamp = path.name[1:-len(".partial")]
            if ({"history", "warm"} <= selected
                    and BACKUP_NAME.fullmatch(stamp) and stamp < backups[-1].name):
                operation_wait.remove_tree(path)
    # Update checkpoints reference daily artifacts instead of duplicating them.
    # Keep referenced sets for the same lifetime as the operation's rollback receipt.
    pinned = set()
    for receipt in root.glob("update-checkpoints/*/*/manifest.json"):
        try:
            if receipt.absolute() != receipt.resolve():
                return
            value = json.loads(receipt.read_bytes()).get("daily_backup", {})
            if BACKUP_NAME.fullmatch(value.get("backup_id", "")):
                pinned.add(value["backup_id"])
        except (OSError, ValueError, TypeError, AttributeError):
            # An unreadable rollback receipt must not authorize pruning its input.
            return
    daily, weekly = backup_policy.retention_settings(retention)
    keep = backup_policy.retained_sets(backups, daily, weekly)
    for name in ("last_full_restore_check.json", "restore_check.json"):
        try:
            receipt = json.loads((root / name).read_bytes())
            if receipt.get("status") == "verified" and receipt.get("verification") == "full":
                pinned.add(receipt["backup_id"])
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError, TypeError):
            return
    for path in backups:
        if path not in keep and path != new_backup and path.name not in pinned:
            operation_wait.remove_tree(path)


def size_bytes(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def content_inventory(path: Path, *, exclude_manifest: bool = True, check=None) -> dict:
    """Hash regular files; refuse links and special files before publication."""
    if path.is_symlink() or not path.is_dir():
        raise ValueError("linux_backup_invalid_files")
    result = {}
    # Startup scans must not materialize/sort an unbounded directory walk before
    # observing cancellation. Inventory equality is independent of entry order.
    items = sorted(path.rglob("*")) if check is None else path.rglob("*")
    for item in items:
        if check is not None:
            check()
        # Reject, rather than silently publish, a contaminated backup/companion.
        # Both canonical and runtime copies keep this inventory basename.
        if item.name == "ad_credentials_master_key":
            raise ValueError("linux_backup_excluded_secret")
        if item.is_symlink() or (not item.is_dir() and not item.is_file()):
            raise ValueError("linux_backup_invalid_files")
        if item.is_file() and not (exclude_manifest and item == path / "manifest.json"):
            if item.stat().st_nlink != 1:
                raise ValueError("linux_backup_invalid_files")
            with item.open("rb") as stream:
                if check is None:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                else:
                    digest = operation_wait.hash_stream(stream, check)
            result[item.relative_to(path).as_posix()] = {"sha256": digest, "size": item.stat().st_size}
        if hasattr(check, 'advance'):
            check.advance(1)  # Validated directories and empty files are work too.
    return result


def backup_files(destination: Path) -> dict:
    # The descriptor-based copy rejects links, hardlinks and special files.
    from deploy.linux.update_checkpoint import snapshot

    source = Path(os.environ["SLI_BACKUP_FILES_ROOT"]).absolute()
    root = backup_root()
    if source.is_relative_to(root) or root.is_relative_to(source):
        raise ValueError("linux_backup_overlapping_files_root")
    # Keep large file copies on the backup disk, never the helper's /tmp tmpfs.
    with snapshot(source.parent, source.name, temporary_root=destination.parent,
                  progress=operation_wait.made_progress) as (private, _):
        operation_wait.copy_tree(private, destination)
    return {"size_bytes": size_bytes(destination), "format": "directory"}


def publish_backup(staging: Path, final: Path) -> None:
    """Allow transient Windows bind-mount handle contention to clear."""
    for attempt in range(4):
        try:
            staging.rename(final)
            return
        except PermissionError:
            if attempt == 3:
                raise
            time.sleep(0.25 * 2**attempt)


def pg_environment(passfile: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""), "PGPASSFILE": str(passfile),
        "PGCONNECT_TIMEOUT": "5", "PGCLIENTENCODING": "UTF8",
        "PGOPTIONS": "-c log_min_error_statement=panic -c log_error_verbosity=terse "
                     "-c statement_timeout=21600000 -c lock_timeout=30000",
    }


@contextmanager
def pg_passfile(*, database: str = "*", reader=None):
    target = postgres_target()
    if "SLI_PG_ADMIN_PASSWORD" in os.environ:
        raise ValueError("linux_backup_inline_secret_forbidden")
    supplied = os.environ.get("SLI_PG_ADMIN_PASSFILE")
    if supplied is not None:
        path = Path(supplied)
        metadata = path.lstat()
        if (not path.is_absolute() or path != path.resolve() or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o077 or metadata.st_uid not in {0, os.geteuid()}):
            raise ValueError("linux_backup_invalid_secret")
        yield path
        return
    password = (reader or (lambda: read_secret("SLI_PG_ADMIN_PASSWORD")))()
    record = ":".join(pgpass_escape(value) for value in (
        target.host, str(target.port), database, target.user, password))
    with helper_temporary_directory(prefix="sli-backup-secret-") as temporary:
        path = Path(temporary) / "pgpass"
        path.write_text(record + "\n", encoding="utf-8")
        path.chmod(0o600)
        yield path


def pg_connect(passfile: Path, database: str = "sli", *, autocommit: bool = False):
    return psycopg.connect(
        **postgres_target().connection(), dbname=database, passfile=str(passfile),
        connect_timeout=5, autocommit=autocommit, options=pg_environment(passfile)["PGOPTIONS"],
    )


PG_DIAGNOSTIC_BYTES = 8192
# Object names can themselves contain private data. Only these repository-owned
# identifiers may leave the tool; unknown objects get a fixed classification.
PG_CHECK_OBJECTS = frozenset({
    ("semantic_qw_signals", "semantic_qw_acl_identity_v265"),
    ("semantic_qw_signals", "password_v2_qw_identity"),
})


def pg_failure_reason(stderr: bytes) -> dict[str, str]:
    """Classify a bounded primary error; never copy server prose or DETAIL."""
    result = {"pg_reason": "unclassified"}
    text = stderr[:PG_DIAGNOSTIC_BYTES].decode("utf-8", errors="replace")
    for line in text.splitlines():
        if line.startswith(("DETAIL:", "CONTEXT:", "HINT:")):
            continue
        match = re.search(r"\b(?:ERROR|FATAL):[ \t]+(.*)", line)
        if match is None:
            continue
        primary = match[1]
        check = re.fullmatch(
            r'new row for relation "([a-z_][a-z0-9_]{0,62})" violates check constraint '
            r'"([a-z_][a-z0-9_]{0,62})"', primary,
        )
        if check:
            result["pg_reason"] = "check_constraint_violation"
            if (check[1], check[2]) in PG_CHECK_OBJECTS:
                result.update(pg_table=check[1], pg_constraint=check[2])
        elif primary.endswith(": No space left on device"):
            result["pg_reason"] = "disk_full"
        elif re.fullmatch(r'password authentication failed for user "[^"\r\n]*"', primary):
            result["pg_reason"] = "authentication_failed"
        # The first ERROR may contain row values, URLs or credentials even
        # without DETAIL. Unknown forms are deliberately not reproduced.
        break
    return result


def pg_tool(arguments: list[str], passfile: Path, *, check=None, watch=None, progress=None) -> None:
    if arguments[0] in {"pg_dump", "pg_dumpall"}:
        arguments = ["ionice", "-c", "2", "-n", "7", "nice", "-n", "10", *arguments]
    # A private, automatically removed spool avoids an unbounded in-memory PIPE
    # and never forwards raw stderr to inherited logs. Read only a fixed prefix.
    with tempfile.TemporaryFile() as stderr:
        if check is None and watch is None:
            result = subprocess.run(
                arguments, env=pg_environment(passfile), stdout=subprocess.DEVNULL,
                stderr=stderr, timeout=TIMEOUT, check=False,
            )
        else:
            if check is not None:
                check()
            environment = pg_environment(passfile)
            if watch is not None:
                application = 'sli_op_' + uuid.uuid4().hex
                environment['PGAPPNAME'] = application
                # Live native work is bounded by observed progress. Keep the
                # diagnostic restrictions when overriding the client timeout.
                environment['PGOPTIONS'] = (environment.get('PGOPTIONS', '') +
                                            ' -c statement_timeout=0 -c lock_timeout=30000')
            result = subprocess.Popen(arguments, env=environment,
                                      stdout=subprocess.DEVNULL, stderr=stderr,
                                      start_new_session=os.name == 'posix')
            result.sli_process_group = os.name == 'posix'
            try:
                if watch is not None:
                    operation_wait.wait_process(result, watch, progress or (
                        lambda: operation_wait.postgres_probe(passfile, application)), check=check)
                else:
                    while result.poll() is None:
                        try:
                            result.wait(timeout=min(0.05, check()))
                        except subprocess.TimeoutExpired:
                            pass
                    check()
            finally:
                if result.poll() is None:
                    result.kill()
                result.wait()  # Reap even on cancellation; no orphaned pg_restore.
        if result.returncode:
            stderr.seek(0)
            error = BackupError("linux_backup_pg_tool_failed", returncode=result.returncode)
            error.pg_diagnostic = pg_failure_reason(stderr.read(PG_DIAGNOSTIC_BYTES))
            raise error
        if watch is not None:
            watch.success()


def row_counts(connection) -> dict[str, int]:
    return {
        table: connection.execute(sql.SQL("SELECT count(*) FROM public.{}").format(
            sql.Identifier(table))).fetchone()[0]
        for table in KEY_TABLES
    }


def dump_postgres(destination: Path) -> dict:
    started = time.monotonic()
    with pg_passfile() as passfile, pg_connect(passfile) as connection:
        # Counts and ledger must describe exactly the snapshot imported by pg_dump.
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        snapshot = connection.execute("SELECT pg_export_snapshot()").fetchone()[0]
        point = connection.execute(
            "SELECT clock_timestamp()::text, pg_current_wal_lsn()::text, txid_current_snapshot()::text"
        ).fetchone()
        max_event_id = connection.execute("SELECT max(id) FROM public.storage_v2_event_identity_allocations").fetchone()[0]
        counts = row_counts(connection)
        ledger = connection.execute("SELECT max(version) FROM public.schema_migrations").fetchone()[0]
        version = connection.execute("SHOW server_version").fetchone()[0]
        database_size = connection.execute("SELECT pg_database_size(current_database())").fetchone()[0]
        watch = operation_wait.Watch('postgres_roles', minimum=TIMEOUT, size=database_size,
                                     history=operation_wait.history_path())
        pg_tool([
            "pg_dumpall", "--no-password", *postgres_target().arguments(),
            "--database=sli", "--roles-only", "--no-role-passwords",
            f"--file={destination.parent / 'roles.sql'}",
        ], passfile, watch=watch, progress=lambda: operation_wait.file_bytes(destination.parent / 'roles.sql'))
        watch = operation_wait.Watch('postgres_dump', minimum=TIMEOUT, size=database_size,
                                     history=operation_wait.history_path())
        pg_tool([
            "pg_dump", "--no-password", *postgres_target().arguments(), "--dbname=sli",
            "--format=directory", "--compress=gzip:3", "--jobs=2", f"--snapshot={snapshot}",
            f"--file={destination}",
        ], passfile, watch=watch, progress=lambda: operation_wait.file_bytes(destination))
    if not (destination / "toc.dat").is_file() or not (destination.parent / "roles.sql").is_file():
        raise RuntimeError("linux_backup_dump_missing")
    return {"database_size_bytes": database_size, "size_bytes": size_bytes(destination) + (destination.parent / "roles.sql").stat().st_size,
            "duration_seconds": time.monotonic() - started,
            "server_version": version, "migration_ledger_max_version": ledger, "row_counts": counts,
            "consistency_point": {"snapshot_at_utc": point[0], "wal_lsn": point[1],
                                  "xact_snapshot": point[2], "max_event_db_id": max_event_id},
            "roles_file": "roles.sql", "role_passwords": False,
            "format": "directory", "compression": "gzip:3", "jobs": 2}


@dataclass(frozen=True)
class ClickHouse:
    name: str
    host: str
    user: str
    password_setting: str
    timeout: int = TIMEOUT
    deadline: float | None = None
    port: int = 8123
    archive_root: Path | None = None
    disk_root: Path | None = None
    server_root: PurePosixPath | None = None
    operation_size: int = 0
    operation_file: Path | None = None
    _transport: dict | None = field(default=None, repr=False, compare=False)

    def query(self, statement: str) -> list[dict]:
        if not statement.startswith(('BACKUP ', 'RESTORE ', 'SELECT count()')):
            return self._query(statement)
        if self.deadline is not None and self.deadline <= time.monotonic():
            raise TimeoutError('linux_backup_clickhouse_deadline_exceeded')
        action = ('backup' if statement.startswith('BACKUP ') else
                  'restore' if statement.startswith('RESTORE ') else 'scan')
        size = self.operation_size
        if action in {'backup', 'scan'}:
            rows = replace(self, timeout=5, deadline=None)._query(
                'SELECT sum(bytes_on_disk) AS bytes FROM system.parts WHERE active')
            size = int(rows[0]['bytes'] or 0) if rows else size
        watch = operation_wait.Watch(self.name + '_' + action, minimum=self.timeout, size=size,
                                     history=operation_wait.history_path())
        transport = {}
        target = replace(self, timeout=min(self.timeout, operation_wait.POLL_SECONDS),
                         deadline=None, _transport=transport)
        query_id = 'sli_backup_query_' + uuid.uuid4().hex
        if action != 'scan':
            statement += (', id=' if ' SETTINGS ' in statement else ' SETTINGS id=') + ch_literal(query_id)
        statement = re.sub(r'\bmax_execution_time=[0-9.]+',
                           'max_execution_time=0', statement)
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(target._query, statement, query_id=query_id)
        try:
            while True:
                try:
                    rows = future.result(timeout=operation_wait.POLL_SECONDS)
                    watch.success()
                    if action == 'backup' and rows:
                        rows = [{**rows[0], '_source_bytes': size}, *rows[1:]]
                    return rows
                except FutureTimeout:
                    if future.done():
                        raise  # The HTTP worker itself failed with a timeout.
                    try:
                        probe = replace(self, timeout=5, deadline=None)._query(
                            'SELECT * FROM system.processes WHERE query_id=' + ch_literal(query_id) if action == 'scan'
                            else 'SELECT * FROM system.backups WHERE id=' + ch_literal(query_id))
                        progress = tuple(tuple(int(row.get(key, 0) or 0) for key in
                                               ('num_files', 'total_size', 'num_entries', 'uncompressed_size',
                                                'compressed_size', 'files_read', 'bytes_read', 'read_rows',
                                                'read_bytes', 'written_rows', 'written_bytes')) for row in probe)
                    except Exception:  # noqa: BLE001 - unavailable telemetry cannot reset a stall
                        progress = None
                    if self.operation_file is not None:
                        progress = operation_wait.file_bytes(self.operation_file), progress
                    watch.check(progress)
        except BaseException:
            # Keep the original cancellation and never permit cleanup while a
            # generated RESTORE is still writing to the disposable databases.
            if not future.done():
                cancel_failed = False
                try:
                    replace(self, timeout=30, deadline=None, _transport=None)._query(
                        'KILL QUERY WHERE query_id=' + ch_literal(query_id) + ' SYNC')
                except Exception:  # noqa: BLE001 - unconfirmed cancellation requires preserving work
                    cancel_failed = True
                finally:
                    self.cancel_transport(transport)
                try:
                    future.result(timeout=35)
                except FutureTimeout:
                    if not future.done():
                        raise RuntimeError('linux_backup_restore_cleanup_required') from None
                except Exception:  # noqa: BLE001 - preserve original safe diagnostic
                    pass
                if cancel_failed:
                    raise RuntimeError('linux_backup_restore_cleanup_required') from None
            raise
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    @staticmethod
    def cancel_transport(transport):
        """Unblock only this worker's HTTP read, including Connection: close."""
        transport['cancelled'] = True
        stream = transport.get('socket')
        if stream is not None:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        connection = transport.get('connection')
        if connection is not None:
            connection.close()

    def _query(self, statement: str, *, query_id=None) -> list[dict]:
        timeout = self.timeout
        endpoint = "/?default_format=JSON"
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
            if timeout <= 0:
                raise TimeoutError("linux_backup_clickhouse_deadline_exceeded")
            query_id = query_id or "sli_backup_query_" + uuid.uuid4().hex
            endpoint += f"&max_execution_time={timeout:.3f}&timeout_before_checking_execution_speed=0"
        if query_id is not None:
            endpoint += "&query_id=" + query_id
        if self._transport is not None:
            endpoint += '&max_execution_time=0'
        connection = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        if self._transport is not None:
            self._transport['connection'] = connection
        try:
            credentials = f"{self.user}:{read_secret(self.password_setting)}".encode()
            connection.request("POST", endpoint, body=statement.encode("utf-8"), headers={
                "Authorization": "Basic " + base64.b64encode(credentials).decode("ascii"),
                "Content-Type": "text/plain; charset=utf-8",
            })
            if self._transport is not None:
                self._transport['socket'] = connection.sock
                if self._transport.get('cancelled'):
                    self.cancel_transport(self._transport)
                    raise OSError('operation_cancelled')
                connection.sock.settimeout(None)
            response = connection.getresponse()
            if response.status != 200:
                numbers = {"http_status": response.status}
                native_code = response.getheader("X-ClickHouse-Exception-Code", "")
                if re.fullmatch(r"[0-9]{1,6}", native_code):
                    numbers["clickhouse_code"] = int(native_code)
                raise BackupError("linux_backup_clickhouse_failed", **numbers)
            payload = response.read(1024 * 1024 + 1)
            if len(payload) > 1024 * 1024:
                raise RuntimeError("linux_backup_clickhouse_response_limit")
            # DDL such as CREATE/DROP DATABASE returns an empty body, not JSON.
            if not payload.strip():
                return []
            return json.loads(payload)["data"]
        except (OSError, http.client.HTTPException):
            # A client timeout alone does not stop the server's RESTORE. Cancel
            # only this generated query before the caller drops temporary DBs.
            if query_id is not None and not (self._transport or {}).get('cancelled'):
                try:
                    replace(self, timeout=30, deadline=None, _transport=None).query(
                        f"KILL QUERY WHERE query_id={ch_literal(query_id)} SYNC")
                except Exception:  # noqa: BLE001, S110 - operator cleanup may still be needed; preserve original failure
                    pass
            raise
        finally:
            connection.close()

    def table_names(self, database: str) -> list[str]:
        """List data tables without reading their parts."""
        tables = self.query("SELECT name FROM system.tables WHERE database=" + ch_literal(database)
                            + " AND engine LIKE '%MergeTree%' ORDER BY name")
        return [table["name"] for table in tables]

    def statistics(self, database: str) -> dict:
        """Physical rows and nonpersonal watermarks; views are not snapshot data."""
        result = {}
        for name in self.table_names(database):
            columns = self.query("SELECT name, type FROM system.columns WHERE database="
                                 + ch_literal(database) + " AND table=" + ch_literal(name) + " ORDER BY name")
            watermarks = [column["name"] for column in columns
                          if column["type"].removeprefix("Nullable(").startswith("DateTime")
                          or (column["name"] in CH_WATERMARK_IDS
                              and column["type"].removeprefix("Nullable(").startswith(("UInt", "Int")))]
            expressions = ["count() AS row_count"] + [
                f"toString(maxOrNull({ch_identifier(column)})) AS max_{index}"
                for index, column in enumerate(watermarks)
            ]
            timeout = self.timeout
            if self.deadline is not None:
                timeout = min(timeout, self.deadline - time.monotonic())
                if timeout <= 0:
                    raise TimeoutError("linux_backup_clickhouse_deadline_exceeded")
            rows = self.query("SELECT " + ", ".join(expressions) + " FROM "
                              + ch_identifier(database) + "." + ch_identifier(name)
                              + f" SETTINGS {CH_BACKUP_LIMITS}, max_execution_time={timeout:.3f}, "
                              "timeout_before_checking_execution_speed=0, max_memory_usage=536870912")
            if len(rows) != 1:
                raise RuntimeError("linux_backup_clickhouse_invalid_metrics")
            result[name] = {"row_count": int(rows[0]["row_count"]), "max_values": {
                column: rows[0][f"max_{index}"] for index, column in enumerate(watermarks)
            }}
        return result

    def backup_disk_path(self, archive: Path) -> str:
        """Map the admitted local archive root to the live ClickHouse disk.

        Compose mounts the same directory at /backups in this helper and at
        /var/lib/clickhouse/backups/scheduled in both ClickHouse services.
        Native services use separate local staging/disk roots. Verify the live
        disk root before backup/restore, including nested update checkpoints.
        """
        root = self.archive_root or backup_root()
        mount = self.server_root or self.archive_root or Path("/var/lib/clickhouse/backups/scheduled")
        try:
            relative = archive.absolute().relative_to(root)
            if archive.absolute() != archive.resolve() or root != root.resolve():
                raise ValueError()
            disks = self.query("SELECT path FROM system.disks WHERE name='backups'")
            if len(disks) != 1:
                raise ValueError()
            disk_root = PurePosixPath(disks[0]["path"]) if self.server_root else Path(disks[0]["path"])
            if not disk_root.is_absolute() or ".." in disk_root.parts:
                raise ValueError()
            expected_disk = self.server_root or self.disk_root
            if expected_disk is not None and disk_root != expected_disk:
                raise ValueError()
            prefix = mount.relative_to(disk_root)
        except (ValueError, KeyError, TypeError):
            raise RuntimeError("linux_backup_clickhouse_disk_path_mismatch") from None
        return (PurePosixPath(prefix.as_posix()) / PurePosixPath(relative.as_posix())).as_posix()

    @contextmanager
    def archive_workspace(self, root: Path):
        # Native CH sees only its own setgid staging, never published PG/files.
        parent = canonical_directory(self.archive_root) if self.archive_root else root
        with tempfile.TemporaryDirectory(prefix=".restore-", dir=parent) as temporary:
            staging = Path(temporary)
            staging.chmod(0o2770)
            try:
                yield staging
            finally:
                operation_wait.remove_tree(staging)

    @contextmanager
    def readable_archive(self, source: Path, root: Path, *, private: bool = False):
        if self.archive_root is None and not private:
            yield self.backup_disk_path(source)
            return
        with self.archive_workspace(root) as staging:
            archive = staging / (self.name + ".zip")
            operation_wait.copy_file(source, archive)
            archive.chmod(0o640)
            yield self.backup_disk_path(archive)

    def backup(self, staging: Path) -> dict:
        if self.archive_root is not None:
            with self.archive_workspace(staging) as private:
                result = self.capture_archive(private)
                operation_wait.copy_file(private / (self.name + ".zip"), staging / (self.name + ".zip"))
                return result
        return self.capture_archive(staging)

    def capture_archive(self, staging: Path) -> dict:
        started = time.monotonic()
        archive = staging / f"{self.name}.zip"
        disk_path = self.backup_disk_path(archive)
        version = self.query("SELECT version() AS version")[0]["version"]
        databases = self.query("SELECT name FROM system.databases WHERE name NOT IN "
                               "('system', 'information_schema', 'INFORMATION_SCHEMA') "
                               "AND NOT startsWith(name, 'sli_backup_') ORDER BY name")
        if not databases:
            raise RuntimeError("linux_backup_clickhouse_no_databases")
        names = [item["name"] for item in databases]
        objects = ", ".join("DATABASE " + ch_identifier(name) for name in names)
        snapshot_started = utc_now().isoformat()
        # Never open this ZIP through ClickHouse before publication: cached
        # Backup-engine readers can prevent directory renames on Windows binds.
        # Live metrics share the capture window but are not immutable ZIP metrics.
        live_tables = {name: self.statistics(name) for name in names}
        rows = replace(self, operation_file=archive).query(f"BACKUP {objects} TO Disk('backups', {ch_literal(disk_path)}) "
                          f"SETTINGS compression_method='deflate', compression_level=3, {CH_BACKUP_LIMITS}")
        if (not rows or rows[0].get("status") != "BACKUP_CREATED"
                or not archive.is_file() or archive.stat().st_size == 0):
            raise RuntimeError("linux_backup_clickhouse_incomplete")
        snapshot_completed = utc_now().isoformat()
        return {"size_bytes": size_bytes(archive), "duration_seconds": time.monotonic() - started,
                "database_size_bytes": int(rows[0].get('_source_bytes') or size_bytes(archive)),
                "server_version": version, "databases": names, "archive": archive.name,
                "table_names": {name: list(tables) for name, tables in live_tables.items()},
                "live_tables": live_tables, "snapshot_started_at_utc": snapshot_started,
                "snapshot_completed_at_utc": snapshot_completed}


def clickhouse_targets() -> tuple[ClickHouse, ...]:
    if native_mode():
        return ()
    targets = []
    native = native_mode()
    for name, docker_host, default_user, user_setting, port in (
        ("history", "clickhouse", "sli_history", "SLI_HISTORY_CLICKHOUSE_USER", 8123),
        ("warm", "warm-tier", "default", "ADLOG_WARM_CLICKHOUSE_USER", 8124 if native else 8123),
    ):
        prefix = f"SLI_{name.upper()}_CLICKHOUSE"
        endpoint_prefix = f"ADLOG_{name.upper()}_CLICKHOUSE"
        host = os.environ.get(endpoint_prefix + "_HOST", "127.0.0.1" if native else docker_host)
        if (not re.fullmatch(r"[a-zA-Z0-9_.:-]+", host)
                or (native and host not in {"127.0.0.1", "::1", "localhost"})):
            raise ValueError("linux_backup_invalid_settings")
        archive_root = disk_root = server_root = None
        if native:
            archive_root = canonical_directory(os.environ.get(
                prefix + "_BACKUP_ROOT", str(backup_root() / "staging" / name)))
            disk_root = canonical_directory(os.environ.get(prefix + "_BACKUP_DISK_ROOT", str(archive_root)))
            if not archive_root.is_relative_to(disk_root):
                raise ValueError("linux_backup_invalid_settings")
            if prefix + "_BACKUP_SERVER_ROOT" in os.environ:
                supplied = os.environ[prefix + "_BACKUP_SERVER_ROOT"]
                if supplied != "/var/lib/clickhouse/backups":
                    raise ValueError("linux_backup_invalid_settings")
                server_root = PurePosixPath(supplied)
        targets.append(ClickHouse(name, host, os.environ.get(user_setting, default_user), prefix + "_PASSWORD",
                                  port=configured_port(endpoint_prefix + "_PORT", port),
                                  archive_root=archive_root, disk_root=disk_root, server_root=server_root))
    if native:  # noqa: SIM102 - keep the native topology check grouped
        if (targets[0].port == targets[1].port
                or targets[0].disk_root.is_relative_to(targets[1].disk_root)
                or targets[1].disk_root.is_relative_to(targets[0].disk_root)
                or any(backup_root().is_relative_to(target.disk_root) for target in targets)):
            raise ValueError("linux_backup_invalid_settings")
    return tuple(targets)


def supported_components() -> tuple[str, ...]:
    return ("postgres", "files") if native_mode() else COMPONENTS


def default_components() -> tuple[str, ...]:
    supported = supported_components()
    return supported if "SLI_BACKUP_FILES_ROOT" in os.environ else supported[:-1]


def complete_backups(root: Path, selected: tuple[str, ...]):
    """Read only metadata and artifact presence, never rehash large recovery sets."""
    for path in reversed(successful_backups(root)):
        try:
            manifest = json.loads((path / "manifest.json").read_bytes())
            completed = datetime.fromisoformat(manifest["completed_at_utc"])
            if completed.tzinfo is None or completed > utc_now() or set(manifest["components"]) != set(selected):
                continue
            artifacts = [path / f"{name}.zip" for name in selected if name in {"history", "warm"}]
            if "postgres" in selected:
                if (path / "postgres").is_symlink():
                    continue
                artifacts.append(path / "postgres/toc.dat")
            if any(item.is_symlink() or not item.is_file() or item.stat().st_size == 0 for item in artifacts):
                continue
            if "files" in selected and ((path / "files").is_symlink() or not (path / "files").is_dir()):
                continue
            yield path, completed
        except (OSError, ValueError, KeyError, TypeError):
            continue


def recent_backup(root: Path, selected: tuple[str, ...]) -> Path | None:
    for path, completed in complete_backups(root, selected):
        if (utc_now() - completed).total_seconds() <= REUSE_SECONDS:
            return path
    return None


def latest_full_backup(root: Path) -> tuple[Path, datetime] | None:
    roots = [root]
    checkpoints = root / "update-checkpoints"
    if not checkpoints.is_symlink() and checkpoints.is_dir():
        roots.extend(path for path in checkpoints.iterdir()
                     if not path.is_symlink() and path.is_dir() and re.fullmatch(r"[a-f0-9]{32}", path.name))
    # A receipt can be missing after publication or can describe a later failure.
    # The immutable manifest is authoritative, including full update checkpoints.
    return max((item for directory in roots
                for item in complete_backups(directory, default_components())),
               key=lambda item: item[1], default=None)


def backup_time() -> tuple[int, int]:
    value = os.environ.get("SLI_BACKUP_TIME", "02:00")
    if not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value):
        raise ValueError("linux_backup_invalid_settings")
    return tuple(map(int, value.split(":")))


def schedule_anchor(latest: tuple[Path, datetime] | None, interval: int) -> datetime | None:
    """Daily captures persist their UTC start in the immutable directory name.

    Other intervals retain completion-based spacing. Older or malformed names
    conservatively use completion as the calendar anchor, without new state.
    """
    if latest is None:
        return None
    path, completed = latest
    if interval == 86400:
        try:
            started = datetime.strptime(path.name, "%Y%m%dT%H%M%S.%fZ").replace(tzinfo=timezone.utc)
            if started <= completed:
                return started
        except ValueError:
            pass
    return completed


def next_backup_time(earliest: datetime, last_success: datetime | None, interval: int,
                     scheduled: tuple[int, int]) -> datetime:
    """Round forward from a daily start anchor, or a nondefault completion interval."""
    if last_success is not None:
        if interval == 86400:
            # Daily means the next local calendar date after capture start,
            # not 24 hours after completion (which skips the following slot).
            next_date = last_success.astimezone().replace(
                hour=0, minute=0, second=0, microsecond=0, tzinfo=None) + timedelta(days=1)
            earliest = max(earliest, next_date.astimezone(timezone.utc))
        else:
            earliest = max(earliest, last_success + timedelta(seconds=interval))
    # Convert each calendar date through the server's local timezone rules, so
    # daylight-saving transitions do not turn 02:00 into a permanently fixed UTC hour.
    local = earliest.astimezone()
    candidate = local.replace(hour=scheduled[0], minute=scheduled[1], second=0, microsecond=0, tzinfo=None)
    if candidate.astimezone(timezone.utc) < earliest:
        candidate += timedelta(days=1)
    return candidate.astimezone(timezone.utc)


def read_result(root: Path) -> dict:
    try:
        result = json.loads((root / "last_result.json").read_bytes())
        if (result["last_result"] in {"success", "failed"}
                and set(result["components"]) == set(default_components())
                and (result["last_success"] is None or BACKUP_NAME.fullmatch(result["last_success"]))):
            return result
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return {}


def record_result(root: Path, selected: tuple[str, ...], result: str, path: Path | None = None) -> None:
    # Partial captures cannot repair the health of the full scheduled recovery set.
    if set(selected) == set(default_components()):
        write_json(root / "last_result.json", {
            "last_result": result, "last_success": path.name if path else read_result(root).get("last_success"),
            "components": list(selected), "completed_at_utc": utc_now().isoformat(),
            "receipt_id": uuid.uuid4().hex,
        })


def run_backup(root: Path, retention: int = 7, *, components: tuple[str, ...] | None = None,
               reuse_recent: bool = False, scheduled_interval: int | None = None,
               writers_fenced: bool = False) -> Path:
    with backup_step("settings"):
        if retention < 1:
            raise ValueError("linux_backup_invalid_retention")
        selected = components if components is not None else default_components()
        # Explicit component callers may request a receipt without data components.
        if len(set(selected)) != len(selected) or not set(selected) <= set(supported_components()):
            raise ValueError("linux_backup_invalid_components")
    with backup_step("lock"), backup_lock(root):
        try:
            with backup_step("reuse"):
                # Recheck under the capture lock: a full update checkpoint may
                # have finished while the scheduled worker waited for that lock.
                latest = latest_full_backup(root) if scheduled_interval is not None else None
                reuse_until = None
                if latest is not None:
                    if scheduled_interval == 86400:
                        reuse_until = next_backup_time(latest[1], schedule_anchor(latest, scheduled_interval),
                                                       scheduled_interval, backup_time())
                    else:
                        reuse_until = latest[1] + timedelta(seconds=scheduled_interval)
                if reuse_until is not None and utc_now() < reuse_until:
                    final = latest[0]
                elif scheduled_interval == 86400:
                    # Once a daily slot is due, completion-based recent reuse
                    # must not substitute the previous calendar day's capture.
                    final = None
                else:
                    final = recent_backup(root, selected) if reuse_recent else None
            if final is None:
                final = capture_backup(root, retention, selected, writers_fenced=writers_fenced)
            else:
                print("linux_backup_reused", flush=True)
        except Exception:
            try:
                record_result(root, selected, "failed")
            except OSError:
                pass  # Preserve the original diagnostic if the backup disk is unavailable.
            raise
        with backup_step("result"):
            record_result(root, selected, "success", final)
            publish_summary(root)
        return final


def publish_summary(root: Path) -> None:
    paths = successful_backups(root)
    manifests = [json.loads((path / 'manifest.json').read_bytes()) for path in paths]
    full = {}
    try:
        full = json.loads((root / 'last_full_restore_check.json').read_bytes())
    except (OSError, ValueError):
        pass
    reserve = backup_policy.space_estimate(max((item.get('components', {}).get('postgres', {}).get('database_size_bytes', 0)
                                               for item in manifests), default=0))['postgres_bytes']
    summary = {'last_backup_at_utc': manifests[-1].get('completed_at_utc') if manifests else None,
               'last_verified_at_utc': full.get('completed_at_utc') if full.get('status') == 'verified' else None,
               'capacity_days': backup_policy.capacity_days(shutil.disk_usage(root).free,
                                                            [item.get('size_bytes', 0) for item in manifests], reserve),
               'observed_at_utc': utc_now().isoformat()}
    directory = root / '.status'
    if directory.is_symlink():
        raise ValueError('linux_backup_invalid_settings')
    directory.mkdir(mode=0o755, exist_ok=True)
    summary['operation_durations'] = operation_wait.read_history(directory / 'summary.json').get('operation_durations', {})
    write_json(directory / 'summary.json', summary)
    (directory / 'summary.json').chmod(0o644)


def capture_backup(root: Path, retention: int, selected: tuple[str, ...], *, writers_fenced: bool = False) -> Path:
    """Capture under the caller's backup lock; checkpoint callers always request a new set."""
    with backup_step("staging"):
        started = time.monotonic()
        stamp = utc_now().strftime("%Y%m%dT%H%M%S.%fZ")
        staging = root / f".{stamp}.partial"
        final = root / stamp
        targets = tuple(target for target in clickhouse_targets() if target.name in selected)
    step = "staging"
    publication_started = False
    try:
        # Preflight both disks before mkdir/pg_dump.
        for target in targets:
            step = "preflight_" + target.name
            if target.archive_root is not None and not target.archive_root.is_dir():
                raise ValueError("linux_backup_invalid_settings")
            target.backup_disk_path((target.archive_root or staging) / f"{target.name}.zip")
        if 'postgres' in selected:
            step = 'capacity'
            if native_mode():
                capture_admission(root)
            else:
                backup_output_admission(root)
        step = "staging"
        staging.mkdir(mode=0o770)
        # Shared group 10001 lets ClickHouse write archives without world access.
        staging.chmod(0o700 if native_mode() else 0o2770)
        step = "postgres"
        components = {"postgres": dump_postgres(staging / "postgres")} if "postgres" in selected else {}
        for target in targets:
            step = target.name
            components[target.name] = target.backup(staging)
        if "files" in selected:
            step = "files"
            components["files"] = backup_files(staging / "files")
        step = "consistency"
        duration = time.monotonic() - started
        capture_limit = None
        if not writers_fenced:
            capture_limit = operation_wait.Watch(
                'capture', minimum=TIMEOUT,
                size=sum(item.get('database_size_bytes', item.get('size_bytes', 0))
                         for item in components.values()),
                history=operation_wait.history_path()).limit
            if duration > capture_limit:
                raise RuntimeError('linux_backup_consistency_window_exceeded')
        step = "inventory"
        manifest = {
            "format_version": 4 if selected != COMPONENTS[:-1] else 3,
            "backup_id": stamp, "status": "success",
            "started_at_utc": stamp, "completed_at_utc": utc_now().isoformat(),
            "duration_seconds": duration, "components": components,
            "consistency_point": {"writers_fenced": writers_fenced,
                                  "mode": "fenced" if writers_fenced else "bounded_acquisition_window",
                                  "max_capture_skew_seconds": capture_limit,
                                  "capture_window_seconds": duration,
                                  "reconciliation": "isolated_drill_required"},
            "size_bytes": sum(item["size_bytes"] for item in components.values()),
            "migration_ledger_max_version": components.get("postgres", {}).get("migration_ledger_max_version"),
            "content_checksums": content_inventory(staging, check=operation_wait.InventoryProgress()),
        }
        step = "manifest"
        write_json(staging / "manifest.json", manifest)
        # Publication and pruning happen only after every component succeeded.
        step = "publication"
        publication_started = True
        publish_backup(staging, final)
        operation_wait.record_success(operation_wait.history_path(), 'capture', duration)
    except Exception as error:
        error.backup_diagnostic = failure_diagnostic(error, step)
        failure = {"status": "failed", "backup_id": stamp, **error.backup_diagnostic}
        try:
            write_json(root / "failure.json", failure)
            if publication_started:
                failure.update(cleanup="pending")
                # All BACKUP operations completed, so this partial is safe to
                # remove. Keep its receipt outside the directory being cleaned.
                write_json(root / "failure.json", failure)
                try:
                    operation_wait.remove_tree(staging)
                except OSError:
                    # Still locked: a later successful backup's prune retries it.
                    write_json(staging / "failure.json", failure)
                else:
                    failure["cleanup"] = "completed"
                    write_json(root / "failure.json", failure)
            elif staging.is_dir():
                write_json(staging / "failure.json", failure)
        except OSError:
            pass  # Receipt failure must not hide the original machine code and step.
        # Earlier failures may leave a server writing after an HTTP timeout;
        # preserve those partials and never prune successful sets on failure.
        raise
    with backup_step("prune"):
        prune(root, retention, final)
    return final


def capture_admission(root: Path, *, regular=False) -> None:
    from deploy.linux.backup_restore_check import postgres_admission

    with pg_passfile() as passfile, pg_connect(passfile) as connection:
        connection.execute('SET TRANSACTION READ ONLY')
        point = connection.execute(PG_CAPACITY_SQL).fetchone()[0]
    component = {'database_size_bytes': point['database_size_bytes']}
    if native_mode():
        from deploy.linux.native_backup import capture_volume_admission, require_separate_disk, ROOT
        from deploy.linux.native_host import Host
        paths = {role: Path(path).resolve() for role, path in pg_capacity_paths(point).items()}
        filesystems = {role: {'device': backup_policy.filesystem(path), 'free_bytes': shutil.disk_usage(path).free}
                       for role, path in paths.items()}
        if regular:
            require_separate_disk(root, paths.values())
        estimate = Host().backup_space_estimate(root if regular else ROOT, pg_bytes=point['database_size_bytes'])
        admit = backup_policy.volume_admission if regular else capture_volume_admission
        admission = admit(root, root, filesystems, estimate['capture_bytes'], work_required=0)
    else:
        admission = postgres_admission(root, point, component)
    if admission['status'] != 'admitted':
        backup_policy.report_refusal(admission)
        raise BackupError(admission['reason'])
    previous = successful_backups(root)
    if previous and not native_mode():
        size = json.loads((previous[-1] / 'manifest.json').read_bytes()).get('size_bytes', 0)
        required = admission['required_bytes'] + backup_policy.space_estimate(backup_bytes=size)['capture_bytes']
        if admission['free_bytes'] < required:
            admission.update(reason='insufficient_backup_disk_space', required_bytes=required)
            backup_policy.report_refusal(admission)
            raise BackupError(admission['reason'])


def backup_output_admission(root: Path) -> None:
    # Capture only reads source databases. Full restore admission below uses a
    # fresh, cluster-bound witness for every data/WAL/tablespace filesystem.
    work = backup_policy.work_root(root)
    if backup_policy.filesystem(root) != backup_policy.filesystem(work):
        admission = {'reason': 'restore_volume_mismatch'}
    else:
        size = backup_policy.last_backup_size(root)
        free = shutil.disk_usage(root).free
        estimate = backup_policy.space_estimate(backup_bytes=size or 0)
        if size is None and free >= backup_policy.GIB:
            with pg_passfile() as passfile, pg_connect(passfile) as connection:
                connection.execute('SET TRANSACTION READ ONLY')
                pg_size = connection.execute('SELECT pg_database_size(current_database())').fetchone()[0]
            expanded = sum(int(target.query('SELECT coalesce(sum(bytes_on_disk), 0) AS size_bytes '
                                            'FROM system.parts WHERE active')[0]['size_bytes'])
                           for target in clickhouse_targets())
            files = backup_policy.tree_bytes(Path(os.environ['SLI_BACKUP_FILES_ROOT'])) if 'SLI_BACKUP_FILES_ROOT' in os.environ else 0
            estimate = backup_policy.space_estimate(pg_size, expanded_ch_bytes=expanded, files_bytes=files)
        required = estimate['capture_bytes']
        admission = ({'reason': 'insufficient_backup_disk_space'}
                     if free < required else {})
        if admission:
            admission.update(required_bytes=required, free_bytes=free, volume=str(root))
    if admission:
        backup_policy.report_refusal(admission)
        raise BackupError(admission['reason'])


# Only pre-CREATE admission deferrals may warn instead of failing the worker.
# Cleanup uncertainty, unknown reasons and execution failures remain failures.
SAFE_RESTORE_DEFERRALS = frozenset({
    "postgres_capacity_unavailable", "postgres_size_estimate_unavailable",
    "insufficient_disk_space", "postgres_restore_busy", "insufficient_backup_disk_space",
    "insufficient_data_disk_space", "restore_volume_mismatch",
})


def light_evidence(root: Path, capture: dict, receipt: dict | None = None, *, manifest_digest: str | None = None) -> bool:
    """Bind integrity evidence to this capture; this is NOT restore admission."""
    try:
        if receipt is None:
            file = root / "restore_check.json"
            if file.is_symlink():
                return False
            receipt = json.loads(file.read_bytes())
        identifier = capture["last_success"]
        if (capture.get("last_result") != "success" or not isinstance(identifier, str)
                or not BACKUP_NAME.fullmatch(identifier) or not capture.get("receipt_id")):
            return False
        path = root / identifier
        manifest = path / "manifest.json"
        if path.is_symlink() or manifest.is_symlink():
            return False
        digest = manifest_digest if manifest_digest is not None else hashlib.sha256(manifest.read_bytes()).hexdigest()
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            return False
        completed = datetime.fromisoformat(capture["completed_at_utc"])
        started = datetime.fromisoformat(receipt["started_at_utc"])
        checked = datetime.fromisoformat(receipt["completed_at_utc"])
        return (receipt.get("status") == "verified" and receipt.get("verification") == "light"
                and receipt.get("backup_id") == identifier
                and receipt.get("capture_receipt_id") == capture["receipt_id"]
                and receipt.get("manifest_sha256") == digest
                and set(receipt["components"]) == {"postgres", "history", "warm"}
                and all(item.get("status") == "verified" for item in receipt["components"].values())
                and completed <= started <= checked <= utc_now())
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return False


def deferred_restore(root: Path, path: Path, result: dict, started: datetime, *, manifest_digest: str | None = None) -> bool:
    """Recognize only an intact admission receipt, never a failed/partial drill."""
    try:
        return (result.get("status") == "skipped" and result.get("verification") == "full"
                and result.get("reason") in SAFE_RESTORE_DEFERRALS
                and result.get("backup_id") == path.name
                and result.get("manifest_sha256") == (manifest_digest if manifest_digest is not None else
                    hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest())
                and set(result["components"]) == {"postgres"}
                and result["components"]["postgres"].get("status") == "skipped"
                and result["components"]["postgres"].get("reason") == result["reason"]
                and started <= datetime.fromisoformat(result["started_at_utc"])
                <= datetime.fromisoformat(result["completed_at_utc"]) <= utc_now())
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return False


def report_assurance(root: Path, reason: str) -> None:
    if read_cycle_failure(root) or read_cycle_result(root).get("status") in {"failed", "unavailable", "running"}:
        print("Копия создана. Предыдущий сбой или незавершённая проверка восстановления не устранены / "
              "Backup created. Previous failure or incomplete restore check remains unresolved "
              "[restore_check_unresolved]", flush=True)
        return
    messages = {
        "full_check_pending": ("Копия создана; полная проверка восстановления — по расписанию",
                               "Backup created; full restore check is scheduled"),
        "postgres_capacity_unavailable": ("Копия создана; проверка отложена: нет свежих сведений о диске базы",
                                          "Backup created; restore check deferred: fresh database disk evidence unavailable"),
        "postgres_size_estimate_unavailable": ("Копия создана; проверка отложена: неизвестен размер базы",
                                               "Backup created; restore check deferred: database size unavailable"),
        "insufficient_disk_space": ("Копия создана; проверка отложена: недостаточно места на диске базы",
                                    "Backup created; restore check deferred: insufficient database disk space"),
        "postgres_restore_busy": ("Копия создана; проверка отложена: другая проверка ещё выполняется",
                                  "Backup created; restore check deferred: another restore check is running"),
    }
    if reason in messages:
        print(" / ".join(messages[reason]) + " [" + reason + "]", flush=True)


def read_cycle_result(root: Path) -> dict:
    """Absent legacy evidence is unknown; damaged evidence must not imply success."""
    try:
        cycle = json.loads((root / "scheduled_cycle.json").read_bytes())
        if (isinstance(cycle, dict) and cycle.get("status") in {"running", "failed", "success", "deferred"}  # noqa: SIM102
                and cycle.get("format_version") == 1):
            if cycle["status"] not in {"success", "deferred"} or (
                    isinstance(cycle.get("capture_result"), dict)
                    and cycle["capture_result"].get("last_result") == "success"
                    and cycle.get("backup_id") == cycle["capture_result"].get("last_success")
                    and cycle["capture_result"].get("receipt_id")
                    and isinstance(cycle.get("backup_id"), str)
                    and BACKUP_NAME.fullmatch(cycle["backup_id"])
                    and datetime.fromisoformat(cycle["started_at_utc"])
                    <= datetime.fromisoformat(cycle["completed_at_utc"]) <= utc_now()):
                if cycle["status"] == "deferred" and not (
                        cycle.get("reason") in SAFE_RESTORE_DEFERRALS
                        # Historical evidence may outlive retention of its artifacts.
                        # Current health below still checks the current manifest.
                        and light_evidence(root, cycle["capture_result"], cycle.get("light_result", {}),
                                           manifest_digest=cycle.get("restore_result", {}).get("manifest_sha256"))
                        and deferred_restore(root, root / cycle["backup_id"], cycle.get("restore_result", {}),
                                             datetime.fromisoformat(cycle["started_at_utc"]),
                                             manifest_digest=cycle.get("light_result", {}).get("manifest_sha256"))):
                    return {"status": "unavailable"}
                return cycle
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        pass
    return {"status": "unavailable"}


def read_cycle_failure(root: Path) -> str | None:
    """Read the heartbeat's fallback failure binding without renewing liveness."""
    try:
        beat = json.loads((root / "heartbeat.json").read_bytes())
        if not isinstance(beat, dict):
            return "unavailable"
        token = beat.get("cycle_failure_id")
        if token is None or isinstance(token, str) and token:
            return token
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError):
        pass
    return "unavailable"


def merge_result(root: Path, beat: dict, *, worker_failed: bool = False) -> None:
    result = read_result(root)
    if result:
        beat.update(last_success=result["last_success"], last_result=result["last_result"])
        if beat["status"] != "running":
            beat["status"] = "success" if result["last_result"] == "success" else "failed"
    if native_mode():
        return
    cycle = read_cycle_result(root)
    beat["cycle_status"] = cycle.get("status", "unknown")
    failure_id = read_cycle_failure(root)
    if failure_id == "unavailable":
        failure_id = uuid.uuid4().hex  # Bind unreadable state; never reuse a sentinel as recovery proof.
    complete = cycle.get("status") == "success" and result == cycle["capture_result"]
    deferred = (cycle.get("status") == "deferred" and result == cycle["capture_result"]
                and light_evidence(root, result, cycle["light_result"]))
    pending = cycle.get("status") in {None, "success", "deferred"} and light_evidence(root, result)
    beat["capture_status"] = result.get("last_result", "unknown")
    beat["restore_assurance"] = "full" if complete else "deferred" if deferred else "pending" if pending else "unknown"
    beat.pop("warning_reason", None)
    if deferred or pending:
        beat["warning_reason"] = cycle["reason"] if deferred else "full_check_pending"
    # A capture/light check never repairs an incomplete or failed required drill.
    # Compare the exact capture receipt, including its unique ID: a newer manual
    # attempt (even on the same set/clock tick) cannot inherit an older full cycle.
    if cycle.get("status") in {"running", "failed"}:
        beat["last_result"] = "failed"
    elif complete or deferred or pending:
        beat["last_result"] = "success"
    elif cycle or result or beat.get("last_result") == "success" or beat["status"] == "success":
        beat["last_result"] = "failed" if result.get("last_result") == "failed" else "unknown"
    # If the initial cycle write fails, the heartbeat is the durable fallback.
    # Recovery must causally acknowledge this failure token in a NEW full cycle;
    # old success or process restart cannot clear it (even at identical times).
    genuine_failure = result.get("last_result") == "failed" or cycle.get("status") in {"failed", "unavailable"}
    if worker_failed or genuine_failure or failure_id and not (complete and cycle.get("recovery_of") == failure_id):
        beat["cycle_failure_id"] = failure_id or uuid.uuid4().hex
        beat["last_result"] = "failed"
        beat["restore_assurance"] = "failed"
        beat.pop("warning_reason", None)
    else:
        beat.pop("cycle_failure_id", None)
    if beat.get("last_result") in {"failed", "unknown"} and beat["status"] != "running":
        beat["status"] = "failed"


def heartbeat(root: Path, status: str, last_success: str | None, last_result: str | None = None,
              *, next_backup: datetime | None = None) -> None:
    # This short lock must be independent of the hours-long capture lock.
    with backup_lock(root, name=".heartbeat.lock"):
        beat = {"status": status, "process_pid": os.getpid(), "heartbeat_at_utc": utc_now().isoformat(),
                "last_success": last_success, "last_result": last_result,
                "next_backup_at_utc": next_backup.isoformat() if next_backup is not None else None}
        merge_result(root, beat, worker_failed=last_result == "failed")
        write_json(root / "heartbeat.json", beat)


def refresh_heartbeat(root: Path) -> None:
    with backup_lock(root, name=".heartbeat.lock"):
        try:
            beat = json.loads((root / "heartbeat.json").read_bytes())
            if not isinstance(beat, dict) or "status" not in beat:
                return
        except (OSError, ValueError):
            return
        # --once refreshes capture evidence, but cannot repair a required full drill
        # or impersonate PID 1 or renew its liveness.
        merge_result(root, beat)
        write_json(root / "heartbeat.json", beat)


def healthy(root: Path) -> bool:
    try:
        beat = json.loads((root / "heartbeat.json").read_text(encoding="utf-8"))
        age = (utc_now() - datetime.fromisoformat(beat["heartbeat_at_utc"])).total_seconds()
        return (beat["process_pid"] == 1 and beat["status"] in {"waiting", "running", "success"}
                and beat.get("last_result") not in {"failed", "unknown"}
                and 0 <= age <= 90)
    except (OSError, ValueError, KeyError, TypeError):
        return False


def scheduled_backup(root: Path, retention: int, *, reuse_recent: bool, scheduled_interval: int) -> Path:
    """Run the full drill after the nightly capture, including a reused full set."""
    # Keep the update probe busy across the gap between capture and restore.
    with backup_lock(root, name=".scheduled-backup.lock"):
        return _scheduled_backup_locked(root, retention, reuse_recent=reuse_recent,
                                        scheduled_interval=scheduled_interval)


def _scheduled_backup_locked(root: Path, retention: int, *, reuse_recent: bool, scheduled_interval: int) -> Path:
    from deploy.linux.backup_restore_check import restore_check

    cycle = {"format_version": 1, "status": "running", "started_at_utc": utc_now().isoformat(),
             "recovery_of": read_cycle_failure(root)}
    # Publish before any work: interruption or a failed final write stays incomplete
    # across restart. Only the scheduled-lock holder can finish this cycle.
    write_json(root / "scheduled_cycle.json", cycle)
    try:
        path = run_backup(root, retention, reuse_recent=reuse_recent, scheduled_interval=scheduled_interval)
        cycle.update(backup_id=path.name, capture_result=read_result(root))
        write_json(root / "scheduled_cycle.json", cycle)
        drill_started = utc_now()
        result = restore_check(root, selected=path)
        if deferred_restore(root, path, result, drill_started):
            # Prove the capture's integrity without claiming a restore. Preserve
            # the skip as the authoritative update admission receipt.
            from deploy.linux.backup_restore_check import light_check

            light = light_check(root, selected=path, publish_receipt=False)
            if read_result(root) != cycle["capture_result"] or not light_evidence(root, cycle["capture_result"], light):
                raise RuntimeError("linux_backup_restore_check_failed")
            cycle.update(status="deferred", reason=result["reason"], light_result=light,
                         restore_result=result, completed_at_utc=utc_now().isoformat())
            write_json(root / "scheduled_cycle.json", cycle)
            report_assurance(root, result["reason"])
            return path
        started = datetime.fromisoformat(result.get("started_at_utc", ""))
        completed = datetime.fromisoformat(result.get("completed_at_utc", ""))
        if (result.get("status") != "verified" or result.get("verification") != "full"
                or result.get("backup_id") != path.name
                or not drill_started <= started <= completed <= utc_now()
                or any(result.get("components", {}).get(name, {}).get("status") != "verified"
                       for name in default_components() if name != "files")
                or cycle["capture_result"].get("last_result") != "success"
                or cycle["capture_result"].get("last_success") != path.name):
            raise RuntimeError("linux_backup_restore_check_failed")
        cycle.update(status="success", completed_at_utc=completed.isoformat())
        write_json(root / "scheduled_cycle.json", cycle)
    except Exception:
        cycle.update(status="failed", completed_at_utc=utc_now().isoformat())
        try:
            write_json(root / "scheduled_cycle.json", cycle)
        except OSError:
            pass  # The durable running marker remains fail-closed; retain the original error.
        print("linux_backup_restore_check_failed", flush=True)
        raise
    print("linux_backup_restore_check_verified", flush=True)
    return path


def serve(root: Path, *, interval: int, delay: int, retention: int) -> None:
    from deploy.linux.backup_restore_check import (
        startup_capture,
        startup_light_check,
        startup_restore_cleanup,
    )
    from deploy.linux.legacy_runtime import shutdown

    startup_restore_cleanup(root)
    status, last_success, last_result = "waiting", None, None
    scheduled = backup_time()
    latest = latest_full_backup(root)
    startup_ready = utc_now() + timedelta(seconds=delay)
    deadline = next_backup_time(startup_ready, schedule_anchor(latest, interval),
                                interval, scheduled)
    future = None
    with ThreadPoolExecutor(max_workers=1) as executor:
        capture = startup_capture(root)
        if capture:
            # Integrity scans may take longer than a health probe. Keep liveness
            # fresh, but remain unknown until real evidence exists. Share the
            # scheduled worker so no new capture/full drill overlaps this scan.
            future = executor.submit(startup_light_check, root, capture)
        while not shutdown.requested():
            if future is not None and future.done():
                try:
                    completed = future.result()
                    last_success = completed.name if completed is not None else None
                    status = "success" if completed is not None else "waiting"
                    last_result = "success" if completed is not None else None
                    if completed is not None:
                        print("linux_backup_succeeded", flush=True)
                except Exception as error:  # noqa: BLE001 - only fixed diagnostics may escape
                    status = "failed"
                    last_result = "failed"
                    report_failure(error, "serve")
                future = None
                latest = latest_full_backup(root)
                earliest = utc_now()
                if last_result == "failed" or latest is None:
                    earliest += timedelta(seconds=interval)
                deadline = next_backup_time(earliest, schedule_anchor(latest, interval),
                                            interval, scheduled)
            if future is None:
                # --once and the updater can publish while this process is waiting.
                observed = latest_full_backup(root)
                if observed != latest:
                    latest = observed
                    deadline = next_backup_time(max(utc_now(), startup_ready), schedule_anchor(latest, interval),
                                                interval, scheduled)
            if future is None and utc_now() >= deadline:
                status = "running"
                future = executor.submit(scheduled_backup, root, retention, reuse_recent=True, scheduled_interval=interval)
            heartbeat(root, status, last_success, last_result, next_backup=deadline if future is None else None)
            shutdown.wait(30, sleep=time.sleep)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--healthcheck", action="store_true")
    parser.add_argument("--publish-pg-capacity", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--component", action="append", choices=COMPONENTS)
    args = parser.parse_args(argv)
    step = "settings"
    try:
        root = backup_root()
        if args.publish_pg_capacity:
            if args.once or args.healthcheck or args.component:
                raise ValueError("linux_backup_invalid_settings")
            raw = sys.stdin.buffer.read(65537)
            if len(raw) > 65536:
                raise ValueError("linux_backup_invalid_capacity")
            publish_pg_capacity(root, json.loads(raw))
            return 0
        if args.healthcheck:
            return 0 if healthy(root) else 1
        interval = int(os.environ.get("SLI_BACKUP_INTERVAL_SECONDS", "86400"))
        delay = int(os.environ.get("SLI_BACKUP_START_DELAY_SECONDS", "300"))
        retention, _ = backup_policy.retention_settings()
        if interval < 60 or delay < 0 or retention < 1:
            raise ValueError("linux_backup_invalid_settings")
        if args.once:
            step = "once"
            selected = tuple(args.component) if args.component else default_components()
            path = run_backup(root, retention, components=selected, reuse_recent=True)
            if set(selected) == set(default_components()):
                from deploy.linux.backup_restore_check import light_check

                step = "integrity"
                light_check(root, selected=path)
            step = "heartbeat"
            refresh_heartbeat(root)
            if set(selected) == set(default_components()):
                report_assurance(root, "full_check_pending")
            print("linux_backup_succeeded")
        else:
            if args.component:
                raise ValueError("linux_backup_components_require_once")
            step = "serve"
            from deploy.linux.legacy_runtime import shutdown

            with shutdown.graceful_shutdown():
                serve(root, interval=interval, delay=delay, retention=retention)
    except Exception as error:  # noqa: BLE001 - database, HTTP and filesystem errors may contain private data
        report_failure(error, step)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

