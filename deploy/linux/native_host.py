"""Administrative Debian storage, account and database configuration.

Preparation installs vendor guards and may start a directory bind mount.
Database starts remain an explicit operation of the installation coordinator.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

try:
    from deploy.linux.native_preinstall import GuardError, cluster_guard, ensure_directory, existing_database, write_guard
except ModuleNotFoundError:  # stdlib-only installed/recovery helper under -I.
    import importlib.util
    _permissions_spec = importlib.util.spec_from_file_location(
        "sli_native_preinstall", Path(__file__).with_name("native_preinstall.py"))
    _permissions = importlib.util.module_from_spec(_permissions_spec)
    _permissions_spec.loader.exec_module(_permissions)
    GuardError = _permissions.GuardError
    cluster_guard = _permissions.cluster_guard
    ensure_directory = _permissions.ensure_directory
    existing_database = _permissions.existing_database
    write_guard = _permissions.write_guard


try:
    import fcntl
    import grp
    import pwd
except ModuleNotFoundError:  # Pure renderers/fake tests also run on Windows.
    fcntl = grp = pwd = None

try:
    from deploy.linux import native_clickhouse_endpoint as clickhouse
    from deploy.linux import backup_policy
except ModuleNotFoundError:  # Debian stdlib-only -I host launcher.
    _spec = importlib.util.spec_from_file_location(
        "sli_clickhouse_endpoint", Path(__file__).with_name("native_clickhouse_endpoint.py"))
    clickhouse = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(clickhouse)
    _spec = importlib.util.spec_from_file_location(
        "sli_backup_policy", Path(__file__).with_name("backup_policy.py"))
    backup_policy = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(backup_policy)


MOUNT = "/srv/sli-db"
DIRECTORY = "/var/lib/sli-db"
MOUNT_UNIT = r"srv-sli\x2ddb.mount"
MIN_DATABASE_FREE = 20 * 1024**3
STATE = "/var/lib/sli/state"
HELPER = "/usr/lib/sli/native_host.py"
VENDOR_START_FILES = ("/lib/systemd/system/clickhouse-server.service", "/etc/init.d/clickhouse-server")
CREDENTIALS_ROOT = Path("/run/credentials")
ACCOUNTS = tuple("sli-" + name for name in (
    "api", "post", "projection", "semantic", "entity", "storage", "context", "remote",
    "exec-light", "exec-heavy", "exec-long", "notify", "report"))
INSTANCES = clickhouse.INSTANCES
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")
SYSTEMD_DIRECTORY = "/etc/systemd/system"
SYSTEMD_FILE = r"sli(?:-[A-Za-z0-9_.@-]*)?\.(?:service|target|timer|slice|mount|socket|path)(?:\.d)?"
SYSTEMD_PATH = re.compile(r"/(?:etc|usr/lib)/systemd/system/(?:" + SYSTEMD_FILE + r"|srv-sli\\x2ddb\.mount(?:\.d)?)")
BACKUP_DROP_IN = "80-sli-backup-mount.conf"
BACKUP_DROP_IN_BODY = "[Unit]\nBindsTo=var-backups-sli.mount\nAfter=var-backups-sli.mount\n"
ROOT_UID = 0
BOOTSTRAP_MARKER = Path(MOUNT + "/pgdata/18/main/.sli-bootstrap.json")
COLD_TABLESPACE = "sli_temp_hdd"
COLD_TABLES = ("sli_agent_packet_inbox", "event_source_representations_v2",
               "storage_v2_archive_sets", "storage_v2_archive_blocks")


class HostError(RuntimeError):
    """Fixed diagnostics only: subprocess output can contain private material."""

    def __init__(self, code, *, command=None, unit=None):
        super().__init__(code)
        self.command = command
        self.unit = unit


def configuration_conflict(*paths):
    code = "native_existing_configuration_conflict"
    if not all(SYSTEMD_PATH.fullmatch(path) for path in paths):
        return GuardError(code, paths[0], "existing file differs from SLI's configuration",
                          f"Run sudo stat -- {shlex.quote(paths[0])} and reconcile it with the installed kit before retrying")
    arguments = " ".join(map(shlex.quote, paths))
    error = GuardError(code, ", ".join(paths), "existing systemd files conflict with SLI setup",
                       "After verifying they belong to a retired installation, run "
                       "sudo sh -c 'd=$(mktemp -d /etc/systemd/sli-before-setup.XXXXXX) || exit; "
                       'for p; do t="$d${p%/*}"; mkdir -p -- "$t" && mv -t "$t" -- "$p" || exit; done; '
                       "systemctl daemon-reload' sh " + arguments + " and retry")
    error.conflict_paths = paths
    return error


def run(argv, *, input=None, allow_no_unit_files=False):
    result = subprocess.run(argv, input=input, capture_output=True, text=True, check=False,
                            timeout=150, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if result.returncode:
        if allow_no_unit_files and result.returncode == 1 and not (result.stdout.strip() or result.stderr.strip()):
            return ""
        command = Path(argv[0]).name
        unit = None
        if command == "systemctl":
            command = " ".join(argv[:2])
            if ((len(argv) == 3 and argv[1] in {"stop", "reset-failed"})
                    or (len(argv) == 4 and argv[1:3] == ["disable", "--now"])):
                unit = argv[-1]
        raise HostError("native_command_failed", command=command, unit=unit)
    return result.stdout


def port_listeners(port):
    try:
        output = run(["ss", "-H", "-ltnp", f"sport = :{port}"])
    except (HostError, OSError, subprocess.SubprocessError):
        return []
    entries = re.findall(r'\("([A-Za-z0-9_.@+-]{1,32})",pid=([1-9][0-9]{0,9}),fd=[0-9]+\)', output)
    return list(dict.fromkeys(f"{name} (PID {pid})" for name, pid in entries))[:5]


def pg_cold(sql):
    """Local peer administration, no passwords, deadline or foreign SQL output."""
    argv = ["runuser", "-u", "postgres", "--", "/usr/lib/postgresql/18/bin/psql",
            "-XqAt", "-w", "-h", "/var/run/postgresql", "-p", "5432", "-d", "sli",
            "-v", "ON_ERROR_STOP=1"]
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                                               "PGAPPNAME": "sli-cold-tables"})
    body = "SET statement_timeout=0; SET lock_timeout=0;\n" + sql
    try:
        while True:
            try:
                output, error = process.communicate(body, timeout=10)
                break
            except subprocess.TimeoutExpired:
                body = None
                print(f"PostgreSQL выполняет шаг или ожидает блокировку; процесс {process.pid} жив.", flush=True)
        if process.returncode:
            for code in ("native_cold_tablespace_conflict", "native_cold_relation_changed"):
                if re.search(r"ERROR:\s+" + code + r"(?:\s|$)", error):
                    raise HostError(code)
            raise HostError("native_cold_sql_failed")
        return output.strip()
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate()


def cold_mount_dropin(root):
    clickhouse.cold_tablespace_root_path(root)
    return (f"[Unit]\nRequiresMountsFor={root}\n[Service]\n"
            f"ExecStartPre=+/usr/bin/python3 -B {HELPER} check-cold-mount\n")


def cold_tablespace_sql(root):
    clickhouse.cold_tablespace_root_path(root)
    location = root + "/pg-tablespace"
    return ("DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname='sli_temp_hdd' "
            f"AND (pg_tablespace_location(oid)<>'{location}' OR spcowner<>(SELECT oid FROM pg_roles "
            "WHERE rolname='postgres'))) THEN RAISE EXCEPTION 'native_cold_tablespace_conflict'; END IF; END $$;\n"
            f"SELECT format('CREATE TABLESPACE %I OWNER postgres LOCATION %L', 'sli_temp_hdd', '{location}') "
            "WHERE NOT EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname='sli_temp_hdd')\\gexec\n")


def cold_rows_sql():
    names = ",".join("'" + name + "'" for name in COLD_TABLES)
    return ("SELECT coalesce(json_agg(row_to_json(r) ORDER BY r.\"table\"),'[]'::json) FROM ("
            "SELECT c.oid::bigint AS oid,c.relname AS \"table\",t.spcname AS tablespace "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "JOIN pg_database d ON d.datname=current_database() "
            "JOIN pg_tablespace t ON t.oid=coalesce(nullif(c.reltablespace,0),d.dattablespace) "
            f"WHERE n.nspname='public' AND c.relkind='r' AND c.relname IN ({names})) r;")


def cold_move_sql(tables, *, rollback):
    if (not isinstance(tables, list) or len(tables) != len(COLD_TABLES)
            or any(not isinstance(row, dict) or row.get("table") not in COLD_TABLES
                   or type(row.get("oid")) is not int or not 0 < row["oid"] < 2**32
                   or not isinstance(row.get("tablespace"), str) or not 0 < len(row["tablespace"]) <= 63
                   or any(ord(c) < 32 for c in row["tablespace"]) for row in tables)
            or {row["table"] for row in tables} != set(COLD_TABLES)):
        raise HostError("native_cold_journal_invalid")
    sql = "BEGIN;\nSET LOCAL statement_timeout=0; SET LOCAL lock_timeout=0;\n"
    for row in tables:
        name = row["table"]  # Fixed allowlist; never executable host data.
        original = "convert_from(decode('" + row["tablespace"].encode("utf-8").hex() + "','hex'),'UTF8')"
        target = row["tablespace"] if rollback else COLD_TABLESPACE
        identifier = '"' + target.replace('"', '""') + '"'
        # Lock first: relation replacement/renaming must not race the OID check.
        sql += f'LOCK TABLE public."{name}" IN ACCESS EXCLUSIVE MODE;\n'
        sql += ("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "JOIN pg_database d ON d.datname=current_database() "
                "JOIN pg_tablespace t ON t.oid=coalesce(nullif(c.reltablespace,0),d.dattablespace) "
                f"WHERE c.oid={row['oid']} AND n.nspname='public' AND c.relname='{name}' AND c.relkind='r' "
                f"AND t.spcname IN ({original},'sli_temp_hdd')) THEN "
                "RAISE EXCEPTION 'native_cold_relation_changed'; END IF; END $$;\n")
        # PostgreSQL carries the table's TOAST with SET TABLESPACE. User indexes
        # keep their own tablespace (including any previously moved indexes).
        sql += f'ALTER TABLE public."{name}" SET TABLESPACE {identifier};\n'
    return sql + "COMMIT;\n"


def account(name):
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def group(value):
    try:
        return grp.getgrgid(value) if isinstance(value, int) else grp.getgrnam(value)
    except KeyError:
        return None


def validate_identity():
    shared = group(10001)
    named = group("sli-secrets")
    if ((shared and (shared.gr_name != "sli-secrets" or shared.gr_mem))
            or (named and named.gr_gid != 10001)
            or any(entry.pw_gid == 10001 for entry in pwd.getpwall())):
        raise HostError("native_secret_group_conflict")
    for name in ACCOUNTS:
        entry = account(name)
        if entry and (not 0 < entry.pw_uid < 1000 or entry.pw_gid == 10001
                      or entry.pw_shell != "/usr/sbin/nologin" or entry.pw_dir != "/nonexistent"):
            raise HostError("native_service_user_conflict")
        if entry and any(g.gr_gid == 10001 for g in grp.getgrall() if name in g.gr_mem):
            raise HostError("native_secret_group_conflict")


def check_ports():
    for port in (5432,):
        for family, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                try:
                    sock.bind((host, port))
                except OSError:
                    listeners = port_listeners(port)
                    reason = "cannot bind" + ("; listeners: " + ", ".join(listeners) if listeners else "")
                    raise GuardError("native_database_port_busy", f"PostgreSQL port {port}", reason,
                                     f"Run sudo ss -ltnp 'sport = :{port}' and stop the retired service "
                                     "before retrying, or use another host") from None


@contextmanager
def administrative_lock():
    fd = os.open("/run/sli-native-host.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise HostError("native_host_lock_invalid")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HostError("native_host_busy") from None
        yield
    finally:
        os.close(fd)


class Host:
    def __init__(self, root=Path("/")):
        self.root = root

    def path(self, name):
        path = self.root / name.lstrip("/")
        # Refuse links anywhere in administrative paths, including dangling links.
        for item in (path, *path.parents):
            if item.is_symlink():
                raise HostError("native_symlink_forbidden")
        return path

    def clickhouse_mode(self):
        return clickhouse.configured_mode(self.root)

    def database_directory(self, name):
        """Match the standalone preinst policy for empty vendor DB directories."""
        path = self.path(name)
        for item in (path.parent, *path.parent.parents):
            if item.exists():
                info = item.lstat()
                if info.st_uid != ROOT_UID or info.st_mode & 0o022:
                    raise HostError("native_path_untrusted")
        if not path.exists():
            return
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or any(path.iterdir()):
            if name == "/etc/postgresql":
                raise existing_database(name)
            raise HostError("native_existing_database")
        postgres = account("postgres") if name in ("/etc/postgresql", "/var/lib/postgresql") else None
        if (info.st_mode & 0o002 or info.st_uid != ROOT_UID
                and (postgres is None or not 0 < postgres.pw_uid < 1000 or info.st_uid != postgres.pw_uid)):
            raise HostError("native_path_untrusted")

    def backup_device(self, path):
        return path.stat().st_dev

    def validate_cold_root(self, value):
        clickhouse.cold_tablespace_root_path(value)
        source = self.path(value)
        if not source.is_dir():
            raise HostError("native_cold_root_invalid")
        for item in (source, *source.parents):
            info = item.lstat()
            if info.st_uid != ROOT_UID or info.st_mode & 0o022 or not info.st_mode & 0o001:
                raise HostError("native_cold_root_untrusted")
        if self.backup_device(source) == self.backup_device(self.path(MOUNT)):
            raise HostError("native_cold_root_same_device")
        result = json.loads(run(["findmnt", "--json", "--target", str(source),
                                 "--output", "UUID,FSTYPE,FSROOT,OPTIONS"]))["filesystems"]
        if (len(result) != 1 or result[0].get("fstype") not in {"ext4", "xfs"}
                or not result[0].get("uuid") or "rw" not in result[0].get("options", "").split(",")):
            raise HostError("native_cold_root_invalid")
        return {"root": value, "uuid": result[0]["uuid"], "fsroot": result[0]["fsroot"]}

    def require_cold_mount(self):
        path = self.path(STATE + "/cold-tablespace.json")
        self.validate_receipt_file(path)
        saved = json.loads(path.read_text())
        if self.validate_cold_root(saved["root"]) != saved:
            raise HostError("native_cold_mount_mismatch")
        return saved["root"]

    def configure_cold_storage(self):
        site = clickhouse.site_configuration(self.root)
        value = site.get("cold_tablespace_root")
        if value is None:
            return None
        identity = self.validate_cold_root(value)
        saved = self.path(STATE + "/cold-tablespace.json")
        if saved.exists():
            self.validate_receipt_file(saved)
            if json.loads(saved.read_text()) != identity:
                raise HostError("native_cold_mount_mismatch")
        target = self.path(value + "/pg-tablespace")
        if target.exists():
            info = target.lstat()
            postgres = account("postgres")
            if (not target.is_dir() or postgres is None or info.st_uid != postgres.pw_uid
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise HostError("native_cold_directory_conflict")
            # Do not adopt arbitrary pre-existing PostgreSQL files.
            if not saved.exists() and any(target.iterdir()):
                raise HostError("native_cold_directory_conflict")
        else:
            self.directory(value + "/pg-tablespace", 0o700, "postgres", "postgres")
        self.write(STATE + "/cold-tablespace.json", json.dumps(identity, sort_keys=True) + "\n", 0o600)
        self.write("/etc/systemd/system/sli-postgresql.service.d/85-sli-cold-mount.conf",
                   cold_mount_dropin(value), 0o644)
        return value

    def place_cold_tables(self, action):
        """One transactional move; durable original placement makes retry/reverse safe."""
        self.receipt()
        site = clickhouse.site_configuration(self.root)
        journal = self.path(STATE + "/cold-tablespace-move.json")
        saved = None
        if journal.exists():
            self.validate_receipt_file(journal)
            saved = json.loads(journal.read_text())
            cold_move_sql(saved["tables"], rollback=True)  # Validate before any mutation.
        if action == "rollback":
            if saved is None:
                raise HostError("native_cold_rollback_missing")
            root = self.require_cold_mount()
        else:
            root = site.get("cold_tablespace_root")
            if root is None:
                raise HostError("native_cold_not_configured")
            self.validate_cold_root(root)
        if saved is not None and saved.get("root") != root:
            raise HostError("native_cold_journal_invalid")
        current = json.loads(pg_cold(cold_rows_sql()))
        cold_move_sql(current, rollback=False)  # All four schema objects must exist.
        if saved is not None:
            before = {row["table"]: row["oid"] for row in saved["tables"]}
            if before != {row["table"]: row["oid"] for row in current}:
                raise HostError("native_cold_relation_changed")
        print("Холодные таблицы и TOAST; индексы остаются на своих дисках.", flush=True)
        for row in current:
            destination = (next(item["tablespace"] for item in saved["tables"] if item["table"] == row["table"])
                           if action == "rollback" else COLD_TABLESPACE)
            print(f"{row['table']}: {row['tablespace']} -> {destination}", flush=True)
        print("Перенос требует блокировки таблиц; ожидание и копирование без лимита времени. "
              "Обратная команда: sudo sli-cold-tables rollback.", flush=True)
        if action == "plan":
            return
        if action == "apply":
            self.configure_cold_storage()
            run(["systemctl", "daemon-reload"])
            pg_cold(cold_tablespace_sql(root))
            if saved is None:
                saved = {"root": root, "tables": current}
                self.write(STATE + "/cold-tablespace-move.json", json.dumps(saved, sort_keys=True) + "\n", 0o600)
        print("Начат перенос одной транзакцией; PostgreSQL: приложение sli-cold-tables.", flush=True)
        pg_cold(cold_move_sql(saved["tables"], rollback=action == "rollback"))
        print("Размещение подтверждено: транзакция завершена. "
              "Исходное размещение сохранено для повторного запуска и rollback.", flush=True)

    def backup_free(self, path):
        return shutil.disk_usage(path).free

    def backup_trusted(self, path):
        for item in (path, *path.parents):
            info = item.lstat()
            if item.is_symlink() or info.st_uid != ROOT_UID or info.st_mode & 0o022:
                raise HostError("native_backup_root_untrusted")

    def backup_mounted(self, source, target):
        # ismount() misses bind mounts on the same filesystem as /var. Distinct
        # canonical directories can share (st_dev, st_ino) only via a bind here.
        return target.is_dir() and source.samefile(target)

    def require_backup_mount(self):
        site = clickhouse.site_configuration(self.root)
        if "backup_root" in site:
            source = self.validate_backup_root(site["backup_root"])
            if not self.backup_mounted(source, self.path("/var/backups/sli")):
                raise HostError("native_backup_root_mount_mismatch")

    def backup_machine_id(self):
        path = self.path('/etc/machine-id')
        return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None

    def backup_space_estimate(self, root, *, pg_bytes=None):
        """Shared by host setup and upgrade prepare; no credentials are read."""
        databases = self.path(MOUNT)
        if pg_bytes is None:
            # Offline/fresh installations cannot answer SQL. Count their files;
            # unlike pg_database_size this includes WAL and is an upper estimate.
            if self.root == Path('/') and (databases / 'pgdata/18/main/PG_VERSION').is_file():
                try:
                    pg_bytes = int(run(['runuser', '-u', 'postgres', '--',
                                        '/usr/lib/postgresql/18/bin/psql', '-X', '-w', '-At',
                                        '-h', '/var/run/postgresql', '-d', 'sli', '-c',
                                        'SELECT pg_database_size(current_database())']).strip())
                except (HostError, ValueError):
                    pass  # PostgreSQL may be stopped during first setup.
            if pg_bytes is None:
                pg_bytes = backup_policy.tree_bytes(databases, excluded={'clickhouse'})
        expanded = 0
        files = backup_policy.tree_bytes(self.path('/var/lib/sli'),
                                        excluded={'state', 'recovery', 'drills', 'transactions', 'backup-status'})
        companion = sum(backup_policy.tree_bytes(self.path(path)) for path in (
            '/var/lib/sli/state', '/var/lib/sli/recovery', '/etc/sli/secrets',
            '/etc/sli/clickhouse', '/etc/postgresql/18/sli'))
        for name in ('runtime.json', 'site.toml'):
            try:
                info = (self.path('/etc/sli') / name).lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode):
                companion += info.st_size
        size = backup_policy.last_backup_size(root, machine_id=self.backup_machine_id(), companion_bytes=companion)
        # Native CH creates a private archive before copying it into the set.
        return backup_policy.space_estimate(pg_bytes, backup_bytes=size,
                                            expanded_ch_bytes=expanded, files_bytes=files,
                                            archive_staging_bytes=expanded, companion_bytes=companion)

    def validate_backup_root(self, value):
        clickhouse.backup_root_path(value)
        try:
            source = self.path(value)
            if not source.is_dir():
                raise HostError("native_backup_root_invalid")
            self.backup_trusted(source)
            if self.backup_device(source) == self.backup_device(self.path(MOUNT)):
                raise HostError("native_backup_root_same_device")
            estimate = self.backup_space_estimate(source / 'native')
            for volume, required in backup_policy.space_requirements(
                    source, source, estimate, include_drill=False).items():
                free = self.backup_free(backup_policy.existing_parent(volume))
                if free < required:
                    backup_policy.report_refusal({'reason': 'insufficient_backup_disk_space', 'volume': str(volume),
                                                  'required_bytes': required, 'free_bytes': free})
                    raise HostError("native_backup_root_insufficient_space")
            return source
        except HostError as error:
            if str(error) == "native_symlink_forbidden":
                raise HostError("native_backup_root_untrusted") from None
            raise
        except OSError:
            raise HostError("native_backup_root_invalid") from None

    def backup_dependent_units(self):
        # The runtime catalog is stdlib-only, including in the installed host CLI.
        try:
            from deploy.linux import native_runtime as runtime
        except ModuleNotFoundError:
            spec = importlib.util.spec_from_file_location(
                "sli_native_runtime", Path(__file__).with_name("native_runtime.py"))
            runtime = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(runtime)
        apps = runtime.selected({"profiles": ["light", "heavy", "long"], "radius_pilot": False})
        return set(units()) | {
            "sli-" + name + suffix for names, suffix in (
                (("ready", "health", "backup", "backup-drill"), ".service"),
                (("health", "backup"), ".timer"), (("runtime", "dotnet"), ".target")) for name in names
        } | {"sli.target", *map(runtime.dotnet_unit_name, apps)}

    def configure_backup_root(self):
        site = clickhouse.site_configuration(self.root)
        if "backup_root" not in site:
            return
        source = self.validate_backup_root(site["backup_root"])
        target = self.path("/var/backups/sli")
        if not self.backup_mounted(source, target) and target.exists() and any(target.iterdir()):
            raise HostError("native_backup_root_target_not_empty")
        self.directory("/var/backups/sli", 0o711)
        self.write("/etc/systemd/system/var-backups-sli.mount",
                   "[Unit]\nDescription=SLI backup volume\nRequiresMountsFor=" + site["backup_root"] + "\n"
                   "Before=sli.target\n[Mount]\nWhat=" + site["backup_root"] + "\n"
                   "Where=/var/backups/sli\nType=none\nOptions=bind\n", 0o644)
        for unit in sorted(self.backup_dependent_units()):
            self.write(f"/etc/systemd/system/{unit}.d/{BACKUP_DROP_IN}", BACKUP_DROP_IN_BODY, 0o644)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "start", "var-backups-sli.mount"])
        if not self.backup_mounted(source, target):
            raise HostError("native_backup_root_mount_mismatch")
        self.directory("/var/backups/sli", 0o711)

    def directory(self, name, mode=0o750, owner="root", group_name="root"):
        path = self.path(name)
        ensure_directory(path, mode, pwd.getpwnam(owner).pw_uid, grp.getgrnam(group_name).gr_gid)
        os.chown(path, pwd.getpwnam(owner).pw_uid, grp.getgrnam(group_name).gr_gid)
        path.chmod(mode)

    def write(self, name, body, mode=0o640, group_name="root"):
        path = self.path(name)
        ensure_directory(path.parent)
        if path.exists() and (not path.is_file() or path.read_text() != body):
            raise configuration_conflict(name)
        if path.exists():
            info = path.stat()
            if (info.st_uid != ROOT_UID or info.st_gid != grp.getgrnam(group_name).gr_gid
                    or stat.S_IMODE(info.st_mode) != mode):
                raise GuardError("native_existing_configuration_permissions", name, "unexpected owner or permissions",
                                 f"Run sudo stat -- {shlex.quote(name)} and verify ownership and mode {mode:04o} before retrying")
        if not path.exists():
            fd, temporary = tempfile.mkstemp(dir=path.parent)
            try:
                with os.fdopen(fd, "w") as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chown(temporary, ROOT_UID, grp.getgrnam(group_name).gr_gid)
                os.chmod(temporary, mode)
                # Publish without overwriting a file created by another helper.
                os.link(temporary, path)
                parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            finally:
                Path(temporary).unlink(missing_ok=True)

    def check_setup_units(self, directory, *, uuid=None, backup=False):
        try:
            from deploy.linux import native_runtime as runtime
        except ModuleNotFoundError:  # Debian stdlib-only -I setup launcher.
            spec = importlib.util.spec_from_file_location(
                "sli_native_runtime", Path(__file__).with_name("native_runtime.py"))
            runtime = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(runtime)
        local_units = units()
        if uuid is None:
            local_units[MOUNT_UNIT] = directory_mount_unit(directory)
        backup_dirs = {name + ".d" for name in self.backup_dependent_units()} if backup else set()
        expected = {SYSTEMD_DIRECTORY: local_units, "/usr/lib/systemd/system": runtime.units({})}

        def matches(path, body):
            if path.is_symlink() or not path.is_file():
                return False
            try:
                self.backup_trusted(path)
            except HostError:
                return False
            info = path.stat()
            return (info.st_gid == ROOT_UID and stat.S_IMODE(info.st_mode) == 0o644
                    and path.read_bytes() == body.encode())

        conflicts = []
        for base, rendered in expected.items():
            root = self.path(base)
            for item in sorted(root.iterdir()) if root.is_dir() else ():
                path = base + "/" + item.name
                if not SYSTEMD_PATH.fullmatch(path):
                    continue
                if item.name in rendered and matches(item, rendered[item.name]):
                    continue
                if (base == SYSTEMD_DIRECTORY and item.name in backup_dirs
                        and not item.is_symlink() and item.is_dir()
                        and set(child.name for child in item.iterdir()) <= {BACKUP_DROP_IN}):
                    # A failed atomic publication can also leave an empty directory.
                    try:
                        self.backup_trusted(item)
                    except HostError:
                        pass
                    else:
                        drop_in = item / BACKUP_DROP_IN
                        if ((not drop_in.exists() and not drop_in.is_symlink())
                                or matches(drop_in, BACKUP_DROP_IN_BODY)):
                            continue
                conflicts.append(path)
        if conflicts:
            raise configuration_conflict(*conflicts)

    def mount(self, expected, *, fresh=False):
        if not UUID.fullmatch(expected):
            raise HostError("native_mount_uuid_invalid")
        try:
            rows = json.loads(run(["findmnt", "--json", "--mountpoint", MOUNT,
                                   "--output", "TARGET,FSTYPE,UUID,OPTIONS"]))["filesystems"]
            if (len(rows) != 1 or rows[0]["target"] != MOUNT or rows[0]["fstype"] != "ext4"
                    or rows[0]["uuid"] != expected):
                raise ValueError
        except (HostError, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
            raise GuardError("native_database_mount_mismatch", MOUNT, f"ext4 filesystem UUID {expected} is not mounted here",
                             f"Run lsblk -f, mount the selected filesystem at {MOUNT}, and rerun sudo sli-setup --uuid {expected}") from None
        source = self.path(MOUNT)
        if fresh:
            self.backup_trusted(source)
            if "rw" not in rows[0].get("options", "").split(","):
                raise HostError("native_database_filesystem_readonly")
            self.require_database_space(source, MOUNT)

    def require_database_space(self, path, name):
        free = self.backup_free(path)
        if free >= MIN_DATABASE_FREE:
            return
        choices = []
        try:
            devices = json.loads(run(["lsblk", "--json", "--list", "--bytes", "--paths", "--output",
                                      "NAME,TYPE,FSTYPE,PTTYPE,UUID,RO,MOUNTPOINTS,FSAVAIL,SIZE"]))["blockdevices"]
        except (OSError, ValueError, KeyError, HostError, subprocess.SubprocessError):
            devices = []
        for device in devices:
            if device.get("ro") not in (False, "0"):
                continue
            filesystem = device.get("fstype")
            uuid = device.get("uuid") or ""
            mounts = [target for target in (device.get("mountpoints") or []) if target]
            available = device.get("fsavail")
            if filesystem in {"ext4", "xfs"} and isinstance(available, int) and available >= MIN_DATABASE_FREE:
                target = next((target for target in mounts if re.fullmatch(r"/[A-Za-z0-9_./-]{0,160}", target)), None)
                if target:
                    label = f"{target} ({available / 1024**3:.1f} GiB free)"
                    if filesystem == "ext4" and UUID.fullmatch(uuid) and target.startswith(("/mnt/", "/srv/", "/media/")):
                        label += f" [mount at {MOUNT} and use --uuid {uuid}]"
                    elif re.fullmatch(r"/(?:srv|mnt)/[A-Za-z0-9_-]+", target) and target != MOUNT:
                        label += f" [if empty, use --directory {target}]"
                    else:
                        continue
                    choices.append((2, available, label))
            elif not mounts and isinstance(device.get("size"), int) and device["size"] >= MIN_DATABASE_FREE:
                device_name = device.get("name") or ""
                if re.fullmatch(r"/dev/[A-Za-z0-9_./-]{1,120}", device_name):
                    size = device["size"]
                    if filesystem == "ext4" and UUID.fullmatch(uuid):
                        choices.append((1, size, f"{device_name} ({size / 1024**3:.1f} GiB capacity, unmounted) "
                                                  f"[if dedicated to SLI, mount at {MOUNT} and use --uuid {uuid}]"))
                    elif device.get("type") == "disk" and not filesystem and not device.get("pttype"):
                        choices.append((0, size, f"{device_name} ({size / 1024**3:.1f} GiB capacity, no detected filesystem) "
                                                  f"[verify it is unused before preparing ext4 for {MOUNT} and --uuid]"))
        if choices:
            candidates = "; ".join(choice[2] for choice in sorted(choices, reverse=True)[:3])
            remedy = (f"Volumes to check: {candidates}. Verify the volume with lsblk -f and rerun sudo sli-setup "
                      "with the corresponding storage option and the other setup flags")
        else:
            remedy = ("Run lsblk -f to locate another disk. Rerun sudo sli-setup --directory /srv/sli-data with an "
                      "empty directory on a larger ext4 or XFS filesystem, or free space here")
        raise GuardError("native_database_space_insufficient", name,
                         f"{free / 1024**3:.1f} GiB free (20 GiB required)", remedy)

    def database_filesystem(self, path, *, writable=True):
        try:
            rows = json.loads(run(["findmnt", "--json", "--target", str(path),
                                   "--output", "TARGET,FSTYPE,OPTIONS,UUID"]))["filesystems"]
            if len(rows) != 1 or rows[0]["fstype"] not in {"ext4", "xfs"}:
                raise HostError("native_database_filesystem_unsupported")
            # ProtectSystem=strict presents a read-only view to observers.
            # Only root prepare/setup must require a writable host filesystem.
            if writable and "rw" not in rows[0]["options"].split(","):
                raise HostError("native_database_filesystem_readonly")
            return rows[0]
        except (KeyError, TypeError, ValueError):
            raise HostError("native_database_filesystem_unsupported") from None

    def validate_database_directory(self, value, *, fresh=True, writable=True, mounted=False, filesystem_uuid=None):
        try:
            clickhouse.database_directory_path(value)
        except ValueError:
            raise HostError("native_database_directory_invalid") from None
        source = self.path(value)
        parent = source if source.exists() else source.parent
        if not parent.is_dir() or source.exists() and not source.is_dir():
            raise HostError("native_database_directory_invalid")
        self.backup_trusted(parent)
        filesystem = self.database_filesystem(parent, writable=writable)
        mounted_directory = mounted or not re.fullmatch(r"/(?:var/lib|srv|mnt)/[A-Za-z0-9_-]+", value)
        if ((mounted_directory and (filesystem.get('target') != str(source.parent) or not filesystem.get('uuid')))
                or (filesystem_uuid is not None and filesystem.get('uuid') != filesystem_uuid)):
            raise HostError("native_database_mount_mismatch")
        if fresh:
            self.require_database_space(parent, value)
        return source

    def select_database_directory(self, *, backup_root=None):
        # A retry must continue preparing the same bind mount even if disk usage changed.
        unit = self.path('/etc/systemd/system/' + MOUNT_UNIT)
        if unit.exists():
            self.backup_trusted(unit)
            body = unit.read_text()
            match = re.search(r'(?m)^What=(/[^\n]+)$', body)
            if match is None or body != directory_mount_unit(match[1]):
                raise configuration_conflict('/etc/systemd/system/' + MOUNT_UNIT)
            self.validate_database_directory(match[1])
            return match[1]

        best = None
        free = 0
        backup = self.path(backup_root) if backup_root else None
        backup_device = self.backup_device(backup) if backup is not None and backup.is_dir() else None
        targets = [DIRECTORY]
        for directory in targets:
            try:
                source = self.validate_database_directory(directory, fresh=False, mounted=directory != DIRECTORY)
                if source.exists() and any(source.iterdir()):
                    raise HostError('native_existing_database')
                parent = source if source.exists() else source.parent
                if self.backup_device(parent) != backup_device:
                    available = self.backup_free(parent)
                    if directory == DIRECTORY and available >= MIN_DATABASE_FREE:
                        return directory
                    if available > free:
                        best, free = directory, available
            except (HostError, OSError) as error:
                if directory == DIRECTORY and str(error) == 'native_existing_database':
                    raise
            if directory == DIRECTORY:
                mounted = json.loads(run(['findmnt', '--json', '--list', '--real',
                                          '--output', 'TARGET,FSTYPE']))['filesystems']
                targets.extend(sorted({row['target'] + '/sli-db' for row in mounted
                                       if row['target'] != '/' and row['fstype'] in {'ext4', 'xfs'}}
                                      - {DIRECTORY}))
        if free < MIN_DATABASE_FREE:
            raise HostError(f'native_database_space_insufficient:{free}')
        return best

    def validate_receipt_file(self, path):
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or stat.S_IMODE(info.st_mode) != 0o600:
            raise HostError("native_preparation_receipt_invalid")

    def receipt(self):
        path = self.path(STATE + "/host-prepared.json")
        self.validate_receipt_file(path)
        try:
            value = json.loads(path.read_text())
            if value["version"] != 1 or value["mount"] != MOUNT:
                raise ValueError
            if value.get("storage_mode", "uuid") == "directory":
                source = self.validate_database_directory(value["directory"], fresh=False, writable=False,
                                                          filesystem_uuid=value.get('filesystem_uuid'))
                if not self.backup_mounted(source, self.path(MOUNT)):
                    raise HostError("native_database_mount_mismatch")
            elif value.get("storage_mode", "uuid") == "uuid":
                self.mount(value["uuid"])
            else:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise HostError("native_preparation_receipt_invalid") from None
        self.vendor_guards()
        return value

    def vendor_guards(self):
        config = self.path("/etc/postgresql-common/createcluster.conf").read_text()
        if not re.search(r"(?m)^create_main_cluster = false\s*\Z", config):
            raise HostError("native_vendor_cluster_guard_missing")

    def vendor_diversions(self, *, install=False):
        # The vendor postinst calls systemctl enable directly and fails on a
        # masked unit. Keep its native/SysV start files under dpkg-managed
        # diversions, so postinst skips registration while the mask stays in
        # force. The original package bytes are preserved across reinstalls.
        for source in VENDOR_START_FILES:
            destination = source + ".sli-vendor"
            owner = run(["dpkg-divert", "--listpackage", source]).strip()
            target = run(["dpkg-divert", "--truename", source]).strip()
            if not owner and target == source and install:
                saved = self.root / destination.lstrip("/")
                if saved.exists() or saved.is_symlink():
                    raise HostError("native_vendor_diversion_conflict")
                run(["dpkg-divert", "--local", "--add", "--rename", "--divert", destination, source])
                owner = run(["dpkg-divert", "--listpackage", source]).strip()
                target = run(["dpkg-divert", "--truename", source]).strip()
            path = self.root / source.lstrip("/")
            if owner != "LOCAL" or target != destination or path.exists() or path.is_symlink():
                raise HostError("native_vendor_diversion_invalid")

    def prepare(self, expected=None, *, directory=DIRECTORY):
        receipt = self.path(STATE + "/host-prepared.json")
        filesystem_uuid = None
        if expected is not None:
            self.mount(expected, fresh=not receipt.exists())
        else:
            source = self.validate_database_directory(directory, fresh=not receipt.exists())
        validate_identity()
        if receipt.exists():
            saved = self.receipt()
            if (saved["uuid"] != expected or expected is None and saved.get("directory") != directory):
                raise HostError("native_database_mount_mismatch")
            return
        if expected is None:
            if source.exists() and any(source.iterdir()):
                raise existing_database(directory)
            target = self.path(MOUNT)
            managed_mount = self.path('/etc/systemd/system/' + MOUNT_UNIT)
            resuming = (managed_mount.exists() and managed_mount.read_text() == directory_mount_unit(directory)
                        and self.backup_mounted(source, target))
            if target.exists() and (not target.is_dir() or any(target.iterdir()) or os.path.ismount(target)) and not resuming:
                raise HostError("native_existing_database")
            filesystem_uuid = self.database_filesystem(source if source.exists() else source.parent).get('uuid')
        config = self.path("/etc/postgresql-common/createcluster.conf")
        backup = self.path(STATE + "/createcluster.conf.before")
        original, current, managed = cluster_guard(config, backup)
        # Do not adopt or stop someone else's database, even if it is not running.
        for name in ("/etc/postgresql", "/var/lib/postgresql", "/var/lib/clickhouse",
                     "/etc/clickhouse-server", MOUNT + "/pgdata", MOUNT + "/clickhouse"):
            if name in ("/etc/postgresql", "/var/lib/postgresql", "/var/lib/clickhouse"):
                self.database_directory(name)
                continue
            path = self.path(name)
            if name == "/etc/clickhouse-server" and self.path(STATE + "/vendor-prepared.json").exists():
                continue  # Package-owned vendor config, guarded before dpkg configured it.
            if path.exists() and (not path.is_dir() or any(path.iterdir())):
                raise HostError("native_existing_database")
        check_ports()
        self.directory(STATE, 0o700)
        self.write(STATE + "/createcluster.conf.before", original, 0o600)
        run(["groupadd", "--system", "--gid", "10001", "sli-secrets"]) if not group(10001) else None
        for name in ACCOUNTS:
            if not account(name):
                run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir",
                     "/nonexistent", "--shell", "/usr/sbin/nologin", name])
        for name in (STATE, "/var/lib/sli/transactions", "/var/lib/sli/recovery", "/run/sli"):
            self.directory(name, 0o700)
        self.directory("/etc/sli/secrets", 0o750, group_name="sli-secrets")
        # Preserve vendor/site settings; the final assignment takes precedence.
        ensure_directory(config.parent)
        if current != managed:
            write_guard(config, managed, 0o644)
        else:
            config.chmod(0o644)
        if expected is None:
            self.directory(directory, 0o755)
            self.directory(MOUNT, 0o755)
            self.write("/etc/systemd/system/" + MOUNT_UNIT, directory_mount_unit(directory), 0o644)
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "start", MOUNT_UNIT])
            if not self.backup_mounted(source, self.path(MOUNT)):
                raise HostError("native_database_mount_mismatch")
        self.write(STATE + "/host-prepared.json", json.dumps(
            {"version": 1, "mount": MOUNT, "uuid": expected,
             **({"filesystem_uuid": filesystem_uuid} if filesystem_uuid else {}),
             **({"storage_mode": "directory", "directory": directory} if expected is None else {})},
            sort_keys=True) + "\n", 0o600)

    def configure(self):
        self.receipt()
        validate_identity()
        check_ports()
        self.configure_backup_root()
        self.configure_cold_storage()
        pg_version = run(["/usr/lib/postgresql/18/bin/postgres", "--version"])
        if not re.search(r"\b18\.", pg_version):
            raise HostError("native_database_version_mismatch")
        # Configure only the named cluster, never an auto-created main cluster.
        clusters = run(["pg_lsclusters", "--no-header"]).splitlines()
        if any(row.split()[:2] != ["18", "sli"] or len(row.split()) < 6
               or row.split()[2:5] != ["5432", "down", "postgres"]
               or row.split()[5] != MOUNT + "/pgdata/18/main" for row in clusters):
            raise HostError("native_unexpected_postgres_cluster")
        self.passwords()
        if not clusters:
            self.directory(MOUNT + "/pgdata", 0o750, "postgres", "postgres")
            run(["pg_createcluster", "18", "sli", "--datadir", MOUNT + "/pgdata/18/main",
                 "--port", "5432", "--start-conf=manual", "--encoding=UTF8", "--locale=C.UTF-8",
                 "--", "--auth-local=peer",
                 "--auth-host=scram-sha-256"])
        data = self.path("/etc/postgresql/18/sli/postgresql.conf").read_text()
        if "# SLI native settings" not in data:
            data += ("\n# SLI native settings\nlisten_addresses = '127.0.0.1'\nport = 5432\n"
                     "password_encryption = 'scram-sha-256'\nshared_buffers = '1GB'\n"
                     "work_mem = '8MB'\nmax_connections = 40\n")
            self.path("/etc/postgresql/18/sli/postgresql.conf").write_text(data)
        self.write(HELPER, Path(__file__).read_text(encoding="utf-8"), 0o644)
        for filename in ("native_clickhouse_endpoint.py", "native_preinstall.py", "native_pins.json", "backup_policy.py"):
            self.write("/usr/lib/sli/" + filename, Path(__file__).with_name(filename).read_text(encoding="utf-8"),
                       0o640 if filename.endswith(".json") else 0o644)
        self.write("/usr/lib/sli/secrets-manifest.json", Path(__file__).with_name("secrets-manifest.json").read_text())
        for name, body in units().items():
            self.write("/etc/systemd/system/" + name, body, 0o644)
        run(["systemctl", "daemon-reload"])

    def passwords(self):
        # The canonical inventory remains shared with Compose. TLS/issuer setup
        # continues through sli_secrets; host bootstrap needs only core passwords.
        manifest = json.loads(Path(__file__).with_name("secrets-manifest.json").read_text())
        names = [name for name, spec in manifest["secrets"].items()
                 if spec == {"kind": "password", "group": "core"} and name not in {"history_password", "warm_password"}]
        if manifest["version"] != 1 or not names or any(not re.fullmatch(r"[a-z][a-z0-9_]*", n) for n in names):
            raise HostError("native_secret_manifest_invalid")
        # Validate the entire existing inventory before generating anything.
        for name in names:
            path = self.path("/etc/sli/secrets/" + name)
            if path.exists():
                info = path.stat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_gid != 10001
                        or stat.S_IMODE(info.st_mode) != 0o640 or info.st_size > 4096):
                    raise HostError("native_secret_invalid")
                value = path.read_text()
                if not value or not value.isascii() or any(char in value for char in "\r\n\x00"):
                    raise HostError("native_secret_invalid")
        for name in names:
            path = self.path("/etc/sli/secrets/" + name)
            if not path.exists():
                self.write("/etc/sli/secrets/" + name, secrets.token_urlsafe(48), group_name="sli-secrets")


def directory_mount_unit(directory):
    return ("[Unit]\nDescription=SLI database directory\nRequiresMountsFor=" + directory + "\n"
            "Before=sli-postgresql.service\n"
            "[Mount]\nWhat=" + directory + "\nWhere=" + MOUNT + "\nType=none\nOptions=bind\n")


def retire_clickhouse(root=Path("/")):
    """Retire only the named SLI units. Data, images and other Docker users survive."""
    names = {"sli-clickhouse-history.service", "sli-clickhouse-warm.service"}
    receipt = root / "var/lib/sli/state/host-prepared.json"
    if receipt.exists() and json.loads(clickhouse.trusted_text(receipt)).get("clickhouse_mode") in {"native", "docker"}:
        names.add("clickhouse-server.service")
    paths = []
    for name in sorted(names - {"clickhouse-server.service"}):
        path = root / "etc/systemd/system" / name
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or (root == Path("/") and info.st_uid != 0):
                raise HostError("native_untrusted_unit")
            paths.append(path)
    # systemctl returns 1 with no output when no unit files match the names.
    unit_files = run(["systemctl", "list-unit-files", "--no-legend", *sorted(names)], allow_no_unit_files=True)
    installed = {parts[0]: parts[1] for line in unit_files.splitlines() if len(parts := line.split()) >= 2}
    listed = run(["systemctl", "list-units", "--all", "--plain", "--no-legend", *sorted(names)])
    # Explicitly named units may appear even when systemd has no definition for them.
    loaded = {parts[0] for line in listed.splitlines() if len(parts := line.split()) >= 2 and parts[1] != "not-found"}
    for name in sorted(names & installed.keys()):
        # Older native packages masked the vendor unit. Keep that fence intact.
        if installed[name].startswith("masked"):
            run(["systemctl", "stop", name])
        else:
            run(["systemctl", "disable", "--now", name])
    for name in sorted((names & loaded) - installed.keys()):
        run(["systemctl", "stop", name])
    for path in paths:
        path.unlink()
    run(["systemctl", "daemon-reload"])
    # Removed units can retain a failed state. Unloaded units need no reset.
    listed_failed = run([
        "systemctl", "list-units", "--failed", "--plain", "--no-legend", *sorted(names)
    ])
    failed = {parts[0] for line in listed_failed.splitlines() if len(parts := line.split()) >= 3 and parts[2] == "failed"}
    for name in sorted(failed & names):
        run(["systemctl", "reset-failed", name])


def ch_config(name, mode="native"):
    endpoint = clickhouse.endpoint(name, mode)
    http, tcp, _, _ = INSTANCES[name]
    root = MOUNT + "/clickhouse/" + name + "/"
    staging = endpoint.backup_server + "/"
    return f"""<clickhouse>
  <logger><level>warning</level><log>/var/log/sli-clickhouse/{name}/server.log</log>
    <errorlog>/var/log/sli-clickhouse/{name}/error.log</errorlog><size>20M</size><count>3</count></logger>
  <listen_host>{'0.0.0.0' if mode == 'docker' else '127.0.0.1'}</listen_host><http_port>{http}</http_port><tcp_port>{tcp}</tcp_port>
  <path>{root}</path><tmp_path>{root}tmp/</tmp_path><user_files_path>{root}user_files/</user_files_path>
  <access_control_path>{root}access/</access_control_path><format_schema_path>{root}format_schemas/</format_schema_path>
  <users_config>/run/sli-ch-{name}/users.xml</users_config>
  <max_server_memory_usage>{3 * 1024**3 if name == 'history' else 2 * 1024**3}</max_server_memory_usage>
  <background_pool_size>2</background_pool_size><background_schedule_pool_size>2</background_schedule_pool_size>
  <merge_tree><number_of_free_entries_in_pool_to_execute_mutation>0</number_of_free_entries_in_pool_to_execute_mutation>
    <number_of_free_entries_in_pool_to_execute_optimize_entire_partition>0</number_of_free_entries_in_pool_to_execute_optimize_entire_partition>
    <number_of_free_entries_in_pool_to_lower_max_size_of_merge>0</number_of_free_entries_in_pool_to_lower_max_size_of_merge></merge_tree>
  <storage_configuration><disks><backups><type>local</type><path>{staging}</path></backups></disks></storage_configuration>
  <backups><allowed_disk>backups</allowed_disk><allowed_path>{staging}</allowed_path>
    <allow_concurrent_backups>false</allow_concurrent_backups></backups><backup_threads>2</backup_threads>
</clickhouse>
"""


def units(mode="native"):
    mount = r"srv-sli\x2ddb.mount"
    dependencies = f"RequiresMountsFor={MOUNT}\nBindsTo={mount}\nAfter={mount}\n"
    guard = f"ExecStartPre=+/usr/bin/python3 -B {HELPER} check-mount\n"
    result = {"sli-postgresql.service": "[Unit]\nDescription=SLI PostgreSQL 18\n" + dependencies +
              "StartLimitIntervalSec=0\n" +
              "[Service]\nType=simple\nUser=postgres\nGroup=postgres\n" + guard +
              "ExecStart=/usr/lib/postgresql/18/bin/postgres -D /srv/sli-db/pgdata/18/main "
              "-c config_file=/etc/postgresql/18/sli/postgresql.conf\n"
              "Restart=on-failure\nRestartSec=5s\n"
              "KillSignal=SIGINT\nTimeoutStopSec=120\nNoNewPrivileges=yes\nPrivateTmp=yes\n" +
              clickhouse.SOCKET_SANDBOX +
              "[Install]\nWantedBy=multi-user.target\n"}
    result["sli-bootstrap-pg.service"] = (
        "[Unit]\nDescription=SLI initial PostgreSQL identities\nRequires=sli-postgresql.service\n"
        "After=sli-postgresql.service\n[Service]\nType=oneshot\nUser=postgres\nGroup=postgres\n" + guard +
        "".join(f"LoadCredential={s}:/etc/sli/secrets/{s}\n" for s in
                ("postgres_password", "migration_password", "runtime_password")) +
        f"ExecStart=/usr/bin/python3 -B {HELPER} bootstrap-pg\nNoNewPrivileges=yes\nPrivateTmp=yes\n" +
        clickhouse.SOCKET_SANDBOX)
    return result


def credential(name):
    """Read only a systemd-delivered 0400/0600 credential owned by this unit."""
    directory = Path(os.environ.get("CREDENTIALS_DIRECTORY", ""))
    if not directory.is_absolute() or directory.is_symlink():
        raise HostError("native_credential_invalid")
    fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        private = info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) in (0o400, 0o600)
        # Debian 13 systemd can retain root ownership and grant the service an
        # ACL (0440) inside its read-only per-unit credential mount.
        delivered = (directory.parent == CREDENTIALS_ROOT and directory.name.endswith(".service")
                     and info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o440
                     and os.statvfs(directory).f_flag & os.ST_RDONLY)
        if not stat.S_ISREG(info.st_mode) or not (private or delivered) or info.st_size > 4096:
            raise HostError("native_credential_invalid")
        body = os.read(fd, 4097).decode("utf-8").rstrip("\r\n")
    finally:
        os.close(fd)
    if not body or any(char in body for char in "\r\n\x00"):
        raise HostError("native_credential_invalid")
    return body


def render_ch(name, mode="native"):
    _, _, user, secret = INSTANCES[name]
    digest = hashlib.sha256(credential(secret).encode()).hexdigest()
    if mode not in {"native", "docker"}:
        raise HostError("native_clickhouse_mode_invalid")
    # The container receives the bridge gateway as client IP for loopback NAT.
    # Its only published listeners are 127.0.0.1; authentication stays mandatory.
    network = "0.0.0.0/0" if mode == "docker" else "127.0.0.1"
    body = (f"<clickhouse><users><{user}><password_sha256_hex>{digest}</password_sha256_hex>"
            f"<networks><ip>{network}</ip></networks><profile>default</profile><quota>default</quota>"
            f"</{user}></users><profiles><default><max_threads>2</max_threads>"
            "<max_memory_usage>536870912</max_memory_usage></default></profiles>"
            "<quotas><default/></quotas></clickhouse>\n")
    path = Path(f"/run/sli-ch-{name}/users.xml")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(body)
    if mode == "docker":
        entry = pwd.getpwnam("sli-ch-" + name)
        os.chown(path, entry.pw_uid, entry.pw_gid)


def check_docker(root=Path("/")):
    """Admit site-listed foreign containers without granting SLI Docker access."""
    settings = clickhouse.site_configuration(root)
    for package, pin in clickhouse.pins()["docker"]["packages"].items():
        installed = run(["dpkg-query", "-W", "-f=${Version}", package]).strip()
        if installed != pin["version"]:
            raise HostError("native_docker_version_mismatch")
    docker_group = group("docker")
    users = (*ACCOUNTS, "postgres")
    if docker_group and (set(docker_group.gr_mem) & set(users)
                         or any(account(n) and account(n).pw_gid == docker_group.gr_gid for n in users)):
        raise HostError("native_docker_socket_exposed")
    clickhouse.check_containers(run, allowed_containers=settings.get("docker_allowed_containers", []))


def run_ch(name):
    if clickhouse.configured_mode() != "docker":
        raise HostError("native_clickhouse_mode_invalid")
    check_docker()
    entry = pwd.getpwnam("sli-ch-" + name)
    argv = clickhouse.endpoint(name, "docker").server_command(entry.pw_uid, entry.pw_gid)
    os.execve(argv[0], argv, {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"})


def stopped_ch(name):
    # --rm removes stopped containers. A CLI/cgroup exit alone is not proof
    # that the daemon-managed DB has stopped (important for rollback/drills).
    clickhouse.cleanup_container(run, "sli-clickhouse-" + name, name)


def bootstrap_pg():
    # The private intent authorizes resuming between role/database creation, with
    # exactly the same secret values. It never authorizes adopting another DB.
    probe = run(["psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c",
                 ("SELECT (SELECT count(*) FROM pg_roles WHERE rolname IN ('sli_migration','adlog_user'))"
                  " + (SELECT count(*) FROM pg_database WHERE datname='sli')")])
    if probe.strip() not in {"0", "1", "2", "3"} or (probe.strip() != "0" and not BOOTSTRAP_MARKER.exists()):
        raise HostError("native_existing_postgres_identities")
    values = [credential(name) for name in ("postgres_password", "migration_password", "runtime_password")]
    intent = json.dumps({"version": 1, "digests": [hashlib.sha256(v.encode()).hexdigest() for v in values]}, sort_keys=True) + "\n"
    if BOOTSTRAP_MARKER.is_symlink():
        raise HostError("native_bootstrap_intent_invalid")
    if BOOTSTRAP_MARKER.exists():
        info = BOOTSTRAP_MARKER.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or BOOTSTRAP_MARKER.read_text() != intent):
            raise HostError("native_bootstrap_intent_invalid")
    else:
        fd = os.open(BOOTSTRAP_MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(intent)
            stream.flush()
            os.fsync(stream.fileno())
        parent_fd = os.open(BOOTSTRAP_MARKER.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    values = [value.replace("'", "''") for value in values]
    script = ("SET log_statement='none'; SET log_min_error_statement='panic'; "
              "SET log_error_verbosity='terse'; SET standard_conforming_strings=on; "
              "SET password_encryption='scram-sha-256'; BEGIN;\n"
              f"ALTER ROLE postgres PASSWORD '{values[0]}';\n" +
              "".join("SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT "
                      f"NOREPLICATION NOBYPASSRLS PASSWORD %L', '{role}', '{value}') "
                      f"WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}')\\gexec\n"
                      for role, value in zip(("sli_migration", "adlog_user"), values[1:])) +
              "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('sli_migration','adlog_user') "
              "AND (NOT rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication "
              "OR rolbypassrls)) THEN RAISE EXCEPTION 'native_role_conflict'; END IF; END $$;\n"
              "COMMIT;\n")
    run(["psql", "-Xq", "-v", "ON_ERROR_STOP=1", "-d", "postgres"], input=script)
    run(["psql", "-Xq", "-v", "ON_ERROR_STOP=1", "-d", "postgres"], input=
        "SELECT 'CREATE DATABASE sli OWNER sli_migration' WHERE NOT EXISTS "
        "(SELECT 1 FROM pg_database WHERE datname='sli')\\gexec\n"
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba "
        "WHERE d.datname='sli' AND r.rolname='sli_migration') THEN RAISE EXCEPTION 'native_database_owner_conflict'; "
        "END IF; END $$;\n")
    run(["psql", "-Xq", "-v", "ON_ERROR_STOP=1", "-d", "sli"], input=
        "REVOKE ALL ON DATABASE sli FROM PUBLIC; GRANT CONNECT ON DATABASE sli TO adlog_user; "
        "REVOKE ALL ON DATABASE postgres FROM PUBLIC; REVOKE CREATE ON SCHEMA public FROM PUBLIC; "
        "GRANT USAGE ON SCHEMA public TO adlog_user;\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    storage = prepare.add_mutually_exclusive_group()
    storage.add_argument("--uuid")
    storage.add_argument("--directory", default=DIRECTORY)
    for name in ("configure", "check-mount", "check-cold-mount", "bootstrap-pg"):
        commands.add_parser(name)
    cold = commands.add_parser("cold-tables", help="Холодные таблицы: план, перенос, возврат на исходные диски")
    cold.add_argument("action", choices=("plan", "apply", "rollback"), nargs="?", default="plan")
    render = commands.add_parser("render-ch")
    render.add_argument("instance", choices=INSTANCES)
    render.add_argument("--mode", choices=("native", "docker"), default="native")
    commands.add_parser("run-ch").add_argument("instance", choices=INSTANCES)
    commands.add_parser("stopped-ch").add_argument("instance", choices=INSTANCES)
    args = parser.parse_args(argv)
    try:
        if args.command in {"prepare", "configure", "check-mount", "check-cold-mount", "cold-tables"} and os.geteuid() != 0:
            raise HostError("native_root_required")
        if args.command in {"prepare", "configure"}:
            os.umask(0o022)
            release = platform.freedesktop_os_release()
            if release.get("ID") != "debian" or release.get("VERSION_ID") != "13" or platform.machine() != "x86_64":
                raise HostError("native_debian13_amd64_required")
            with administrative_lock():
                if args.command == "prepare":
                    Host().prepare(args.uuid, directory=args.directory)
                else:
                    Host().configure()
        elif args.command == "check-mount":
            Host().receipt()
        elif args.command == "check-cold-mount":
            Host().require_cold_mount()
        elif args.command == "cold-tables":
            with administrative_lock():
                Host().place_cold_tables(args.action)
        elif args.command == "render-ch":
            render_ch(args.instance, args.mode)
        elif args.command == "run-ch":
            run_ch(args.instance)
        elif args.command == "stopped-ch":
            stopped_ch(args.instance)
        else:
            bootstrap_pg()
    except (HostError, GuardError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        _spec = importlib.util.spec_from_file_location('sli_diagnostics', Path(__file__).with_name('native_diagnostics.py'))
        diagnostics = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(diagnostics)
        diagnostics.failure(error, default='native_host_failed')
        return 1
    print("native_host_verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
