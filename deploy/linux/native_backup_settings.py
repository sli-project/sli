"""Root coordinator for optional, separately stored native recovery sets."""
from __future__ import annotations

import json
import os
import re
import secrets
import socket
import stat
import struct
import subprocess
from contextlib import contextmanager, suppress
from pathlib import Path

from deploy.linux import backup_policy, native_backup, native_host, native_install, native_runtime, native_upgrade
from deploy.linux import native_clickhouse_endpoint as clickhouse

POLICY = Path("/etc/sli/backup-settings.json")
SOCKET = Path("/run/sli/backup-settings/control.sock")
ARCHIVES = "sli-regular-backups"
MAX_FRAME = 8192
REVISION = re.compile(r"[A-Za-z0-9._-]{1,128}")
IDENTITY_KEYS = {"uuid", "target", "fsroot"}
ERRORS = {
    "backup_settings_revision_conflict",
    "backup_settings_unavailable",
    "backup_settings_invalid",
    "native_backup_root_invalid",
    "native_backup_root_untrusted",
    "native_backup_root_same_device",
    "native_backup_root_insufficient_space",
    "native_backup_root_mount_mismatch",
}


class SettingsError(RuntimeError):
    pass


def require(condition, code="backup_settings_invalid"):
    if not condition:
        raise SettingsError(code)


def initial_policy():
    return {"schema_version": 1, "enabled": False, "path": None, "revision": "0", "identity": None}


def canonical_path(value):
    try:
        require(isinstance(value, str) and len(value.encode("utf-8")) <= 4096, "native_backup_root_invalid")
        clickhouse.backup_root_path(value)
    except (ValueError, UnicodeError):
        raise SettingsError("native_backup_root_invalid") from None
    path = Path(value)
    require(path.parts[1] not in {"home", "root", "run", "tmp", "proc", "sys", "dev"}
            and not path.is_relative_to("/var/tmp"), "native_backup_root_invalid")
    return path


def read_policy():
    if not POLICY.is_symlink() and not POLICY.exists():
        return None
    try:
        trusted = native_install.trusted_path(POLICY)
        require(not trusted.stat().st_mode & 0o077, "backup_settings_unavailable")
        with trusted.open("rb") as stream:
            data = stream.read(MAX_FRAME + 1)
        require(len(data) <= MAX_FRAME, "backup_settings_unavailable")
        state = json.loads(data, object_pairs_hook=unique_object)
        require(isinstance(state, dict) and set(state) == set(initial_policy()) and type(state["schema_version"]) is int
                and state["schema_version"] == 1 and type(state["enabled"]) is bool
                and REVISION.fullmatch(state["revision"]), "backup_settings_unavailable")
        if state["path"] is not None:
            canonical_path(state["path"])
        identity = state["identity"]
        require(identity is None or (isinstance(identity, dict) and set(identity) == IDENTITY_KEYS
                                     and all(isinstance(v, str) and v for v in identity.values())),
                "backup_settings_unavailable")
        require((not state["enabled"] or identity is not None) and
                (identity is None or state["path"] is not None), "backup_settings_unavailable")
        return state
    except (OSError, ValueError, TypeError, RuntimeError):
        raise SettingsError("backup_settings_unavailable") from None


def save_policy(state):
    native_install.atomic(POLICY, state)


def timer_command(*arguments):
    subprocess.run(["/usr/bin/systemctl", *arguments, native_install.BACKUP_TIMER], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                   env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})


def apply_schedule(enabled):
    if not enabled:
        state = native_install.backup_schedule()
        if state in {"masked", "masked-runtime"}:
            timer_command("stop")
            return
        if state == "not-found":
            return
    timer_command("enable" if enabled else "disable", "--now")


def mount_identity(path):
    try:
        result = subprocess.run(["/usr/bin/findmnt", "--json", "--target", str(path),
                                 "--output", "UUID,TARGET,FSROOT,OPTIONS"],
                                check=True, capture_output=True, timeout=3,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        row, = json.loads(result.stdout)["filesystems"]
        identity = {key: row[key] for key in IDENTITY_KEYS}
        require(all(isinstance(value, str) and value for value in identity.values())
                and identity["target"] != "/" and path.is_relative_to(identity["target"])
                and "rw" in row["options"].split(","), "native_backup_root_mount_mismatch")
        return identity
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        raise SettingsError("native_backup_root_mount_mismatch") from None


def storage_identity(value, *, capacity=False):
    path = canonical_path(value)
    machine = native_host.Host()
    archives = path / ARCHIVES
    try:
        machine.backup_trusted(path)
        require(path.is_dir(), "native_backup_root_invalid")
        pgdata = Path(native_host.POSTGRES_DATA_DIRECTORY)
        database_paths = [Path(native_host.MOUNT), pgdata, pgdata / "pg_wal"]
        tablespaces = pgdata / "pg_tblspc"
        if tablespaces.is_dir():
            database_paths.extend(tablespaces.iterdir())
        require(not any(item.exists() and native_backup.same_disk(path, item)
                        for item in database_paths), "native_backup_root_same_device")
        # A bind mount can use a different name for the canonical recovery tree.
        site_root = clickhouse.site_configuration().get("backup_root")
        if site_root:
            require(not path.is_relative_to(Path(site_root) / native_backup.ROOT.name),
                    "native_backup_root_invalid")
        require(not any(item.exists() and item.samefile(native_backup.ROOT)
                        for item in (path, *path.parents) if native_backup.ROOT.is_dir()),
                "native_backup_root_invalid")
        identity = mount_identity(path)
        if archives.is_symlink() or archives.exists():
            machine.backup_trusted(archives)
            require(archives.is_dir() and not archives.stat().st_mode & 0o077,
                    "native_backup_root_untrusted")
            require(mount_identity(archives) == identity and archives.stat().st_dev == path.stat().st_dev,
                    "native_backup_root_mount_mismatch")
        if capacity:
            machine.require_backup_capacity(path, archives)
        return identity
    except OSError:
        raise SettingsError("native_backup_root_invalid") from None


def load_or_migrate():
    """Caller holds the backup/upgrade lock during a legacy policy adoption."""
    current = read_policy()
    if current is not None:
        return current
    state = initial_policy()
    if native_install.backup_schedule() in native_install.ENABLED_BACKUP_SCHEDULES:
        path = clickhouse.site_configuration().get("backup_root")
        if path is not None:
            state["path"] = path
            try:
                state.update(enabled=True, identity=storage_identity(path, capacity=True))
            except (SettingsError, native_host.HostError):
                pass  # A compatible old destination may be selected after repair.
        if not state["enabled"]:
            apply_schedule(False)
    save_policy(state)
    return state


@contextmanager
def operation():
    with native_upgrade.operation_lock(native_backup.ROOT), native_host.administrative_lock():
        native_runtime.no_transaction()
        receipt = native_runtime.document(native_install.STATE / "package-install.json")
        require(receipt.get("status") == "configured" and not receipt.get("first_start_pending"),
                "backup_settings_unavailable")
        yield


def response(state):
    status = "unconfigured"
    if state["path"] is not None:
        status = "unavailable"
        if state["identity"] is not None:
            with suppress(SettingsError, native_host.HostError):
                if storage_identity(state["path"]) == state["identity"]:
                    status = "ready"
    return {"ok": True, "enabled": state["enabled"], "path": state["path"],
            "revision": state["revision"], "storage_status": status}


def update(state, request):
    require(request["revision"] == state["revision"], "backup_settings_revision_conflict")
    enabled, path = request["enabled"], request["path"]
    if not enabled and path is None:
        path = state["path"]
    identity = state["identity"]
    if enabled or path != state["path"]:
        identity = storage_identity(path, capacity=enabled)
        if path == state["path"] and state["identity"] is not None:
            require(identity == state["identity"], "native_backup_root_mount_mismatch")
    updated = dict(state, enabled=enabled, path=path, identity=identity, revision=secrets.token_hex(16))
    try:
        apply_schedule(enabled)
        save_policy(updated)
    except (OSError, RuntimeError, subprocess.SubprocessError):
        # Capture consults policy under this same lock; a changed link alone
        # cannot authorize a write. Restore the previous timer intent on error.
        with suppress(OSError, RuntimeError, subprocess.SubprocessError):
            if read_policy() == updated:
                save_policy(state)
            apply_schedule(state["enabled"])
        raise
    return response(updated)


def handle(request):
    try:
        validate_request(request)
        if request["action"] == "get":
            state = read_policy()
            if state is None:
                with operation():
                    state = load_or_migrate()
            return response(state)
        with operation():
            return update(load_or_migrate(), request)
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        code = str(error)
        return {"ok": False, "error": code if code in ERRORS else "backup_settings_unavailable"}


def validate_request(request):
    require(isinstance(request, dict))
    if request.get("action") == "get":
        require(set(request) == {"action"})
        return
    require(request.get("action") == "set" and set(request) == {"action", "enabled", "path", "revision"}
            and type(request["enabled"]) is bool and isinstance(request["revision"], str)
            and REVISION.fullmatch(request["revision"]))
    if request["path"] is not None:
        canonical_path(request["path"])
    else:
        require(not request["enabled"], "native_backup_root_invalid")


def unique_object(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs))
    return result


def read_request(stream):
    frame = stream.readline(MAX_FRAME + 1)
    require(len(frame) <= MAX_FRAME and frame.endswith(b"\n"))
    try:
        request = json.loads(frame.decode("utf-8"), object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        raise SettingsError("backup_settings_invalid") from None
    validate_request(request)
    return request


def serve_connection(connection, allowed_uid):
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, uid, _ = struct.unpack("3i", credentials)
    if uid != allowed_uid:
        return
    connection.settimeout(2)
    with connection.makefile("rb") as stream:
        try:
            reply = handle(read_request(stream))
        except SettingsError as error:
            reply = {"ok": False, "error": str(error)}
    connection.sendall(json.dumps(reply, separators=(",", ":")).encode("utf-8") + b"\n")


def serve():
    import grp
    import pwd

    uid = pwd.getpwnam("sli-api").pw_uid
    gid = grp.getgrnam("sli-api").gr_gid
    parent = SOCKET.parent
    native_host.Host().backup_trusted(parent)
    if SOCKET.exists() or SOCKET.is_symlink():
        info = SOCKET.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0, "backup_settings_unavailable")
        SOCKET.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(SOCKET))
        os.chown(SOCKET, 0, gid)
        SOCKET.chmod(0o660)
        listener.listen(8)
        while True:
            connection, _ = listener.accept()
            with connection, suppress(OSError):
                serve_connection(connection, uid)


@contextmanager
def selected_storage(state, *, create=False):
    path = canonical_path(state["path"])

    def check():
        require(storage_identity(state["path"]) == state["identity"], "native_backup_root_mount_mismatch")

    check()
    # Pin the mount during the job so it cannot be normally unmounted between
    # the admission check and the existing archive writer.
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        check()
        require(os.fstat(descriptor).st_dev == path.stat().st_dev, "native_backup_root_mount_mismatch")
        archives = path / ARCHIVES
        if create:
            archives.mkdir(mode=0o700, exist_ok=True)
            check()
        yield archives, check
    finally:
        os.close(descriptor)
