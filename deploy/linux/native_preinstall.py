"""Stdlib guard embedded in sli-host preinst, before vendor DB postinsts run."""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

START_FILES = ('/lib/systemd/system/clickhouse-server.service', '/etc/init.d/clickhouse-server')


def ensure_directory(path, mode=0o755, uid=0, gid=0, *, parent_mode=0o755, exist_ok=True):
    """Set ownership/modes only on directories we create, never existing parents.

    Also embedded in preinst: it must work before any package is unpacked.
    Start private while creating each component, then publish its explicit mode.
    """
    if not exist_ok and (path.exists() or path.is_symlink()):
        raise FileExistsError(path)
    missing = []
    for item in (path, *path.parents):
        if item.is_symlink():
            raise RuntimeError('native_symlink_forbidden')
        if not item.exists():
            missing.append(item)
        elif not item.is_dir():
            raise RuntimeError('native_directory_required')
    for item in reversed(missing):
        try:
            item.mkdir(mode=0o700)
        except FileExistsError:
            if item == path and not exist_ok:
                raise
            if item.is_symlink() or not item.is_dir():
                raise RuntimeError('native_directory_required') from None
            continue
        wanted_uid, wanted_gid = (uid, gid) if item == path else (0, 0)
        info = item.stat()
        if (info.st_uid, info.st_gid) != (wanted_uid, wanted_gid):
            os.chown(item, wanted_uid, wanted_gid)
        item.chmod(mode if item == path else parent_mode)


class GuardError(RuntimeError):
    """Only installer-owned path labels and fixed diagnostics may be displayed."""

    def __init__(self, code, name, reason, remedy):
        super().__init__(code)
        self.detail = f'{name}: {reason}. {remedy}'


def checked_trusted(path, name):
    try:
        trusted(path)
    except RuntimeError as error:
        raise GuardError(str(error), name, 'path or parent is a symlink, not root-owned, or group/world-writable',
                         'Check this path and its parents; restore root ownership and remove group/world write access') from None


def postgres_uid():
    import pwd
    try:
        return pwd.getpwnam('postgres').pw_uid
    except KeyError:
        return None


def database_directory(path, name):
    # The leaf is vendor-owned; administrative ancestors remain strictly trusted.
    checked_trusted(path.parent, name.rsplit('/', 1)[0])
    if path.is_symlink():
        raise GuardError('native_symlink_forbidden', name, 'symbolic link is forbidden',
                         'Use a real empty directory; inspect the link before replacing it')
    if not path.exists():
        return
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or any(path.iterdir()):
        raise GuardError('native_existing_database', name, 'not an empty directory',
                         'Preserve any existing database and choose a host without existing database data')
    uid = postgres_uid() if name in ('/etc/postgresql', '/var/lib/postgresql') and info.st_uid != 0 else None
    if info.st_uid != 0 and (uid is None or not 0 < uid < 1000 or info.st_uid != uid):
        raise GuardError('native_path_untrusted', name, 'unexpected owner (requires root or system postgres for PostgreSQL)',
                         'Verify the directory owner and the system postgres account before retrying')
    if info.st_mode & 0o002:
        raise GuardError('native_path_untrusted', name, 'directory is world-writable (o+w)',
                         'Remove world write access with chmod o-w on this directory before retrying')


def diagnostic(error):
    detail = error.detail if isinstance(error, GuardError) else 'Check journalctl -t sli-setup for the error code'
    return 'SLI cannot prepare database startup guards. ' + detail + '.'


def trusted(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise RuntimeError('native_symlink_forbidden')
        if item.exists():
            info = item.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError('native_path_untrusted')


def package_install(action, release, *, root=Path('/')):
    """Remember dpkg's install/upgrade distinction before unpack replaces helpers.

    Last-configured-version alone is ambiguous after remove without purge.
    This marker only requests staging; it cannot authorize database adoption.
    """
    if action not in {'install', 'upgrade'} or not re.fullmatch(r'[a-z0-9][a-z0-9.+-]{0,63}', release):
        raise RuntimeError('native_install_release_invalid')
    state = root / 'var/lib/sli/state'
    marker = state / 'reuse-package.json'
    trusted(marker)
    installed = state / 'installed.json'
    trusted(installed)
    if action != 'install' or not installed.exists():
        marker.unlink(missing_ok=True)
        return
    fd, temporary = tempfile.mkstemp(dir=state)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump({'schema_version': 1, 'release': release}, stream)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, marker)
        if os.name == 'posix':
            directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def cleanup_bytecode(root, inventory):
    """Remove only unsealed bytecode, never follow links or hide other files."""
    if not isinstance(inventory, dict) or root.is_symlink() or not root.is_dir():
        raise RuntimeError('native_recovery_cache_invalid')
    pending = []
    for cache in root.rglob('__pycache__'):
        trusted(cache)  # Every ancestor: root-owned, no g+w/o+w/symlinks.
        if not stat.S_ISDIR(cache.lstat().st_mode):
            raise RuntimeError('native_recovery_cache_invalid')
        files = []
        for path in cache.iterdir():
            trusted(path)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RuntimeError('native_recovery_cache_invalid')
            if path.relative_to(root).as_posix() not in inventory:
                if path.suffix != '.pyc':
                    raise RuntimeError('native_recovery_cache_invalid')
                files.append(path)
        pending.append((cache, files))
    # Validate all candidates before deleting anything. No recursive deletion.
    for cache, files in pending:
        for path in files:
            path.unlink()
        if cache.relative_to(root).as_posix() not in inventory and not any(cache.iterdir()):
            cache.rmdir()


def cleanup_recovery(release, *, recovery=Path('/var/lib/sli/recovery'), runtimes=Path('/opt/sli/runtimes')):
    """Bootstrap old sealed coordinators without importing their cached code."""
    if not re.fullmatch(r'[a-z0-9][a-z0-9.+-]{0,63}', release):
        raise RuntimeError('native_recovery_cache_invalid')
    root = recovery / release
    seal = root / 'recovery.json'
    trusted(seal)
    value = json.loads(seal.read_bytes())
    python = Path(value['python'])
    if (value.get('schema_version') != 1 or value.get('release') != release
            or not python.is_relative_to(runtimes) or len(python.relative_to(runtimes).parts) != 3
            or not re.fullmatch(r'[a-z0-9][a-z0-9.+-]{0,63}', python.parent.parent.name)
            or python.parent.name != 'bin' or python.name != 'python3.14'):
        raise RuntimeError('native_recovery_cache_invalid')
    cleanup_bytecode(root, value['content_checksums'])
    cleanup_bytecode(python.parent.parent, value['runtime_inventory'])


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=30,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode:
        raise RuntimeError('native_vendor_diversion_invalid')
    return result.stdout.strip()


def prepare(root=Path('/')):
    state = root / 'var/lib/sli/state'
    checked_trusted(state, '/var/lib/sli/state')
    if (state / 'host-prepared.json').exists():
        return  # Existing installs retain their accepted host/recovery guards.
    for name in ('etc/postgresql', 'var/lib/postgresql', 'var/lib/clickhouse'):
        path = root / name
        database_directory(path, '/' + name)
    config = root / 'etc/postgresql-common/createcluster.conf'
    checked_trusted(config, '/etc/postgresql-common/createcluster.conf')
    checked_trusted(root / 'etc/systemd/system', '/etc/systemd/system')
    original_path = state / 'createcluster.conf.before'
    checked_trusted(original_path, '/var/lib/sli/state/createcluster.conf.before')
    original = original_path.read_text() if original_path.exists() else config.read_text() if config.exists() else ''
    managed = original.rstrip() + '\n# SLI host preparation\ncreate_main_cluster = false\n'
    if config.exists() and config.read_text() not in (original, managed):
        raise RuntimeError('native_existing_configuration_conflict')
    ensure_directory(state, 0o700)
    state.chmod(0o700)
    if not original_path.exists():
        original_path.write_text(original)
        original_path.chmod(0o600)
    ensure_directory(config.parent)
    config.write_text(managed)
    config.chmod(0o644)
    marker = state / 'vendor-prepared.json'
    checked_trusted(marker, '/var/lib/sli/state/vendor-prepared.json')
    marker.write_text(json.dumps({'schema_version': 1}) + '\n')
    marker.chmod(stat.S_IRUSR | stat.S_IWUSR)


if __name__ == '__main__':
    try:
        if os.geteuid() != 0:
            raise RuntimeError('native_root_required')
        os.umask(0o022)
        if len(sys.argv) == 4 and sys.argv[1] == '--package-install':
            package_install(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 3 and sys.argv[1] == '--clean-recovery':
            accepted = Path(sys.argv[2])
            if accepted.parent != Path('/opt/sli/releases'):
                raise RuntimeError('native_recovery_cache_invalid')
            cleanup_recovery(accepted.name)
        else:
            prepare()
    except Exception as error:  # noqa: BLE001 - fixed diagnostics before package helpers exist
        try:
            import syslog
            syslog.openlog('sli-setup')
            code = str(error) if isinstance(error, RuntimeError) else 'native_preinstall_failed'
            syslog.syslog(syslog.LOG_ERR, code + ': ' + diagnostic(error))
        except (ImportError, OSError):
            pass
        # Never forward arbitrary paths, existing config or command output.
        print(diagnostic(error))
        raise SystemExit(1) from None
