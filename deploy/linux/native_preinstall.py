"""Stdlib guard embedded in sli-host preinst, before vendor DB postinsts run."""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

START_FILES = ('/lib/systemd/system/clickhouse-server.service', '/etc/init.d/clickhouse-server')
POSTGRES_DATA_DIRECTORY = '/srv/sli-db/pgdata/18/main'


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
        self.console_message = f'{name}: {reason}. {remedy}'


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


def existing_database(name):
    if name == '/etc/postgresql':
        return GuardError('native_existing_database', name, 'existing PostgreSQL configuration (expected an empty directory)',
                          'Check sudo pg_lsclusters. After retiring and backing up the existing database, run '
                          'sudo mv -T -n -- /etc/postgresql /etc/postgresql.before-sli and retry')
    return GuardError('native_existing_database', name, 'not an empty directory',
                      'Preserve the existing database and rerun sudo sli-setup --directory /srv/sli-data on a '
                      'dedicated empty volume if this is your selected storage, or use another host')


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
        if name == '/etc/postgresql':
            raise existing_database(name)
        raise GuardError('native_existing_database', name, 'not an empty directory',
                         f'After retiring and backing up the existing database, run sudo mv -T -n -- {name} '
                         f'{name}.before-sli and retry, or choose another host')
    uid = postgres_uid() if name in ('/etc/postgresql', '/var/lib/postgresql') and info.st_uid != 0 else None
    if info.st_uid != 0 and (uid is None or not 0 < uid < 1000 or info.st_uid != uid):
        raise GuardError('native_path_untrusted', name, 'unexpected owner (requires root or system postgres for PostgreSQL)',
                         'Verify the directory owner and the system postgres account before retrying')
    if info.st_mode & 0o002:
        raise GuardError('native_path_untrusted', name, 'directory is world-writable (o+w)',
                         'Remove world write access with chmod o-w on this directory before retrying')


def diagnostic(error):
    detail = error.console_message if isinstance(error, GuardError) else 'Run sudo journalctl -t sli-setup -n 80 --no-pager'
    return 'SLI cannot prepare database startup guards. ' + detail + '.'


def cluster_guard(config, backup):
    """Accept original and previously managed bytes, preserving the first backup."""
    name = '/etc/postgresql-common/createcluster.conf'
    current = config.read_text() if config.exists() else ''
    original = backup.read_text() if backup.exists() else current
    guard = '\n# SLI host preparation\ncreate_main_cluster = false\n'
    legacy_suffix = re.compile(r'(?:\n# SLI host preparation\ncreate_main_cluster = false[ \t]*)+\Z')
    original_base = legacy_suffix.sub('', original.rstrip()).rstrip()
    unmanaged = re.sub(r'(?m)^[ \t]*create_main_cluster[ \t]*=[^\n]*(?:\n|$)', '',
                       original_base).rstrip()
    managed = unmanaged + guard
    if (config.exists() and current not in (original, managed)
            and legacy_suffix.sub('', current.rstrip()).rstrip() != original_base):
        raise GuardError('native_existing_configuration_conflict', name, 'settings changed after SLI saved them',
                         'Run sudo diff -u /var/lib/sli/state/createcluster.conf.before '
                         f'{name} and reconcile the settings before retrying')
    return original, current, managed


def write_guard(path, text, mode):
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        if os.name == 'posix':
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


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
    if action != 'install' or not installed.exists() or not recovery_required(root=root):
        marker.unlink(missing_ok=True)
        return
    write_guard(marker, json.dumps({'schema_version': 1, 'release': release}) + '\n', 0o600)


def retain_legacy_dotnet(*, root=Path('/')):
    """Keep the accepted publication before dpkg replaces the unversioned package."""
    current = root / 'opt/sli/current'
    trusted(current.parent)
    if not current.is_symlink():
        return
    accepted = current.readlink()
    if accepted.parent != root / 'opt/sli/releases' or not re.fullmatch(r'[a-z0-9][a-z0-9.+-]{0,63}', accepted.name):
        raise RuntimeError('native_release_invalid')
    manifest = accepted / 'native-runtime.json'
    trusted(manifest)
    if not manifest.is_file():
        raise RuntimeError('native_release_invalid')
    source = root / 'opt/sli/dotnet' / accepted.name
    saved = accepted / 'dotnet'
    trusted(source)
    trusted(saved)
    if saved.exists() or not source.exists():
        return
    # New publications already belong to the retained, versioned release package.
    owned = subprocess.run(['/usr/bin/dpkg-query', '-L', 'sli-release-' + accepted.name],
                           check=True, capture_output=True, text=True).stdout.splitlines()
    if str(source / 'Sli.Server') in owned:
        return
    for path in (source, *source.rglob('*')):
        trusted(path)
        if not (path.is_dir() or path.is_file()):
            raise RuntimeError('native_dotnet_publish_invalid')
    if not (source / 'Sli.Server').is_file():
        raise RuntimeError('native_dotnet_publish_invalid')
    with tempfile.TemporaryDirectory(dir=accepted, prefix='.dotnet-retain-') as staging:
        copy = Path(staging) / 'dotnet'
        shutil.copytree(source, copy, copy_function=os.link)
        for directory in (*[path for path in copy.rglob('*') if path.is_dir()], copy):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.replace(copy, saved)
        descriptor = os.open(accepted, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def recovery_required(*, root=Path('/'), state=None, current=None, releases=None, recovery=None):
    """Only a fresh or explicitly interrupted first start bypasses upgrade recovery."""
    state = root / 'var/lib/sli/state' if state is None else state
    current = root / 'opt/sli/current' if current is None else current
    releases = root / 'opt/sli/releases' if releases is None else releases
    recovery = root / 'var/lib/sli/recovery' if recovery is None else recovery
    installed = state / 'installed.json'
    receipt = state / 'package-install.json'
    for path in (installed, receipt):
        trusted(path)
        if path.exists() and not path.is_file():
            raise RuntimeError('native_install_interrupted_requires_recovery')
    trusted(current.parent)
    selected = current.is_symlink() or current.exists()
    if not receipt.exists():
        return installed.exists() or selected
    value = json.loads(receipt.read_bytes())
    release = value.get('release')
    if (value.get('schema_version') != 1 or value.get('first_start_pending') is not True
            or value.get('status') not in {'configuring', 'failed'}
            or not isinstance(release, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.+-]{0,63}', release)):
        return True
    candidate = releases / release
    if selected and (not current.is_symlink() or current.readlink() != candidate):
        return True
    if installed.exists() and (not selected or json.loads(installed.read_bytes()).get('release') != str(candidate)):
        return True
    seal = recovery / release / 'recovery.json'
    trusted(seal)
    return seal.exists()


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
    prepared = state / 'host-prepared.json'
    checked_trusted(prepared, '/var/lib/sli/state/host-prepared.json')
    if prepared.exists():
        return  # Existing installs retain their accepted host/recovery guards.
    marker = state / 'vendor-prepared.json'
    checked_trusted(marker, '/var/lib/sli/state/vendor-prepared.json')
    config = root / 'etc/postgresql-common/createcluster.conf'
    checked_trusted(config, '/etc/postgresql-common/createcluster.conf')
    checked_trusted(root / 'etc/systemd/system', '/etc/systemd/system')
    original_path = state / 'createcluster.conf.before'
    checked_trusted(original_path, '/var/lib/sli/state/createcluster.conf.before')
    if marker.exists():
        if not marker.is_file() or json.loads(marker.read_bytes()) != {'schema_version': 1} or not original_path.is_file():
            raise RuntimeError('native_vendor_cluster_guard_missing')
    else:
        for name in ('etc/postgresql', 'var/lib/postgresql', 'var/lib/clickhouse'):
            database_directory(root / name, '/' + name)
    original, current, managed = cluster_guard(config, original_path)
    ensure_directory(state, 0o700)
    state.chmod(0o700)
    if not original_path.exists():
        write_guard(original_path, original, 0o600)
    ensure_directory(config.parent)
    if current != managed:
        write_guard(config, managed, 0o644)
    else:
        config.chmod(0o644)
    write_guard(marker, json.dumps({'schema_version': 1}) + '\n', 0o600)


if __name__ == '__main__':
    try:
        if os.geteuid() != 0:
            raise RuntimeError('native_root_required')
        os.umask(0o022)
        if len(sys.argv) == 4 and sys.argv[1] == '--package-install':
            package_install(sys.argv[2], sys.argv[3])
        elif sys.argv[1:] == ['--retain-legacy-dotnet']:
            retain_legacy_dotnet()
        elif sys.argv[1:] == ['--recovery-kind']:
            print('accepted' if recovery_required() else 'unfinished')
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
            code = str(error) if isinstance(error, RuntimeError) else ''
            syslog.syslog(syslog.LOG_ERR, code if re.fullmatch(r'native_[a-z_]{1,100}', code) else 'native_preinstall_failed')
        except (ImportError, OSError):
            pass
        # Never forward arbitrary paths, existing config or command output.
        print(diagnostic(error), file=sys.stderr)
        raise SystemExit(1) from None
