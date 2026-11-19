"""Remove native SLI packages. Keep site data unless explicitly asked to erase it."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path


STATE = Path('/var/lib/sli/state')
CURRENT = Path('/opt/sli/current')
SYSTEM_UNITS = Path('/etc/systemd/system')
VENDOR_UNITS = Path('/usr/lib/systemd/system')
DB_MOUNT = r'srv-sli\x2ddb.mount'
BACKUP_MOUNT = 'var-backups-sli.mount'
MOUNTS = {DB_MOUNT: 'SLI database directory', BACKUP_MOUNT: 'SLI backup volume'}
PACKAGE = re.compile(r'sli(?:-host|-rollback-hold|-server-dotnet|-(?:release|runtime)-[a-z0-9.+-]+)?')
UNIT = re.compile(r'sli(?:-[A-Za-z0-9_.@:-]+)?\.(?:service|target|slice|timer|socket|path)')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'}


def run(*argv, capture=False):
    result = subprocess.run(argv, env=ENV, check=True, text=True, stdout=subprocess.PIPE if capture else None)
    return result.stdout if capture else ''


def trusted(path):
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if info.st_uid != 0 or info.st_mode & 0o022 or item.is_symlink():
            raise RuntimeError(f'Unsafe SLI path: {item}')


@contextmanager
def setup_lock():
    import fcntl

    fd = os.open('/run/sli-setup.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError('Unsafe SLI setup lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('SLI setup or removal is already running') from None
        yield
    finally:
        os.close(fd)


def owned_mounts():
    for name, description in MOUNTS.items():
        path = SYSTEM_UNITS / name
        if path.is_file() and not path.is_symlink():
            trusted(path)
            if f'Description={description}' in path.read_text(encoding='utf-8').splitlines():
                yield name


def stop_services():
    files = run('systemctl', 'list-unit-files', '--no-legend', '--no-pager', capture=True)
    loaded = run('systemctl', 'list-units', '--all', '--plain', '--full', '--no-legend', '--no-pager', capture=True)
    rows = [line.split() for line in loaded.splitlines() if line.strip()]
    for name, _, active, *_ in rows:
        if name.startswith(('sli-upgrade-', 'sli-drill-', 'sli-restore-')) and active not in {'inactive', 'failed'}:
            raise RuntimeError(f'Wait for {name} to finish before removing SLI')

    units = sorted(name for name, state, active, *_ in rows
                   if UNIT.fullmatch(name) and (state == 'loaded' or active not in {'inactive', 'failed'}))
    timers = [name for name in units if name.endswith(('.timer', '.socket', '.path'))]
    databases = [name for name in units if name == 'sli-postgresql.service' or name.startswith('sli-clickhouse-')]
    writers = [name for name in units if name not in timers and name not in databases and not name.endswith('.slice')]
    for group in (timers, writers, databases):
        if group:
            run('systemctl', 'stop', *group)
    for name in units:
        if not name.endswith('.service'):
            continue
        error = None
        try:
            props = run('systemctl', 'show', name, '-p', 'LoadState,ActiveState,MainPID,ControlGroup', capture=True)
        except subprocess.CalledProcessError as failure:
            error, props = failure, failure.stdout or ''
        values = dict(line.split('=', 1) for line in props.splitlines())
        group = values.get('ControlGroup', '')
        if values.get('LoadState') == 'not-found' and values.get('ActiveState') == 'inactive' and (
            values.get('MainPID', '0') == '0' and not group
        ):
            continue
        if error is not None:
            raise error
        if values.get('ActiveState') not in {'inactive', 'failed'} or values.get('MainPID') != '0':
            raise RuntimeError(f'Service is still running: {name}')
        if group:
            path = Path('/sys/fs/cgroup' + group)
            if not group.startswith('/') or group == '/' or '..' in path.parts or any(
                file.read_text().strip() for file in path.rglob('cgroup.procs')
            ):
                raise RuntimeError(f'Service still has processes: {name}')

    file_rows = [line.split() for line in files.splitlines() if line.strip()]
    for flag, states in (((), {'enabled', 'linked'}), (('--runtime',), {'enabled-runtime', 'linked-runtime'})):
        enabled = [name for name, state, *_ in file_rows if UNIT.fullmatch(name) and state in states]
        if enabled:
            run('systemctl', 'disable', *flag, *enabled)


def package_list():
    rows = run('dpkg-query', '-W', '-f=${Package} ${db:Status-Status} ${Protected}\n', capture=True)
    return {name: fields == ['yes'] for name, status, *fields in map(str.split, rows.splitlines())
            if PACKAGE.fullmatch(name) and status != 'not-installed'}


@contextmanager
def park_legacy_state():
    # Old prerms refuse removal with the installed receipt, or a stale current
    # link. The services have already stopped. Use same-directory renames and
    # restore the metadata even if dpkg fails. Re-running also restores any
    # metadata parked by an interrupted run.
    pairs = []
    try:
        for path in (CURRENT, STATE / 'installed.json'):
            saved = path.with_name(path.name + '.sli-removing')
            trusted(path.parent)
            for entry in (path, saved):
                if entry.exists() or entry.is_symlink():
                    if path == CURRENT:
                        info = entry.lstat()
                        if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
                            raise RuntimeError('SLI current path is not a root-owned symlink')
                    else:
                        trusted(entry)
                        if not entry.is_file():
                            raise RuntimeError('SLI installed receipt is not a regular file')
            if path.exists() or path.is_symlink():
                if saved.exists() or saved.is_symlink():
                    raise RuntimeError(f'Conflicting SLI removal metadata: {path}')
                path.rename(saved)
            pairs.append((path, saved))
        yield
    finally:
        for path, saved in reversed(pairs):
            if saved.exists() or saved.is_symlink():
                if path.exists() or path.is_symlink():
                    raise RuntimeError(f'SLI removal metadata changed concurrently: {path}')
                saved.rename(path)


def delete_packages():
    packages = package_list()
    if 'sli' in packages:
        run('dpkg', '--purge', 'sli')
        del packages['sli']
    if 'sli-rollback-hold' in packages:
        legacy = ['--force-remove-protected'] if packages.pop('sli-rollback-hold') else []
        run('dpkg', *legacy, '--purge', 'sli-rollback-hold')
    for name in sorted(packages, key=lambda name: (name in {'sli-server-dotnet', 'sli-host'}, name == 'sli-host', name)):
        run('dpkg', '--purge', name)


def remove_units(mounts):
    archive = None
    for directory, label in ((SYSTEM_UNITS, 'local'), (VENDOR_UNITS, 'vendor')):
        trusted(directory)
        if not directory.exists():
            continue
        for path in directory.iterdir():
            name = path.name.removesuffix('.d')
            if not UNIT.fullmatch(name) and name not in mounts:
                continue
            if archive is None:
                parent = STATE / 'removed-units'
                trusted(parent)
                parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                archive = Path(tempfile.mkdtemp(dir=parent))
            target = archive / label
            target.mkdir(mode=0o700, exist_ok=True)
            shutil.move(path, target / path.name)
    run('systemctl', 'daemon-reload')


def receipt(path):
    trusted(path)
    if not path.exists():
        return None
    if not path.is_file():
        raise RuntimeError(f'Invalid SLI storage receipt: {path}')
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise RuntimeError(f'Invalid SLI storage receipt: {path}')
    return value


def purge_paths(root=Path('/')):
    paths = [root / path for path in ('etc/sli', 'var/backups/sli', 'var/lib/sli-ca-offline', 'var/lib/sli')]
    saved = receipt(STATE / 'host-prepared.json')
    if saved is not None:
        if saved.get('version') != 1 or saved.get('mount') != '/srv/sli-db':
            raise RuntimeError('Invalid SLI database storage receipt')
        mode = saved.get('storage_mode', 'uuid')
        if mode == 'directory':
            value = saved.get('directory', '')
            if (not re.fullmatch(r'/(?:var/lib|srv|mnt)/[A-Za-z0-9_-]+', value)
                    or value in {'/srv/sli-db', '/var/lib/sli', '/var/lib/postgresql', '/var/lib/clickhouse'}):
                raise RuntimeError('Invalid SLI database directory')
            storage = root / value.lstrip('/')
            trusted(storage)
            if not storage.is_dir():
                raise RuntimeError('SLI database directory is unavailable')
        elif mode == 'uuid':
            storage = root / 'srv/sli-db'
            value = run('findmnt', '--noheadings', '--mountpoint', str(storage), '--output', 'UUID,FSTYPE', capture=True)
            if not saved.get('uuid') or value.split() != [saved['uuid'], 'ext4']:
                raise RuntimeError('SLI database volume does not match the storage receipt')
        else:
            raise RuntimeError('Invalid SLI database storage mode')
        paths[0:0] = [storage / 'pgdata', storage / 'clickhouse', root / 'etc/postgresql/18/sli']

    cold = receipt(STATE / 'cold-tablespace.json')
    if cold is not None:
        value = cold.get('root', '')
        if not re.fullmatch(r'/(?:mnt|srv)/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*', value) or (
            value == '/srv/sli-db' or value.startswith('/srv/sli-db/')
        ):
            raise RuntimeError('Invalid SLI tablespace directory')
        storage = root / value.lstrip('/')
        trusted(storage)
        rows = json.loads(run('findmnt', '--json', '--target', str(storage), '--output', 'UUID,FSROOT', capture=True))
        if rows['filesystems'] != [{'uuid': cold.get('uuid'), 'fsroot': cold.get('fsroot')}]:
            raise RuntimeError('SLI tablespace volume does not match the storage receipt')
        paths.insert(0, storage / 'pg-tablespace')

    mount_rows = json.loads(run('findmnt', '--json', '--list', '--output', 'TARGET', capture=True))
    mounted = [Path(row['target']) for row in mount_rows['filesystems']]
    for path in paths:
        trusted(path.parent)
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise RuntimeError(f'Unsafe SLI data directory: {path}')
        if any(mount == path or path in mount.parents for mount in mounted):
            raise RuntimeError(f'Unexpected mount in SLI data directory: {path}')
    return paths


def restore_cluster_guard():
    backup = STATE / 'createcluster.conf.before'
    config = Path('/etc/postgresql-common/createcluster.conf')
    trusted(backup)
    trusted(config)
    if backup.is_file() and config.is_file():
        original = backup.read_text(encoding='utf-8')
        managed = original.rstrip() + '\n# SLI host preparation\ncreate_main_cluster = false\n'
        if config.read_text(encoding='utf-8') == managed:
            config.write_text(original, encoding='utf-8')


def remove(*, purge_data):
    stop_services()
    mounts = tuple(owned_mounts())
    if mounts:
        run('systemctl', 'stop', *mounts)
    paths = purge_paths() if purge_data else ()
    with park_legacy_state():
        delete_packages()
    remove_units(mounts)
    if purge_data:
        restore_cluster_guard()
        for path in paths:
            if path.exists():
                shutil.rmtree(path)
        CURRENT.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--purge-data', action='store_true', help='also erase SLI data and configuration on this host')
    mode.add_argument('--stop-services', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.exit(1, 'Run SLI removal with sudo\n')
    try:
        if args.stop_services:
            stop_services()
        else:
            with setup_lock():
                remove(purge_data=args.purge_data)
            print('SLI packages removed. ' + ('SLI data erased.' if args.purge_data else 'SLI data retained.'))
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'SLI removal failed: {error}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
