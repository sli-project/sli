#!/usr/bin/python3 -I
"""Remove native SLI packages. Keep site data unless explicitly asked to erase it."""
from __future__ import annotations

import argparse
import errno
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
GENERATED_UNITS = Path('/run/systemd/generator')
TRANSIENT_UNITS = Path('/run/systemd/transient')
DOTNET_GENERATOR = Path('/usr/lib/systemd/system-generators/sli-dotnet-api')
CLUSTER_GUARD = Path('/etc/postgresql-common/createcluster.conf')
DB_MOUNT = r'srv-sli\x2ddb.mount'
BACKUP_MOUNT = 'var-backups-sli.mount'
MOUNTS = (DB_MOUNT, BACKUP_MOUNT)
PACKAGE = re.compile(r'sli(?:-host|-rollback-hold|-server-dotnet|-(?:release|runtime)-[a-z0-9.+-]+)?')
UNIT_SUFFIXES = {'.service', '.target', '.slice', '.timer', '.socket', '.path', '.mount'}
# Setup renders these files outside dpkg. Match only its installed paths and
# identifying directives, including units emitted by the packaged generator.
LOCAL_UNITS = {
    'sli-postgresql.service': 'ExecStart=/usr/lib/postgresql/18/bin/postgres -D /srv/sli-db/pgdata/18/main '
                              '-c config_file=/etc/postgresql/18/sli/postgresql.conf\n',
    'sli-bootstrap-pg.service': 'ExecStart=/usr/bin/python3 -B /usr/lib/sli/native_host.py bootstrap-pg\n',
    BACKUP_MOUNT: 'Where=/var/backups/sli\nType=none\nOptions=bind\n',
}
RUNTIME_SERVICES = (
    'api', 'post-collection', 'what-where-when', 'semantic', 'entity-state', 'storage-lifecycle',
    'ad-snapshot-manifest-coordinator', 'remote-access', 'notification-delivery', 'notification-setup',
    'report-producer', 'executor-light', 'executor-heavy', 'executor-long',
)
RUNTIME_UNITS = {
    'sli.target': 'Description=SLI platform\n',
    'sli-runtime.target': 'Description=SLI application',
    'sli.slice': 'Description=SLI applications\n',
    'sli-health.timer': 'Unit=sli-health.service\n',
    'sli-ready.service': 'ExecStart=/usr/bin/python3 -I -B /usr/lib/sli/native_runtime.py control ready\n',
    'sli-health.service': 'ExecStart=/usr/bin/python3 -I -B /usr/lib/sli/native_runtime.py control health\n',
    'sli-backup.timer': 'Unit=sli-backup.service\n',
    'sli-backup.service': 'ExecStart=/usr/bin/python3 -I -B /usr/lib/sli/native_backup.py launch capture\n',
    'sli-backup-drill.service': 'ExecStart=/usr/bin/python3 -I -B /usr/lib/sli/native_backup.py launch drill\n',
    **{'sli-' + name.replace('executor-', 'executor@') + '.service':
       f'ExecStart=/usr/bin/python3 -I -B /usr/lib/sli/native_runtime.py launch {name}\n'
       for name in RUNTIME_SERVICES},
}
DOTNET_TARGET = 'sli-dotnet.target'
DOTNET_SERVICES = {f'sli-dotnet-{name}.service' for name in RUNTIME_SERVICES}
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'}


def database_directory_path(value):
    if (not isinstance(value, str)
            or not (re.fullmatch(r'/(?:var/lib|srv|mnt)/[A-Za-z0-9_-]+', value)
                    or re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)*sli-db(?:-2)?', value))
            or value.startswith(('/srv/sli-db/', '/var/lib/sli/', '/var/lib/postgresql/',
                                 '/var/lib/clickhouse/', '/var/backups/sli/', '/opt/sli/',
                                 '/home/', '/root/', '/run/', '/tmp/', '/var/tmp/'))
            or value in {'/srv/sli-db', '/var/lib/sli', '/var/lib/postgresql', '/var/lib/clickhouse'}):
        raise ValueError('native_database_directory_invalid')
    return value


def directory_mount_unit(directory):
    return ('[Unit]\nDescription=SLI database directory\nRequiresMountsFor=' + directory + '\n'
            'Before=sli-postgresql.service\n'
            '[Mount]\nWhat=' + directory + '\nWhere=/srv/sli-db\nType=none\nOptions=bind\n')


def run(*argv, capture=False):
    result = subprocess.run(argv, env=ENV, check=True, text=True, stdout=subprocess.PIPE if capture else None)
    return result.stdout if capture else ''


def postgres_uid():
    import pwd

    try:
        uid = pwd.getpwnam('postgres').pw_uid
    except KeyError:
        return None
    return uid if 0 < uid < 1000 else None


def trusted(path, *, postgres_paths=()):
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode) or (
            info.st_uid != 0 and (item not in postgres_paths or info.st_uid != postgres_uid())
        ):
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


def unit_text(path):
    trusted(path)
    return path.read_text(encoding='utf-8') if path.is_file() else ''


def unit_inventory(packages):
    files = run('dpkg-query', '--listfiles', *packages, capture=True).splitlines() if packages else ()
    package_paths = {Path('/usr' + name if name.startswith('/lib/systemd/') else name) for name in files}
    packaged = {path for path in package_paths if path.parent in (SYSTEM_UNITS, VENDOR_UNITS)
                and path.suffix in UNIT_SUFFIXES}
    for path in sorted(packaged):
        trusted(path)

    rendered = set()
    for directory, units in ((SYSTEM_UNITS, LOCAL_UNITS), (VENDOR_UNITS, RUNTIME_UNITS)):
        for name, directive in units.items():
            path = directory / name
            if '\n' + directive in unit_text(path):
                rendered.add(path)
    database_mount = SYSTEM_UNITS / DB_MOUNT
    body = unit_text(database_mount)
    what = re.search(r'(?m)^What=(/[^\n]+)$', body)
    if what is not None and body == directory_mount_unit(what[1]):
        rendered.add(database_mount)

    generated = set()
    if DOTNET_GENERATOR in package_paths:
        target = GENERATED_UNITS / DOTNET_TARGET
        if '\nDescription=SLI .NET application writers\n' in unit_text(target):
            generated.add(target)
        for name in DOTNET_SERVICES:
            path = GENERATED_UNITS / name
            command = re.search(r'^ExecStart=(/opt/sli/dotnet/[a-z0-9][a-z0-9.+-]{0,63}/Sli\.Server)(?: |\n)',
                                unit_text(path), re.MULTILINE)
            if command and Path(command[1]) in package_paths:
                generated.add(path)

    # Archive only the drop-in files SLI wrote. A .d directory can also
    # contain administrator overrides that must stay in place.
    dropins = set()
    for name in LOCAL_UNITS.keys() | RUNTIME_UNITS.keys() | DOTNET_SERVICES | {DOTNET_TARGET}:
        directory = SYSTEM_UNITS / (name + '.d')
        backup = directory / '80-sli-backup-mount.conf'
        if unit_text(backup) == '[Unit]\nBindsTo=var-backups-sli.mount\nAfter=var-backups-sli.mount\n':
            dropins.add(backup)
    cold = SYSTEM_UNITS / 'sli-postgresql.service.d/85-sli-cold-mount.conf'
    if re.fullmatch(r'\[Unit\]\nRequiresMountsFor=/(?:mnt|srv)/[\w/-]+\n\[Service\]\n'
                    r'ExecStartPre=\+/usr/bin/python3 -B /usr/lib/sli/native_host.py check-cold-mount\n', unit_text(cold)):
        dropins.add(cold)
    return packaged | rendered | generated, (rendered - packaged) | dropins


def service_plan(owned, *, package_removal=False):
    files = run('systemctl', 'list-unit-files', '--no-legend', '--no-pager', capture=True)
    loaded = run('systemctl', 'list-units', '--all', '--plain', '--full', '--no-legend', '--no-pager', capture=True)
    rows = [line.split() for line in loaded.splitlines() if line.strip()]
    file_rows = [line.split() for line in files.splitlines() if line.strip()]
    for name, _, active, *_ in rows:
        if active in {'inactive', 'failed'}:
            continue
        upgrade = re.fullmatch(r'sli-upgrade-[0-9a-f]{32}\.service', name) or name == 'sli-reuse-check.service'
        drill = re.fullmatch(r'sli-drill-([0-9a-f]{16})-(?:pg|history|warm)\.service', name)
        restore = name.startswith('sli-restore-') and name.endswith('.service')
        body = unit_text(TRANSIENT_UNITS / name) if upgrade or drill or restore else ''
        if (upgrade and '/native_upgrade.py' in body
                or drill and f'/{drill[1]}/' in body
                or restore and any(f'/{script}.py' in body
                                   for script in ('native_backup', 'native_restore', 'restore_existing'))):
            raise RuntimeError(f'Wait for {name} to finish before removing SLI')

    owned_names = {path.name for path in owned}
    listed = {row[0] for row in rows + file_rows}
    # Existing sli-server-dotnet maintainer scripts stop these names too.
    # Detect foreign replacements before dpkg can run that script.
    package_stops = {name for name in listed if package_removal and (
        name == DOTNET_TARGET or name.startswith('sli-dotnet-') and name.endswith('.service')
    )}
    names = set()
    for name in sorted(listed & (owned_names | package_stops)):
        fragment = run('systemctl', 'show', '-p', 'FragmentPath', '--value', '--', name, capture=True).strip()
        path = Path('/usr' + fragment if fragment.startswith('/lib/systemd/') else fragment)
        if path in owned and path.name == name:
            names.add(name)
        elif name in package_stops and fragment:
            raise RuntimeError(f'Package removal would stop an unmanaged unit: {name}')

    units = sorted(name for name, state, active, *_ in rows
                   if name in names and name not in MOUNTS and (state == 'loaded' or active not in {'inactive', 'failed'}))
    return units, file_rows, names


def stop_services(plan=None, *, disable=True):
    if plan is None:
        owned, _ = unit_inventory(package_list())
        plan = service_plan(owned)
    units, _, _ = plan
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

    if disable:
        disable_services(plan)


def disable_services(plan):
    _, file_rows, names = plan
    for flag, states in (((), {'enabled', 'linked'}), (('--runtime',), {'enabled-runtime', 'linked-runtime'})):
        enabled = [name for name, state, *_ in file_rows if name in names and name not in MOUNTS and state in states]
        if enabled:
            run('systemctl', 'disable', *flag, *enabled)


def package_list():
    rows = run('dpkg-query', '-W', '-f=${Package} ${db:Status-Status} ${Protected}\n', capture=True)
    return {name: fields == ['yes'] for name, status, *fields in map(str.split, rows.splitlines())
            if PACKAGE.fullmatch(name) and status != 'not-installed'}


def legacy_state():
    pairs = []
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
        if (path.exists() or path.is_symlink()) and (saved.exists() or saved.is_symlink()):
            raise RuntimeError(f'Conflicting SLI removal metadata: {path}')
        pairs.append((path, saved))
    return pairs


@contextmanager
def park_legacy_state(pairs):
    # Old prerms refuse removal with the receipt or a current link. Restore
    # the metadata even if dpkg fails or a prior run left an entry parked.
    parked = []
    try:
        for path, saved in pairs:
            if path.exists() or path.is_symlink():
                path.rename(saved)
            parked.append((path, saved))
        yield
    finally:
        for path, saved in reversed(parked):
            if saved.exists() or saved.is_symlink():
                if path.exists() or path.is_symlink():
                    raise RuntimeError(f'SLI removal metadata changed concurrently: {path}')
                saved.rename(path)


def delete_packages(packages):
    if 'sli' in packages:
        run('dpkg', '--purge', 'sli')
        del packages['sli']
    if 'sli-rollback-hold' in packages:
        legacy = ['--force-remove-protected'] if packages.pop('sli-rollback-hold') else []
        run('dpkg', *legacy, '--purge', 'sli-rollback-hold')
    for name in sorted(packages, key=lambda name: (name in {'sli-server-dotnet', 'sli-host'}, name == 'sli-host', name)):
        run('dpkg', '--purge', name)


def remove_units(paths, parent):
    if paths:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        archive = Path(tempfile.mkdtemp(dir=parent))
        for path in sorted(paths):
            directory, label = (SYSTEM_UNITS, 'local') if path.is_relative_to(SYSTEM_UNITS) else (VENDOR_UNITS, 'vendor')
            target = archive / label / path.relative_to(directory)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.move(path, target)
            if path.parent.name.endswith('.d'):
                remove_empty_directory(path.parent)
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


def purge_paths(root=Path('/'), *, backup_unmount_pending=False, database_unmounted=False):
    paths = [root / path for path in ('etc/sli', 'var/backups/sli', 'var/lib/sli-ca-offline', 'var/lib/sli')]
    postgres_config = root / 'etc/postgresql/18/sli'
    postgres_paths = (postgres_config, postgres_config.parent, postgres_config.parent.parent)
    empty_version = None
    saved = receipt(STATE / 'host-prepared.json')
    if saved is not None:
        if saved.get('version') != 1 or saved.get('mount') != '/srv/sli-db':
            raise RuntimeError('Invalid SLI database storage receipt')
        mode = saved.get('storage_mode', 'uuid')
        if mode == 'directory':
            try:
                value = database_directory_path(saved.get('directory'))
            except ValueError:
                raise RuntimeError('Invalid SLI database directory') from None
            storage = root / value.lstrip('/')
            trusted(storage)
            if not storage.is_dir():
                raise RuntimeError('SLI database directory is unavailable')
            expected = saved.get('filesystem_uuid')
            if not isinstance(expected, str) or not expected:
                raise RuntimeError('SLI database storage receipt has no filesystem UUID')
            volume = run('findmnt', '--noheadings', '--target', str(storage), '--output', 'UUID,FSTYPE', capture=True)
            if volume.split() not in ([expected, 'ext4'], [expected, 'xfs']):
                raise RuntimeError('SLI database volume does not match the storage receipt')
        elif mode == 'uuid':
            storage = root / 'srv/sli-db'
            value = run('findmnt', '--noheadings', '--mountpoint', str(storage), '--output', 'UUID,FSTYPE', capture=True)
            if not saved.get('uuid') or value.split() != [saved['uuid'], 'ext4']:
                raise RuntimeError('SLI database volume does not match the storage receipt')
        else:
            raise RuntimeError('Invalid SLI database storage mode')
        paths[0:0] = [storage / 'pgdata', storage / 'clickhouse', postgres_config]
        trusted(postgres_config, postgres_paths=postgres_paths)
        empty_version = postgres_config.parent

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
    mounted = {Path(row['target']) for row in mount_rows['filesystems']}
    if database_unmounted and root / 'srv/sli-db' in mounted:
        raise RuntimeError('SLI database mount is still mounted')
    if empty_version in mounted:
        raise RuntimeError(f'Unexpected mount in SLI data directory: {empty_version}')
    for path in paths:
        trusted(path.parent, postgres_paths=postgres_paths)
        pending = backup_unmount_pending and path == root / 'var/backups/sli' and path in mounted
        if pending:
            # The external volume is preserved. Inspect the underlying directory
            # and repeat the mount checks after unmounting it.
            mounted.remove(path)
        elif path.is_symlink() or (path.exists() and not path.is_dir()):
            raise RuntimeError(f'Unsafe SLI data directory: {path}')
        if any(mount == path or path in mount.parents for mount in mounted):
            raise RuntimeError(f'Unexpected mount in SLI data directory: {path}')
    return paths, empty_version


def cluster_guard_to_restore():
    backup = STATE / 'createcluster.conf.before'
    trusted(backup)
    trusted(CLUSTER_GUARD)
    if backup.is_file() and CLUSTER_GUARD.is_file():
        original = backup.read_text(encoding='utf-8')
        managed = original.rstrip() + '\n# SLI host preparation\ncreate_main_cluster = false\n'
        if CLUSTER_GUARD.read_text(encoding='utf-8') == managed:
            return original, managed
    return None


def remove_empty_directory(path):
    try:
        path.rmdir()
    except OSError as error:
        if error.errno not in {errno.ENOENT, errno.ENOTEMPTY, errno.EEXIST}:
            raise


def remove(*, purge_data):
    packages = package_list()
    owned, unit_paths = unit_inventory(packages)
    plan = service_plan(owned, package_removal='sli-server-dotnet' in packages)
    mounts = tuple(name for name in MOUNTS if name in plan[2])
    legacy = legacy_state()
    archive = STATE / 'removed-units'
    if unit_paths:
        trusted(archive)
        if archive.exists() and not archive.is_dir():
            raise RuntimeError(f'Unsafe SLI unit archive: {archive}')
    if purge_data:
        guard = cluster_guard_to_restore()
        purge_paths(backup_unmount_pending=BACKUP_MOUNT in mounts)

    stop_services(plan, disable=False)
    if mounts:
        run('systemctl', 'stop', *mounts)
        if purge_data:
            purge_paths(database_unmounted=DB_MOUNT in mounts)
    disable_services(plan)
    with park_legacy_state(legacy):
        delete_packages(packages)
    remove_units(unit_paths, archive)
    if purge_data:
        paths, empty_version = purge_paths(database_unmounted=DB_MOUNT in mounts)
        if guard is not None and CLUSTER_GUARD.read_text(encoding='utf-8') == guard[1]:
            CLUSTER_GUARD.write_text(guard[0], encoding='utf-8')
        for path in paths:
            if path.exists():
                shutil.rmtree(path)
        if empty_version is not None:
            remove_empty_directory(empty_version)
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
