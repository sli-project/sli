"""Native daily recovery sets and isolated, bounded restore drills.

The data manifest stays in its original format. A separate private manifest binds
the protected companion and data bytes. Creation never implies restore_verified.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path('/var/backups/sli/native')
DRILLS = Path(os.environ.get('SLI_RESTORE_CHECK_ROOT', str(ROOT.parent / 'restore-check')))
HELPER = '/usr/lib/sli/native_backup.py'
RUNTIME_HELPER = Path('/usr/lib/sli/native_runtime.py')
CGROUP_ROOT = Path('/sys/fs/cgroup')
PROC_ROOT = Path('/proc')
MEMINFO = Path('/proc/meminfo')
CONFIG = Path('/etc/sli')
STATE = Path('/var/lib/sli/state')
DATA = Path('/var/lib/sli')
SYSTEMD_ENVIRONMENT = ('INVOCATION_ID', 'NOTIFY_SOCKET', 'WATCHDOG_PID', 'WATCHDOG_USEC')
# Native host state never belongs to the replaceable application data tree.
try:
    from deploy.linux.native_runtime import PRESERVED_DATA_DIRECTORIES as EXCLUDED_FILES
    from deploy.linux.native_runtime import ensure_directory
except ModuleNotFoundError:  # stdlib launcher; release imports happen after dispatch.
    _spec = importlib.util.spec_from_file_location('sli_native_runtime', Path(__file__).with_name('native_runtime.py'))
    _runtime = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_runtime)
    EXCLUDED_FILES = _runtime.PRESERVED_DATA_DIRECTORIES
    ensure_directory = _runtime.ensure_directory
FAILURE_MESSAGES = {
    'native_drill_memory_unavailable': 'Cannot determine available memory for restore verification / Не удалось определить доступную память для проверки восстановления.',
    'native_site_operation_stall_invalid': 'operation_stall_minutes must be an integer from 1 to 180 / operation_stall_minutes: целое число от 1 до 180.',
    'operation_stalled': 'No progress; inspect the reported step / Нет прогресса: проверьте указанный шаг.',
    'operation_deadline_exceeded': 'Machine safety limit reached / Достигнут страховочный предел машины.',
    'native_transaction_pending': 'Backup cannot start while an upgrade transaction is pending. Finish or recover the upgrade first.',
    'native_host_busy': 'Another native administrative operation is running. Retry the backup after it finishes.',
    'native_backup_root_invalid': 'The configured backup directory is unavailable.',
    'native_backup_root_untrusted': 'The configured backup directory has unsafe ownership, permissions or links.',
    'native_backup_root_same_device': 'The backup directory must be on a different device from the databases.',
    'native_backup_root_insufficient_space': 'The backup volume lacks space for the recovery set.',
    'native_backup_root_mount_mismatch': 'The configured backup volume is not mounted at /var/backups/sli.',
    'native_backup_hash_mismatch': 'Backup integrity check failed / Проверка целостности резервной копии не пройдена.',
    'native_backup_data_mismatch': 'Backup data check failed / Проверка данных резервной копии не пройдена.',
    'native_restore_source_not_private': 'Use a recovery set accessible only to root / Копия должна быть доступна только root.',
    'native_restore_version_mismatch': 'Install the Debian kit for the version in this backup / Установите комплект версии, из которой сделана копия.',
    'native_restore_retry_same_backup': 'Repeat the command with the same recovery set / Повторите команду с той же копией.',
    'native_restore_target_not_fresh': 'Use a clean server or a configured installation of the same version / Нужен чистый сервер или настроенная установка той же версии.',
    'native_restore_ad_key_required': 'The original AD credentials key must be provisioned on the destination / На сервере должен быть исходный ключ учётных данных AD.',
}
MESSAGES = {
    'native_backup_old_set_untrusted': 'Old backup could not be verified; left untouched for manual review / '
                                     'Старый набор не прошёл проверку; сохранён без изменений для ручной проверки.',
    'native_backup_complete': 'Backup operation completed / Операция резервного копирования завершена.',
}


def require(condition, code='native_backup_invalid'):
    if not condition:
        raise RuntimeError(code)


def command(argv, *, timeout=120):
    result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False,
                            env={'PATH': '/usr/lib/postgresql/18/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0, 'native_backup_command_failed')
    return result.stdout


def units():
    from deploy.linux.native_clickhouse_endpoint import SOCKET_SANDBOX
    from deploy.linux.operation_wait import stall_seconds
    watchdog = f'WatchdogSec={stall_seconds()}\nNotifyAccess=main\nRuntimeMaxSec=infinity\n'
    return {
        'sli-backup.timer': '[Unit]\nDescription=SLI daily backup\nPartOf=sli.target\n'
        '[Timer]\nOnCalendar=*-*-* 02:00:00\nPersistent=true\nRandomizedDelaySec=15m\n'
        'Unit=sli-backup.service\n[Install]\nWantedBy=sli.target\n',
        'sli-backup.service': '[Unit]\nDescription=SLI native recovery set\nPartOf=sli.target\n'
        'After=sli-ready.service\nRequires=sli-ready.service\n[Service]\nType=exec\n' + watchdog +
        f'ExecStart=/usr/bin/python3 -I -B {HELPER} launch capture\n'
        'WorkingDirectory=/opt/sli/current\nUMask=0077\nTimeoutStartSec=12h\nTimeoutStopSec=120\nKillMode=control-group\n'
        'NoNewPrivileges=yes\nProtectHome=yes\nPrivateTmp=yes\n' + SOCKET_SANDBOX,
        'sli-backup-drill.service': '[Unit]\nDescription=SLI isolated restore drill\n'
        '[Service]\nType=exec\n' + watchdog +
        f'ExecStart=/usr/bin/python3 -I -B {HELPER} launch drill\n'
        'WorkingDirectory=/opt/sli/current\nUMask=0077\nTimeoutStartSec=12h\nTimeoutStopSec=8min\nKillMode=control-group\n',
    }


def configure():
    from deploy.linux import backup_policy
    from deploy.linux import native_host as host

    host.Host().require_backup_mount()
    estimate = host.Host().backup_space_estimate(ROOT)
    admission = capture_volume_admission(ROOT, ROOT, {
        'data': {'device': backup_policy.filesystem(Path(host.MOUNT)),
                 'free_bytes': shutil.disk_usage(host.MOUNT).free}},
        estimate['capture_bytes'], work_required=0)
    if admission['status'] != 'admitted':
        backup_policy.report_refusal(admission)
    require(admission['status'] == 'admitted', 'native_backup_separate_volume_required')
    machine = host.Host()
    machine.directory(str(ROOT), 0o700)
    machine.write(HELPER, Path(__file__).read_text(), 0o644)
    for name, body in units().items():
        if '[Service]' in body:
            budget = systemd_budget(Path(host.MOUNT))
            body = body.replace('TimeoutStartSec=12h', 'TimeoutStartSec=' + str(budget))
            daily, weekly = backup_policy.retention_settings()
            settings = {'SLI_RESTORE_CHECK_ROOT': str(DRILLS), 'SLI_BACKUP_RETENTION': str(daily),
                        'SLI_BACKUP_WEEKLY_RETENTION': str(weekly)}
            body = body.replace('[Service]\n', '[Service]\n' + ''.join(
                'Environment=' + json.dumps(key + '=' + value.replace('%', '%%')) + '\n' for key, value in settings.items()))
        machine.write('/usr/lib/systemd/system/' + name, body, 0o644)
    command(['systemctl', 'daemon-reload'])


def systemd_budget(path):
    from deploy.linux.operation_wait import Watch, native_rate
    from deploy.linux.native_host import Host
    estimate = Host().backup_space_estimate(ROOT)
    # Configuring capture must not probe an optional drill workspace.
    rate = min(native_rate(item) for item in (path, ROOT))
    return int(max(Watch(step, minimum=0, size=estimate[step + '_io_bytes'], native=True, rate=rate,
                         history=DATA / 'backup-status/summary.json').limit for step in ('capture', 'drill')))


def capture_volume_admission(root, work, data_filesystems, required, *, work_required=None):
    """Directory installs without a backup volume may keep local copies."""
    from deploy.linux import backup_policy
    from deploy.linux import native_clickhouse_endpoint as clickhouse
    local = clickhouse.database_directory() and 'backup_root' not in clickhouse.site_configuration()
    admit = backup_policy.local_copy_admission if local else backup_policy.volume_admission
    return admit(root, work, data_filesystems, required, work_required=work_required)


def launch(action, arguments=()):
    # The stdlib-only host launcher verifies the pinned release before exec.
    helper = RUNTIME_HELPER
    for item in (helper, *helper.parents):
        info = item.lstat()
        require(not item.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022,
                'native_backup_untrusted_launcher')
    spec = importlib.util.spec_from_file_location('sli_backup_runtime', helper)
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    if action == 'restore' and not (STATE / 'installed.json').exists():
        from importlib.util import module_from_spec, spec_from_file_location

        installer = helper.with_name('native_install.py')
        runtime.trusted(installer)
        install_spec = spec_from_file_location('sli_restore_install', installer)
        install = module_from_spec(install_spec)
        install_spec.loader.exec_module(install)
        root, manifest, _ = install.inventory(runtime.document(STATE / 'pending-release.json')['release'])
    else:
        root, manifest, _ = runtime.release()
    runtime.trusted(root / 'deploy/linux/native_backup.py')
    if action == 'restore':
        arguments = (str(Path(arguments[0]).absolute()),)
    os.chdir(root)
    os.execve(manifest['python'], [manifest['python'], '-B', '-m', 'deploy.linux.native_backup', action, *arguments],
              {'PATH': '/usr/lib/postgresql/18/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
               **{key: os.environ[key] for key in ('SLI_RESTORE_CHECK_ROOT', 'SLI_BACKUP_RETENTION',
                                                   'SLI_BACKUP_WEEKLY_RETENTION', *SYSTEMD_ENVIRONMENT) if key in os.environ}})


@contextmanager
def environment(values):
    previous = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(values)
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def settings():
    values = {'PATH': '/usr/lib/postgresql/18/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'LC_ALL': 'C.UTF-8', 'SLI_DEPLOYMENT_MODE': 'native',
            'SLI_RESTORE_CHECK_ROOT': str(DRILLS),
            'SLI_PG_ADMIN_PASSWORD_FILE': '/etc/sli/secrets/postgres_password',
            'SLI_BACKUP_RETENTION': os.environ.get('SLI_BACKUP_RETENTION', '7'),
            'SLI_BACKUP_WEEKLY_RETENTION': os.environ.get('SLI_BACKUP_WEEKLY_RETENTION', '4')}
    values.update({key: os.environ[key] for key in SYSTEMD_ENVIRONMENT if key in os.environ})
    return values


def copy_private(source, destination):
    from deploy.linux.update_checkpoint import snapshot
    from deploy.linux.operation_wait import copy_tree, made_progress

    with snapshot(source.parent, source.name, temporary_root=destination.parent, progress=made_progress) as (private, _):
        copy_tree(private, destination,
                  copy_function=lambda source, target: copy_file(Path(source), Path(target)))
    # snapshot copies files using the process umask; enforce root-only on disk.
    for path in destination.rglob('*'):
        path.chmod(0o700 if path.is_dir() else 0o600)
        made_progress()


def copy_file(source, destination):
    from deploy.linux.update_checkpoint import open_directory
    from deploy.linux.operation_wait import copy_stream, made_progress

    parent = open_directory(source.parent.absolute())
    try:
        opened = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(opened, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            with destination.open('xb') as output:
                copy_stream(stream, output)
        destination.chmod(0o600)
        made_progress()
    finally:
        os.close(parent)


def secret_sources():
    """Validate the online credential inventory before stopping a working runtime."""
    from deploy.linux import native_install as install

    inventory = json.loads(install.trusted(Path(__file__).with_name('secrets-manifest.json')))
    from server.sli.core.ad_credential_secrets import MASTER_KEY_REF, MASTER_KEY_SPEC
    require(inventory['secrets'].get(MASTER_KEY_REF) == MASTER_KEY_SPEC, 'native_backup_inventory_invalid')
    config = json.loads(install.trusted(CONFIG / 'runtime.json'))
    sources = {}
    for name, spec in inventory['secrets'].items():
        if spec['group'] == 'offline' or spec.get('backup') == 'exclude':
            continue
        require(name.isidentifier())
        source = CONFIG / 'secrets' / name
        if source.exists() or source.is_symlink():
            install.trusted(source)
            sources[name] = source
        else:
            # Notification credentials are imported only when configured. Their
            # absence is valid on a fresh native host; existing ones still pass
            # the same trust checks and are included in the companion.
            require(name in {'history_password', 'warm_password'} or spec['group'] == 'notifications'
                    or spec['group'] == 'agents' and not config.get('agents', False),
                    'native_backup_secret_missing')
    # Setup owns a bounded private directory; config, SMTP marker and password
    # must travel together. Never recursively import arbitrary secret material.
    notifications = CONFIG / 'secrets/notifications'
    if notifications.exists() or notifications.is_symlink():
        require(not notifications.is_symlink() and notifications.is_dir(), 'native_backup_inventory_invalid')
        allowed = {'telegram.json', 'smtp.json', 'smtp.ready', 'notification_telegram_token', 'notification_smtp_password'}
        for path in notifications.iterdir():
            require(path.name in allowed, 'native_backup_inventory_invalid')
            install.trusted(path)
            sources['notifications/' + path.name] = path
    return sources


def companion(destination):
    from deploy.linux import native_install as install

    sources = secret_sources()
    ensure_directory(destination, 0o700, exist_ok=False)
    secret_root = destination / 'secrets'
    ensure_directory(secret_root, 0o700, exist_ok=False)
    for name, source in sources.items():
        ensure_directory((secret_root / name).parent, 0o700, parent_mode=0o700)
        (secret_root / name).write_bytes(install.trusted(source))
        (secret_root / name).chmod(0o600)
    # Configuration is allowlisted: never recursively copy an offline root key.
    for name in ('runtime.json', 'site.toml'):
        source = CONFIG / name
        if source.exists():
            (destination / name).write_bytes(install.trusted(source))
    copy_private(STATE, destination / 'state')
    copy_private(DATA / 'recovery', destination / 'recovery')
    copy_private(Path('/etc/postgresql/18/sli'), destination / 'postgresql')
    (destination / 'packages.tsv').write_bytes(command(
        ['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Architecture}\n']))
    for path in destination.rglob('*'):
        path.chmod(0o700 if path.is_dir() else 0o600)


def inventory_progress():
    from deploy.linux.operation_wait import InventoryProgress
    return InventoryProgress()


def verify(path, identifier=None):
    from deploy.linux import backup
    from deploy.linux.operation_wait import InventoryProgress

    manifest = json.loads((path / 'manifest.json').read_bytes())
    require(manifest.get('schema_version') == 1 and manifest.get('status') == 'backup_created'
            and manifest.get('backup_id') == (identifier or path.name)
            and manifest.get('content_checksums') == backup.content_inventory(path, check=InventoryProgress()),
            'native_backup_hash_mismatch')
    data = path / manifest['data_path']
    require(data.parent == path / 'data' and backup.BACKUP_NAME.fullmatch(data.name))
    data_manifest = json.loads((data / 'manifest.json').read_bytes())
    require(data_manifest.get('status') == 'success'
            and set(data_manifest['components']) in ({'postgres', 'files'}, set(backup.COMPONENTS))
            and data_manifest['content_checksums'] == backup.content_inventory(data, check=InventoryProgress()),
            'native_backup_data_mismatch')
    return manifest, data, data_manifest


def prune(new):
    from deploy.linux import backup, backup_policy

    # Keep the last successful drill until another restore has actually passed.
    root = new.parent
    receipt = root / 'restore-verified.json'
    protected = json.loads(receipt.read_bytes())['backup_id'] if receipt.exists() else None
    verify(new)
    candidates = sorted(path for path in root.iterdir() if not path.is_symlink() and path.is_dir()
                        and backup.BACKUP_NAME.fullmatch(path.name))
    daily, weekly = backup_policy.retention_settings()
    keep = backup_policy.retained_sets(candidates, daily, weekly)
    warnings = []
    for path in root.iterdir():
        if (not path.is_symlink() and path.is_dir() and backup.BACKUP_NAME.fullmatch(path.name)
                and path not in keep and path.name < new.name and path.name != protected):
            try:
                verify(path)
            except Exception:  # noqa: BLE001 - any failed old-set verification forbids deletion; never log its contents.
                warning = {'reason_code': 'native_backup_old_set_untrusted', 'backup_id': path.name}
                warnings.append(warning)
                report_warning(warning)
                continue
            from deploy.linux.operation_wait import remove_tree

            remove_tree(path)
    return warnings


def report_warning(warning):
    code = warning['reason_code']
    diagnostic = f'reason_code={code} backup_id={warning["backup_id"]}'
    print(f'Warning: {MESSAGES[code]} ({diagnostic})')
    try:
        import syslog
        syslog.openlog('sli-native-backup')
        syslog.syslog(syslog.LOG_WARNING, diagnostic)
    except (ImportError, OSError):
        pass  # stdout is also collected by the systemd service journal.


def publish_summary(root, warnings=()):
    from deploy.linux import backup, backup_policy, native_host, operation_wait

    untrusted = {item['backup_id'] for item in warnings}
    paths = sorted(path for path in root.iterdir() if path.name not in untrusted
                   and path.is_dir() and not path.is_symlink()
                   and backup.BACKUP_NAME.fullmatch(path.name))
    manifests = [json.loads((path / 'manifest.json').read_bytes()) for path in paths]
    receipt = root / 'restore-verified.json'
    verified = json.loads(receipt.read_bytes()) if receipt.exists() else {}
    reserve = backup_policy.space_estimate(max((item.get('database_size_bytes', 0)
                                               for item in manifests), default=0))['postgres_bytes']
    status = DATA / 'backup-status'
    require(not status.is_symlink(), 'native_backup_invalid_summary')
    ensure_directory(status, 0o755)
    status.chmod(0o755)
    backup.write_json(status / 'summary.json', {
        'operation_machine_id': operation_wait.read_history(status / 'summary.json').get('operation_machine_id'),
        'operation_samples': operation_wait.read_history(status / 'summary.json').get('operation_samples', {}),
        'operation_durations': operation_wait.read_history(status / 'summary.json').get('operation_durations', {}),
        'last_backup_at_utc': manifests[-1].get('created_at_utc') if manifests else None,
        'same_disk_as_postgres': same_disk(root, Path(native_host.MOUNT)) if manifests else None,
        'last_verified_at_utc': verified.get('completed_at_utc') if verified.get('status') == 'restore_verified' else None,
        'capacity_days': backup_policy.capacity_days(shutil.disk_usage(root).free,
                                                     [item.get('size_bytes', 0) for item in manifests], reserve),
        'observed_at_utc': backup.utc_now().isoformat(),
        'warnings': list(warnings),
    })
    (status / 'summary.json').chmod(0o644)


def same_disk(backup_root, postgres_root):
    """Compare filesystem devices and their underlying Linux block devices."""
    def disks(device):
        entry = Path(f'/sys/dev/block/{os.major(device)}:{os.minor(device)}')
        if not entry.exists():
            return set()
        return parents(entry.resolve(strict=True))

    def parents(entry):
        if (entry / 'partition').is_file():
            return parents(entry.parent)
        slaves = list((entry / 'slaves').glob('*'))
        return set().union(*(parents(path.resolve(strict=True)) for path in slaves)) if slaves else {entry}

    try:
        source = backup_root.stat().st_dev
        target = postgres_root.stat().st_dev
        if source == target:
            return True
        return bool(disks(source) & disks(target)) if sys.platform == 'linux' else False
    except OSError:
        return None


def capture():
    from deploy.linux import backup, native_backup_settings as policy, native_host, native_runtime

    with backup.backup_lock(ROOT):
        state = policy.read_policy()
        if state is not None and not state['enabled']:
            return
        with native_host.administrative_lock():
            native_runtime.no_transaction()
            if state is None:
                state = policy.load_or_migrate()
        if state['enabled']:
            with policy.selected_storage(state, create=True) as (root, check):
                return capture_locked(root, storage_check=check)


def capture_locked(root, *, writers_fenced=False, storage_check=None):
    """Caller holds the canonical backup lock; upgrade owns the fence."""
    from deploy.linux import backup
    from deploy.linux import native_host as host
    from deploy.linux import native_runtime as runtime

    # The recovery-set lock is shared with drill/pruning and must also be taken
    # by the upgrade coordinator. Keep the host preflight lock short: readiness
    # probes use it too and must continue during an online backup.
    stamp = backup.utc_now().strftime('%Y%m%dT%H%M%S.%fZ')
    staging = root / ('.' + stamp + '.partial')
    final = root / stamp
    started = time.monotonic()
    try:
        cleanup_drills()
        with host.administrative_lock():
            machine = host.Host()
            machine.receipt()
            machine.require_backup_mount()
            if not writers_fenced:
                runtime.no_transaction()
            release, _, digest = runtime.release()
            installed = runtime.document(STATE / 'installed.json')
            require(installed.get('release') == str(release) and installed.get('manifest_sha256') == digest,
                    'native_backup_registry_mismatch')
        with environment(settings()):
            if storage_check is None:
                backup.capture_admission(root)
            else:
                backup.capture_admission(root, regular=True)
                storage_check()
        ensure_directory(staging, 0o700, exist_ok=False)
        data_root = staging / 'data'
        ensure_directory(data_root, 0o700, exist_ok=False)
        file_root = staging / 'file-source'
        ensure_directory(file_root, 0o700, exist_ok=False)
        # Native databases and backup sets live outside DATA. Administrative
        # state/recovery goes in the companion; drills must never recurse.
        for source in DATA.iterdir():
            if source.name in EXCLUDED_FILES:
                continue
            if source.is_dir() and not source.is_symlink():
                copy_private(source, file_root / source.name)
            else:
                copy_file(source, file_root / source.name)
        env = settings() | {'SLI_BACKUP_ROOT': str(data_root), 'SLI_BACKUP_FILES_ROOT': str(file_root)}
        with environment(env):
            data = backup.run_backup(data_root, retention=1, components=("postgres", "files"),
                                     writers_fenced=writers_fenced)
        from deploy.linux.operation_wait import remove_tree

        remove_tree(file_root)
        companion(staging / 'companion')
        data_manifest = json.loads((data / 'manifest.json').read_bytes())
        duration = time.monotonic() - started
        capture_size = sum(item.get('database_size_bytes', item.get('size_bytes', 0))
                           for item in data_manifest['components'].values())
        if not writers_fenced:
            from deploy.linux.operation_wait import Watch
            capture_limit = Watch('capture', minimum=backup.TIMEOUT, size=capture_size,
                                  history=DATA / 'backup-status/summary.json').limit
            require(duration <= capture_limit, 'native_backup_capture_window_exceeded')
        manifest = {'schema_version': 1, 'backup_id': stamp, 'status': 'backup_created',
                    'data_path': data.relative_to(staging).as_posix(),
                    'created_at_utc': backup.utc_now().isoformat(),
                    'size_bytes': backup.size_bytes(staging),
                    'machine_id': host.Host().backup_machine_id(),
                    'database_size_bytes': data_manifest['components']['postgres'].get('database_size_bytes', 0),
                    'consistency_point': {'writers_fenced': writers_fenced, 'capture_window_seconds': duration,
                                          'mode': 'fenced' if writers_fenced else 'bounded_acquisition_window'},
                    'content_checksums': backup.content_inventory(staging, check=inventory_progress())}
        backup.write_json(staging / 'manifest.json', manifest)
        if storage_check is not None:
            storage_check()
        staging.rename(final)
        verify(final)
        from deploy.linux.operation_wait import record_success
        record_success(DATA / 'backup-status/summary.json', 'capture', duration,
                       size=capture_size + manifest['size_bytes'])
        warnings = prune(final) if not writers_fenced else []
        backup.write_json(root / 'last-result.json', {'schema_version': 1, 'status': 'backup_created',
                                                     'backup_id': stamp, 'terminal': True, 'warnings': warnings})
        if not writers_fenced:
            publish_summary(root, warnings)
        return final
    except Exception:
        if storage_check is not None:
            storage_check()
        backup.write_json(root / 'last-result.json', {'schema_version': 1, 'status': 'failed',
                                                     'backup_id': stamp, 'terminal': True})
        raise


def drill_unit_stopped(unit):
    row = dict(line.split('=', 1) for line in command(
        ['systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'MainPID', '-p', 'ControlGroup']
    ).decode().splitlines() if '=' in line)
    require(row.get('ActiveState') in {'inactive', 'failed'} and row.get('MainPID') == '0',
            'native_drill_cleanup_unit_active')
    group = row.get('ControlGroup', '')
    require(not group or (group.startswith('/system.slice/') and '..' not in Path(group).parts),
            'native_drill_cleanup_cgroup_invalid')
    path = CGROUP_ROOT / group.lstrip('/')
    require(not group or not path.exists()
            or not any(item.read_text().strip() for item in path.rglob('cgroup.procs')),
            'native_drill_cleanup_cgroup_active')


def stop_drill(units):
    # Attempt every stop even if a previous unit failed. A cleanup failure must
    # never publish a restore_verified receipt.
    failed = False
    for unit in reversed(units):
        try:
            command(['systemctl', 'stop', unit], timeout=150)
            drill_unit_stopped(unit)
        except Exception:  # noqa: BLE001 - continue cleanup of remaining DBs
            failed = True
    require(not failed, 'native_drill_cleanup_failed')


def drill_idle(work):
    """Inspect only: collection never stops another coordinator's databases."""
    prefix = 'sli-drill-' + work.name + '-'
    require(CGROUP_ROOT.is_dir() and PROC_ROOT.is_dir(), 'native_drill_cleanup_inspection_unavailable')
    rows = command(['systemctl', 'list-units', '--all', '--plain', '--no-legend', prefix + '*']).decode()
    for row in rows.splitlines():
        unit = row.split()[0]
        require(unit.startswith(prefix) and unit.endswith('.service'), 'native_drill_cleanup_unit_unexpected')
        drill_unit_stopped(unit)
    for group in (CGROUP_ROOT / 'system.slice').glob(prefix + '*'):
        require(not any(path.read_text().strip() for path in group.rglob('cgroup.procs')),
                'native_drill_cleanup_cgroup_active')
    for process in PROC_ROOT.iterdir():
        if not process.name.isdecimal():
            continue
        try:
            require(str(work).encode() not in (process / 'cmdline').read_bytes(),
                    'native_drill_cleanup_process_active')
            require(prefix not in (process / 'cgroup').read_text(), 'native_drill_cleanup_process_active')
        except FileNotFoundError:
            continue  # Process exited during inspection; other errors retain work.
    legacy_containers = any((work / name).exists() or (work / name).is_symlink() for name in ('history', 'warm'))
    if not legacy_containers:
        return
    if shutil.which('docker'):
        names = command(['/usr/bin/docker', 'container', 'ls', '--all', '--format', '{{.Names}}']).decode()
        for name in names.splitlines():
            if name.startswith(prefix):
                rows = json.loads(command(['/usr/bin/docker', 'container', 'inspect', name]))
                require(len(rows) == 1 and rows[0].get('State', {}).get('Running') is False
                        and rows[0].get('State', {}).get('Pid') == 0
                        and rows[0].get('State', {}).get('Restarting') is False,
                        'native_drill_cleanup_container_active')
    else:
        require(not Path('/var/run/docker.sock').exists(), 'native_drill_cleanup_docker_unavailable')


def cleanup_drills():
    """Caller holds the backup/upgrade lock. Legacy work has no owner receipt:

    retain it all while any transaction is unfinished or cannot be inspected.
    """
    from deploy.linux import native_upgrade as upgrade
    from deploy.linux.operation_wait import remove_tree

    result = {'removed_directories': 0, 'freed_bytes': 0}
    candidates = []
    phase = 'native_drill_cleanup_inspection_unavailable'

    def retained(work, code):
        print('native_drill_cleanup_retained ' + json.dumps(
            {'directory': work.name[:128], 'reason_code': code}, ensure_ascii=True), file=sys.stderr)

    try:
        if not DRILLS.exists() or DRILLS != DRILLS.resolve():
            return result
        for path in DRILLS.iterdir():
            if not path.is_dir():
                continue
            if not re.fullmatch(r'[a-f0-9]{16}', path.name):
                retained(path, 'native_drill_cleanup_unrecognized_directory')
            elif path.is_symlink() or path != path.resolve():
                retained(path, 'native_drill_cleanup_untrusted_directory')
            else:
                candidates.append(path)
        if not candidates:
            return result
        if upgrade.TRANSACTIONS.exists():
            phase = 'native_drill_cleanup_transaction_unconfirmed'
            for path in upgrade.TRANSACTIONS.iterdir():
                require(path == path.resolve() and re.fullmatch(r'[a-f0-9]{32}', path.name))
                if not upgrade.finished_transaction(upgrade.Journal(path)):
                    for work in candidates:
                        retained(work, 'native_drill_cleanup_transaction_pending')
                    return result
        for work in candidates:
            phase = 'native_drill_cleanup_inspection_unavailable'
            try:
                drill_idle(work)
                phase = 'native_drill_cleanup_remove_failed'
                size = 0
                for parent, _, files in os.walk(work, followlinks=False):
                    for name in files:
                        info = (Path(parent) / name).lstat()
                        if stat.S_ISREG(info.st_mode):
                            size += getattr(info, 'st_blocks', 0) * 512 if hasattr(info, 'st_blocks') else info.st_size
                remove_tree(work)
                result['removed_directories'] += 1
                result['freed_bytes'] += size
            except Exception as error:  # Fail closed; never reproduce command output or private paths.
                codes = {'native_drill_cleanup_' + suffix for suffix in (
                    'unit_active', 'unit_unexpected', 'cgroup_invalid', 'cgroup_active',
                    'process_active', 'container_active', 'docker_unavailable', 'inspection_unavailable')}
                retained(work, str(error) if str(error) in codes else phase)
    except Exception:
        for work in candidates:
            retained(work, phase)
        print('native_drill_cleanup_unconfirmed', file=sys.stderr)
    if result['removed_directories']:
        print('native_drill_cleanup: ' + ' '.join(f'{key}={value}' for key, value in result.items()))
    return result


def drill_memory():
    """Reserve memory for isolated PostgreSQL verification."""
    match = re.search(r'^MemAvailable:\s+(\d+)\s+kB$', MEMINFO.read_text(), re.MULTILINE)
    require(match is not None and int(match[1]) > 0, 'native_drill_memory_unavailable')
    share = int(match[1]) * 1024 // 8
    require(share >= 1024, 'native_drill_memory_unavailable')
    return {'pg': share * 2}


@contextmanager
def isolated_databases(work, *, cleanup=None):
    """Fresh systemd cgroups, data directories, credentials and loopback ports.

    No SQL client in the drill receives a working-install endpoint. The units
    follow the coordinator's lifetime, or have a large manual-run safety cap.
    """
    import pwd
    import socket

    from deploy.linux import native_host as host
    from deploy.linux.operation_wait import coordinator_unit

    from deploy.linux import native_clickhouse_endpoint as clickhouse
    database_paths = '/srv/sli-db'
    directory_alias = clickhouse.database_directory()
    if directory_alias:
        database_paths += ' ' + directory_alias
    for port in (55432,):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', port))
    password = secrets.token_urlsafe(48)
    passfile = work / 'password'
    passfile.write_text(password)
    passfile.chmod(0o600)
    env = settings() | {'SLI_PG_PORT': '55432', 'SLI_PG_ADMIN_PASSWORD_FILE': str(passfile),
                        'SLI_HELPER_RUNTIME_ROOT': str(work / 'helpers')}
    memory = drill_memory()
    started = []
    coordinator = coordinator_unit()
    lifetime = (['--property=BindsTo=' + coordinator, '--property=After=' + coordinator,
                 '--property=RuntimeMaxSec=infinity'] if coordinator else
                ['--property=RuntimeMaxSec=' + str(max(43200, systemd_budget(work)))])

    def directory(path, user):
        entry = pwd.getpwnam(user)
        ensure_directory(path, 0o700, entry.pw_uid, entry.pw_gid, exist_ok=False)
        os.chown(path, entry.pw_uid, entry.pw_gid)

    def start(name, user, argv):
        unit = 'sli-drill-' + work.name + '-' + name + '.service'
        started.append(unit)  # Even failed start must be inspected and stopped.
        command(['systemd-run', '--quiet', '--unit=' + unit, '--property=User=' + user,
                 *lifetime, '--property=TimeoutStopSec=120',
                 '--property=KillMode=control-group',
                 '--property=MemoryMax=' + str(memory[name]),
                 '--property=ProtectSystem=strict', '--property=ReadWritePaths=' + str(work),
                 '--property=InaccessiblePaths=' + database_paths + ' /etc/sli/secrets',
                 '--property=ProtectHome=yes', '--property=PrivateTmp=yes', '--property=NoNewPrivileges=yes',
                 '--property=TasksMax=512', '--property=UMask=0077',
                 *(['--property=SuccessExitStatus=143'] if name != 'pg' else []),
                 '--', *argv])

    try:
        pg = work / 'pg'
        directory(pg, 'postgres')
        initpass = pg / 'init-password'
        initpass.write_text(password)
        initpass.chmod(0o600)
        os.chown(initpass, pwd.getpwnam('postgres').pw_uid, pwd.getpwnam('postgres').pw_gid)
        command(['runuser', '-u', 'postgres', '--', '/usr/lib/postgresql/18/bin/initdb',
                 '-D', str(pg / 'data'), '--auth-local=trust', '--auth-host=scram-sha-256',
                 '--pwfile=' + str(initpass), '--no-locale', '--encoding=UTF8'])
        initpass.unlink()
        start('pg', 'postgres', ['/usr/lib/postgresql/18/bin/postgres', '-D', str(pg / 'data'),
                                '-p', '55432', '-h', '127.0.0.1', '-k', str(pg),
                                '-c', f'shared_buffers={memory["pg"] // 8 // 1024}kB',
                                '-c', f'maintenance_work_mem={memory["pg"] // 4 // 1024}kB',
                                '-c', f'work_mem={max(64, memory["pg"] // 192 // 1024)}kB',
                                '-c', 'max_parallel_maintenance_workers=0',
                                '-c', 'max_parallel_workers=0', '-c', 'max_connections=12'])
        with environment(env):
            from deploy.linux import backup
            from deploy.linux.operation_wait import Watch
            readiness = Watch('drill_postgres', minimum=3600)
            while True:
                try:
                    with backup.pg_passfile() as pgpass, backup.pg_connect(pgpass, 'postgres', autocommit=True) as conn:
                        conn.execute('CREATE DATABASE sli TEMPLATE template0')
                    break
                except Exception:  # noqa: BLE001 - bounded startup probe; never disclose database diagnostics
                    readiness.check()
                    time.sleep(30)
            yield env
    finally:
        stop_drill(started)
        if cleanup is not None:
            cleanup['databases_stopped'] = True


def drill():
    from deploy.linux import backup, native_backup_settings as policy

    with backup.backup_lock(ROOT):
        state = policy.read_policy()
        require(state and state['identity'], 'native_drill_no_backup')
        with policy.selected_storage(state) as (root, _):
            names = root.iterdir() if root.is_dir() else ()
            candidates = sorted(path for path in names if path.is_dir() and not path.is_symlink()
                                and backup.BACKUP_NAME.fullmatch(path.name))
            if not candidates:
                cleanup_drills()
            require(candidates, 'native_drill_no_backup')
            return drill_locked(candidates[-1], root)


def drill_locked(selected, root, *, prune_sets=True, upgrade_checkpoint=False):
    """Verify this exact set while the caller holds the canonical backup lock."""
    from deploy.linux import backup, backup_policy, native_host
    from deploy.linux import restore_existing as restore
    from deploy.linux.update_checkpoint import snapshot

    cleanup_drills()
    # Pin manifest identity as well as content. All restores read the copy.
    started = time.monotonic()
    expected_sha = hashlib.sha256((selected / 'manifest.json').read_bytes()).hexdigest()
    work = DRILLS / secrets.token_hex(8)
    result = {'schema_version': 1, 'status': 'running', 'backup_id': selected.name,
              'manifest_sha256': expected_sha, 'terminal': False, 'stage': 'snapshot', 'databases_stopped': True}
    result_path = root / 'drill-result.json'
    backup.write_json(result_path, result)
    work_created = False
    try:
        # New verification restores PostgreSQL and files; legacy archives remain untouched.
        _, data, data_manifest = verify(selected)
        pg_size = data_manifest['components']['postgres'].get('database_size_bytes')
        require(type(pg_size) is int and pg_size > 0, 'native_drill_size_unavailable')
        estimate = backup_policy.space_estimate(pg_size, backup_bytes=backup.size_bytes(selected),
                                                expanded_ch_bytes=0)
        data_root = Path(native_host.MOUNT)
        # Pre-migration checkpoints prove restorability, not disk-failure safety.
        # Reuse local-copy space/reserve checks only for that explicit purpose;
        # scheduled drills still require a separate backup volume.
        admit = capture_volume_admission if upgrade_checkpoint else backup_policy.volume_admission
        admission = admit(root, DRILLS, {
            'data': {'device': backup_policy.filesystem(data_root), 'free_bytes': shutil.disk_usage(data_root).free}},
            estimate['drill_copy_bytes'], work_required=estimate['work_bytes'])
        if admission['status'] != 'admitted':
            backup_policy.report_refusal(admission)
            raise RuntimeError('native_drill_' + admission['reason'])
        ensure_directory(DRILLS, 0o711)
        ensure_directory(work, 0o711, exist_ok=False)
        work_created = True
        from deploy.linux.operation_wait import made_progress
        with snapshot(root, selected.name, temporary_root=root, progress=made_progress) as (private, _):
            require(hashlib.sha256((private / 'manifest.json').read_bytes()).hexdigest() == expected_sha)
            _, data, manifest = verify(private, selected.name)
            result['stage'] = 'restore'
            backup.write_json(result_path, result)
            result['databases_stopped'] = False
            with isolated_databases(work, cleanup=result) as env, environment(env | {'SLI_BACKUP_ROOT': str(private)}):
                files = work / 'files'
                ensure_directory(files, 0o700, exist_ok=False)
                restore.restore_components(data, private, manifest, ("postgres", "files"), files_root=files)
                installed = json.loads((private / 'companion/state/installed.json').read_bytes())
                with backup.pg_passfile() as pgpass, backup.pg_connect(pgpass) as conn:
                    ledger = [{'version': v, 'name': n, 'sha256': h} for v, n, h in conn.execute(
                        'SELECT version, name, sha256 FROM public.schema_migrations ORDER BY version').fetchall()]
                from deploy.linux.native_pg_inventory import verify_ledger
                try:
                    verify_ledger(ledger, installed['migration_ledger'],
                                  root=Path(installed['release']) if installed.get('release') else None)
                except ValueError:
                    raise RuntimeError('native_drill_ledger_mismatch') from None
                # Read back protected configuration/trust into a distinct root;
                # no secret or digest leaves this root-only directory.
                copy_private(private / 'companion', work / 'companion')
                require(backup.content_inventory(private / 'companion', exclude_manifest=False, check=inventory_progress())
                        == backup.content_inventory(work / 'companion', exclude_manifest=False, check=inventory_progress()))
        from deploy.linux.operation_wait import remove_tree

        require(result['databases_stopped'], 'native_drill_cleanup_unconfirmed')
        remove_tree(work)  # Only after every disposable DB has stopped.
        result.update(status='restore_verified', terminal=True, stage='complete', databases_stopped=True,
                      verified_components=['postgres', 'files'],
                      duration_seconds=time.monotonic() - started,
                      completed_at_utc=backup.utc_now().isoformat())
        from deploy.linux.operation_wait import record_success
        record_success(DATA / 'backup-status/summary.json', 'drill', result['duration_seconds'],
                       size=estimate['drill_io_bytes'])
        backup.write_json(root / 'restore-verified.json', result)
        backup.write_json(result_path, result)
        if prune_sets:
            warnings = prune(selected)
            publish_summary(root, warnings)
        return result
    except Exception:
        result.update(status='failed', terminal=True)
        if not result['databases_stopped']:
            result['cleanup_reason_code'] = 'native_drill_cleanup_unconfirmed'
        elif work_created and work.exists():
            try:
                from deploy.linux.operation_wait import remove_tree

                remove_tree(work)
            except Exception:
                result['cleanup_reason_code'] = 'native_drill_work_remove_failed'
        backup.write_json(result_path, result)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('capture', 'drill', 'launch', 'restore', 'settings'))
    parser.add_argument('operation', nargs='?')
    parser.add_argument('source', nargs='?')
    args = parser.parse_args(argv)

    def interrupted(signum, frame):
        raise InterruptedError('native_backup_interrupted')

    try:
        require(os.geteuid() == 0, 'native_root_required')
        os.umask(0o077)
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        if args.action == 'launch':
            require(args.operation in {'capture', 'drill', 'restore', 'settings'}
                    and (args.operation == 'restore') == (args.source is not None))
            launch(args.operation, (args.source,)) if args.source else launch(args.operation)
        elif args.action == 'restore':
            from deploy.linux.native_restore import restore

            require(args.operation is not None and args.source is None)
            restore(Path(args.operation))
        elif args.action == 'capture':
            result = capture()
            if result is not None:
                print(f'Backup / Копия: {result}', flush=True)
            else:
                print('native_backup_schedule_disabled', flush=True)
        elif args.action == 'settings':
            from deploy.linux.native_backup_settings import serve

            require(args.operation is None and args.source is None)
            serve()
        else:
            drill()
    except Exception as error:  # noqa: BLE001 - only fixed diagnostics may cross the CLI boundary
        code = str(error) if (isinstance(error, RuntimeError)
                              or isinstance(error, ValueError) and str(error) in FAILURE_MESSAGES) else ''
        if code in FAILURE_MESSAGES or re.fullmatch(r'native_[a-z0-9_]{1,120}', code):
            message = FAILURE_MESSAGES.get(code, 'Backup operation failed / Операция резервного копирования не выполнена.')
            print(f'Backup failed: {message} (reason_code={code})', file=sys.stderr)
        else:
            print('native_backup_failed', file=sys.stderr)
        return 1
    print(f'native_backup_complete: {MESSAGES["native_backup_complete"]}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
