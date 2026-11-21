"""Durable native upgrade preparation, APT activation and checkpoint recovery.

Preparation ends fenced at checkpoint_verified, never at committed. Recovery
executes the accepted saved code with its retained, pinned private interpreter.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True

try:
    from deploy.linux.native_preinstall import cleanup_bytecode, ensure_directory
except ModuleNotFoundError:  # stdlib-only installed/recovery helper under -I.
    import importlib.util
    _permissions_spec = importlib.util.spec_from_file_location(
        "sli_native_preinstall", Path(__file__).with_name("native_preinstall.py"))
    _permissions = importlib.util.module_from_spec(_permissions_spec)
    _permissions_spec.loader.exec_module(_permissions)
    ensure_directory = _permissions.ensure_directory
    cleanup_bytecode = _permissions.cleanup_bytecode


TRANSACTIONS = Path('/var/lib/sli/transactions')
RECOVERY = Path('/var/lib/sli/recovery')
UNITS = Path('/usr/lib/systemd/system')
OVERRIDES = Path('/etc/systemd/system')
RUNTIME_HELPER = Path('/usr/lib/sli/native_runtime.py')
VOLATILE_UNITS = Path('/run/systemd/system')
POSTGRES_CONFIG = Path('/etc/postgresql/18/sli')
TERMINAL = {'committed', 'rolled_back', 'failed', 'aborted_before_checkpoint'}
NEXT = {'preflight': {'fenced', 'recovering'}, 'fenced': {'checkpoint_verified', 'recovering'},
        'checkpoint_verified': {'migrating', 'recovering'},
        'migrating': {'candidate_testing', 'recovering'}, 'candidate_testing': {'committed', 'recovering'},
        'recovering': {'candidate_testing', 'rolled_back', 'failed'}}


def require(condition, code='native_upgrade_invalid'):
    if not condition:
        raise RuntimeError(code)


FAILURE_MESSAGES = {
    'native_reuse_installation_required': 'A complete retained SLI installation is required / Требуется полная сохранённая установка SLI.',
    'native_reuse_coordinator_mismatch': 'Run sli-setup --reuse-existing from the newly installed package / Запустите sli-setup --reuse-existing из нового комплекта.',
    'native_reuse_readiness_failed': 'Retained databases failed readiness; preserve state and inspect the reuse check unit / Сохранённые БД не прошли проверку; сохраните данные и проверьте службу sli-reuse-check.',
    'native_transaction_pending': 'An unfinished transaction requires recovery; do not remove its journal / Незавершённая транзакция требует восстановления; не удаляйте журнал.',
    'native_service_user_conflict': 'Retained service account identity differs / Идентичность служебной учётной записи не совпадает.',
    'native_secret_group_conflict': 'Retained secret group identity differs / Идентичность группы секретов не совпадает.',
    'native_install_interrupted_requires_recovery': 'The retained install receipt is incomplete; recovery is required / Сохранённая установка неполная; требуется восстановление.',
    'native_setup_configuration_conflict': 'Retained site settings differ from the accepted receipt / Настройки не совпадают с принятой установкой.',
    'native_site_operation_stall_invalid': 'operation_stall_minutes must be an integer from 1 to 180 / operation_stall_minutes: целое число от 1 до 180.',
    'operation_stalled': 'Operation made no progress; inspect the reported step and last progress time / Нет прогресса: проверьте указанный шаг и время последнего прогресса.',
    'operation_deadline_exceeded': 'Machine safety limit reached; inspect the reported step / Достигнут страховочный предел машины: проверьте указанный шаг.',
    'native_writers_still_running': 'An application writer still has a live PID or a populated cgroup.',
    'native_cgroup_invalid': 'An application unit reported an invalid cgroup path.',
    'native_upgrade_pg_busy': 'PostgreSQL still has an active application transaction.',
    'native_upgrade_ch_busy': 'ClickHouse still has an active query or mutation.',
    'native_upgrade_checkpoint_storage_invalid': 'The checkpoint storage path is invalid.',
    'native_upgrade_checkpoint_mismatch': 'The checkpoint manifest does not match the transaction.',
    'native_upgrade_checkpoint_unverified': 'Checkpoint verification is missing or does not match this transaction / Проверка контрольной копии не подтверждена или не соответствует транзакции.',
    'native_upgrade_fence_failed': 'Application fencing failed before the checkpoint; the previous release was retained.',
    'native_upgrade_checkpoint_failed': 'Checkpoint preparation failed; the previous release was retained.',
    'native_upgrade_restart_failed': 'Preparation was aborted before the checkpoint, but restarting the previous release failed; retry recovery.',
    'native_upgrade_operation_busy': 'A backup, restore drill or another upgrade is running. Retry the upgrade after it finishes.',
    'native_host_busy': 'Another native administrative operation is running. Retry the upgrade after it finishes.',
    'native_backup_secret_missing': 'A required online backup credential is missing.',
    'native_install_api_unready': 'The candidate API did not become ready.',
    'native_install_workers_unhealthy': 'The candidate worker health checks did not pass.',
    'native_install_command_failed': 'A required native service or migration command failed.',
    'native_upgrade_service_unready': 'A required application service is not running.',
    'native_upgrade_incompatible_inventory': 'The releases have incompatible runtime or database inventories.',
    'native_upgrade_migration_not_authorized': 'The release does not authorize this database migration.',
    'native_pg_sql_inventory_mismatch': 'PostgreSQL SQL differs from the package ledger / SQL PostgreSQL не совпадает с ledger пакета.',
    'native_pg_migration_sql_unsupported': 'PostgreSQL migration cannot join the atomic package transaction / Миграцию PostgreSQL нельзя включить в общую транзакцию обновления.',
    'native_pg_migration_checksum_mismatch': 'An applied PostgreSQL migration has a different SHA-256 / SHA-256 применённой миграции PostgreSQL не совпадает с пакетом.',
    'native_pg_migration_ledger_mismatch': 'PostgreSQL migration names or order differ from the package / Имена или порядок миграций PostgreSQL не совпадают с пакетом.',
    'native_pg_migration_readback_failed': 'PostgreSQL did not confirm the applied migration / PostgreSQL не подтвердил применённую миграцию.',
    'native_pg_migration_owner_required': 'PostgreSQL local peer access as postgres with schema owner membership is required / Требуется локальный peer-доступ postgres с правами владельца схемы.',
    'native_pg_migration_failed': 'PostgreSQL package migration failed over local peer access / Не удалось применить миграции пакета через локальный peer-доступ PostgreSQL.',
    'native_upgrade_reconciliation_required': 'The previous upgrade failed; explicit package reconciliation is required.',
    'native_upgrade_committed_no_rollback': 'The upgrade is committed; restoring its old checkpoint would lose new data.',
    'native_upgrade_no_previous_release': 'No completed update of this release is available to roll back.',
    'native_upgrade_previous_packages_unavailable': 'Run sudo sli-rollback with the path to the previous trusted Debian kit, or make that version available to APT.',
    'native_upgrade_rollback_package_failed': 'The previous data is restored. Check APT diagnostics and repeat sudo sli-rollback to finish installing the previous kit.',
    'native_upgrade_insufficient_space': 'There is not enough space for the checkpoint and isolated restore.',
    'native_upgrade_migration_interrupted': 'The migration was interrupted before durable completion; the verified checkpoint was restored to avoid replaying uncertain SQL.',
    'native_upgrade_recovery_pending': 'Checkpoint recovery is incomplete; run resume-package again to finish restoring the previous release.',
    'native_upgrade_candidate_missing': 'The unpacked candidate release is missing; repeat the package installation before resuming.',
    'native_upgrade_restore_databases_unready': 'The database engines are still recovering or unavailable; retry resume-package when they are ready.',
    'native_upgrade_package_recovery_failed': 'The interrupted package state could not be finalized; check package manager diagnostics and retry resume-package.',
    'native_upgrade_service_failed': 'The upgrade service failed; inspect journalctl -u sli-upgrade-* and resume the transaction.',
}


class ServiceFailure(RuntimeError):
    def __init__(self, code, returncode):
        super().__init__(code)
        self.returncode = returncode


def systemd_available():
    if not VOLATILE_UNITS.is_dir():
        return False
    try:
        return subprocess.run(['/usr/bin/systemctl', 'show', '--property=Version', '--value'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              check=False, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def run_service(action, transaction, arguments):
    """Re-enter the already trusted release/interpreter outside APT's cgroup."""
    from deploy.linux import operation_wait, native_runtime as runtime

    require(re.fullmatch(r'[0-9a-f]{32}', transaction), 'native_upgrade_identity_invalid')
    unit = 'sli-upgrade-' + transaction + '.service'
    if operation_wait.coordinator_unit() == unit or not systemd_available():
        return False
    argv = ['/usr/bin/systemd-run', '--unit=' + unit, '--property=Type=exec',
            '--property=WatchdogSec=' + str(operation_wait.stall_seconds()), '--property=NotifyAccess=main',
            '--property=RuntimeMaxSec=infinity', '--property=KillMode=control-group', '--wait', '--pipe', '--collect',
            # systemd-cat execs Python in the same PID (NotifyAccess=main).
            # --pipe alone sends output only to APT, bypassing the journal.
            '/usr/bin/systemd-cat', '--identifier=sli-upgrade', sys.executable, '-I', '-B', __file__,
            action, *arguments]
    print(f'Upgrade service / Служба обновления: {unit}; journalctl -u {unit}', flush=True)
    result = subprocess.run(argv, check=False,
                            env={'PATH': '/usr/lib/postgresql/18/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                 'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
    print(f'{unit}: exit_code={result.returncode}', flush=True)
    if result.returncode:
        code = 'native_upgrade_service_failed'
        if (TRANSACTIONS / transaction / 'journal.json').exists():
            try:
                value = runtime.document(TRANSACTIONS / transaction / 'journal.json')
                code = value.get('restart_reason_code') or value.get('failure_reason_code', code)
                code = recover_service_failure(unit, transaction) or code
            except Exception as error:
                code = failure_code(error)
        raise ServiceFailure(code if code in FAILURE_MESSAGES else 'native_upgrade_service_failed', result.returncode)
    return True


def recover_service_failure(unit, transaction):
    """A watchdog can kill Python before its ordinary recovery handler runs."""
    from deploy.linux import native_backup as native, native_install as install, native_runtime as runtime

    journal = Journal(TRANSACTIONS / transaction)
    if journal.value['status'] not in {'preflight', 'fenced', 'aborted_before_checkpoint', 'migrating',
                                     'candidate_testing', 'recovering', 'committed', 'rolled_back'}:
        return None  # The ordinary exception handler already recovered/published.
    if journal.value['status'] == 'aborted_before_checkpoint' and journal.value.get('services_restored'):
        return None
    state = subprocess.run(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState,MainPID,Result,ControlGroup'],
                           capture_output=True, text=True, check=False, timeout=10)
    fields = dict(line.split('=', 1) for line in state.stdout.splitlines() if '=' in line)
    if fields.get('ActiveState') not in {'inactive', 'failed'} or fields.get('MainPID') != '0':
        return None  # Includes a competing invocation: never recover a live unit.
    group = fields.get('ControlGroup')
    if group is None:
        return None
    if group:
        require(group.startswith('/') and group.endswith('/' + unit) and '..' not in Path(group).parts,
                'native_cgroup_invalid')
        path = native.CGROUP_ROOT / group.lstrip('/')
        if path.exists() and any(item.read_text().strip() for item in path.rglob('cgroup.procs')):
            return None
    with operation_lock(native.ROOT):
        journal = Journal(journal.path)
        value = journal.value
        code = 'operation_stalled' if fields.get('Result') == 'watchdog' else 'native_upgrade_service_failed'
        value['failure_reason_code'] = code
        journal.write()
        if value['status'] in {'preflight', 'fenced', 'aborted_before_checkpoint'}:
            require(runtime.release()[0].name == value['previous'], 'native_upgrade_intent_mismatch')
            value.update(status='aborted_before_checkpoint', step='before', services_restored=False)
            journal.write()
            restart_aborted_prepare(journal)
        elif value['status'] == 'committed':
            finish_committed(journal, install.inventory(value.get('accepted_release', value['candidate'])))
        elif value['status'] == 'rolled_back':
            finish_rollback(journal)
        elif value['status'] in {'migrating', 'candidate_testing', 'recovering'}:
            if value['status'] == 'migrating' and value['step'] == 'before':
                value['schema_changed'] = True  # Never replay uncertain SQL.
                journal.write()
            try:
                recover_compatible(journal)
            except Exception:
                publish(journal, 'failed', terminal=False, reason_code='native_upgrade_recovery_pending')
                return 'native_upgrade_recovery_pending'
        return code


def failure_code(error):
    # Exception text from SQL, URLs or commands can contain credentials or rows.
    # Only the finite public diagnostic vocabulary may leave the coordinator.
    code = str(error) if isinstance(error, (RuntimeError, ValueError)) else ''
    return code if code in FAILURE_MESSAGES else 'native_upgrade_failed'


def failure_message(code):
    return FAILURE_MESSAGES.get(code, 'The native upgrade could not be completed; inspect its transaction result.')


def digest(path, *, progress=False):
    from deploy.linux.native_install import trusted, trusted_path

    if progress:
        from deploy.linux.operation_wait import hash_stream, InventoryProgress

        with trusted_path(path).open('rb') as stream:
            check = InventoryProgress()
            result = hash_stream(stream, check)
            check.advance(1)
            return result
    return hashlib.sha256(trusted(path)).hexdigest()


def sync_tree(root, *, recursive=True):
    """Make saved recovery/checkpoint bytes durable before journalling success."""
    from deploy.linux.operation_wait import made_progress

    descendants = sorted(root.rglob('*'), reverse=True) if recursive else []
    for path in [*descendants, root]:
        require(not path.is_symlink())
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        made_progress()


def runtime_inventory(root, sealed=None):
    from deploy.linux.native_install import trusted

    # A new seal includes supplied bytecode; only a saved seal defines extras.
    if sealed is not None:
        cleanup_bytecode(root, sealed)
    result = {}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            require(path.resolve(strict=True).is_relative_to(root), 'native_recovery_runtime_link')
            result[name] = {'link': os.readlink(path)}
        elif path.is_file():
            body = trusted(path)
            result[name] = {'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body)}
        else:
            require(path.is_dir(), 'native_recovery_runtime_invalid')
    return result


@contextmanager
def operation_lock(root):
    import fcntl

    descriptor = os.open(root / '.backup.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('native_upgrade_operation_busy') from None
        yield
    finally:
        os.close(descriptor)


def save_recovery(root, manifest, manifest_digest):
    """Freeze code and unit definitions before the next package can unpack.

    The versioned runtime stays at its build prefix, protected by the rollback
    dependency package. It must never be replaced by a host Python fallback.
    """
    from deploy.linux import backup, native_backup as native, native_install as install, operation_wait

    destination = RECOVERY / root.name
    ensure_directory(RECOVERY, 0o700)
    ensure_directory(destination, 0o700)
    seal = destination / 'recovery.json'
    if seal.exists():
        verify_recovery(root.name)
        return
    require(not (destination / 'release').exists(), 'native_recovery_incomplete')
    native.copy_private(root, destination / 'release')
    units = destination / 'units'
    ensure_directory(units, 0o700, exist_ok=False)
    local_units = destination / 'local-units'
    ensure_directory(local_units, 0o700, exist_ok=False)
    masked = []
    names = {path.name for directory in (UNITS, OVERRIDES) for path in directory.glob('sli*')
             if path.suffix in {'.service', '.timer', '.target', '.slice', '.mount'}}
    for name in sorted(names):
        path = UNITS / name
        if path.exists() or path.is_symlink():
            (units / name).write_bytes(install.trusted(path))
            (units / name).chmod(0o600)
        override = OVERRIDES / name
        if override.is_symlink():
            require(os.readlink(override) == '/dev/null', 'native_recovery_unit_link')
            masked.append(name)
        elif override.exists():
            (local_units / name).write_bytes(install.trusted(override))
            (local_units / name).chmod(0o600)
        dropins = OVERRIDES / (name + '.d')
        if dropins.exists():
            native.copy_private(dropins, local_units / dropins.name)
    require(any(units.iterdir()), 'native_recovery_units_missing')
    # Include the complete code/runtime dependency inventory, not only four CLIs.
    value = {'schema_version': 1, 'release': root.name, 'manifest_sha256': manifest_digest,
             'python': manifest['python'], 'python_sha256': manifest['python_sha256'],
             'runtime_inventory': runtime_inventory(Path(manifest['python']).parent.parent),
             'masked_units': masked,
             'content_checksums': backup.content_inventory(destination, exclude_manifest=False,
                                                          check=operation_wait.InventoryProgress())}
    install.atomic(seal, value)
    sync_tree(destination)
    verify_recovery(root.name)


def verify_recovery(release):
    from deploy.linux import backup, native_install as install, operation_wait

    require(re.fullmatch(r'[a-z0-9][a-z0-9.+-]{0,63}', release))
    root = RECOVERY / release
    value = json.loads(install.trusted(root / 'recovery.json'))
    require(value.get('schema_version') == 1 and value.get('release') == release)
    cleanup_bytecode(root, value['content_checksums'])
    inventory = backup.content_inventory(root, exclude_manifest=False, check=operation_wait.InventoryProgress())
    inventory.pop('recovery.json', None)
    require(inventory == value.get('content_checksums'), 'native_recovery_hash_mismatch')
    python = Path(value['python'])
    require(python.is_relative_to(install.RUNTIMES) and len(python.relative_to(install.RUNTIMES).parts) == 3
            and python.name == 'python3.14' and python.parent.name == 'bin'
            and digest(python) == value['python_sha256'] and os.access(python, os.X_OK),
            'native_recovery_runtime_mismatch')
    require(runtime_inventory(python.parent.parent, value['runtime_inventory']) == value['runtime_inventory'],
            'native_recovery_runtime_mismatch')
    require(digest(root / 'release/native-runtime.json') == value['manifest_sha256'],
            'native_recovery_manifest_mismatch')
    return root, value


class Journal:
    def __init__(self, path):
        from deploy.linux.native_install import trusted

        self.path = path
        self.value = json.loads(trusted(path / 'journal.json'))
        require(self.value.get('schema_version') == 1 and self.value.get('transaction') == path.name
                and self.value.get('status') in set(NEXT) | TERMINAL
                and self.value.get('step') in {'before', 'after'}, 'native_upgrade_journal_invalid')

    def write(self):
        from deploy.linux.native_install import atomic

        stamp = datetime.now(timezone.utc).isoformat()
        self.value['updated_at_utc'] = stamp
        self.value.setdefault('events', []).append({'phase': self.value['status'], 'step': self.value['step'], 'utc': stamp})
        atomic(self.path / 'journal.json', self.value)

    def transition(self, phase):
        require(phase in NEXT.get(self.value['status'], set())
                and self.value['step'] == 'after', 'native_upgrade_phase_invalid')
        self.value.update(status=phase, step='before')
        self.write()  # Intent must reach disk before any side effect.

    def complete(self, **values):
        require(self.value['step'] == 'before', 'native_upgrade_phase_invalid')
        self.value.update(values, step='after')
        self.write()


def database_quiet():
    """Read counters only; never log SQL rows or cancel another connection."""
    from deploy.linux import backup, native_backup as native

    with native.environment(native.settings()):
        with backup.pg_passfile() as passfile, backup.pg_connect(passfile, 'postgres') as connection:
            # The application database can be absent between DROP and CREATE
            # during an interrupted restore. Count writers across the cluster.
            row = connection.execute("SELECT count(*) FROM pg_stat_activity WHERE "
                                     "backend_type='client backend' AND pid<>pg_backend_pid() "
                                     "AND xact_start IS NOT NULL").fetchone()
            require(row == (0,), 'native_upgrade_pg_busy')


def unit_absent(unit):
    """An unloaded unit has no active job; unreadable state is not absence."""
    result = subprocess.run(['systemctl', 'show', unit, '--no-pager',
                             '--property=LoadState,ActiveState,MainPID,ControlGroup'],
                            capture_output=True, text=True, timeout=5, check=False,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    row = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    require(bool(row.get('LoadState')), 'native_upgrade_unit_state_unconfirmed')
    if row['LoadState'] == 'not-found':
        # Timers do not have MainPID/ControlGroup properties. If supplied for a
        # service, neither may indicate remaining work.
        require(row.get('ActiveState') == 'inactive' and row.get('MainPID', '0') == '0'
                and not row.get('ControlGroup'), 'native_upgrade_unit_state_unconfirmed')
        return True
    require(result.returncode == 0, 'native_upgrade_unit_state_unconfirmed')
    return False


def stop_units(units, *, timeout=120):
    from deploy.linux import native_install as install

    present = [unit for unit in units if not unit_absent(unit)]
    if not present:
        return
    try:
        install.command(['systemctl', 'stop', *present], timeout=timeout)
    except RuntimeError:
        # apt removal may unload a unit between show and stop. Only confirmed
        # absence excuses the failed command; real stop/permission errors stay.
        if not all(unit_absent(unit) for unit in present):
            raise


def fence():
    from deploy.linux import native_install as install, native_runtime as runtime

    # Stop scheduling before draining; stopping API gives clients a retryable
    # transport failure and never acknowledges an uncommitted import.
    stop_units(('sli-backup.timer', 'sli-health.timer'))
    stop_units(('sli-backup.service', 'sli-backup-drill.service'), timeout=600)
    runtime.stop_services(('api',), timeout=180)
    runtime.stop_writers()  # Cooperative SIGTERM plus every MainPID/cgroup readback.
    stop_units(('sli-ready.service',))
    # Type=simple only proves process creation. After power loss PostgreSQL may
    # still be replaying WAL/checkpointing when systemd reports it active.
    wait_restore_databases()
    database_quiet()


def preflight():
    from deploy.linux import native_host as host, native_runtime as runtime, native_install as install, native_backup as native

    with host.administrative_lock():
        host.Host().receipt()
        host.validate_identity()
        root, manifest, manifest_digest = runtime.release()
        installed = runtime.document(install.STATE / 'installed.json')
        require(installed.get('release') == str(root) and installed.get('manifest_sha256') == manifest_digest,
                'native_upgrade_registry_mismatch')
        recovery, saved = verify_recovery(root.name)
        require(saved['manifest_sha256'] == manifest_digest and saved['python'] == manifest['python'],
                'native_upgrade_recovery_mismatch')
        runtime.configuration()
        install.site_configuration()
        native.secret_sources()
        return root, recovery


def file_metadata():
    from deploy.linux import native_backup as native
    from deploy.linux.operation_wait import made_progress
    from itertools import chain
    import stat

    result = {}
    for scope, root in (('files', native.DATA), ('state', native.STATE)):
        paths = [path for path in root.iterdir() if scope != 'files' or path.name not in native.EXCLUDED_FILES]
        descendants = (item for child in paths if child.is_dir() for item in child.rglob('*'))
        for path in chain(paths, descendants):
            relative = path.relative_to(root)
            if scope == 'files' and relative.parts[0] in native.EXCLUDED_FILES:
                continue
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'native_upgrade_files_invalid')
            result[scope + '/' + relative.as_posix()] = [info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]
            made_progress()
    return result


def checkpoint_root(journal):
    """Keep new checkpoints on the backup volume; retain old journal readers."""
    from deploy.linux import native_backup as native

    storage = journal.value.get('checkpoint_storage', 'transaction')
    require(storage in {'transaction', 'backup_volume'}, 'native_upgrade_checkpoint_storage_invalid')
    root = (native.ROOT / 'upgrade-checkpoints' / journal.path.name
            if storage == 'backup_volume' else journal.path / 'checkpoints')
    require(root == root.resolve(), 'native_upgrade_checkpoint_storage_invalid')
    return root


def checkpoint_verification(value):
    # Existing transactions retain the stronger proof they originally required.
    mode = value.get('checkpoint_verification', 'restore')
    require(mode in ('integrity', 'restore'), 'native_upgrade_checkpoint_unverified')
    return mode


def checkpoint_receipt(journal):
    from deploy.linux import native_install as install

    value = journal.value
    mode = checkpoint_verification(value)
    checkpoint = checkpoint_root(journal) / value['checkpoint']
    require(digest(checkpoint / 'manifest.json') == value['checkpoint_sha256'],
            'native_upgrade_checkpoint_mismatch')
    name = 'integrity-verified.json' if mode == 'integrity' else 'restore-verified.json'
    receipt = json.loads(install.trusted(checkpoint.parent / name))
    require(isinstance(receipt, dict) and receipt.get('backup_id') == checkpoint.name
            and receipt.get('manifest_sha256') == value['checkpoint_sha256']
            and receipt.get('terminal') is True
            and receipt.get('status') == mode + '_verified'
            and receipt.get('checkpoint_verification', 'restore') == mode
            and (mode == 'integrity' or receipt.get('databases_stopped') is True),
            'native_upgrade_checkpoint_unverified')
    return receipt


def finished_transaction(journal):
    """Terminal intent alone does not prove that the accepted services returned."""
    from deploy.linux import native_install as install

    value = journal.value
    result = json.loads(install.trusted(journal.path / 'result.json'))
    compatible_abort = (value['status'] == 'aborted_before_checkpoint' and value.get('reuse_existing') is True
                        and not value.get('schema_changed') and result.get('status') == 'rolled_back'
                        and result.get('preparation_aborted') is True)
    if (value['step'] != 'after' or result.get('terminal') is not True
            or result.get('status') != value['status'] and not compatible_abort):
        return False
    if value['status'] == 'committed':
        return bool(value.get('accepted_release')) and value.get('services_restored') is True
    return (value['status'] in {'rolled_back', 'aborted_before_checkpoint'}
            and value.get('services_restored') is True)


def cleanup_checkpoints():
    """Collect terminal transaction sets, retaining the latest accepted commit.

    The canonical operation lock serializes this with capture, restore and APT.
    Unknown entries and unreadable journals prevent collection: they may identify
    the latest commit. Finish the complete inventory before deleting any set.
    """
    from deploy.linux.operation_wait import remove_tree

    try:
        if not TRANSACTIONS.exists():
            return
        finished = []
        for path in TRANSACTIONS.iterdir():
            if not re.fullmatch(r'[a-f0-9]{32}', path.name):
                print('native_upgrade_checkpoint_storage_unexpected ' +
                      json.dumps({'name': path.name[:128]}, ensure_ascii=True), file=sys.stderr)
                raise RuntimeError('native_upgrade_checkpoint_storage_unexpected')
            require(path == path.resolve(), 'native_upgrade_checkpoint_storage_invalid')
            journal = Journal(path)
            if finished_transaction(journal):
                finished.append(journal)
        commits = []
        for journal in finished:
            if journal.value['status'] == 'committed' and not journal.value.get('kind'):
                stamps = [event['utc'] for event in journal.value.get('events', [])
                          if event.get('phase') == 'committed' and event.get('step') == 'after']
                # An undated accepted commit must not lose its recovery set.
                require(stamps, 'native_upgrade_checkpoint_storage_invalid')
                commits.append((min(stamps), journal.path.name))
        latest = max(commits)[1] if commits else None
        for journal in finished:
            if journal.path.name != latest:
                root = checkpoint_root(journal)
                if root.exists():
                    remove_tree(root)
    except Exception:  # Never turn cleanup failure into a new recovery attempt.
        print('native_upgrade_checkpoint_cleanup_unconfirmed: Cleanup stopped because transaction state or storage '
              'could not be confirmed / Очистка остановлена: состояние транзакций или хранилища не подтверждено.',
              file=sys.stderr)


def prepare(candidate, transaction, *, target_version=None, previous_version=None, reuse_existing=False):
    from deploy.linux import backup_policy, native_host, native_backup as native, native_install as install, native_runtime as runtime

    require(re.fullmatch(r'[a-z0-9][a-z0-9.+-]{0,63}', candidate)
            and re.fullmatch(r'[0-9a-f]{32}', transaction), 'native_upgrade_identity_invalid')
    package_intent = {}
    if target_version is not None or previous_version is not None:
        require(all(isinstance(version, str) and re.fullmatch(r'[0-9][a-zA-Z0-9.+~]*-[0-9]+~deb13', version)
                    for version in (target_version, previous_version)), 'native_upgrade_package_invalid')
        package_intent = {'target_version': target_version, 'previous_version': previous_version}
    arguments = [candidate, transaction]
    if package_intent:
        arguments += ['--target-version', target_version, '--previous-version', previous_version]
    if reuse_existing:
        arguments.append('--reuse-existing')  # The service must keep the retained-data path.
    if run_service('prepare', transaction, arguments):
        return Journal(TRANSACTIONS / transaction).value
    path = TRANSACTIONS / transaction
    # The same lock is used by capture, pruning and restore. Never hold the short
    # host readiness lock while restoring a disposable drill.
    with operation_lock(native.ROOT):
        native.cleanup_drills()
        cleanup_checkpoints()
        root, recovery = preflight()
        require(root.name != candidate, 'native_upgrade_same_release')
        if not path.exists():
            runtime.no_transaction()
            if reuse_existing:
                validate_reuse_receipt(root)
                require(previous_version == package_metadata(root)['version'], 'native_upgrade_intent_mismatch')
                # Check migration authority before starting even the retained DBs.
                _, previous, previous_digest = install.inventory(root.name)
                candidate_root, manifest, candidate_digest = install.inventory(candidate)
                migration_required(previous, manifest, previous_digest, candidate_root)
                runtime.stop_writers()
                install.command(['systemctl', 'start', *runtime.DATABASES])
                check_reused_databases(candidate)
            else:
                install.wait_health()
            # Capture needs its own space; an explicit drill admits its workspace.
            estimate = native_host.Host().backup_space_estimate(native.ROOT)
            for volume, required in backup_policy.space_requirements(
                    native.ROOT, native.DRILLS, estimate, include_drill=False).items():
                free = shutil.disk_usage(backup_policy.existing_parent(volume)).free
                if free < required:
                    backup_policy.report_refusal({'reason': 'insufficient_backup_disk_space', 'volume': str(volume),
                                                  'required_bytes': required, 'free_bytes': free})
                    raise RuntimeError('native_upgrade_insufficient_space')
            ensure_directory(path, 0o700, exist_ok=False)
            stamp = datetime.now(timezone.utc).isoformat()
            install.atomic(path / 'journal.json', {'schema_version': 1, 'transaction': transaction,
                           'candidate': candidate, 'previous': root.name, 'recovery_sha256': digest(recovery / 'recovery.json'),
                           **package_intent, **({'reuse_existing': True, 'coordinator_release': candidate,
                               'coordinator_manifest_sha256': candidate_digest,
                               'coordinator_sha256': digest(candidate_root / 'deploy/linux/native_upgrade.py')}
                               if reuse_existing else {}),
                           'checkpoint_storage': 'backup_volume', 'checkpoint_verification': 'integrity',
                           'status': 'preflight', 'step': 'before', 'created_at_utc': stamp,
                           'events': [{'phase': 'preflight', 'step': 'before', 'utc': stamp}]})
            directory = os.open(TRANSACTIONS, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        journal = Journal(path)
        value = journal.value
        verification = checkpoint_verification(value)
        require(value['candidate'] == candidate and value['previous'] == root.name
                and value['recovery_sha256'] == digest(recovery / 'recovery.json')
                and all(value.get(key) == expected for key, expected in package_intent.items()),
                'native_upgrade_intent_mismatch')
        require(value['status'] in {'preflight', 'fenced', 'checkpoint_verified'}, 'native_upgrade_recovery_required')
        failure_phase = 'native_upgrade_fence_failed'
        try:
            with install.setup_deadline():
                if value['status'] == 'preflight':
                    if value['step'] == 'before':
                        journal.complete()
                    journal.transition('fenced')
                fence()  # Recheck actual state after interruption; do not trust a phase name.
                failure_phase = 'native_upgrade_checkpoint_failed'
                if value['status'] == 'fenced':
                    if value['step'] == 'before':
                        journal.complete()
                    checkpoints = checkpoint_root(journal)
                    if value.get('checkpoint_storage') == 'backup_volume':
                        ensure_directory(checkpoints.parent, 0o700)
                    ensure_directory(checkpoints, 0o700)
                    if 'checkpoint' not in value:
                        install.atomic(path / 'file-metadata.json', file_metadata())
                        value['file_metadata_sha256'] = digest(path / 'file-metadata.json')
                        journal.write()
                        checkpoint = native.capture_locked(checkpoints, writers_fenced=True)
                        # Persist identity before verification; resume cannot choose another set.
                        value['checkpoint'] = checkpoint.name
                        value['checkpoint_sha256'] = digest(checkpoint / 'manifest.json')
                        journal.write()
                    checkpoint = checkpoints / value['checkpoint']
                    require(digest(checkpoint / 'manifest.json') == value['checkpoint_sha256'],
                            'native_upgrade_checkpoint_mismatch')
                    checkpoint_manifest = native.verify(checkpoint)[0]
                    require(checkpoint_manifest['consistency_point']['writers_fenced'] is True)
                    if verification == 'restore':
                        result = native.drill_locked(checkpoint, checkpoints, prune_sets=False, upgrade_checkpoint=True)
                        require(result.get('status') == 'restore_verified' and result.get('terminal') is True
                                and result.get('databases_stopped') is True
                                and result.get('manifest_sha256') == value['checkpoint_sha256'],
                                'native_upgrade_checkpoint_unverified')
                        value.setdefault('operation_durations', {})['drill_seconds'] = result.get('duration_seconds', 0)
                    else:
                        install.atomic(checkpoints / 'integrity-verified.json', {
                            'schema_version': 1, 'status': 'integrity_verified', 'terminal': True,
                            'checkpoint_verification': 'integrity', 'backup_id': checkpoint.name,
                            'manifest_sha256': value['checkpoint_sha256'],
                            'completed_at_utc': datetime.now(timezone.utc).isoformat()})
                    checkpoint_receipt(journal)
                    value.setdefault('operation_durations', {})['checkpoint_seconds'] = checkpoint_manifest[
                        'consistency_point'].get('capture_window_seconds', 0)
                    sync_tree(checkpoints)
                    journal.transition('checkpoint_verified')
                    journal.complete()
                else:
                    checkpoint = checkpoint_root(journal) / value['checkpoint']
                    require(digest(checkpoint / 'manifest.json') == value['checkpoint_sha256'],
                            'native_upgrade_checkpoint_mismatch')
                    native.verify(checkpoint)
                    checkpoint_receipt(journal)
                    if value['step'] == 'before':
                        journal.complete()
                install.atomic(path / 'result.json', {'schema_version': 1, 'transaction': transaction,
                               'status': 'checkpoint_verified', 'terminal': False, 'writers_fenced': True,
                               'checkpoint_verification': verification})
                return journal.value
        except Exception as error:
            code = failure_code(error)
            if code == 'native_upgrade_failed':
                code = failure_phase
            journal.value['failure_reason_code'] = code
            if value['status'] in {'preflight', 'fenced'}:
                # Capture/verification do not mutate the accepted databases.
                # No application migration or switch has begun.
                value.update(status='aborted_before_checkpoint', step='before', services_restored=False)
                journal.write()
                restart_aborted_prepare(journal)
            else:
                publish(journal, 'failed', terminal=False, reason_code=code)
            if failure_code(error) == 'native_upgrade_failed':
                raise RuntimeError(code) from None
            raise


def restart_aborted_prepare(journal):
    """Open readiness only after a durable, pre-migration abort; retry on failure."""
    from deploy.linux import native_install as install

    value = journal.value
    require(value['status'] == 'aborted_before_checkpoint' and not value.get('schema_changed'),
            'native_upgrade_recovery_required')
    # Older accepted readiness helpers know rolled_back, but not the newer
    # pre-checkpoint abort status. Keep the precise phase in the durable journal.
    result_status = 'rolled_back' if value.get('reuse_existing') else 'aborted_before_checkpoint'
    # Publish before start_checked: sli-ready must see a terminal transaction.
    publish(journal, result_status, accepted_release=value['previous'], services_restored=False, preparation_aborted=True)
    try:
        if value.get('reuse_existing'):
            # Reuse installs sli-host before preparation, unlike ordinary APT.
            # The accepted services must run with their accepted helpers/units.
            recovery, _ = verify_recovery(value['previous'])
            restore_helpers(recovery, True)
            for path in (recovery / 'units').iterdir():
                destination = UNITS / path.name
                require(not destination.is_symlink(), 'native_upgrade_unit_symlink')
                destination.write_bytes(install.trusted(path))
                destination.chmod(0o644)
            restore_agents_unit(recovery)
            testing_units()
            start_checked(retained_runtime(recovery))
        else:
            start_checked()
        install.command(['systemctl', 'start', 'sli.target', 'sli-backup.timer', 'sli-health.timer'])
    except Exception:
        value.update(services_restored=False, restart_reason_code='native_upgrade_restart_failed')
        journal.write()
        publish(journal, result_status, accepted_release=value['previous'], services_restored=False,
                restart_reason_code='native_upgrade_restart_failed', preparation_aborted=True)
        raise RuntimeError('native_upgrade_restart_failed') from None
    value.update(step='after', services_restored=True)
    value.pop('restart_reason_code', None)
    journal.write()
    publish(journal, result_status, accepted_release=value['previous'], services_restored=True, preparation_aborted=True)
    cleanup_checkpoints()


def package_metadata(root):
    from deploy.linux import native_install as install

    value = json.loads(install.trusted(root / 'native-package.json'))
    require(value.get('schema_version') == 1 and value.get('release') == root.name
            and re.fullmatch(r'[0-9][a-zA-Z0-9.+~]*-[0-9]+~deb13', value.get('version', '')),
            'native_upgrade_package_invalid')
    return value


def validate_reuse_receipt(root):
    from deploy.linux import native_install as install

    receipt = json.loads(install.trusted(install.STATE / 'package-install.json'))
    require(receipt.get('status') == 'configured' and receipt.get('release') == root.name
            and receipt.get('first_start_pending', False) is False,
            'native_install_interrupted_requires_recovery')
    require(receipt.get('site_sha256') == install.site_digest(install.site_configuration()),
            'native_setup_configuration_conflict')
    install.validate_agents(install.site_configuration())


def check_reused_databases(candidate):
    """Run the new read-only inventory checks with systemd-delivered credentials.

    No old application start, storage preparation, secret ensure or CA issuance.
    The usual ready adapter checks old ledger/roles/plugins/pointers and engines.
    Its own readiness watchdog bounds engine recovery after a stopped install.
    """
    from deploy.linux import native_install as install

    root, manifest, _ = install.inventory(candidate)
    script = root / 'deploy/linux/native_upgrade.py'
    install.trusted(script)
    credentials = [f'--property=LoadCredential={name}:{install.SECRETS / name}'
                   for name in ('postgres_password',)]
    try:
        install.command(['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                         '--unit=sli-reuse-check', *credentials,
                         manifest['python'], '-I', '-B', str(script), 'check-reuse', candidate],
                        cwd=root, env=install.environment(), timeout=None)
    except RuntimeError:
        raise RuntimeError('native_reuse_readiness_failed') from None


def reuse_existing(candidate):
    """New-package coordinator; retain the normal checkpoint/activation rollback."""
    from deploy.linux import native_install as install, native_runtime as runtime, native_backup as native
    import uuid

    root, _, _ = install.inventory(candidate)
    with operation_lock(native.ROOT):
        try:
            runtime.no_transaction()
        except (OSError, ValueError):
            raise RuntimeError('native_transaction_pending') from None
        previous, _ = preflight()
        if previous == root:
            # Same release retry repeats acceptance only, never bootstrap or SQL.
            install.configure_guarded(candidate)
            return
    version = package_metadata(root)['version']
    for path in TRANSACTIONS.iterdir():
        value = Journal(path).value
        if value.get('target_version') == version:
            require(value['status'] == 'aborted_before_checkpoint' and value.get('services_restored') is True,
                    'native_upgrade_reconciliation_required')
    prepare(candidate, uuid.uuid4().hex, target_version=version,
            previous_version=package_metadata(previous)['version'], reuse_existing=True)
    configure_package(candidate, version)


def package_transaction(version):
    matches = []
    for path in TRANSACTIONS.iterdir():
        journal = Journal(path)
        if journal.value.get('target_version') == version:
            matches.append(journal)
    require(matches, 'native_upgrade_package_intent_required')
    return max(matches, key=lambda journal: journal.value['created_at_utc'])


def prepare_package(version):
    from deploy.linux import native_runtime as runtime
    import uuid

    require(re.fullmatch(r'[0-9][a-zA-Z0-9.+~]*-[0-9]+~deb13', version), 'native_upgrade_package_invalid')
    root = runtime.release()[0]
    previous = package_metadata(root)['version']
    if version == previous:
        return  # Same-version reinstall, or explicit reconciliation after rollback.
    # A failed transaction requires explicit operator reconciliation; configure
    # and repeated APT must never silently try the candidate again.
    matches = []
    for path in TRANSACTIONS.iterdir():
        journal = Journal(path)
        if journal.value.get('target_version') == version:
            matches.append(journal)
    if matches:
        journal = max(matches, key=lambda item: item.value['created_at_utc'])
        if journal.value['status'] == 'aborted_before_checkpoint':
            if not journal.value.get('services_restored'):
                resume_package(version)
        elif journal.value['status'] != 'committed':
            require(journal.value['status'] == 'checkpoint_verified' and journal.value['step'] == 'after',
                    'native_upgrade_reconciliation_required')
            # An explicit resume has finished preparation. APT may now recheck
            # that same checkpoint, without allocating another transaction.
            resume_package(version)
            return
    transaction = uuid.uuid4().hex
    candidate = 'apt-' + hashlib.sha256(version.encode()).hexdigest()[:24]
    prepare(candidate, transaction, target_version=version, previous_version=previous)


def resume_package(version):
    """Resume one durable intent; package reconciliation runs outside APT locks."""
    from deploy.linux import native_runtime as runtime

    journal = package_transaction(version)
    if run_service('resume-package', journal.path.name, [version]):
        return Journal(journal.path).value
    value = journal.value
    if value['status'] == 'aborted_before_checkpoint':
        from deploy.linux import native_backup as native

        with operation_lock(native.ROOT):
            require(runtime.release()[0].name == value['previous'], 'native_upgrade_intent_mismatch')
            restart_aborted_prepare(journal)
        return journal.value
    if value['status'] in {'migrating', 'candidate_testing', 'recovering', 'committed', 'rolled_back'}:
        if value['status'] != 'rolled_back':
            release = value.get('activation_release') or value.get('testing_release') or value['candidate']
            if value.get('recovery_in_progress'):
                release = value.get('activation_release', value['candidate'])
            configure_package(release, version)
        journal = package_transaction(version)
        if journal.value['status'] == 'rolled_back':
            from deploy.linux import native_backup as native

            with operation_lock(native.ROOT):
                finish_rollback(journal)
            reconcile(version)
        return journal.value
    root = runtime.release()[0]
    candidate = value['coordinator_release'] if value.get('reuse_existing') else 'apt-' + hashlib.sha256(version.encode()).hexdigest()[:24]
    require(value['status'] in {'preflight', 'fenced', 'checkpoint_verified'}
            and value['candidate'] == candidate and value['previous'] == root.name
            and value.get('previous_version') == package_metadata(root)['version'],
            'native_upgrade_reconciliation_required')
    return prepare(candidate, journal.path.name, target_version=version,
                   previous_version=value['previous_version'],
                   **({'reuse_existing': True} if value.get('reuse_existing') else {}))


def check_package(version):
    from deploy.linux import native_runtime as runtime

    root = runtime.release()[0]
    if package_metadata(root)['version'] == version:
        runtime.no_transaction()
        return
    journal = package_transaction(version)
    require(journal.value['status'] == 'checkpoint_verified' and journal.value['step'] == 'after'
            and journal.value['previous'] == root.name, 'native_upgrade_package_intent_required')


def worker_logins_added(previous_roles, candidate_roles):
    """A release may add only migrate-provisioned worker logins, unprivileged.

    migrate.configure_worker_logins creates these NOINHERIT logins and refuses
    any extra privilege; every other role change still blocks the upgrade.
    """
    from deploy.linux.migrate import WORKER_LOGINS

    if not isinstance(previous_roles, list) or not isinstance(candidate_roles, list):
        return False
    old = {tuple(row) for row in previous_roles}
    new = {tuple(row) for row in candidate_roles}
    allowed = {login for login, _, _ in WORKER_LOGINS}
    allowed.update({"adlog_storage_lifecycle_worker", "adlog_storage_lifecycle_delete", "adlog_storage_lifecycle_guard"})
    return old <= new and all(row[0] in allowed and not any(row[1:]) for row in new - old)


def compatible(previous, candidate):
    keys = ('python', 'python_sha256', 'postgres_version', 'migration_ledger', 'plugins')
    require(all(key in previous and previous[key] == candidate.get(key) for key in keys)
            and 'roles' in previous
            and (previous['roles'] == candidate.get('roles')
                 or worker_logins_added(previous['roles'], candidate.get('roles'))),
            'native_upgrade_incompatible_inventory')


def migration_required(previous, candidate, previous_digest, root):
    """Only an explicitly bound, forward ledger may change the schema."""
    if previous['migration_ledger'] == candidate.get('migration_ledger'):
        compatible(previous, candidate)
        return False
    compatible(previous, {**candidate, 'migration_ledger': previous['migration_ledger']})
    old, new = previous['migration_ledger'], candidate.get('migration_ledger')
    bound = candidate.get('checkpoint_upgrade_from')
    require((bound is None or bound == previous_digest)
            and isinstance(new, list) and len(new) > len(old) and new[:len(old)] == old,
            'native_upgrade_migration_not_authorized')
    from deploy.linux.installed_state import ledger_matches
    from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

    checksums = {str(path.relative_to(root)): digest(path)
                 for path in (root / 'config/postgres_migrations').glob('*.sql')}
    ledger_matches({**candidate, 'migrations': checksums}, {
        'migration_ledger': new, 'migration_ledger_max': max(row['version'] for row in new)})
    # Every new ledger entry must have actual forward SQL in this release.
    inventory = {item.version: item for item in forward_migration_inventory(root / 'config/postgres_migrations')}
    for row in new[len(old):]:
        item = inventory.get(row['version'])
        require(item is not None and item.name == row['name'] and item.sha256 == row['sha256'],
                'native_upgrade_migration_sql_missing')
    return True


def wait_restore_databases():
    """Probe engines without requiring the schema we are about to recover."""
    from deploy.linux import native_runtime as runtime
    try:
        runtime.wait_databases()
    except RuntimeError as error:
        if str(error) == 'native_database_unready':
            raise RuntimeError('native_upgrade_restore_databases_unready') from None
        raise


def restore_checkpoint(journal, *, committed_source=None):
    """Replay a fenced set for automatic recovery or a separate operator intent."""
    from deploy.linux import backup, native_backup as native, native_install as install
    from deploy.linux import native_runtime as runtime, restore_existing as restore
    from deploy.linux import operation_wait
    from deploy.linux.update_checkpoint import snapshot

    require(journal.value['status'] != 'committed'
            and not any(event['phase'] == 'committed' for event in journal.value.get('events', [])),
            'native_upgrade_committed_no_rollback')
    require(journal.value['status'] == 'recovering' and journal.value['step'] == 'before',
            'native_upgrade_recovery_intent_required')
    source_journal = committed_source or journal
    if committed_source is not None:
        require(journal.value.get('kind') == 'rollback' and journal.value.get('safety_backup')
                and journal.value.get('checkpoint_transaction') == source_journal.path.name
                and source_journal.value['status'] == 'committed' and finished_transaction(source_journal),
                'native_upgrade_recovery_intent_required')
    metadata = source_journal.path / 'file-metadata.json'
    require(digest(metadata) == source_journal.value['file_metadata_sha256'], 'native_upgrade_metadata_mismatch')
    checkpoint = checkpoint_root(source_journal) / source_journal.value['checkpoint']
    checkpoint_receipt(source_journal)
    fence()
    with snapshot(checkpoint.parent, checkpoint.name, temporary_root=checkpoint.parent,
                  progress=operation_wait.made_progress) as (private, _):
        require(digest(private / 'manifest.json') == source_journal.value['checkpoint_sha256'],
                'native_upgrade_checkpoint_mismatch')
        manifest, data, data_manifest = native.verify(private, checkpoint.name)
        require(manifest['consistency_point']['writers_fenced'] is True)
        # Configuration has not changed contract during a SQL-only upgrade.
        # Rewrite captured bytes in place, preserving service ownership/modes.
        install.command(['systemctl', 'stop', *runtime.DATABASES])
        companion = private / 'companion'
        configuration = [(companion / 'postgresql', POSTGRES_CONFIG)]
        if committed_source is None:
            configuration.insert(0, (companion / 'secrets', native.CONFIG / 'secrets'))
        else:
            from deploy.linux.native_restore import restore_credentials, secret_material

            config = json.loads((companion / 'runtime.json').read_bytes())
            restore_credentials(secret_material(companion, config), config)
        for source, destination in configuration:
            source_files = set(backup.content_inventory(source, exclude_manifest=False))
            target_files = set(backup.content_inventory(destination, exclude_manifest=False))
            require(source_files == target_files, 'native_upgrade_configuration_inventory_changed')
            for path in source.rglob('*'):
                if path.is_file():
                    target = destination / path.relative_to(source)
                    if destination == POSTGRES_CONFIG:
                        import pwd

                        info = target.lstat()
                        require(target.resolve(strict=True) == target and info.st_uid in {0, pwd.getpwnam('postgres').pw_uid}
                                and not info.st_mode & 0o022, 'native_upgrade_postgres_configuration_untrusted')
                    else:
                        install.trusted(target)
                    target.write_bytes(path.read_bytes())
            sync_tree(destination)
        for name in ('runtime.json', 'site.toml'):
            if (companion / name).exists():
                target = native.CONFIG / name
                install.trusted(target)
                target.write_bytes((companion / name).read_bytes())
                sync_tree(target)
        install.command(['systemctl', 'start', *runtime.DATABASES])
        wait_restore_databases()
        with native.environment(native.settings()):
            restore.restore_components(data, private, data_manifest, ("postgres",), replace_existing=True)
        # Administrative roots must survive, especially this journal/checkpoint.
        for path in native.DATA.iterdir():
            if path.name not in native.EXCLUDED_FILES:
                require(not path.is_symlink(), 'native_upgrade_files_symlink')
                if path.is_dir():
                    operation_wait.remove_tree(path)
                else:
                    path.unlink()
                    operation_wait.made_progress()
        for source in (data / 'files').iterdir():
            require(source.name not in native.EXCLUDED_FILES, 'native_upgrade_files_reserved')
            destination = native.DATA / source.name
            if source.is_dir():
                operation_wait.copy_tree(source, destination)
            else:
                operation_wait.copy_file(source, destination)
        observed = {}
        for path in native.DATA.iterdir():
            if path.name in native.EXCLUDED_FILES:
                continue
            if path.is_dir():
                observed.update({path.name + '/' + key: value for key, value in
                                 backup.content_inventory(path, exclude_manifest=False,
                                                          check=operation_wait.InventoryProgress()).items()})
            else:
                observed[path.name] = {'sha256': digest(path, progress=True), 'size': path.stat().st_size}
        require(backup.content_inventory(data / 'files', exclude_manifest=False,
                                         check=operation_wait.InventoryProgress()) == observed,
                'native_upgrade_files_readback_failed')
        # State is a separate protected component, never overlaid onto the journal.
        for path in native.STATE.iterdir():
            require(not path.is_symlink())
            if path.is_dir():
                operation_wait.remove_tree(path)
            else:
                path.unlink()
                operation_wait.made_progress()
        operation_wait.copy_tree(companion / 'state', native.STATE, dirs_exist_ok=True)
        for name, (uid, gid, mode) in json.loads(install.trusted(metadata)).items():
            relative = Path(name)
            require(not relative.is_absolute() and '..' not in relative.parts and len(relative.parts) > 1)
            base = {'files': native.DATA, 'state': native.STATE}[relative.parts[0]]
            target = base.joinpath(*relative.parts[1:])
            require(target.resolve(strict=True) == target and target.is_relative_to(base))
            os.chown(target, uid, gid)
            target.chmod(mode)
            operation_wait.made_progress()
        for path in native.DATA.iterdir():
            if path.name not in native.EXCLUDED_FILES:
                sync_tree(path)
        sync_tree(native.STATE)
        journal.value['checkpoint_restored'] = True
        journal.write()


def switch(root, manifest, manifest_digest, previous_receipt_path=None):
    from deploy.linux import native_install as install

    installed_path = install.STATE / 'installed.json'
    receipt = json.loads(install.trusted(previous_receipt_path or installed_path))
    installed_at = (receipt.get('installed_at_utc') if receipt.get('release') == str(root)
                    else datetime.now(timezone.utc).isoformat())
    temporary = install.CURRENT.with_name('.upgrade-current')
    if temporary.is_symlink():
        require(os.readlink(temporary) == str(root), 'native_upgrade_pointer_busy')
    else:
        require(not temporary.exists(), 'native_upgrade_pointer_busy')
        temporary.symlink_to(root)
    os.replace(temporary, install.CURRENT)
    directory = os.open(install.CURRENT.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    selected_receipt = dict(manifest, release=str(root), manifest_sha256=manifest_digest)
    if installed_at is not None:
        selected_receipt['installed_at_utc'] = installed_at
    install.atomic(installed_path, selected_receipt)


def testing_units(transaction=None):
    from deploy.linux import native_install as install

    for unit in ('sli-ready.service', 'sli-health.service', 'sli-dotnet-api.service'):
        path = VOLATILE_UNITS / (unit + '.d') / '90-sli-upgrade.conf'
        if transaction:
            ensure_directory(path.parent)
            value = ('SLI_NATIVE_UPGRADE_TESTING=1' if unit == 'sli-dotnet-api.service'
                     else 'SLI_NATIVE_UPGRADE_TRANSACTION=' + transaction)
            path.write_text('[Service]\nEnvironment=' + value + '\n')
            path.chmod(0o644)
        else:
            path.unlink(missing_ok=True)
    install.command(['systemctl', 'daemon-reload'])


def start_checked(checked_runtime=None):
    from deploy.linux import native_install as install, native_runtime as runtime

    if checked_runtime is not None:
        runtime = checked_runtime
    config = runtime.configuration()
    unit_name = getattr(runtime, 'active_unit_name', runtime.unit_name)
    # After apt remove the stopped units are unloaded, and reset-failed on an
    # unloaded unit exits 1. Only failed units need their state cleared.
    names = ['sli-ready.service', 'sli-health.service', *map(unit_name, runtime.selected(config))]
    failed = [name for name in names if subprocess.run(['systemctl', 'is-failed', '--quiet', name],
                                                        check=False, timeout=30).returncode == 0]
    if failed:
        install.command(['systemctl', 'reset-failed', *failed])
    install.command(['systemctl', 'start', 'sli-ready.service'])
    target = 'sli-dotnet.target' if unit_name('api').startswith('sli-dotnet-') else 'sli-runtime.target'
    install.command(['systemctl', 'start', target])
    install.wait_api(config)
    install.wait_health()
    for service in runtime.selected(config):
        row = runtime.systemd(service)
        require(row.get('ActiveState') == 'active' and int(row.get('MainPID', '0')) > 1,
                'native_upgrade_service_unready')


def publish(journal, status, *, terminal=True, reason_code=None, **values):
    from deploy.linux import native_install as install

    if reason_code or 'failure_reason_code' in journal.value:
        code = reason_code or journal.value['failure_reason_code']
        values.update(reason_code=code, message=failure_message(code))
    if journal.value.get('operation_durations'):
        values['operation_durations'] = journal.value['operation_durations']
    verification = journal.value.get('checkpoint_verification', 'restore')
    if verification in ('integrity', 'restore'):
        values['checkpoint_verification'] = verification
    install.atomic(journal.path / 'result.json', dict(schema_version=1, transaction=journal.path.name,
                   status=status, terminal=terminal, **values))


def configure_candidate(root, manifest):
    from deploy.linux import native_install as install, native_runtime as runtime

    # Generate candidate units with candidate code, never overwrite its host
    # helper with the coordinator's older module after APT has unpacked it.
    install.trusted(root / 'deploy/linux/native_runtime.py')
    code = ('import json,sys; sys.path.insert(0,sys.argv[1]); '
            'from deploy.linux.native_runtime import configure; configure(json.loads(sys.argv[2]))')
    config = runtime.configuration()
    site = install.site_configuration()
    if 'notification_proxy' in site:
        config = dict(config, notification_proxy=site['notification_proxy'])
    else:
        config = {key: value for key, value in config.items() if key != 'notification_proxy'}
    install.command([manifest['python'], '-I', '-B', '-c', code, str(root),
                     json.dumps(config, sort_keys=True)], cwd=root, env=install.environment())


def restore_helpers(recovery, preserve_coordinator=False):
    from deploy.linux import native_install as install

    for name in ('native_host.py', 'native_runtime.py', 'native_install.py', 'native_backup.py',
                 'native_upgrade.py', 'native_clickhouse_endpoint.py', 'native_preinstall.py', 'native_pins.json', 'secrets-manifest.json', 'backup_policy.py', 'operation_wait.py'):
        destination = RUNTIME_HELPER.parent / name
        require(not destination.is_symlink(), 'native_upgrade_helper_symlink')
        if preserve_coordinator and name == 'native_upgrade.py':
            # Retain the verified new launcher's journal-bound reuse dispatch.
            continue
        source = recovery / 'release/deploy/linux' / name
        # Legacy services do not import these newer helpers. Keep them available
        # to the new setup/resume entry points, which survive a runtime rollback.
        if name in {'operation_wait.py', 'native_preinstall.py'} and not source.exists() and not source.is_symlink():
            continue
        destination.write_bytes(install.trusted(source))
        destination.chmod(0o640 if name.endswith('.json') else 0o644)


def retained_runtime(recovery):
    """Use the accepted service catalog, which can predate new worker units."""
    from deploy.linux import native_install as install

    path = recovery / 'release/deploy/linux/native_runtime.py'
    install.trusted(path)
    spec = importlib.util.spec_from_file_location('sli_accepted_runtime', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def restore_agents_unit(recovery):
    """A frozen release snapshot may predate an accepted agents reconfiguration."""
    from deploy.linux import native_install as install, native_runtime as runtime

    intent = install.STATE / 'agents-reconfigure.json'
    if intent.exists() or intent.is_symlink():
        require(runtime.document(intent).get('status') in {'applied', 'configured'},
                'native_agents_reconfigure_pending')
        # Use the restored runtime settings and the accepted coordinator's
        # renderer. Never edit the sealed recovery snapshot or replay its old flag.
        # .NET units are regenerated from the restored runtime.json at reload.
        rendered = runtime.units(runtime.configuration())
        if 'sli-api.service' not in rendered:
            return
        body = rendered['sli-api.service']
        saved = install.trusted(recovery / 'units/sli-api.service').decode('utf-8')
        install.replace_managed(UNITS / 'sli-api.service', {saved, body}, body)


def activate(journal, candidate):
    from deploy.linux import native_install as install, native_runtime as runtime

    old, previous, old_digest = install.inventory(journal.value['previous'])
    root, manifest, manifest_digest = candidate
    require(package_metadata(root)['version'] == journal.value['target_version'], 'native_upgrade_package_mismatch')
    migrating = migration_required(previous, manifest, old_digest, root)
    # Verify the retained source/runtime and checkpoint again before switching.
    recovery, _ = verify_recovery(old.name)
    require(digest(recovery / 'recovery.json') == journal.value['recovery_sha256'], 'native_upgrade_recovery_mismatch')
    checkpoint = checkpoint_root(journal) / journal.value['checkpoint']
    require(digest(checkpoint / 'manifest.json') == journal.value['checkpoint_sha256'], 'native_upgrade_checkpoint_mismatch')
    checkpoint_receipt(journal)
    prepared = journal.value['status'] == 'checkpoint_verified'
    if prepared:
        fence()
        # Persist the actual unpacked release before the first irreversible intent.
        journal.value.update(activation_release=root.name, schema_changed=migrating)
        journal.write()
        journal.transition('migrating')
        if migrating:
            from deploy.linux.native_pg_migrate import migrate

            migration_started = time.monotonic()
            migrate(root)
            journal.value.setdefault('operation_durations', {})['migration_seconds'] = time.monotonic() - migration_started
        journal.complete()
    if journal.value['status'] == 'migrating':
        require(journal.value['step'] == 'after', 'native_upgrade_migration_interrupted')
        journal.transition('candidate_testing')
    require(journal.value['status'] == 'candidate_testing', 'native_upgrade_reconciliation_required')
    journal.value.update(candidate=root.name, testing_release=root.name, candidate_writes_possible=True)
    journal.write()
    if not prepared:
        fence()
    configure_candidate(root, manifest)
    switch(root, manifest, manifest_digest)
    testing_units(journal.path.name)
    start_checked()
    # Save accepted management code without the temporary test overrides.
    fence()
    testing_units()
    install.preserve_recovery(root, manifest, manifest_digest)
    if journal.value['step'] == 'before':
        journal.complete()
    journal.transition('committed')
    journal.complete(accepted_release=root.name)
    finish_committed(journal, candidate)


def finish_committed(journal, candidate):
    """Commit is a one-way boundary, including intent before its completion write."""
    from deploy.linux import native_install as install

    root, manifest, manifest_digest = candidate
    require(journal.value['status'] == 'committed', 'native_upgrade_reconciliation_required')
    require(package_metadata(root)['version'] == journal.value['target_version'], 'native_upgrade_package_mismatch')
    switch(root, manifest, manifest_digest)
    testing_units()
    if journal.value['step'] == 'before':
        journal.complete(accepted_release=root.name)
    # Durable commit precedes opening ingress. Never roll back a committed
    # transaction, even if the subsequent start/readback fails.
    publish(journal, 'committed', accepted_release=root.name, schema_changed=journal.value.get('schema_changed', False))
    receipt = json.loads(install.trusted(install.STATE / 'package-install.json'))
    receipt.update(release=root.name, status='configured')
    install.atomic(install.STATE / 'package-install.json', receipt)
    start_checked()
    install.command(['systemctl', 'enable', '--now', 'sli.target', 'sli-backup.timer'])
    journal.value['services_restored'] = True
    journal.write()
    publish(journal, 'committed', accepted_release=root.name, schema_changed=journal.value.get('schema_changed', False),
            services_restored=True)
    cleanup_checkpoints()


def recover_compatible(journal):
    """Return the old application, restoring the complete set after SQL intent."""
    from deploy.linux import native_install as install, native_runtime as runtime

    require(journal.value['status'] != 'committed'
            and not any(event['phase'] == 'committed' for event in journal.value.get('events', [])),
            'native_upgrade_committed_no_rollback')
    journal.value['recovery_in_progress'] = True
    journal.write()
    fence()
    if journal.value['status'] != 'recovering':
        if journal.value['step'] == 'before':
            journal.complete()
        journal.transition('recovering')
    recovery, _ = verify_recovery(journal.value['previous'])
    root, manifest, manifest_digest = install.inventory(journal.value['previous'])
    if (journal.value['step'] == 'before' and not journal.value.get('checkpoint_restored')
            and journal.value.get('schema_changed')):
        restore_checkpoint(journal)
        journal.value['checkpoint_restored'] = True
        journal.write()
    switch(root, manifest, manifest_digest, recovery / 'installed.json')
    restore_helpers(recovery, bool(journal.value.get('reuse_existing')))
    # Restore the saved vendor definitions. Local overrides were never changed.
    for path in (recovery / 'units').iterdir():
        destination = UNITS / path.name
        require(not destination.is_symlink(), 'native_upgrade_unit_symlink')
        destination.write_bytes(path.read_bytes())
        destination.chmod(0o644)
    restore_agents_unit(recovery)
    testing_units(journal.path.name)
    if journal.value['step'] == 'before':
        journal.complete()
    # The same closed-ingress health gate validates the restored release.
    journal.value.update(testing_release=root.name)
    journal.transition('candidate_testing')
    if journal.value.get('reuse_existing'):
        start_checked(retained_runtime(recovery))
    else:
        start_checked()
    fence()
    testing_units()
    journal.complete()
    journal.transition('recovering')
    journal.complete()
    journal.transition('rolled_back')
    finish_rollback(journal)


def finish_rollback(journal):
    from deploy.linux import native_install as install

    require(journal.value['status'] == 'rolled_back', 'native_upgrade_reconciliation_required')
    if journal.value['step'] == 'before':
        journal.complete(accepted_release=journal.value['previous'])
    publish(journal, 'rolled_back', accepted_release=journal.value['previous'], package_reconciliation_required=True)
    if journal.value.get('reuse_existing'):
        recovery, _ = verify_recovery(journal.value['previous'])
        start_checked(retained_runtime(recovery))
    else:
        start_checked()
    install.command(['systemctl', 'enable', '--now', 'sli.target', 'sli-backup.timer'])
    journal.value['services_restored'] = True
    journal.write()
    publish(journal, 'rolled_back', accepted_release=journal.value['previous'], package_reconciliation_required=True,
            services_restored=True)
    cleanup_checkpoints()


def configure_package(release, version):
    from deploy.linux import native_install as install, native_runtime as runtime, native_backup as native

    matches = [Journal(path) for path in TRANSACTIONS.iterdir()]
    matches = [item for item in matches if item.value.get('target_version') == version]
    journal = max(matches, key=lambda item: item.value['created_at_utc']) if matches else None
    if journal is None:
        root = runtime.release()[0]
        require(root.name == release, 'native_upgrade_package_intent_required')
        require(package_metadata(root)['version'] == version, 'native_upgrade_package_mismatch')
        install.configure_guarded(release)
        return
    require(journal.value['status'] in {'checkpoint_verified', 'migrating', 'candidate_testing', 'recovering', 'committed'},
            'native_upgrade_reconciliation_required')
    script = install.RELEASES / release / 'deploy/linux/native_upgrade.py'
    if Path(__file__).resolve() == script:
        root, manifest, manifest_digest = install.inventory(release)
        # The old coordinator prepares/checkpoints the old writers. Acceptance
        # and resumptions need the candidate's .NET catalog, not its Python one.
        journal.value.update(dotnet_coordinator=True, coordinator_release=release,
                             coordinator_manifest_sha256=manifest_digest,
                             coordinator_sha256=hashlib.sha256(install.trusted(script)).hexdigest())
        journal.write()
    if run_service('configure-package', journal.path.name, [release, version]):
        return
    with operation_lock(native.ROOT):
        try:
            with install.setup_deadline():
                _configure_package(journal, release)
        except Exception as error:
            journal.value['failure_reason_code'] = failure_code(error)
            journal.write()
            if journal.value['status'] != 'committed':
                try:
                    # Recovery is outside the expired watchdog. Its operations
                    # retain their own progress watches and cancellation cleanup.
                    recover_compatible(journal)
                except Exception:
                    fenced = False
                    try:
                        fence()
                        fenced = True
                    except Exception:
                        pass
                    try:
                        testing_units()
                    except Exception:
                        pass
                    journal.write()
                    publish(journal, 'failed', terminal=False, writers_fenced=fenced,
                            reason='native_upgrade_recovery_failed', reason_code='native_upgrade_recovery_pending')
            raise  # dpkg/APT must report failure even when the old runtime is healthy.


def _configure_package(journal, release):
    from deploy.linux import native_install as install

    value = journal.value
    if value['status'] == 'migrating' and value['step'] == 'before':
        # SQL files own their transaction boundaries. An absent durable
        # completion cannot distinguish a fully applied file from a
        # partial non-atomic one. Never replay either on uncertain data.
        value.update(schema_changed=True, failure_reason_code='native_upgrade_migration_interrupted')
        journal.write()
        recover_compatible(journal)
    elif value['status'] == 'recovering' or value.get('recovery_in_progress'):
        recover_compatible(journal)
    elif value['status'] == 'committed':
        finish_committed(journal, install.inventory(value.get('accepted_release', release)))
    else:
        activate(journal, install.inventory(release))


def reconcile(version):
    """Operator command after APT exits; never called by maintainer scripts."""
    from deploy.linux import native_install as install, native_runtime as runtime, native_backup as native
    import subprocess

    with operation_lock(native.ROOT):
        journal = package_transaction(version)
        require(journal.value['status'] == 'rolled_back' and journal.value['step'] == 'after',
                'native_upgrade_reconciliation_required')
        previous = journal.value['previous_version']
        require(runtime.release()[0].name == journal.value['previous'], 'native_upgrade_registry_mismatch')
        # dpkg must merge its interrupted write journal before APT will run.
        # The rejected candidate's postinst deliberately returns 1 at rolled_back;
        # it cannot replay SQL. Fatal dpkg errors must stop before starting APT.
        repaired = subprocess.run(['dpkg', '--configure', 'sli'], capture_output=True, check=False, timeout=1200)
        require(repaired.returncode in {0, 1}, 'native_upgrade_package_recovery_failed')
        # APT obtains its own locks and refuses another active package manager.
        install.command(['apt-get', '-y', '--allow-downgrades', 'install',
                         *[name + '=' + previous for name in ('sli', 'sli-host', 'sli-rollback-hold')]], timeout=1200)
        for name in ('sli', 'sli-host', 'sli-rollback-hold'):
            value = subprocess.run(['dpkg-query', '-W', '-f=${Status}\t${Version}', name],
                                   capture_output=True, text=True, check=True, timeout=10).stdout
            require(value == 'install ok installed\t' + previous, 'native_upgrade_package_mismatch')
        install.wait_health()
        publish(journal, 'rolled_back', accepted_release=journal.value['previous'], package_reconciliation_required=False)

def launch(candidate, transaction, *, action='prepare', arguments=None):
    # This entry point runs with Debian stdlib before importing any release code.
    saved_launcher = Path(__file__).parent.parent == RECOVERY
    helper = Path(__file__).with_name('native_runtime.py') if saved_launcher else RUNTIME_HELPER
    for item in (helper, *helper.parents):
        info = item.lstat()
        require(not item.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022)
    spec = importlib.util.spec_from_file_location('sli_upgrade_runtime', helper)
    runtime = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(runtime)
    # A killed switch may have changed current before registry/recovery sealing.
    # Dispatch pending package work with its retained previous coordinator,
    # independently of the current pointer and the newly unpacked host helper.
    pending = []
    if action in {'resume-package', 'configure-package', 'prepare-package', 'check-package', 'reconcile'} and arguments:
        version = arguments[-1]
        if TRANSACTIONS.exists():
            for path in TRANSACTIONS.iterdir():
                value = runtime.document(path / 'journal.json')
                if value.get('target_version') == version:
                    pending.append(value)
    if action == 'configure-package' and arguments and not saved_launcher:
        # Only the new sli-host postinst uses this dispatcher. Retained
        # preinst/prerm code still validates and checkpoints the accepted release.
        spec = importlib.util.spec_from_file_location('sli_candidate_install', helper.with_name('native_install.py'))
        install = importlib.util.module_from_spec(spec)
        runtime.trusted(helper.with_name('native_install.py'))
        spec.loader.exec_module(install)
        root, manifest, _ = install.inventory(arguments[0])
        require(runtime.document(root / 'native-package.json').get('version') == arguments[-1],
                'native_upgrade_package_mismatch')
        script = root / 'deploy/linux/native_upgrade.py'
        runtime.trusted(script)
        os.execve(manifest['python'], [manifest['python'], '-I', '-B', str(script), action, *arguments],
                  install.environment())
        return
    if action == 'rollback':
        # Current may already point to the previous release after an interrupted
        # switch. Retry with the coordinator that wrote the operator intent.
        retry = None
        if TRANSACTIONS.exists():
            for path in TRANSACTIONS.iterdir():
                value = runtime.document(path / 'journal.json')
                if value.get('kind') == 'rollback' and not value.get('services_restored'):
                    retry = value
                    break
        if retry:
            release = retry['candidate']
            require(re.fullmatch(r'[a-z0-9][a-z0-9.+-]{0,63}', release), 'native_upgrade_journal_invalid')
            saved = RECOVERY / release
            manifest = runtime.document(saved / 'release/native-runtime.json')
            manifest_digest = hashlib.sha256(runtime.trusted(saved / 'release/native-runtime.json')).hexdigest()
        else:
            root, manifest, manifest_digest = runtime.release()
            saved = RECOVERY / root.name
    elif pending:
        value = max(pending, key=lambda item: item['created_at_utc'])
        if value.get('reuse_existing') or value.get('dotnet_coordinator'):
            # Preparation and resumption must both use the new coordinator,
            # even while current still points to a legacy accepted release.
            spec = importlib.util.spec_from_file_location('sli_reuse_install', helper.with_name('native_install.py'))
            install = importlib.util.module_from_spec(spec)
            runtime.trusted(helper.with_name('native_install.py'))
            spec.loader.exec_module(install)
            root, manifest, manifest_digest = install.inventory(value['coordinator_release'])
            script = root / 'deploy/linux/native_upgrade.py'
            require(manifest_digest == value.get('coordinator_manifest_sha256')
                    and hashlib.sha256(runtime.trusted(script)).hexdigest() == value.get('coordinator_sha256'),
                    'native_reuse_coordinator_mismatch')
            os.execve(manifest['python'], [manifest['python'], '-I', '-B', str(script), action, *arguments],
                      install.environment())
            return
        previous = value['previous']
        require(re.fullmatch(r'[a-z0-9][a-z0-9.+-]{0,63}', previous), 'native_upgrade_journal_invalid')
        saved = RECOVERY / previous
        manifest = runtime.document(saved / 'release/native-runtime.json')
        manifest_digest = hashlib.sha256(runtime.trusted(saved / 'release/native-runtime.json')).hexdigest()
    else:
        root, manifest, manifest_digest = runtime.release()
        saved = RECOVERY / root.name
    seal = runtime.document(saved / 'recovery.json')
    script = saved / 'release/deploy/linux/native_upgrade.py'
    body = runtime.trusted(script)
    expected = seal['content_checksums']['release/deploy/linux/native_upgrade.py']
    require(expected['sha256'] == hashlib.sha256(body).hexdigest()
            and seal['python'] == manifest['python'] and seal['manifest_sha256'] == manifest_digest)
    os.execve(manifest['python'], [manifest['python'], '-I', '-B', str(script), action,
                                *(arguments if arguments is not None else [candidate, transaction])],
              {'PATH': '/usr/lib/postgresql/18/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
               **{key: os.environ[key] for key in ('INVOCATION_ID', 'NOTIFY_SOCKET', 'WATCHDOG_PID', 'WATCHDOG_USEC')
                  if key in os.environ}})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('launch', 'prepare', 'dispatch', 'prepare-package', 'check-package',
                                         'configure-package', 'reconcile', 'resume-package', 'reuse-existing', 'check-reuse', 'rollback'))
    parser.add_argument('arguments', nargs='+')
    parser.add_argument('--target-version')
    parser.add_argument('--previous-version')
    parser.add_argument('--reuse-existing', action='store_true')
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() == 0, 'native_root_required')
        os.umask(0o022)
        if args.action == 'launch':
            if args.arguments[0] in {'reconcile', 'resume-package', 'rollback'}:
                launch(None, None, action=args.arguments[0], arguments=args.arguments[1:])
            else:
                launch(*args.arguments)
        elif args.action == 'dispatch':
            require(args.arguments[0] in {'prepare-package', 'check-package', 'configure-package'})
            launch(None, None, action=args.arguments[0], arguments=args.arguments[1:])
        else:
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
            if args.action == 'rollback':
                from deploy.linux.native_restore import rollback

                require(args.arguments[0] == 'latest' and len(args.arguments) <= 2)
                os.umask(0o077)
                rollback(Path(args.arguments[1]) if len(args.arguments) == 2 else None)
                print('Previous version restored / Предыдущая версия восстановлена')
                return 0
            if args.action in {'reuse-existing', 'check-reuse'}:
                from deploy.linux import native_install as install, native_runtime as runtime

                root, manifest, _ = install.inventory(args.arguments[0])
                require(Path(__file__).resolve() == root / 'deploy/linux/native_upgrade.py'
                        and Path(sys.executable) == Path(manifest['python']), 'native_reuse_coordinator_mismatch')
                if args.action == 'check-reuse':
                    runtime.ready()
                    return 0
            options = {}
            if args.target_version is not None or args.previous_version is not None:
                require(args.action == 'prepare', 'native_upgrade_package_invalid')
                options = dict(target_version=args.target_version, previous_version=args.previous_version)
            if args.reuse_existing:
                require(args.action == 'prepare', 'native_upgrade_package_invalid')
                options['reuse_existing'] = True
            {'prepare': prepare, 'prepare-package': prepare_package, 'check-package': check_package,
             'configure-package': configure_package, 'reconcile': reconcile,
             'resume-package': resume_package, 'reuse-existing': reuse_existing}[args.action](*args.arguments, **options)
    except Exception as error:  # noqa: BLE001 - allowlisted diagnostics only; no private exception text
        code = failure_code(error)
        print(f'Upgrade failed: {failure_message(code)} (reason_code={code})', file=sys.stderr)
        version = args.arguments[-1]
        if args.action == 'reuse-existing' and code != 'native_root_required':
            try:
                from deploy.linux import native_install as install

                target = package_metadata(install.inventory(args.arguments[0])[0])['version']
                package_transaction(target)
            except (OSError, RuntimeError, ValueError, KeyError, TypeError):
                pass  # Admission can refuse without ever creating a transaction.
            else:
                version = target
        if re.fullmatch(r'[0-9][a-zA-Z0-9.+~]*-[0-9]+~deb13', version):
            # Admission can fail before any journal exists. In that case the
            # public resume command has no intent to resume; repeat APT instead.
            try:
                package_transaction(version)
            except (OSError, RuntimeError, ValueError):
                recovery_command = 'bash ./install-beta-kit'
            else:
                # The installed wrapper already supplies the launch action.
                recovery_command = f'sudo sli-native-upgrade resume-package {version}'
            print(f'Recovery / \u0412\u043e\u0441\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u0438\u0435: '
                  f'{recovery_command}', file=sys.stderr)
        return error.returncode if isinstance(error, ServiceFailure) else 1
    print('native_upgrade_checkpoint_verified' if args.action in {'prepare', 'launch'}
          and args.arguments[0] != 'reconcile' else 'native_upgrade_verified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
