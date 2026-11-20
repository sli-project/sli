"""Native upgrade phases/resume with fake DBs and services, no real database."""
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup, native_backup as native, native_host as host
from deploy.linux import native_install as install, native_runtime as runtime, native_upgrade as upgrade
from deploy.linux import native_pg_migrate

TX = 'a' * 32
REAL_FENCE = upgrade.fence

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='POSIX durable transactions, fcntl and package recovery; Linux CI')


@pytest.fixture(autouse=True)
def native_clickhouse_mode(monkeypatch):
    monkeypatch.setattr(upgrade, 'systemd_available', lambda: False)
    # Temporary-root lifecycle fakes do not provision real system ownership.
    def directory(path, mode=0o755, *owners, **options):
        path.mkdir(mode=mode, parents=True, exist_ok=options.get('exist_ok', True))

    monkeypatch.setattr(upgrade, 'ensure_directory', directory)
    monkeypatch.setattr(install, 'ensure_directory', directory)
    monkeypatch.setattr(host.clickhouse, 'configured_mode', lambda root=Path('/'): 'native')


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


@pytest.fixture
def operation(tmp_path, monkeypatch):
    from deploy.linux import operation_wait
    monkeypatch.setattr(install, 'setup_watch', lambda: operation_wait.Watch(
        'migration_setup', minimum=0, stall=1800, native=True))
    events = []
    transactions = tmp_path / 'transactions'
    transactions.mkdir()
    backups = tmp_path / 'backups'
    backups.mkdir()
    recovery = tmp_path / 'recovery/old'
    write(recovery / 'recovery.json', {'schema_version': 1})
    monkeypatch.setattr(upgrade, 'TRANSACTIONS', transactions)
    monkeypatch.setattr(runtime, 'TRANSACTIONS', transactions)
    monkeypatch.setattr(native, 'ROOT', backups)
    monkeypatch.setattr(native, 'DRILLS', tmp_path)
    monkeypatch.setattr(install, 'trusted', lambda path: path.read_bytes())
    monkeypatch.setattr(runtime, 'trusted', lambda path: path.read_bytes())
    monkeypatch.setattr(upgrade, 'preflight', lambda: (Path('/accepted/old'), recovery))
    monkeypatch.setattr(install, 'wait_health', lambda: None)
    monkeypatch.setattr(backup, 'size_bytes', lambda path: 1)
    monkeypatch.setattr(upgrade.shutil, 'disk_usage', lambda path: SimpleNamespace(free=100 * 1024**3))
    monkeypatch.setattr(upgrade, 'fence', lambda: events.append('fence'))
    monkeypatch.setattr(upgrade, 'file_metadata', lambda: {})
    monkeypatch.setattr(upgrade, 'start_checked', lambda: events.append('restart-old'))
    monkeypatch.setattr(install, 'command', lambda *a, **kw: None)
    captured = []

    def capture(root, *, writers_fenced):
        assert writers_fenced is True
        events.append('capture')
        checkpoint = root / f'20261017T010000.{len(captured):06}Z'
        write(checkpoint / 'manifest.json', {'consistency_point': {'writers_fenced': True}})
        captured.append(checkpoint)
        return checkpoint

    def verify(path):
        events.append('verify')
        return json.loads((path / 'manifest.json').read_text()), None, None

    def drill(path, root, *, prune_sets, upgrade_checkpoint):
        assert path.parent == root and not prune_sets and upgrade_checkpoint is True
        events.append('drill')
        result = {'schema_version': 1, 'backup_id': path.name,
                  'manifest_sha256': upgrade.digest(path / 'manifest.json'),
                  'terminal': True, 'status': 'restore_verified', 'databases_stopped': True}
        write(root / 'restore-verified.json', result)
        return result

    monkeypatch.setattr(native, 'capture_locked', capture)
    monkeypatch.setattr(native, 'verify', verify)
    monkeypatch.setattr(native, 'drill_locked', drill)
    return SimpleNamespace(events=events, transactions=transactions, captured=captured,
                           path=transactions / TX, capture=capture, drill=drill, recovery=recovery)


def test_preparation_fences_before_capture_and_never_commits(operation):
    result = upgrade.prepare('new', TX)
    assert result['status'] == 'checkpoint_verified' and result['step'] == 'after'
    assert operation.events.index('fence') < operation.events.index('capture') < operation.events.index('verify')
    assert result['checkpoint_verification'] == 'integrity' and 'drill' not in operation.events
    receipt = json.loads((operation.path / 'result.json').read_text())
    assert receipt['terminal'] is False and receipt['writers_fenced'] is True
    assert [(e['phase'], e['step']) for e in result['events']] == [
        ('preflight', 'before'), ('preflight', 'after'), ('fenced', 'before'), ('fenced', 'after'),
        ('fenced', 'after'), ('fenced', 'after'), ('checkpoint_verified', 'before'), ('checkpoint_verified', 'after')]
    with pytest.raises(RuntimeError, match='native_transaction_pending'):
        runtime.no_transaction()


def test_prepared_resume_rechecks_fence_hash_and_receipt_without_new_backup(operation):
    first = upgrade.prepare('new', TX)
    operation.events.clear()
    assert upgrade.prepare('new', TX) == first
    assert operation.events == ['fence', 'verify']
    assert len(operation.captured) == 1


def test_new_checkpoint_and_resume_keep_data_on_backup_volume(operation):
    value = upgrade.prepare('new', TX)
    assert value['checkpoint_storage'] == 'backup_volume'
    checkpoint = operation.captured[0]
    assert checkpoint.parent == native.ROOT / 'upgrade-checkpoints' / TX
    assert not (operation.path / 'checkpoints').exists()
    assert upgrade.prepare('new', TX)['checkpoint'] == checkpoint.name
    assert len(operation.captured) == 1


def test_checkpoint_storage_refuses_symlink_before_capture(operation, tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    (native.ROOT / 'upgrade-checkpoints').symlink_to(outside, target_is_directory=True)
    with pytest.raises(RuntimeError, match='checkpoint_storage_invalid'):
        upgrade.prepare('new', TX)
    assert not operation.captured and not list(outside.iterdir())


@pytest.mark.parametrize('step', ['before', 'after'])
def test_preflight_resume_performs_fence_and_new_checkpoint(operation, step):
    write(operation.path / 'journal.json', {'schema_version': 1, 'transaction': TX, 'candidate': 'new',
          'previous': 'old', 'recovery_sha256': upgrade.digest(operation.recovery / 'recovery.json'),
          'status': 'preflight', 'step': step})
    assert upgrade.prepare('new', TX)['status'] == 'checkpoint_verified'
    assert len(operation.captured) == 1 and operation.events[0] == 'fence'
    assert operation.captured[0].parent == operation.path / 'checkpoints'


def test_resume_after_checkpoint_intent_completes_without_repeating_drill(operation):
    upgrade.prepare('new', TX)
    journal = upgrade.Journal(operation.path)
    journal.value['step'] = 'before'
    journal.write()
    operation.events.clear()
    assert upgrade.prepare('new', TX)['step'] == 'after'
    assert operation.events == ['fence', 'verify']


@pytest.mark.parametrize('failure', ['fence', 'capture', 'verify'])
def test_prepare_failure_aborts_before_checkpoint(operation, monkeypatch, failure):
    owner, attr = (upgrade, 'fence') if failure == 'fence' else (
        native, 'verify' if failure == 'verify' else 'capture_locked')
    monkeypatch.setattr(owner, attr, lambda *a, **k: (_ for _ in ()).throw(RuntimeError('injected')))
    code = 'native_upgrade_fence_failed' if failure == 'fence' else 'native_upgrade_checkpoint_failed'
    with pytest.raises(RuntimeError, match=code):
        upgrade.prepare('new', TX)
    receipt = json.loads((operation.path / 'result.json').read_text())
    assert receipt['status'] == 'aborted_before_checkpoint' and receipt['terminal'] is True
    assert receipt['reason_code'] == code and receipt['services_restored'] is True
    journal = upgrade.Journal(operation.path)
    assert journal.value['status'] == 'aborted_before_checkpoint'
    assert 'restart-old' in operation.events
    runtime.no_transaction()


def test_reuse_abort_restores_accepted_helpers_and_units_before_health(operation, monkeypatch, tmp_path):
    upgrade.prepare('new', TX)
    journal = upgrade.Journal(operation.path)
    journal.value.update(status='aborted_before_checkpoint', step='before', reuse_existing=True)
    journal.write()
    units = tmp_path / 'units'
    units.mkdir()
    saved = operation.recovery / 'units'
    saved.mkdir()
    (saved / 'sli-ready.service').write_text('accepted-ready')
    monkeypatch.setattr(upgrade, 'UNITS', units)
    monkeypatch.setattr(upgrade, 'verify_recovery', lambda name: (operation.recovery, {}))
    monkeypatch.setattr(upgrade, 'restore_helpers', lambda path, preserve: operation.events.append(('helpers-restored', preserve)))
    monkeypatch.setattr(upgrade, 'restore_agents_unit', lambda path: None)
    monkeypatch.setattr(upgrade, 'testing_units', lambda: operation.events.append('daemon-reload'))
    accepted_runtime = object()
    monkeypatch.setattr(upgrade, 'retained_runtime', lambda path: accepted_runtime, raising=False)
    def start(checked_runtime):
        assert checked_runtime is accepted_runtime
        assert ('helpers-restored', True) in operation.events
        assert (units / 'sli-ready.service').read_text() == 'accepted-ready'
        assert 'daemon-reload' in operation.events
    monkeypatch.setattr(upgrade, 'start_checked', start)
    upgrade.restart_aborted_prepare(journal)
    assert journal.value['services_restored'] is True
    result = json.loads((operation.path / 'result.json').read_text())
    assert result['services_restored'] is True
    assert result['status'] == 'rolled_back' and result['preparation_aborted'] is True
    assert journal.value['status'] == 'aborted_before_checkpoint'
    assert upgrade.finished_transaction(journal)
    result['preparation_aborted'] = False
    write(operation.path / 'result.json', result)
    assert not upgrade.finished_transaction(journal)


def test_power_loss_after_capture_before_durable_identity_creates_fresh_set(operation, monkeypatch):
    def capture(*args, **kwargs):
        operation.capture(*args, **kwargs)
        raise KeyboardInterrupt
    monkeypatch.setattr(native, 'capture_locked', capture)
    with pytest.raises(KeyboardInterrupt):
        upgrade.prepare('new', TX)
    assert 'checkpoint' not in upgrade.Journal(operation.path).value
    monkeypatch.setattr(native, 'capture_locked', operation.capture)
    upgrade.prepare('new', TX)
    assert len(operation.captured) == 2 and all(path.exists() for path in operation.captured)


@pytest.mark.parametrize('field', ['candidate', 'previous', 'recovery_sha256'])
def test_resume_refuses_changed_intent_before_fence(operation, field):
    upgrade.prepare('new', TX)
    journal = upgrade.Journal(operation.path)
    journal.value[field] = 'changed'
    journal.write()
    operation.events.clear()
    with pytest.raises(RuntimeError, match='intent_mismatch'):
        upgrade.prepare('new', TX)
    assert not operation.events


@pytest.mark.parametrize('kind', ['manifest', 'data', 'receipt', 'unfenced'])
def test_resume_refuses_unproven_checkpoint(operation, monkeypatch, kind):
    upgrade.prepare('new', TX)
    path = operation.captured[0]
    if kind == 'manifest':
        (path / 'manifest.json').write_text('changed')
    elif kind == 'data':
        monkeypatch.setattr(native, 'verify', lambda path: (_ for _ in ()).throw(RuntimeError('data_changed')))
    elif kind == 'receipt':
        write(path.parent / 'integrity-verified.json', {'status': 'failed'})
    else:
        journal = upgrade.Journal(operation.path)
        journal.value.update(status='fenced', step='after')
        journal.write()
        monkeypatch.setattr(native, 'verify', lambda path: ({'consistency_point': {'writers_fenced': False}}, None, None))
    with pytest.raises(RuntimeError):
        upgrade.prepare('new', TX)


@pytest.mark.parametrize('phase', ['migrating', 'candidate_testing', 'recovering', 'committed', 'rolled_back', 'failed'])
def test_resume_after_irreversible_intent_requires_recovery(operation, phase):
    upgrade.prepare('new', TX)
    journal = upgrade.Journal(operation.path)
    journal.value.update(status=phase, step='before')
    journal.write()
    operation.events.clear()
    with pytest.raises(RuntimeError, match='recovery_required'):
        upgrade.prepare('new', TX)
    assert not operation.events


@pytest.mark.parametrize('phase', list(upgrade.NEXT))
def test_journal_requires_fsynced_intent_and_completion_before_next_phase(tmp_path, monkeypatch, phase):
    monkeypatch.setattr(install, 'trusted', lambda path: path.read_bytes())
    value = {'schema_version': 1, 'transaction': TX, 'status': phase, 'step': 'before'}
    path = tmp_path / TX
    write(path / 'journal.json', value)
    journal = upgrade.Journal(path)
    target = sorted(upgrade.NEXT[phase])[0]
    with pytest.raises(RuntimeError, match='phase_invalid'):
        journal.transition(target)
    journal.complete()
    journal.transition(target)
    assert upgrade.Journal(path).value['status'] == target
    assert upgrade.Journal(path).value['step'] == 'before'
    with pytest.raises(RuntimeError, match='phase_invalid'):
        journal.transition('preflight')


def test_cli_reports_backup_lock_before_starting_upgrade(operation, monkeypatch, capsys):
    monkeypatch.setattr(upgrade.os, 'geteuid', lambda: 0)
    with backup.backup_lock(native.ROOT):
        assert upgrade.main(['prepare', 'new', TX]) == 1
    output = capsys.readouterr().err
    assert 'backup, restore drill or another upgrade is running' in output
    assert 'reason_code=native_upgrade_operation_busy' in output
    assert not operation.path.exists() and not operation.events


def test_another_operation_and_disk_admission_leave_runtime_untouched(operation, monkeypatch):
    with backup.backup_lock(native.ROOT), pytest.raises(RuntimeError, match='operation_busy'):
        upgrade.prepare('new', TX)
    assert not operation.path.exists() and not operation.events
    monkeypatch.setattr(upgrade.shutil, 'disk_usage', lambda path: SimpleNamespace(free=0))
    with pytest.raises(RuntimeError, match='insufficient_space'):
        upgrade.prepare('new', TX)
    assert not operation.path.exists() and not operation.events


def test_other_unfinished_transaction_blocks_prepare(operation):
    (operation.transactions / ('b' * 32)).mkdir()
    with pytest.raises(FileNotFoundError):
        upgrade.prepare('new', TX)
    assert not operation.path.exists() and not operation.events


def test_unhealthy_old_runtime_is_not_stopped(operation, monkeypatch):
    monkeypatch.setattr(install, 'wait_health', lambda: (_ for _ in ()).throw(RuntimeError('unhealthy')))
    with pytest.raises(RuntimeError, match='unhealthy'):
        upgrade.prepare('new', TX)
    assert not operation.path.exists() and not operation.events


@pytest.mark.parametrize('missing_secret', [False, True])
def test_preflight_checks_registry_recovery_configuration_and_online_secrets(monkeypatch, missing_secret):
    calls = []
    monkeypatch.setattr(host, 'administrative_lock', nullcontext)
    monkeypatch.setattr(host, 'Host', lambda: SimpleNamespace(receipt=lambda: calls.append('mount')))
    monkeypatch.setattr(host, 'validate_identity', lambda: calls.append('identity'))
    monkeypatch.setattr(runtime, 'release', lambda: (Path('/accepted/old'), {'python': '/accepted/python'}, 'digest'))
    monkeypatch.setattr(runtime, 'document', lambda path: {'release': '/accepted/old', 'manifest_sha256': 'digest'})
    monkeypatch.setattr(upgrade, 'verify_recovery', lambda release: (Path('/saved/old'), {'python': '/accepted/python', 'manifest_sha256': 'digest'}))
    monkeypatch.setattr(runtime, 'configuration', lambda: calls.append('configuration'))
    monkeypatch.setattr(install, 'site_configuration', lambda: calls.append('site'))
    def secrets():
        calls.append('secrets')
        if missing_secret:
            raise RuntimeError('native_backup_secret_missing')
    monkeypatch.setattr(native, 'secret_sources', secrets)
    if missing_secret:
        with pytest.raises(RuntimeError, match='secret_missing'):
            upgrade.preflight()
    else:
        assert upgrade.preflight() == (Path('/accepted/old'), Path('/saved/old'))
    assert calls == ['mount', 'identity', 'configuration', 'site', 'secrets']


def test_fence_stops_ingress_then_every_writer_and_checks_database(monkeypatch):
    events = []
    monkeypatch.setattr(install, 'command', lambda argv, **kwargs: events.append(argv))
    monkeypatch.setattr(upgrade, 'unit_absent', lambda unit: False, raising=False)
    monkeypatch.setattr(runtime, 'stop_writers', lambda: events.append('writers-stopped'))
    monkeypatch.setattr(runtime, 'stop_services', lambda services, **kw: events.append(
        ['systemctl', 'stop', *map(runtime.active_unit_name, services)]))
    monkeypatch.setattr(upgrade, 'wait_restore_databases', lambda: events.append('db-ready'))

    def quiet():
        assert 'db-ready' in events, 'Cold-boot engines must be ready before reading writer counters'
        events.append('db-quiet')

    monkeypatch.setattr(upgrade, 'database_quiet', quiet)
    upgrade.fence()
    assert events.index(['systemctl', 'stop', 'sli-dotnet-api.service']) < events.index('writers-stopped')
    assert events.index('writers-stopped') < events.index('db-quiet')
    assert events.index('writers-stopped') < events.index('db-ready') < events.index('db-quiet')
    assert events[0] == ['systemctl', 'stop', 'sli-backup.timer', 'sli-health.timer']


@pytest.mark.parametrize('missing', ['sli-backup.timer', 'sli-backup.service', 'sli-backup-drill.service',
                                   'sli-health.timer', 'sli-ready.service'])
def test_fence_tolerates_unloaded_ancillary_unit(monkeypatch, missing):
    import subprocess

    calls = []
    def command(argv, **kwargs):
        assert missing not in argv, 'unloaded unit must not block rollback'
        calls.append(argv)

    def show(argv, **kwargs):
        absent = argv[2] == missing
        return SimpleNamespace(returncode=int(absent), stdout=(
            'LoadState=' + ('not-found' if absent else 'loaded') +
            '\nActiveState=inactive\nMainPID=0\nControlGroup=\n'))

    monkeypatch.setattr(subprocess, 'run', show)
    monkeypatch.setattr(install, 'command', command)
    monkeypatch.setattr(runtime, 'stop_services', lambda *args, **kwargs: None)
    monkeypatch.setattr(runtime, 'stop_writers', lambda: None)
    monkeypatch.setattr(upgrade, 'wait_restore_databases', lambda: None)
    monkeypatch.setattr(upgrade, 'database_quiet', lambda: None)
    upgrade.fence()
    assert all(argv[:2] == ['systemctl', 'stop'] for argv in calls)


def test_candidate_failure_rolls_back_with_unloaded_units_without_resume(activation, monkeypatch):
    import subprocess

    health = []
    def start():
        health.append(1)
        if len(health) == 1:
            raise RuntimeError('native_install_api_unready')

    def command(argv, **kwargs):
        if argv[:2] == ['systemctl', 'stop']:
            raise RuntimeError('native_install_command_failed')

    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=1,
        stdout='LoadState=not-found\nActiveState=inactive\nMainPID=0\nControlGroup=\n'))
    monkeypatch.setattr(upgrade, 'fence', REAL_FENCE)
    monkeypatch.setattr(install, 'command', command)
    monkeypatch.setattr(upgrade, 'start_checked', start)
    monkeypatch.setattr(runtime, 'stop_services', lambda *args, **kwargs: None)
    monkeypatch.setattr(runtime, 'stop_writers', lambda: None)
    monkeypatch.setattr(upgrade, 'wait_restore_databases', lambda: None)
    monkeypatch.setattr(upgrade, 'database_quiet', lambda: None)
    with pytest.raises(RuntimeError, match='native_install_api_unready'):
        upgrade.configure_package('new', '2.0-1~deb13')
    result = json.loads((activation.operation.path / 'result.json').read_text())
    assert result['status'] == 'rolled_back' and result['terminal'] is True
    assert result['services_restored'] is True
    assert 'switch-old' in activation.operation.events
    assert len(health) == 3


@pytest.mark.parametrize('pg,ch', [(0, 0), (1, 0), (0, 1)])
def test_database_fence_uses_postgres_counters_without_clickhouse(monkeypatch, pg, ch):
    calls = []
    connection = SimpleNamespace(execute=lambda sql: SimpleNamespace(fetchone=lambda: (pg,)))
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(Path('/unused')))
    def connect(passfile, database='sli'):
        assert database == 'postgres', 'Quiescence must work while restore has dropped sli'
        return nullcontext(connection)
    monkeypatch.setattr(backup, 'pg_connect', connect)
    def query(sql):
        assert 'system.mutations' in sql and 'system.processes' in sql and 'currentQueryID()' in sql
        calls.append(sql)
        return [{'n': ch}]
    monkeypatch.setattr(backup, 'clickhouse_targets', lambda: [SimpleNamespace(query=query)] * 2)
    if pg:
        with pytest.raises(RuntimeError, match='pg_busy'):
            upgrade.database_quiet()
    else:
        upgrade.database_quiet()
        assert calls == []


@pytest.fixture
def saved(tmp_path, monkeypatch):
    root = tmp_path / 'releases/old'
    root.mkdir(parents=True)
    runtimes = tmp_path / 'runtimes'
    python = runtimes / 'old/bin/python3.14'
    python.parent.mkdir(parents=True)
    python.write_bytes(b'synthetic-runtime')
    python.chmod(0o755)
    library = python.parent.parent / 'lib'
    library.mkdir()
    (library / 'libpython.so').write_bytes(b'synthetic-library')
    (library / 'libpython-link.so').symlink_to('libpython.so')
    manifest = {'schema_version': 1, 'python': str(python), 'python_sha256': hashlib.sha256(python.read_bytes()).hexdigest()}
    write(root / 'native-runtime.json', manifest)
    (root / 'code.py').write_text('accepted-code')
    script = root / 'deploy/linux/native_upgrade.py'
    script.parent.mkdir(parents=True)
    script.write_text('accepted-upgrade')
    units = tmp_path / 'units'
    units.mkdir()
    (units / 'sli-api.service').write_text('accepted-unit')
    monkeypatch.setattr(upgrade, 'RECOVERY', tmp_path / 'recovery')
    monkeypatch.setattr(upgrade, 'UNITS', units)
    monkeypatch.setattr(upgrade, 'OVERRIDES', tmp_path / 'overrides')
    monkeypatch.setattr(install, 'RUNTIMES', runtimes)
    monkeypatch.setattr(install, 'trusted', lambda path: path.read_bytes())
    upgrade.save_recovery(root, manifest, upgrade.digest(root / 'native-runtime.json'))
    return SimpleNamespace(root=root, python=python, library=library, manifest=manifest)


def test_saved_code_and_units_survive_original_package_replacement(saved):
    (saved.root / 'code.py').write_text('candidate-code')
    root, value = upgrade.verify_recovery('old')
    assert (root / 'release/code.py').read_text() == 'accepted-code'
    assert (root / 'units/sli-api.service').read_text() == 'accepted-unit'
    assert value['python'] == str(saved.python)
    assert all(p.stat().st_mode & 0o077 == 0 for p in root.rglob('*'))
    seal = (root / 'recovery.json').read_bytes()
    upgrade.save_recovery(saved.root, saved.manifest, value['manifest_sha256'])
    assert (root / 'recovery.json').read_bytes() == seal


def test_recovery_preserves_local_unit_overrides_and_dropins(saved):
    # A separate accepted release captures the local policy without changing old recovery.
    root = saved.root.with_name('with-overrides')
    __import__('shutil').copytree(saved.root, root)
    overrides = upgrade.OVERRIDES
    overrides.mkdir()
    (overrides / 'sli-api.service').symlink_to('/dev/null')
    (overrides / 'sli-postgresql.service').write_text('[Service]\nExecStart=/accepted/postgres\n')
    dropins = overrides / 'sli-api.service.d'
    dropins.mkdir()
    (dropins / 'limits.conf').write_text('[Service]\nMemoryMax=512M\n')
    upgrade.save_recovery(root, saved.manifest, upgrade.digest(root / 'native-runtime.json'))
    recovery, seal = upgrade.verify_recovery('with-overrides')
    assert seal['masked_units'] == ['sli-api.service']
    assert (recovery / 'local-units/sli-postgresql.service').read_text() == '[Service]\nExecStart=/accepted/postgres\n'
    assert (recovery / 'local-units/sli-api.service.d/limits.conf').read_text() == '[Service]\nMemoryMax=512M\n'


@pytest.mark.parametrize('kind', ['code', 'unit', 'interpreter', 'library', 'link', 'extra'])
def test_recovery_tamper_refused_before_prepare(saved, kind):
    root = upgrade.RECOVERY / 'old'
    if kind in {'code', 'unit', 'extra'}:
        path = root / {'code': 'release/code.py', 'unit': 'units/sli-api.service', 'extra': 'extra'}[kind]
    elif kind == 'interpreter':
        path = saved.python
    elif kind == 'library':
        path = saved.library / 'libpython.so'
    else:
        path = saved.library / 'libpython-link.so'
        path.unlink()
        path.symlink_to('/etc/passwd')
    if kind != 'link':
        path.write_bytes(b'tampered')
    with pytest.raises(RuntimeError, match='native_recovery_'):
        upgrade.verify_recovery('old')


def test_cli_uses_fixed_diagnostic_and_nonzero_result(monkeypatch, capsys):
    monkeypatch.setattr(upgrade.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(upgrade, 'prepare', lambda *args: (_ for _ in ()).throw(RuntimeError('private-diagnostic')))
    assert upgrade.main(['prepare', 'new', TX]) == 1
    output = capsys.readouterr()
    assert 'reason_code=native_upgrade_failed' in output.err and not output.out
    assert 'inspect its transaction result' in output.err and 'private-diagnostic' not in output.err


@pytest.mark.parametrize('saved_launcher', [False, True])
def test_launcher_uses_saved_code_pinned_runtime_and_clean_environment(saved, tmp_path, monkeypatch, saved_launcher):
    recovery, seal = upgrade.verify_recovery('old')
    helper = (recovery if saved_launcher else tmp_path) / 'native_runtime.py'
    helper.write_text('from pathlib import Path\nimport json\n'
                      f"def release(): return Path('/accepted/old'), {{'python':{str(saved.python)!r}}}, {seal['manifest_sha256']!r}\n"
                      'def document(path): return json.loads(path.read_bytes())\n'
                      'def trusted(path): return path.read_bytes()\n')
    if saved_launcher:
        monkeypatch.setattr(upgrade, '__file__', str(recovery / 'native_upgrade.py'))
    else:
        monkeypatch.setattr(upgrade, 'RUNTIME_HELPER', helper)
    original = Path.lstat
    monkeypatch.setattr(Path, 'lstat', lambda path: SimpleNamespace(st_uid=0, st_mode=0o100755)
                        if path in (helper, *helper.parents) else original(path))
    calls = []
    monkeypatch.setattr(upgrade.sys, 'dont_write_bytecode', upgrade.sys.dont_write_bytecode)
    monkeypatch.setattr(upgrade.os, 'execve', lambda *args: calls.append(args))
    monkeypatch.setenv('LD_PRELOAD', 'untrusted')
    monkeypatch.setenv('PYTHONPATH', 'untrusted')
    monkeypatch.setenv('NOTIFY_SOCKET', '@sli-upgrade-test')
    monkeypatch.setenv('INVOCATION_ID', 'b' * 32)
    monkeypatch.setenv('WATCHDOG_PID', str(os.getpid()))
    monkeypatch.setenv('WATCHDOG_USEC', '1800000000')
    upgrade.launch('new', TX)
    executable, argv, env = calls[0]
    assert executable == str(saved.python)
    assert argv == [str(saved.python), '-I', '-B', str(recovery / 'release/deploy/linux/native_upgrade.py'), 'prepare', 'new', TX]
    assert set(env) == {'PATH', 'LC_ALL', 'PYTHONDONTWRITEBYTECODE',
                        'NOTIFY_SOCKET', 'INVOCATION_ID', 'WATCHDOG_PID', 'WATCHDOG_USEC'}
    assert env['NOTIFY_SOCKET'] == '@sli-upgrade-test'
    assert env['INVOCATION_ID'] == 'b' * 32


def test_launcher_refuses_symlink_before_import(tmp_path, monkeypatch):
    source = tmp_path / 'code'
    source.write_text('raise AssertionError("must not execute")')
    link = tmp_path / 'native_runtime.py'
    link.symlink_to(source)
    monkeypatch.setattr(upgrade, 'RUNTIME_HELPER', link)
    with pytest.raises(RuntimeError):
        upgrade.launch('new', TX)


def test_package_launcher_uses_previous_recovery_when_current_is_unsealed(saved, tmp_path, monkeypatch):
    recovery, _ = upgrade.verify_recovery('old')
    helper = tmp_path / 'native_runtime.py'
    helper.write_text('from pathlib import Path\nimport json\n'
                      'def release(): raise AssertionError("current must not be read")\n'
                      'def document(path): return json.loads(path.read_bytes())\n'
                      'def trusted(path): return path.read_bytes()\n')
    monkeypatch.setattr(upgrade, 'RUNTIME_HELPER', helper)
    transactions = tmp_path / 'transactions'
    write(transactions / TX / 'journal.json', {'target_version': '2.0-1~deb13', 'previous': 'old',
                                               'created_at_utc': '2026-10-26', 'status': 'candidate_testing'})
    monkeypatch.setattr(upgrade, 'TRANSACTIONS', transactions)
    original = Path.lstat
    monkeypatch.setattr(Path, 'lstat', lambda path: SimpleNamespace(st_uid=0, st_mode=0o100755)
                        if path in (helper, *helper.parents) else original(path))
    calls = []
    monkeypatch.setattr(upgrade.os, 'execve', lambda *args: calls.append(args))
    upgrade.launch(None, None, action='resume-package', arguments=['2.0-1~deb13'])
    assert str(recovery / 'release/deploy/linux/native_upgrade.py') in calls[0][1]
    assert calls[0][1][-2:] == ['resume-package', '2.0-1~deb13']


def test_sync_tree_fsyncs_files_and_directories(tmp_path, monkeypatch):
    from deploy.linux import operation_wait

    (tmp_path / 'directory').mkdir()
    (tmp_path / 'directory/file').write_text('data')
    calls = []
    progress = []
    monkeypatch.setattr(operation_wait, 'made_progress', lambda: progress.append(len(calls)))
    original = os.fsync
    def sync(fd):
        calls.append(os.readlink('/proc/self/fd/' + str(fd)))
        original(fd)
    monkeypatch.setattr(upgrade.os, 'fsync', sync)
    upgrade.sync_tree(tmp_path)
    assert calls[-1] == str(tmp_path)
    assert calls.index(str(tmp_path / 'directory/file')) < calls.index(str(tmp_path / 'directory'))
    assert progress == list(range(1, len(calls) + 1))


@pytest.fixture
def activation(operation, monkeypatch, tmp_path):
    upgrade.prepare('apt-intent', TX)
    journal = upgrade.Journal(operation.path)
    journal.value.update(target_version='2.0-1~deb13', previous_version='1.0-1~deb13')
    journal.write()
    manifest = {'python': '/accepted/python', 'python_sha256': 'a' * 64,
                'postgres_version': '18.test', 'clickhouse_version': '26.8.test',
                'migration_ledger': [1], 'roles': ['synthetic'], 'plugins': {'synthetic': 1}}
    old, new = tmp_path / 'old', tmp_path / 'new'
    for root in (old, new):
        root.mkdir()
    state = tmp_path / 'state'
    write(state / 'package-install.json', {'schema_version': 1, 'status': 'configured', 'release': 'old'})
    units = tmp_path / 'units'
    units.mkdir()
    (operation.recovery / 'units').mkdir()
    (operation.recovery / 'units/sli-api.service').write_text('accepted-unit')
    monkeypatch.setattr(upgrade, 'UNITS', units)
    monkeypatch.setattr(install, 'STATE', state)
    monkeypatch.setattr(install, 'inventory', lambda name: ((old if name == 'old' else new), dict(manifest), name + '-digest'))
    monkeypatch.setattr(upgrade, 'package_metadata', lambda root: {'version': '2.0-1~deb13' if root == new else '1.0-1~deb13'})
    monkeypatch.setattr(upgrade, 'verify_recovery', lambda name: (operation.recovery, {}))
    monkeypatch.setattr(runtime, 'release', lambda: (old, manifest, 'old-digest'))
    monkeypatch.setattr(runtime, 'configuration', lambda: {})
    monkeypatch.setattr(runtime, 'configure', lambda config: operation.events.append('units-configured'))
    monkeypatch.setattr(upgrade, 'configure_candidate', lambda *args: operation.events.append('units-configured'))
    monkeypatch.setattr(upgrade, 'restore_helpers', lambda *args: operation.events.append('helpers-restored'))
    monkeypatch.setattr(upgrade, 'retained_runtime', lambda path: runtime, raising=False)
    monkeypatch.setattr(upgrade, 'switch', lambda root, *args: operation.events.append('switch-' + root.name))
    monkeypatch.setattr(upgrade, 'testing_units', lambda tx=None: operation.events.append('testing-on' if tx else 'testing-off'))
    monkeypatch.setattr(upgrade, 'start_checked', lambda: operation.events.append('health'))
    monkeypatch.setattr(install, 'preserve_recovery', lambda *args: operation.events.append('save-recovery'))
    monkeypatch.setattr(install, 'command', lambda argv, **kwargs: operation.events.append(argv))
    operation.events.clear()
    return SimpleNamespace(journal=journal, old=old, new=new, manifest=manifest, operation=operation)


def test_apt_accepts_only_after_closed_candidate_health_and_durable_commit(activation):
    a = activation
    upgrade.configure_package('new', '2.0-1~deb13')
    value = upgrade.Journal(a.operation.path).value
    assert value['status'] == 'committed' and value['step'] == 'after'
    assert value['schema_changed'] is False and value['candidate_writes_possible'] is True
    events = a.operation.events
    assert events.index('testing-on') < events.index('health') < events.index('save-recovery')
    result = json.loads((a.operation.path / 'result.json').read_text())
    assert result['status'] == 'committed' and result['terminal'] is True
    assert json.loads((install.STATE / 'package-install.json').read_text())['release'] == 'new'


def test_blocked_apt_setup_has_reason_and_returns_old_services(activation, monkeypatch):
    import signal
    from deploy.linux import operation_wait
    a = activation
    monkeypatch.setattr(install, 'setup_watch', lambda: operation_wait.Watch(
        'migration_setup', minimum=0, stall=0.02, native=True))
    monkeypatch.setattr(upgrade, 'configure_candidate', lambda *args: signal.pause())
    with pytest.raises(operation_wait.OperationTimeout):
        upgrade.configure_package('new', '2.0-1~deb13')
    result = json.loads((a.operation.path / 'result.json').read_text())
    assert result['status'] == 'rolled_back' and result['terminal']
    assert result['reason_code'] in {'operation_stalled', 'operation_deadline_exceeded'}
    assert 'switch-old' in a.operation.events and 'health' in a.operation.events
    assert ['systemctl', 'enable', '--now', 'sli.target', 'sli-backup.timer'] in a.operation.events
    assert signal.getitimer(signal.ITIMER_REAL) == (0, 0)


@pytest.mark.parametrize('failure', ['candidate', 'inventory', 'recovery-save'])
def test_failed_apt_returns_error_restores_old_runtime_and_never_retries(activation, monkeypatch, failure):
    a = activation
    calls = []
    def health():
        calls.append('health')
        if len(calls) == 1 and failure == 'candidate':
            raise RuntimeError('synthetic-health-failure')
    monkeypatch.setattr(upgrade, 'start_checked', health)
    if failure == 'inventory':
        monkeypatch.setattr(upgrade, 'compatible', lambda *args: (_ for _ in ()).throw(RuntimeError('incompatible')))
    elif failure == 'recovery-save':
        monkeypatch.setattr(install, 'preserve_recovery', lambda *args: (_ for _ in ()).throw(RuntimeError('save-failed')))
    with pytest.raises(RuntimeError):
        upgrade.configure_package('new', '2.0-1~deb13')
    journal = upgrade.Journal(a.operation.path)
    assert journal.value['status'] == 'rolled_back'
    result = json.loads((a.operation.path / 'result.json').read_text())
    assert result['package_reconciliation_required'] is True
    assert 'switch-old' in a.operation.events
    assert 'helpers-restored' in a.operation.events
    before = list(a.operation.events)
    with pytest.raises(RuntimeError, match='reconciliation_required'):
        upgrade.configure_package('new', '2.0-1~deb13')
    assert before == a.operation.events


def test_recovered_failure_keeps_public_cause_in_terminal_result(activation, monkeypatch):
    calls = []

    def start():
        calls.append('start')
        if len(calls) == 1:
            raise RuntimeError('native_install_api_unready')

    monkeypatch.setattr(upgrade, 'start_checked', start)
    with pytest.raises(RuntimeError, match='native_install_api_unready'):
        upgrade.configure_package('new', '2.0-1~deb13')
    result = json.loads((activation.operation.path / 'result.json').read_text())
    assert result['status'] == 'rolled_back'
    assert result['reason_code'] == 'native_install_api_unready'
    assert result['message'] == 'The candidate API did not become ready.'


@pytest.mark.parametrize('error,code,message', [
    (RuntimeError('native_install_api_unready'), 'native_install_api_unready', 'The candidate API did not become ready.'),
    (RuntimeError('native_upgrade_reconciliation_required'), 'native_upgrade_reconciliation_required',
     'explicit package reconciliation is required'),
    (RuntimeError('native_upgrade_restore_databases_unready'), 'native_upgrade_restore_databases_unready',
     'database engines are still recovering or unavailable'),
    (RuntimeError('native_upgrade_package_recovery_failed'), 'native_upgrade_package_recovery_failed',
     'interrupted package state could not be finalized'),
    (RuntimeError('password=private-value'), 'native_upgrade_failed', 'inspect its transaction result'),
    (ValueError('password=private-value'), 'native_upgrade_failed', 'inspect its transaction result'),
])
def test_cli_failure_is_explained_without_private_exception_text(monkeypatch, capsys, error, code, message):
    monkeypatch.setattr(upgrade.os, 'geteuid', lambda: 0, raising=False)
    monkeypatch.setattr(upgrade, 'prepare_package', lambda *args: (_ for _ in ()).throw(error))
    assert upgrade.main(['prepare-package', '2.0-1~deb13']) == 1
    output = capsys.readouterr().err
    assert message in output and f'reason_code={code}' in output
    assert 'private-value' not in output and 'Traceback' not in output


def test_failure_after_committed_never_restores_checkpoint_or_old_code(activation, monkeypatch):
    calls = []
    def health():
        calls.append('health')
        if len(calls) == 2:
            raise RuntimeError('after-commit')
    monkeypatch.setattr(upgrade, 'start_checked', health)
    with pytest.raises(RuntimeError, match='after-commit'):
        upgrade.configure_package('new', '2.0-1~deb13')
    assert upgrade.Journal(activation.operation.path).value['status'] == 'committed'
    assert 'switch-old' not in activation.operation.events


@pytest.mark.parametrize('key', ['python', 'python_sha256', 'postgres_version', 'migration_ledger', 'roles', 'plugins'])
def test_compatible_downgrade_requires_exact_database_and_contract_inventory(activation, key):
    upgrade.compatible(activation.manifest, dict(activation.manifest))
    candidate = {**activation.manifest, key: 'changed'}
    with pytest.raises(RuntimeError, match='incompatible_inventory'):
        upgrade.compatible(activation.manifest, candidate)


def test_retired_clickhouse_version_does_not_block_compatible_package(activation):
    candidate = dict(activation.manifest)
    candidate.pop('clickhouse_version')
    upgrade.compatible(activation.manifest, candidate)


def test_recovery_failure_stays_fenced_and_reports_failure(activation, monkeypatch):
    monkeypatch.setattr(upgrade, 'start_checked', lambda: (_ for _ in ()).throw(RuntimeError('unhealthy')))
    with pytest.raises(RuntimeError):
        upgrade.configure_package('new', '2.0-1~deb13')
    result = json.loads((activation.operation.path / 'result.json').read_text())
    assert result['status'] == 'failed' and result['writers_fenced'] is True


def test_reconcile_is_explicit_exact_version_apt_outside_maintainer_script(activation, monkeypatch):
    import subprocess

    a = activation
    a.journal.value.update(status='rolled_back', step='after')
    a.journal.write()
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout='install ok installed\t1.0-1~deb13'))
    upgrade.reconcile('2.0-1~deb13')
    argv = a.operation.events[0]
    assert argv == ['apt-get', '-y', '--allow-downgrades', 'install', 'sli=1.0-1~deb13',
                    'sli-host=1.0-1~deb13', 'sli-rollback-hold=1.0-1~deb13']
    assert json.loads((a.operation.path / 'result.json').read_text())['package_reconciliation_required'] is False


@pytest.mark.parametrize('configure_exit', [0, 1])
def test_reconcile_finalizes_interrupted_dpkg_before_apt(activation, monkeypatch, configure_exit):
    import subprocess

    a = activation
    a.journal.value.update(status='rolled_back', step='after')
    a.journal.write()
    finalized = []

    def run(argv, **kwargs):
        if argv[0] == 'dpkg':
            assert argv == ['dpkg', '--configure', 'sli']
            finalized.append(True)
            return SimpleNamespace(returncode=configure_exit)
        return SimpleNamespace(stdout='install ok installed\t1.0-1~deb13')

    def command(argv, **kwargs):
        assert finalized, 'APT refuses an interrupted dpkg write journal'
        a.operation.events.append(argv)

    monkeypatch.setattr(subprocess, 'run', run)
    monkeypatch.setattr(install, 'command', command)
    upgrade.reconcile('2.0-1~deb13')
    assert json.loads((a.operation.path / 'result.json').read_text())['package_reconciliation_required'] is False
    assert len(list(a.operation.transactions.iterdir())) == 1


def test_reconcile_dpkg_fatal_error_never_runs_apt(activation, monkeypatch):
    import subprocess

    a = activation
    a.journal.value.update(status='rolled_back', step='after')
    a.journal.write()
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=2))
    with pytest.raises(RuntimeError, match='native_upgrade_package_recovery_failed'):
        upgrade.reconcile('2.0-1~deb13')
    assert not a.operation.events


def test_volatile_testing_overrides_are_scoped_and_removed(tmp_path, monkeypatch):
    monkeypatch.setattr(upgrade, 'VOLATILE_UNITS', tmp_path)
    monkeypatch.setattr(install, 'command', lambda *a, **k: None)
    upgrade.testing_units(TX)
    assert (tmp_path / 'sli-dotnet-api.service.d/90-sli-upgrade.conf').read_text().endswith('SLI_NATIVE_UPGRADE_TESTING=1\n')
    assert TX in (tmp_path / 'sli-ready.service.d/90-sli-upgrade.conf').read_text()
    upgrade.testing_units()
    assert not list(tmp_path.rglob('*.conf'))


def test_package_prepare_binds_version_to_new_verified_checkpoint(operation, monkeypatch):
    monkeypatch.setattr(runtime, 'release', lambda: (Path('/accepted/old'), {}, 'digest'))
    monkeypatch.setattr(upgrade, 'package_metadata', lambda root: {'version': '1.0-1~deb13'})
    upgrade.prepare_package('2.0-1~deb13')
    journal = upgrade.package_transaction('2.0-1~deb13')
    assert journal.value['previous_version'] == '1.0-1~deb13'
    assert journal.value['status'] == 'checkpoint_verified'
    upgrade.check_package('2.0-1~deb13')
    operation.events.clear()
    upgrade.prepare_package('2.0-1~deb13')
    assert operation.events == ['fence', 'verify']
    assert len(list(operation.transactions.iterdir())) == 1


@pytest.mark.parametrize('failure', ['fence', 'capture', 'verify'])
def test_package_kill_preserves_version_intent_and_public_resume(operation, monkeypatch, failure):
    monkeypatch.setattr(runtime, 'release', lambda: (Path('/accepted/old'), {}, 'digest'))
    monkeypatch.setattr(upgrade, 'package_metadata', lambda root: {'version': '1.0-1~deb13'})
    owner, attr = (upgrade, 'fence') if failure == 'fence' else (
        native, 'verify' if failure == 'verify' else 'capture_locked')
    original = getattr(owner, attr)

    def interrupted(*args, **kwargs):
        value = upgrade.package_transaction('2.0-1~deb13').value
        assert value['previous_version'] == '1.0-1~deb13'
        raise KeyboardInterrupt

    monkeypatch.setattr(owner, attr, interrupted)
    with pytest.raises(KeyboardInterrupt):
        upgrade.prepare_package('2.0-1~deb13')
    journal = upgrade.package_transaction('2.0-1~deb13')
    captured = len(operation.captured)
    with pytest.raises(RuntimeError, match='reconciliation_required'):
        upgrade.prepare_package('2.0-1~deb13')
    monkeypatch.setattr(owner, attr, original)
    assert upgrade.resume_package('2.0-1~deb13')['status'] == 'checkpoint_verified'
    assert upgrade.package_transaction('2.0-1~deb13').path == journal.path
    assert len(operation.captured) == (captured if failure == 'verify' else 1)
    upgrade.prepare_package('2.0-1~deb13')
    upgrade.check_package('2.0-1~deb13')
    assert len(list(operation.transactions.iterdir())) == 1


@pytest.mark.parametrize('field,value', [('previous_version', '9.0-1~deb13'), ('target_version', '9.0-1~deb13')])
def test_prepare_resume_rejects_changed_package_intent(operation, field, value):
    upgrade.prepare('new', TX, target_version='2.0-1~deb13', previous_version='1.0-1~deb13')
    journal = upgrade.Journal(operation.path)
    journal.value[field] = value
    journal.write()
    operation.events.clear()
    with pytest.raises(RuntimeError, match='intent_mismatch'):
        upgrade.prepare('new', TX, target_version='2.0-1~deb13', previous_version='1.0-1~deb13')
    assert not operation.events


@pytest.mark.parametrize('phase', ['failed'])
def test_public_package_resume_never_replays_migration_or_terminal_transaction(operation, monkeypatch, phase):
    monkeypatch.setattr(runtime, 'release', lambda: (Path('/accepted/old'), {}, 'digest'))
    monkeypatch.setattr(upgrade, 'package_metadata', lambda root: {'version': '1.0-1~deb13'})
    upgrade.prepare_package('2.0-1~deb13')
    journal = upgrade.package_transaction('2.0-1~deb13')
    journal.value.update(status=phase)
    journal.write()
    operation.events.clear()
    with pytest.raises(RuntimeError, match='reconciliation_required'):
        upgrade.resume_package('2.0-1~deb13')
    assert not operation.events


@pytest.mark.parametrize('phase', ['migrating', 'candidate_testing', 'committed', 'recovering'])
@pytest.mark.parametrize('step', ['before', 'after'])
def test_late_configure_resumes_same_transaction_without_replaying_sql(activation, monkeypatch, phase, step):
    a = activation
    a.journal.value.update(status=phase, step=step, candidate='new', schema_changed=True,
                           testing_release='old' if phase == 'recovering' and step == 'after' else 'new')
    a.journal.write()
    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda j: a.operation.events.append('restore'))
    upgrade.configure_package('new', '2.0-1~deb13')
    value = upgrade.Journal(a.operation.path).value
    rollback = phase == 'recovering' or (phase == 'migrating' and step == 'before')
    assert value['status'] == ('rolled_back' if rollback else 'committed')
    assert not any(isinstance(e, list) and 'migrate' in e for e in a.operation.events)
    assert ('restore' in a.operation.events) == (rollback and step == 'before')
    assert ('switch-old' in a.operation.events) == rollback
    assert len(list(a.operation.transactions.iterdir())) == 1


def test_interruption_before_schema_intent_still_restores_checkpoint(activation, monkeypatch):
    a = activation
    a.journal.value.update(status='migrating', step='before', candidate='new')
    a.journal.write()
    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda j: a.operation.events.append('restore'))
    upgrade.configure_package('new', '2.0-1~deb13')
    assert 'restore' in a.operation.events
    result = json.loads((a.operation.path / 'result.json').read_text())
    assert result['reason_code'] == 'native_upgrade_migration_interrupted'


def test_recovery_candidate_gate_resumes_rollback_instead_of_committing_candidate(activation, monkeypatch):
    a = activation
    a.journal.value.update(status='candidate_testing', step='before', candidate='new',
                           recovery_in_progress=True, testing_release='old', checkpoint_restored=True)
    a.journal.write()
    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda j: pytest.fail('already restored'))
    upgrade.configure_package('new', '2.0-1~deb13')
    assert upgrade.Journal(a.operation.path).value['status'] == 'rolled_back'
    assert 'switch-new' not in a.operation.events


@pytest.mark.parametrize('point', ['restore', 'switch-old', 'testing-on', 'health', 'testing-off'])
def test_recovery_can_be_interrupted_again_and_resumed(activation, monkeypatch, point):
    a = activation
    a.journal.value.update(status='recovering', step='before', candidate='new', schema_changed=True)
    a.journal.write()
    calls = []

    def action(name):
        calls.append(name)
        if name == point and calls.count(name) == 1:
            raise KeyboardInterrupt

    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda j: action('restore'))
    monkeypatch.setattr(upgrade, 'switch', lambda root, *args: action('switch-' + root.name))
    monkeypatch.setattr(upgrade, 'testing_units', lambda tx=None: action('testing-on' if tx else 'testing-off'))
    monkeypatch.setattr(upgrade, 'start_checked', lambda: action('health'))
    with pytest.raises(KeyboardInterrupt):
        upgrade.configure_package('new', '2.0-1~deb13')
    upgrade.configure_package('new', '2.0-1~deb13')
    assert upgrade.Journal(a.operation.path).value['status'] == 'rolled_back'
    assert calls.count('restore') == (2 if point == 'restore' else 1)


@pytest.mark.parametrize('phase', ['migrating', 'candidate_testing', 'committed'])
@pytest.mark.parametrize('step', ['before', 'after'])
def test_public_resume_after_each_durable_forward_write(activation, monkeypatch, phase, step):
    a = activation
    original = upgrade.Journal.write
    interrupted = []

    def write_and_interrupt(journal):
        original(journal)
        if journal.value['status'] == phase and journal.value['step'] == step and not interrupted:
            interrupted.append(True)
            raise KeyboardInterrupt

    monkeypatch.setattr(upgrade.Journal, 'write', write_and_interrupt)
    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda j: a.operation.events.append('restore'))
    monkeypatch.setattr(upgrade, 'reconcile', lambda version: a.operation.events.append('reconcile'))
    with pytest.raises(KeyboardInterrupt):
        upgrade.configure_package('new', '2.0-1~deb13')
    result = upgrade.resume_package('2.0-1~deb13')
    rollback = phase == 'migrating' and step == 'before'
    assert result['status'] == ('rolled_back' if rollback else 'committed')
    assert ('restore' in a.operation.events) == rollback
    assert ('reconcile' in a.operation.events) == rollback
    assert len(list(a.operation.transactions.iterdir())) == 1


@pytest.mark.parametrize('step', ['before', 'after'])
def test_public_resume_finishes_interrupted_rollback_terminal_intent(activation, monkeypatch, step):
    a = activation
    a.journal.value.update(status='rolled_back', step=step)
    a.journal.write()
    monkeypatch.setattr(upgrade, 'reconcile', lambda version: a.operation.events.append('reconcile'))
    assert upgrade.resume_package('2.0-1~deb13')['step'] == 'after'
    assert 'health' in a.operation.events
    assert a.operation.events[-1] == 'reconcile'


@pytest.mark.parametrize('point', ['switch-new', 'testing-off', 'receipt', 'health', 'enable'])
def test_public_resume_finishes_commit_after_each_interrupted_side_effect(activation, monkeypatch, point):
    a = activation
    a.journal.value.update(status='committed', step='after', candidate='new', accepted_release='new')
    a.journal.write()
    calls = []

    def action(name):
        calls.append(name)
        if name == point and calls.count(name) == 1:
            raise KeyboardInterrupt

    original = install.atomic

    def atomic(path, value):
        original(path, value)
        if path.name == 'package-install.json':
            action('receipt')

    monkeypatch.setattr(install, 'atomic', atomic)
    monkeypatch.setattr(upgrade, 'switch', lambda root, *args: action('switch-' + root.name))
    monkeypatch.setattr(upgrade, 'testing_units', lambda tx=None: action('testing-off'))
    monkeypatch.setattr(upgrade, 'start_checked', lambda: action('health'))
    monkeypatch.setattr(install, 'command', lambda *args, **kwargs: action('enable'))
    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda j: pytest.fail('committed restore'))
    with pytest.raises(KeyboardInterrupt):
        upgrade.resume_package('2.0-1~deb13')
    assert upgrade.resume_package('2.0-1~deb13')['status'] == 'committed'
    assert calls[-1] == 'enable'
    assert 'switch-old' not in calls
    assert len(list(a.operation.transactions.iterdir())) == 1


def test_failed_recovery_remains_nonterminal_and_publicly_retryable(activation, monkeypatch):
    a = activation
    a.journal.value.update(status='recovering', step='before', schema_changed=True)
    a.journal.write()
    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda j: (_ for _ in ()).throw(OSError('private data')))
    with pytest.raises(OSError):
        upgrade.resume_package('2.0-1~deb13')
    result = json.loads((a.operation.path / 'result.json').read_text())
    assert result['terminal'] is False
    assert result['reason_code'] == 'native_upgrade_recovery_pending'
    assert 'private data' not in json.dumps(result)
    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda j: a.operation.events.append('restore'))
    monkeypatch.setattr(upgrade, 'reconcile', lambda version: a.operation.events.append('reconcile'))
    assert upgrade.resume_package('2.0-1~deb13')['status'] == 'rolled_back'


def test_public_resume_cli_dispatches_to_retained_coordinator(monkeypatch):
    calls = []
    monkeypatch.setattr(upgrade.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(upgrade, 'launch', lambda *args, **kwargs: calls.append((args, kwargs)))
    assert upgrade.main(['launch', 'resume-package', '2.0-1~deb13']) == 0
    assert calls == [((None, None), {'action': 'resume-package', 'arguments': ['2.0-1~deb13']})]


def test_package_check_requires_matching_prepared_intent(activation):
    upgrade.check_package('2.0-1~deb13')
    activation.journal.value.update(status='rolled_back')
    activation.journal.write()
    with pytest.raises(RuntimeError, match='intent_required'):
        upgrade.check_package('2.0-1~deb13')
    with pytest.raises(RuntimeError, match='intent_required'):
        upgrade.check_package('3.0-1~deb13')


def test_same_version_package_prepare_does_not_fence(operation, monkeypatch):
    monkeypatch.setattr(runtime, 'release', lambda: (Path('/accepted/old'), {}, 'digest'))
    monkeypatch.setattr(upgrade, 'package_metadata', lambda root: {'version': '1.0-1~deb13'})
    upgrade.prepare_package('1.0-1~deb13')
    assert not operation.events and not operation.path.exists()


def test_reconcile_refuses_wrong_dpkg_state_and_never_claims_success(activation, monkeypatch):
    import subprocess

    activation.journal.value.update(status='rolled_back', step='after')
    activation.journal.write()
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=1, stdout='install ok half-configured\t1.0-1~deb13'))
    with pytest.raises(RuntimeError, match='package_mismatch'):
        upgrade.reconcile('2.0-1~deb13')
    assert json.loads((activation.operation.path / 'result.json').read_text())['terminal'] is False


def test_start_checked_uses_accepted_service_catalog_for_legacy_rollback(monkeypatch):
    config = {'profiles': ['light'], 'radius_pilot': False}
    calls = []
    accepted = SimpleNamespace(configuration=lambda: config, selected=lambda cfg: ('api',),
                               unit_name=lambda service: 'sli-api.service',
                               systemd=lambda service: {'ActiveState': 'active', 'MainPID': '42'})
    monkeypatch.setattr(runtime, 'selected', lambda cfg: (_ for _ in ()).throw(AssertionError('candidate services used')))
    monkeypatch.setattr(install, 'command', lambda argv, **kwargs: calls.append(argv))
    monkeypatch.setattr(install, 'wait_api', lambda config: None)
    monkeypatch.setattr(install, 'wait_health', lambda: None)
    monkeypatch.setattr(upgrade.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=1))
    upgrade.start_checked(accepted)
    assert calls == [['systemctl', 'start', 'sli-ready.service'], ['systemctl', 'start', 'sli-runtime.target']]


def test_start_checked_resets_only_selected_service_instances(monkeypatch):
    config = {'profiles': ['light'], 'radius_pilot': False}
    calls = []
    monkeypatch.setattr(runtime, 'configuration', lambda: config)
    monkeypatch.setattr(runtime, 'systemd', lambda service: {'ActiveState': 'active', 'MainPID': '42'})
    monkeypatch.setattr(install, 'command', lambda argv, **kwargs: calls.append(argv))
    monkeypatch.setattr(install, 'wait_api', lambda config: None)
    monkeypatch.setattr(install, 'wait_health', lambda: None)
    failed = {'value': True}
    monkeypatch.setattr(upgrade.subprocess, 'run',
                        lambda argv, **kwargs: SimpleNamespace(returncode=0 if failed['value'] else 1))
    upgrade.start_checked()
    assert calls[0][:2] == ['systemctl', 'reset-failed']
    assert 'sli-dotnet-executor-light.service' in calls[0]
    assert 'sli-dotnet-executor-heavy.service' not in calls[0]
    assert 'sli-dotnet-executor-long.service' not in calls[0]
    # Units unloaded after apt remove are not failed: nothing to reset.
    calls.clear()
    failed['value'] = False
    upgrade.start_checked()
    assert not any(argv[:2] == ['systemctl', 'reset-failed'] for argv in calls)


def test_same_release_configure_checks_package_version(activation, monkeypatch):
    calls = []
    monkeypatch.setattr(install, 'configure', lambda release: calls.append(release))
    upgrade.configure_package('old', '1.0-1~deb13')
    assert calls == ['old']
    with pytest.raises(RuntimeError, match='package_mismatch'):
        upgrade.configure_package('old', '9.0-1~deb13')
    assert calls == ['old']


def test_failed_cleanup_never_claims_writers_stopped(activation, monkeypatch):
    calls = []
    def fence():
        calls.append('fence')
        if len(calls) > 1:
            raise RuntimeError('cannot-prove-stop')
    monkeypatch.setattr(upgrade, 'fence', fence)
    monkeypatch.setattr(upgrade, 'start_checked', lambda: (_ for _ in ()).throw(RuntimeError('unhealthy')))
    with pytest.raises(RuntimeError, match='unhealthy'):
        upgrade.configure_package('new', '2.0-1~deb13')
    result = json.loads((activation.operation.path / 'result.json').read_text())
    assert result['status'] == 'failed' and result['writers_fenced'] is False
    value = upgrade.Journal(activation.operation.path).value
    assert value['status'] == 'candidate_testing' and value['recovery_in_progress'] is True


@pytest.mark.parametrize('legacy', [False, True])
def test_recovery_restores_helpers_independently_of_new_host_package(tmp_path, monkeypatch, legacy):
    saved = tmp_path / 'saved'
    helpers = saved / 'release/deploy/linux'
    helpers.mkdir(parents=True)
    installed = tmp_path / 'installed'
    installed.mkdir()
    monkeypatch.setattr(upgrade, 'RUNTIME_HELPER', installed / 'native_runtime.py')
    monkeypatch.setattr(install, 'trusted', lambda path: path.read_bytes())
    names = ('native_host.py', 'native_runtime.py', 'native_install.py', 'native_backup.py',
             'native_upgrade.py', 'native_clickhouse_endpoint.py', 'native_preinstall.py', 'native_pins.json', 'secrets-manifest.json', 'backup_policy.py', 'operation_wait.py')
    for name in names:
        if not (legacy and name in {'operation_wait.py', 'native_preinstall.py'}):
            (helpers / name).write_text('accepted-' + name)
        (installed / name).write_text('candidate-' + name)
    upgrade.restore_helpers(saved, legacy)
    for name in names:
        if legacy and name in {'operation_wait.py', 'native_preinstall.py', 'native_upgrade.py'}:
            assert (installed / name).read_text() == 'candidate-' + name
        else:
            assert (installed / name).read_text() == 'accepted-' + name


def test_candidate_units_use_candidate_code_and_pinned_runtime(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(install, 'trusted', lambda path: b'validated')
    monkeypatch.setattr(install, 'command', lambda argv, **kwargs: calls.append((argv, kwargs)))
    monkeypatch.setattr(runtime, 'configuration', lambda: {'schema_version': 1, 'profiles': ['light']})
    upgrade.configure_candidate(tmp_path, {'python': '/pinned/python'})
    argv, kwargs = calls[0]
    assert argv[:4] == ['/pinned/python', '-I', '-B', '-c']
    assert argv[-2] == str(tmp_path) and json.loads(argv[-1])['profiles'] == ['light']
    assert kwargs['cwd'] == tmp_path and 'PYTHONPATH' not in kwargs['env']


def migration_candidate(a):
    path = a.new / 'config/postgres_migrations/002_synthetic.sql'
    path.parent.mkdir(parents=True)
    path.write_text("DROP TABLE synthetic; INSERT INTO public.schema_migrations(version, name) VALUES (2, 'synthetic');")
    old = {'version': 1, 'name': '001_base.sql', 'sha256': 'a' * 64}
    new = {'version': 2, 'name': 'synthetic', 'sha256': upgrade.digest(path)}
    previous = {**a.manifest, 'migration_ledger': [old]}
    candidate = {**previous, 'migration_ledger': [old, new], 'checkpoint_upgrade_from': 'old-digest'}
    return previous, candidate


def test_unpinned_forward_migration_is_authorized_by_ledger_and_sql(activation):
    # Owner 02.11: packages never carried checkpoint_upgrade_from; the forward
    # ledger and exact SQL still decide.
    a = activation
    previous, candidate = migration_candidate(a)
    del candidate['checkpoint_upgrade_from']
    assert upgrade.migration_required(previous, candidate, 'old-digest', a.new) is True
    (a.new / 'config/postgres_migrations/002_synthetic.sql').unlink()
    with pytest.raises(RuntimeError):
        upgrade.migration_required(previous, candidate, 'old-digest', a.new)


@pytest.mark.parametrize('fault', ['binding', 'prefix', 'missing-sql', 'tamper', 'database-version'])
def test_destructive_migration_requires_bound_forward_sql(activation, fault):
    a = activation
    previous, candidate = migration_candidate(a)
    assert upgrade.migration_required(previous, candidate, 'old-digest', a.new) is True
    if fault == 'binding':
        candidate['checkpoint_upgrade_from'] = 'other-digest'
    elif fault == 'prefix':
        candidate['migration_ledger'] = candidate['migration_ledger'][1:]
    elif fault == 'missing-sql':
        (a.new / 'config/postgres_migrations/002_synthetic.sql').unlink()
    elif fault == 'tamper':
        (a.new / 'config/postgres_migrations/002_synthetic.sql').write_text('changed')
    else:
        candidate['postgres_version'] = '19.test'
    with pytest.raises((RuntimeError, ValueError)):
        upgrade.migration_required(previous, candidate, 'old-digest', a.new)


@pytest.mark.parametrize('fault', ['migrator', 'candidate-health', 'after-commit', None])
def test_migration_intent_precedes_sql_and_restore_depends_on_commit(activation, monkeypatch, fault):
    a = activation
    monkeypatch.setattr(upgrade, 'migration_required', lambda *args: True)
    def migrate(root):
        assert root == a.new
        value = upgrade.Journal(a.operation.path).value
        assert value['status'] == 'migrating' and value['step'] == 'before' and value['schema_changed'] is True
        a.operation.events.append('migrated')
        if fault == 'migrator':
            raise RuntimeError('synthetic-migration-fault')
    monkeypatch.setattr(native_pg_migrate, 'migrate', migrate)
    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda journal: a.operation.events.append('checkpoint-restored'))
    calls = []
    def health():
        calls.append(True)
        if len(calls) == (2 if fault == 'after-commit' else 1) and fault in {'candidate-health', 'after-commit'}:
            raise RuntimeError('synthetic-health-fault')
    monkeypatch.setattr(upgrade, 'start_checked', health)
    if fault:
        with pytest.raises(RuntimeError):
            upgrade.configure_package('new', '2.0-1~deb13')
    else:
        upgrade.configure_package('new', '2.0-1~deb13')
    value = upgrade.Journal(a.operation.path).value
    if fault in {'migrator', 'candidate-health'}:
        assert value['status'] == 'rolled_back'
        assert a.operation.events.index('checkpoint-restored') < a.operation.events.index('switch-old')
    else:
        assert value['status'] == 'committed' and 'checkpoint-restored' not in a.operation.events


@pytest.mark.parametrize('changed_status', ['committed', 'failed'])
def test_checkpoint_restore_cannot_rewind_committed_history(activation, changed_status):
    a = activation
    a.journal.value.update(status=changed_status, events=[{'phase': 'committed', 'step': 'before'}])
    a.journal.write()
    for action in (upgrade.restore_checkpoint, upgrade.recover_compatible):
        with pytest.raises(RuntimeError, match='committed_no_rollback'):
            action(a.journal)
    assert not a.operation.events


def test_file_metadata_excludes_journal_recovery_and_records_original_modes(tmp_path, monkeypatch):
    data = tmp_path / 'data'
    (data / 'state').mkdir(parents=True)
    (data / 'evidence').mkdir()
    (data / 'evidence/probe').write_bytes(b'synthetic')
    (data / 'evidence/probe').chmod(0o640)
    (data / 'state/installed.json').write_text('{}')
    (data / 'transactions').mkdir()
    (data / 'transactions/unreadable-link').symlink_to('/missing')
    monkeypatch.setattr(native, 'DATA', data)
    monkeypatch.setattr(native, 'STATE', data / 'state')
    result = upgrade.file_metadata()
    assert set(result) == {'files/evidence', 'files/evidence/probe', 'state/installed.json'}
    assert result['files/evidence/probe'][2] == 0o640


@pytest.fixture
def checkpoint_restore(activation, monkeypatch, tmp_path):
    from deploy.linux import restore_existing, update_checkpoint
    import pwd

    a = activation
    data_root = tmp_path / 'live'
    state = data_root / 'state'
    state.mkdir(parents=True)
    (state / 'installed.json').write_text('candidate-state')
    (data_root / 'evidence').mkdir()
    (data_root / 'evidence/probe').write_text('candidate')
    (data_root / 'candidate-only').write_text('discard')
    checkpoint = a.operation.captured[0]
    source = checkpoint / 'data/set'
    (source / 'files/evidence').mkdir(parents=True)
    (source / 'files/evidence/probe').write_text('accepted')
    companion = checkpoint / 'companion'
    (companion / 'state').mkdir(parents=True)
    (companion / 'state/installed.json').write_text('old-state')
    config = tmp_path / 'config'
    pg = tmp_path / 'postgresql'
    for name, destination in [('secrets', config / 'secrets'), ('clickhouse', config / 'clickhouse'), ('postgresql', pg)]:
        (companion / name).mkdir(parents=True)
        (companion / name / 'probe').write_text('old-config')
        destination.mkdir(parents=True)
        (destination / 'probe').write_text('candidate-config')
    monkeypatch.setattr(native, 'DATA', data_root)
    monkeypatch.setattr(native, 'STATE', state)
    monkeypatch.setattr(native, 'CONFIG', config)
    monkeypatch.setattr(upgrade, 'POSTGRES_CONFIG', pg)
    monkeypatch.setattr(pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=os.getuid()))
    def trusted(path):
        assert not path.is_relative_to(pg)  # Debian's PG config need not be root-owned.
        return path.read_bytes()
    monkeypatch.setattr(install, 'trusted', trusted)
    monkeypatch.setattr(install, 'trusted_path', lambda path: path)
    monkeypatch.setattr(upgrade, 'wait_restore_databases', lambda: None)
    monkeypatch.setattr(update_checkpoint, 'snapshot', lambda *args, **kwargs: nullcontext((checkpoint, None)))
    monkeypatch.setattr(native, 'verify', lambda *args: (
        {'consistency_point': {'writers_fenced': True}}, source,
        {'components': {'history': {'databases': ['accepted']}, 'warm': {'databases': ['accepted']}}}))
    class Target:
        def __init__(self, name):
            self.name = name
        def query(self, sql):
            a.operation.events.append((self.name, sql))
            return [{'name': name} for name in ['system', 'accepted', 'candidate-only']] if sql.startswith('SELECT') else []
    monkeypatch.setattr(backup, 'clickhouse_targets', lambda: [Target('history'), Target('warm')])
    monkeypatch.setattr(restore_existing, 'restore_components', lambda *args, **kwargs: a.operation.events.append(
        ('restore', args[3], kwargs)))
    write(a.operation.path / 'file-metadata.json', {})
    a.journal.value['file_metadata_sha256'] = upgrade.digest(a.operation.path / 'file-metadata.json')
    a.journal.value.update(status='recovering', step='before')
    a.journal.write()
    a.operation.events.clear()
    return a, data_root, config


def test_checkpoint_restores_postgres_files_and_protected_state(checkpoint_restore):
    a, data_root, config = checkpoint_restore
    upgrade.restore_checkpoint(a.journal)
    assert (data_root / 'evidence/probe').read_text() == 'accepted'
    assert not (data_root / 'candidate-only').exists()
    assert (data_root / 'state/installed.json').read_text() == 'old-state'
    assert (config / 'secrets/probe').read_text() == 'old-config'
    assert ('restore', ('postgres',), {'replace_existing': True}) in a.operation.events
    assert not any(isinstance(e, tuple) and 'DROP DATABASE' in str(e) for e in a.operation.events)
    assert a.journal.value['checkpoint_restored'] is True and a.operation.path.exists()


@pytest.mark.parametrize('failure', [False, True])
def test_integrity_checkpoint_restores_without_full_drill_receipt(checkpoint_restore, monkeypatch, failure):
    from deploy.linux import restore_existing

    a, data_root, config = checkpoint_restore
    root = upgrade.checkpoint_root(a.journal)
    write(root / 'integrity-verified.json', {'schema_version': 1, 'status': 'integrity_verified',
          'checkpoint_verification': 'integrity', 'terminal': True,
          'backup_id': a.journal.value['checkpoint'], 'manifest_sha256': a.journal.value['checkpoint_sha256']})
    a.journal.value['checkpoint_verification'] = 'integrity'
    a.journal.write()
    (root / 'restore-verified.json').unlink(missing_ok=True)
    if failure:
        def refuse(*args, **kwargs):
            raise RuntimeError('injected restore failure')
        monkeypatch.setattr(restore_existing, 'restore_components', refuse)
        with pytest.raises(RuntimeError, match='injected restore failure'):
            upgrade.restore_checkpoint(a.journal)
        assert not a.journal.value.get('checkpoint_restored')
        assert not a.journal.value.get('services_restored')
    else:
        upgrade.restore_checkpoint(a.journal)
        assert (data_root / 'evidence/probe').read_text() == 'accepted'
        assert (config / 'secrets/probe').read_text() == 'old-config'
        assert a.journal.value['checkpoint_restored'] is True


def test_checkpoint_file_stages_report_ongoing_progress(checkpoint_restore, monkeypatch):
    from deploy.linux import operation_wait

    a, data_root, _ = checkpoint_restore
    checkpoint = a.operation.captured[0]
    for name in ('one', 'two', 'evidence/three'):
        (checkpoint / 'data/set/files' / name).write_bytes(b'x' * (2 * 1024**2 + 1))
    for name in ('old-one', 'old-two', 'evidence/old-three'):
        (data_root / name).write_bytes(b'old')
    (checkpoint / 'companion/state/extra').mkdir()
    (checkpoint / 'companion/state/extra/receipt').write_text('old-state')
    (data_root / 'state/obsolete').mkdir()
    (data_root / 'state/obsolete/receipt').write_text('candidate')
    phase, progress = ['other'], {}
    monkeypatch.setattr(operation_wait, 'made_progress', lambda: progress.setdefault(phase[0], []).append(True))

    def tracked(name, function):
        def run(*args, **kwargs):
            previous, phase[0] = phase[0], name
            try:
                return function(*args, **kwargs)
            finally:
                phase[0] = previous
        return run

    for module, name in ((operation_wait, 'copy_file'), (operation_wait, 'remove_tree'),
                         (backup, 'content_inventory'), (upgrade, 'digest'), (upgrade, 'sync_tree')):
        monkeypatch.setattr(module, name, tracked(name, getattr(module, name)))
    upgrade.restore_checkpoint(a.journal)
    for name in ('copy_file', 'remove_tree', 'content_inventory', 'digest', 'sync_tree'):
        assert len(progress.get(name, [])) > 1, name
    assert (data_root / 'one').read_bytes() == b'x' * (2 * 1024**2 + 1)


@pytest.mark.parametrize('fault', ['metadata', 'checkpoint', 'receipt'])
def test_checkpoint_tamper_refused_before_database_restore(checkpoint_restore, fault):
    a, data_root, _ = checkpoint_restore
    if fault == 'metadata':
        (a.operation.path / 'file-metadata.json').write_text('tampered')
    elif fault == 'checkpoint':
        (a.operation.captured[0] / 'manifest.json').write_text('tampered')
    else:
        write(a.operation.captured[0].parent / 'integrity-verified.json', {})
    with pytest.raises(RuntimeError):
        upgrade.restore_checkpoint(a.journal)
    assert (data_root / 'evidence/probe').read_text() == 'candidate'
    assert not any(isinstance(e, tuple) and e[0] == 'restore' for e in a.operation.events)


def test_restore_refuses_writable_postgres_configuration(checkpoint_restore):
    a, _, _ = checkpoint_restore
    (upgrade.POSTGRES_CONFIG / 'probe').chmod(0o666)
    with pytest.raises(RuntimeError, match='postgres_configuration_untrusted'):
        upgrade.restore_checkpoint(a.journal)
    assert not any(isinstance(e, tuple) and e[0] == 'restore' for e in a.operation.events)


@pytest.mark.parametrize('phase', ['rolled_back', 'failed', 'checkpoint_verified'])
def test_old_checkpoint_requires_active_recovery_intent(checkpoint_restore, phase):
    a, data_root, _ = checkpoint_restore
    a.journal.value.update(status=phase, step='after')
    with pytest.raises(RuntimeError, match='recovery_intent_required'):
        upgrade.restore_checkpoint(a.journal)
    assert not a.operation.events and (data_root / 'evidence/probe').read_text() == 'candidate'


def test_failed_destructive_restore_never_starts_old_runtime(activation, monkeypatch):
    a = activation
    monkeypatch.setattr(upgrade, 'migration_required', lambda *args: True)
    def migrate(root):
        raise RuntimeError('partial-migration')
    monkeypatch.setattr(native_pg_migrate, 'migrate', migrate)
    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda *args: (_ for _ in ()).throw(RuntimeError('restore-fault')))
    with pytest.raises(RuntimeError, match='partial-migration'):
        upgrade.configure_package('new', '2.0-1~deb13')
    result = json.loads((a.operation.path / 'result.json').read_text())
    assert result['status'] == 'failed' and result['writers_fenced'] is True
    assert 'switch-old' not in a.operation.events and 'health' not in a.operation.events


def test_restore_readiness_uses_postgres_without_application_schema(monkeypatch):
    queries = []
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext('passfile'))
    connection = SimpleNamespace(execute=lambda sql: (queries.append(sql) or SimpleNamespace(fetchone=lambda: (1,))))
    def connect(passfile, database):
        assert passfile == 'passfile' and database == 'postgres'
        return nullcontext(connection)
    monkeypatch.setattr(backup, 'pg_connect', connect)
    monkeypatch.setattr(backup, 'clickhouse_targets', lambda: pytest.fail('must not probe retired engines'))
    upgrade.wait_restore_databases()
    assert queries == ['SELECT 1']


@pytest.mark.parametrize('replace_existing', [False, True])
def test_checkpoint_postgres_restore_resumes_after_database_drop(tmp_path, monkeypatch, replace_existing):
    from deploy.linux import restore_existing as restore

    (tmp_path / 'postgres').mkdir()
    (tmp_path / 'postgres/toc.dat').write_bytes(b'fixture')
    (tmp_path / 'roles.sql').write_text('fixture roles')
    state = {'exists': False}
    commands = []

    def execute(sql):
        commands.append(sql)
        if 'FROM pg_database' in sql:
            return SimpleNamespace(fetchone=lambda: (1,) if state['exists'] else None)
        if sql.startswith('CREATE DATABASE sli'):
            state['exists'] = True
        return SimpleNamespace(fetchone=lambda: (283,) if 'max(version)' in sql else (False,))

    connection = SimpleNamespace(execute=execute)

    def connect(passfile, database='sli', **kwargs):
        if database == 'sli' and not state['exists']:
            raise RuntimeError('fixture_database_missing')
        return nullcontext(connection)

    monkeypatch.setattr(backup, 'pg_connect', connect)
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(Path('/fixture/passfile')))
    monkeypatch.setattr(backup, 'postgres_target', lambda: SimpleNamespace(arguments=lambda: []))
    monkeypatch.setattr(backup, 'pg_tool', lambda *args, watch: commands.append('pg_restore'))
    monkeypatch.setattr(backup, 'row_counts', lambda conn: {'probe': 32})
    monkeypatch.setattr(restore, 'analyze_postgres', lambda *args: None)

    def roles(*args):
        # The real role renderer invokes psql against sli before replacement.
        with connect(Path('/fixture/passfile')):
            commands.append('roles-staged')

    monkeypatch.setattr(restore, 'restore_roles', roles)
    manifest = {'components': {'postgres': {'row_counts': {'probe': 32}}}, 'migration_ledger_max_version': 283}
    if replace_existing:
        restore.restore_postgres(tmp_path, manifest, replace_existing=True)
        assert state['exists'] and 'pg_restore' in commands
        assert commands.index('roles-staged') < commands.index('DROP DATABASE IF EXISTS sli WITH (FORCE)')
    else:
        with pytest.raises(RuntimeError, match='fixture_database_missing'):
            restore.restore_postgres(tmp_path, manifest, replace_existing=False)
        assert not state['exists'] and not commands
