"""Disposable filesystem lifecycle; no real services, containers or databases."""
from contextlib import contextmanager, nullcontext
import json
from pathlib import Path

import pytest

from deploy.linux import native_backup as native, native_runtime as runtime
from deploy.linux import native_upgrade as upgrade, native_install as install, restore_existing, backup_policy, backup, native_host
from tests.unit.test_linux_native_backup_admission import drill_storage  # noqa: F401
from tests.unit.test_linux_native_upgrade_prepare import preparation, TX  # noqa: F401


@pytest.fixture
def cleanup_host(tmp_path, monkeypatch):
    for name in ('drills', 'transactions', 'cgroups', 'proc', 'backups'):
        (tmp_path / name).mkdir()
    monkeypatch.setattr(native, 'DRILLS', tmp_path / 'drills')
    monkeypatch.setattr(native, 'ROOT', tmp_path / 'backups')
    monkeypatch.setattr(native, 'CGROUP_ROOT', tmp_path / 'cgroups')
    monkeypatch.setattr(native, 'PROC_ROOT', tmp_path / 'proc', raising=False)
    monkeypatch.setattr(runtime, 'TRANSACTIONS', tmp_path / 'transactions')
    monkeypatch.setattr(upgrade, 'TRANSACTIONS', tmp_path / 'transactions')
    monkeypatch.setattr(install, 'trusted', lambda path: path.read_bytes())
    monkeypatch.setattr(install, 'atomic', lambda path, value: path.write_text(json.dumps(value)))
    monkeypatch.setattr(native.shutil, 'which', lambda name: None)
    monkeypatch.setattr(native, 'command', lambda *a, **k: b'')
    return tmp_path


@pytest.mark.parametrize('stopped', [True, False])
def test_failed_drill_removes_work_only_after_confirmed_stop(drill_storage, monkeypatch, stopped):
    monkeypatch.setattr(native, 'capture_volume_admission', lambda *a, **k: {'status': 'admitted'})
    monkeypatch.setattr(backup_policy, 'filesystem', lambda path: 'synthetic')
    @contextmanager
    def databases(work, *, cleanup=None):
        (work / 'database').write_bytes(b'keep until stopped')
        try:
            yield {}
        finally:
            if cleanup is not None:
                cleanup['databases_stopped'] = stopped

    def fail(*a, **k):
        raise RuntimeError('native_drill_restore_failed')

    monkeypatch.setattr(native, 'isolated_databases', databases)
    monkeypatch.setattr(restore_existing, 'restore_components', fail)
    with pytest.raises(RuntimeError, match='native_drill_restore_failed'):
        native.drill_locked(drill_storage.selected, drill_storage.root, upgrade_checkpoint=True)
    result = json.loads((drill_storage.root / 'drill-result.json').read_text())
    assert result['status'] == 'failed' and result['terminal'] is True
    assert bool(list(drill_storage.drills.iterdir())) is not stopped
    assert result['databases_stopped'] is stopped
    if not stopped:
        assert result['cleanup_reason_code'] == 'native_drill_cleanup_unconfirmed'
    assert not (drill_storage.root / 'restore-verified.json').exists()


def abandoned():
    work = native.DRILLS / ('a' * 16)
    work.mkdir()
    (work / 'payload').write_bytes(b'abandoned')
    return work


def test_stale_drill_cleanup_is_scoped_and_reports_bytes(cleanup_host, capsys):
    work = abandoned()
    info = (work / 'payload').stat()
    allocated = info.st_blocks * 512 if hasattr(info, 'st_blocks') else 9
    foreign = native.DRILLS / 'manual-copy'
    foreign.mkdir()
    outside = cleanup_host / ('b' * 16)
    outside.mkdir()
    result = native.cleanup_drills()
    assert not work.exists() and foreign.exists() and outside.exists()
    assert result == {'removed_directories': 1, 'freed_bytes': allocated}
    diagnostic = capsys.readouterr()
    assert f'freed_bytes={allocated}' in diagnostic.out
    assert 'manual-copy' in diagnostic.err and 'native_drill_cleanup_unrecognized_directory' in diagnostic.err


@pytest.mark.parametrize('live', ['unit', 'cgroup', 'process', 'container', 'restarting_container', 'unknown'])
def test_stale_drill_keeps_live_or_uninspectable_work(cleanup_host, monkeypatch, capsys, live):
    work = abandoned()
    prefix = 'sli-drill-' + work.name + '-'
    def command(argv, **kwargs):
        if live == 'unknown':
            raise RuntimeError('inspection_failed')
        if argv[0] == 'systemctl':
            if argv[1] == 'list-units':
                return (prefix + 'pg.service loaded active running\n').encode() if live == 'unit' else b''
            assert argv[1] == 'show'  # Garbage collection must never stop a live unit.
            return b'ActiveState=active\nMainPID=42\nControlGroup=\n'
        state = {'Running': live != 'restarting_container', 'Pid': 0 if live == 'restarting_container' else 42,
                 'Restarting': live == 'restarting_container'}
        return json.dumps([{'State': state}]).encode() if 'inspect' in argv else (prefix + 'history\n').encode()
    monkeypatch.setattr(native, 'command', command)
    if live == 'cgroup':
        child = native.CGROUP_ROOT / 'system.slice' / (prefix + 'pg.service') / 'child'
        child.mkdir(parents=True)
        (child / 'cgroup.procs').write_text('42\n')
    elif live == 'process':
        process = native.PROC_ROOT / '42'
        process.mkdir()
        (process / 'cmdline').write_bytes(b'postgres\0-D\0' + str(work).encode() + b'/pg/data\0')
        (process / 'cgroup').write_text('')
    elif live in {'container', 'restarting_container'}:
        (work / 'history').mkdir()
        monkeypatch.setattr(native.shutil, 'which', lambda name: '/usr/bin/docker')
    native.cleanup_drills()
    assert (work / 'payload').read_bytes() == b'abandoned'
    code = {'unit': 'unit_active', 'cgroup': 'cgroup_active', 'process': 'process_active',
            'container': 'container_active', 'restarting_container': 'container_active',
            'unknown': 'inspection_unavailable'}[live]
    diagnostic = capsys.readouterr().err
    assert work.name in diagnostic and 'native_drill_cleanup_' + code in diagnostic


def journal(identifier, status, *, restored=True, accepted=None, step='after'):
    path = upgrade.TRANSACTIONS / identifier
    path.mkdir()
    value = {'schema_version': 1, 'transaction': identifier, 'status': status, 'step': step,
             'checkpoint_storage': 'backup_volume', 'services_restored': restored}
    if accepted:
        value.update(accepted_release='accepted', events=[{'phase': 'committed', 'step': 'after', 'utc': accepted}])
    (path / 'journal.json').write_text(json.dumps(value))
    (path / 'result.json').write_text(json.dumps({'status': status, 'terminal': True, 'services_restored': restored}))
    checkpoint = native.ROOT / 'upgrade-checkpoints' / identifier
    checkpoint.mkdir(parents=True)
    (checkpoint / 'data').write_bytes(b'recovery')
    return checkpoint


@pytest.mark.parametrize('status', ['preflight', 'checkpoint_verified', 'recovering', 'failed',
                                  'rolled_back', 'aborted_before_checkpoint'])
def test_checkpoint_cleanup_preserves_unfinished_or_unrestored(cleanup_host, status):
    checkpoint = journal('a' * 32, status, restored=False)
    upgrade.cleanup_checkpoints()
    assert (checkpoint / 'data').read_bytes() == b'recovery'


def test_checkpoint_cleanup_keeps_only_latest_accepted_success(cleanup_host):
    old = journal('a' * 32, 'committed', accepted='2026-10-30T00:00:00+00:00')
    latest = journal('b' * 32, 'committed', accepted='2026-10-31T00:00:00+00:00')
    rollback = journal('c' * 32, 'rolled_back')
    abort = journal('d' * 32, 'aborted_before_checkpoint')
    pending = journal('e' * 32, 'checkpoint_verified')
    upgrade.cleanup_checkpoints()
    assert latest.exists() and pending.exists()
    assert not any(path.exists() for path in (old, rollback, abort))
    upgrade.cleanup_checkpoints()  # Restart/idempotence.
    assert latest.exists()


def test_committed_without_restored_services_keeps_its_checkpoint(cleanup_host):
    pending = journal('a' * 32, 'committed', restored=False, accepted='2026-10-30T00:00:00+00:00')
    journal('b' * 32, 'committed', accepted='2026-10-31T00:00:00+00:00')
    upgrade.cleanup_checkpoints()
    assert (pending / 'data').read_bytes() == b'recovery'


@pytest.mark.parametrize('entry', ['unknown_directory', 'renamed_journal', 'unknown_file',
                                  'invalid_json', 'missing_journal', 'wrong_identity', 'invalid_result'])
def test_uncertain_transaction_entry_blocks_all_checkpoint_cleanup(cleanup_host, monkeypatch, capsys, entry):
    old = journal('a' * 32, 'committed', accepted='2026-10-30T00:00:00+00:00')
    latest = journal('b' * 32, 'committed', accepted='2026-10-31T00:00:00+00:00')
    rollback = journal('c' * 32, 'rolled_back')
    pending = journal('d' * 32, 'checkpoint_verified', restored=False)
    checkpoints = [old, latest, rollback, pending]
    unexpected = upgrade.TRANSACTIONS / 'manual-copy'
    if entry == 'unknown_file':
        unexpected.write_text('unrecognized transaction entry')
    elif entry == 'unknown_directory':
        unexpected.mkdir()
    else:
        checkpoints.append(journal('e' * 32, 'committed', accepted='2026-11-01T00:00:00+00:00'))
        path = upgrade.TRANSACTIONS / ('e' * 32)
        if entry == 'renamed_journal':
            path.rename(unexpected)
        elif entry == 'invalid_json':
            (path / 'journal.json').write_text('{')
        elif entry == 'missing_journal':
            (path / 'journal.json').unlink()
        elif entry == 'wrong_identity':
            value = json.loads((path / 'journal.json').read_text())
            value['transaction'] = 'f' * 32
            (path / 'journal.json').write_text(json.dumps(value))
        else:
            (path / 'result.json').write_text('{')
    # Inspect the uncertain entry last, after finding collectible checkpoints.
    # Collection must wait for the complete inventory, regardless of directory order.
    original = Path.iterdir
    monkeypatch.setattr(Path, 'iterdir', lambda path: iter(sorted(original(path), key=lambda item: item.name))
                        if path == upgrade.TRANSACTIONS else original(path))
    upgrade.cleanup_checkpoints()
    assert all((checkpoint / 'data').read_bytes() == b'recovery' for checkpoint in checkpoints)
    diagnostic = capsys.readouterr().err
    assert 'native_upgrade_checkpoint_cleanup_unconfirmed' in diagnostic
    if entry.startswith('unknown') or entry == 'renamed_journal':
        assert 'native_upgrade_checkpoint_storage_unexpected' in diagnostic and 'manual-copy' in diagnostic


def test_active_transaction_protects_legacy_drill_without_owner(cleanup_host):
    work = abandoned()
    journal('a' * 32, 'checkpoint_verified')
    native.cleanup_drills()
    assert work.exists()


def test_pending_transaction_reports_each_retained_drill(cleanup_host, capsys):
    first = abandoned()
    second = native.DRILLS / ('b' * 16)
    second.mkdir()
    journal('a' * 32, 'checkpoint_verified')
    native.cleanup_drills()
    diagnostics = [json.loads(line.split(' ', 1)[1]) for line in capsys.readouterr().err.splitlines()
                   if line.startswith('native_drill_cleanup_retained ')]
    assert {row['directory'] for row in diagnostics} == {first.name, second.name}
    assert all(row['reason_code'] == 'native_drill_cleanup_transaction_pending' for row in diagnostics)
    assert first.exists() and second.exists()


def test_stale_drill_cleanup_refuses_link(cleanup_host, monkeypatch, capsys):
    work = abandoned()
    original = Path.is_symlink
    monkeypatch.setattr(Path, 'is_symlink', lambda path: path == work or original(path))
    native.cleanup_drills()
    assert (work / 'payload').read_bytes() == b'abandoned'
    diagnostic = capsys.readouterr().err
    assert work.name in diagnostic and 'native_drill_cleanup_untrusted_directory' in diagnostic


def test_checkpoint_cleanup_refuses_redirected_storage(cleanup_host, monkeypatch):
    checkpoint = journal('a' * 32, 'rolled_back')
    outside = cleanup_host / 'outside'
    outside.mkdir()
    (outside / 'data').write_bytes(b'foreign')
    original = Path.resolve
    monkeypatch.setattr(Path, 'resolve', lambda path, *a, **k:
                        outside if path == checkpoint else original(path, *a, **k))
    upgrade.cleanup_checkpoints()
    assert (checkpoint / 'data').read_bytes() == b'recovery'
    assert (outside / 'data').read_bytes() == b'foreign'


def test_checkpoint_cleanup_supports_legacy_transaction_storage(cleanup_host):
    source = journal('a' * 32, 'rolled_back')
    path = upgrade.TRANSACTIONS / ('a' * 32)
    value = json.loads((path / 'journal.json').read_text())
    value.pop('checkpoint_storage')
    (path / 'journal.json').write_text(json.dumps(value))
    source.rename(path / 'checkpoints')
    upgrade.cleanup_checkpoints()
    assert path.is_dir() and not (path / 'checkpoints').exists()


def test_drill_name_collision_never_removes_preexisting_work(drill_storage, monkeypatch):
    work = drill_storage.drills / ('a' * 16)
    work.mkdir(parents=True)
    (work / 'data').write_bytes(b'preexisting')
    monkeypatch.setattr(native.secrets, 'token_hex', lambda count: 'a' * 16)
    monkeypatch.setattr(native, 'cleanup_drills', lambda: None)
    monkeypatch.setattr(native, 'capture_volume_admission', lambda *a, **k: {'status': 'admitted'})
    monkeypatch.setattr(backup_policy, 'filesystem', lambda path: 'synthetic')
    with pytest.raises(FileExistsError):
        native.drill_locked(drill_storage.selected, drill_storage.root, upgrade_checkpoint=True)
    assert (work / 'data').read_bytes() == b'preexisting'


@pytest.mark.parametrize('restart_fails', [False, True])
def test_aborted_prepare_cleans_checkpoint_only_after_services_return(preparation, monkeypatch, restart_fails):
    def fail(*a, **k):
        raise RuntimeError('injected')
    monkeypatch.setattr(native, 'verify', fail)
    if restart_fails:
        monkeypatch.setattr(upgrade, 'start_checked', fail)
    with pytest.raises(RuntimeError):
        upgrade.prepare('new', TX)
    checkpoint = native.ROOT / 'upgrade-checkpoints' / TX
    assert checkpoint.exists() is restart_fails


@pytest.mark.parametrize('operation', ['capture', 'drill', 'prepare'])
def test_operation_collects_abandoned_drill_before_admission(cleanup_host, monkeypatch, operation):
    work = abandoned()
    def fail(*a, **k):
        raise RuntimeError('admission_failed')
    monkeypatch.setattr(backup, 'backup_lock', lambda root: nullcontext())
    if operation == 'capture':
        monkeypatch.setattr(native_host, 'administrative_lock', nullcontext)
        monkeypatch.setattr(native_host.Host, 'receipt', fail)
        action = native.capture
    elif operation == 'prepare':
        monkeypatch.setattr(upgrade, 'systemd_available', lambda: False)
        monkeypatch.setattr(upgrade, 'operation_lock', lambda root: nullcontext())
        monkeypatch.setattr(upgrade, 'preflight', fail)
        action = lambda: upgrade.prepare('new', TX)
    else:
        action = native.drill
    expected = 'native_drill_no_backup' if operation == 'drill' else 'admission_failed'
    with pytest.raises(RuntimeError, match=expected):
        action()
    assert not work.exists()


@pytest.mark.parametrize('status', ['committed', 'rolled_back'])
@pytest.mark.parametrize('restart_fails', [False, True])
def test_terminal_cleanup_follows_service_acceptance(cleanup_host, monkeypatch, status, restart_fails):
    old = journal('a' * 32, 'committed', accepted='2026-10-30T00:00:00+00:00')
    current = journal('b' * 32, status, restored=False,
                      accepted='2026-10-31T00:00:00+00:00' if status == 'committed' else None)
    item = upgrade.Journal(upgrade.TRANSACTIONS / ('b' * 32))
    item.value.update(previous='old', target_version='2.0-1~deb13')
    monkeypatch.setattr(upgrade, 'switch', lambda *a: None)
    monkeypatch.setattr(upgrade, 'testing_units', lambda *a: None)
    monkeypatch.setattr(upgrade, 'package_metadata', lambda root: {'version': '2.0-1~deb13'})
    monkeypatch.setattr(install, 'STATE', cleanup_host / 'state')
    install.STATE.mkdir()
    (install.STATE / 'package-install.json').write_text('{}')
    def start():
        assert old.exists() and current.exists()
        if restart_fails:
            raise RuntimeError('restart_failed')
    monkeypatch.setattr(upgrade, 'start_checked', start)
    monkeypatch.setattr(install, 'command', lambda *a, **k: None)
    monkeypatch.setattr(install, 'backup_schedule', lambda: 'disabled')
    def action():
        if status == 'committed':
            upgrade.finish_committed(item, (Path('/accepted/new'), {}, 'digest'))
        else:
            upgrade.finish_rollback(item)
    if restart_fails:
        with pytest.raises(RuntimeError, match='restart_failed'):
            action()
        assert old.exists() and current.exists()
    else:
        action()
        assert current.exists() is (status == 'committed')
        assert old.exists() is (status == 'rolled_back')


def test_postgres_drill_cleanup_needs_no_docker(cleanup_host, monkeypatch):
    work = abandoned()
    monkeypatch.setattr(native.shutil, 'which', lambda name: '/usr/bin/docker')

    def command(argv, **kwargs):
        assert not any('docker' in value for value in argv)
        return b''

    monkeypatch.setattr(native, 'command', command)
    native.cleanup_drills()
    assert not work.exists()
