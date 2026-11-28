"""Portable prepare failure tests; fake POSIX persistence, DBs and systemd only."""
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

from deploy.linux import backup, native_backup as native, native_install as install
from deploy.linux import native_package, native_preinstall as preinstall, native_runtime as runtime, native_upgrade as upgrade
from deploy.linux import native_pg_migrate, operation_wait

VERSION = '2.0-1~deb13'
TX = 'a' * 32
READ_BACKUP_SCHEDULE = install.backup_schedule
START_CHECKED = upgrade.start_checked
FENCE = upgrade.fence
STOP_APPLICATION = upgrade.stop_application


def make_integrity_receipt(journal):
    root = upgrade.checkpoint_root(journal)
    receipt = {'schema_version': 1, 'status': 'integrity_verified', 'terminal': True,
               'checkpoint_verification': 'integrity', 'backup_id': journal.value['checkpoint'],
               'manifest_sha256': journal.value['checkpoint_sha256']}
    path = root / 'integrity-verified.json'
    path.write_text(json.dumps(receipt))
    journal.value['checkpoint_verification'] = 'integrity'
    journal.write()
    return path, receipt


def test_new_prepare_verifies_integrity_without_drill(preparation, monkeypatch):
    monkeypatch.setattr(native, 'drill_locked', lambda *a, **k: pytest.fail('unexpected full restore'))
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    assert journal.value['checkpoint_verification'] == 'integrity'
    root = upgrade.checkpoint_root(journal)
    receipt = json.loads((root / 'integrity-verified.json').read_text())
    assert receipt['status'] == 'integrity_verified' and receipt['terminal'] is True
    assert receipt['checkpoint_verification'] == 'integrity'
    assert receipt['backup_id'] == journal.value['checkpoint']
    assert receipt['manifest_sha256'] == journal.value['checkpoint_sha256']
    assert 'databases_stopped' not in receipt and not (root / 'restore-verified.json').exists()
    result = json.loads((journal.path / 'result.json').read_text())
    assert result['checkpoint_verification'] == 'integrity'


def test_integrity_prepare_resume_keeps_mode_and_checkpoint(preparation, monkeypatch):
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    original = journal.value['checkpoint']
    assert journal.value['checkpoint_verification'] == 'integrity'
    monkeypatch.setattr(native, 'drill_locked', lambda *a, **k: pytest.fail('resume added a full restore'))
    assert upgrade.resume_package(VERSION)['checkpoint'] == original
    assert preparation.events.count('capture') == 1


@pytest.mark.parametrize('failed', [False, True])
def test_legacy_checkpoint_mode_keeps_full_restore_on_resume(preparation, monkeypatch, failed):
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    journal.value.pop('checkpoint_verification', None)
    journal.value.update(status='fenced', step='after')
    journal.write()
    root = upgrade.checkpoint_root(journal)
    (root / 'restore-verified.json').unlink(missing_ok=True)
    original = native.drill_locked
    calls = []
    def drill(*args, **kwargs):
        calls.append(True)
        if failed:
            raise RuntimeError('native_upgrade_checkpoint_unverified')
        return original(*args, **kwargs)
    monkeypatch.setattr(native, 'drill_locked', drill)
    if failed:
        with pytest.raises(RuntimeError, match='native_upgrade_checkpoint_unverified'):
            upgrade.resume_package(VERSION)
        journal = upgrade.package_transaction(VERSION)
        assert journal.value['status'] == 'aborted_before_checkpoint'
        assert journal.value['services_restored'] is True
        assert not (root / 'restore-verified.json').exists()
    else:
        assert upgrade.resume_package(VERSION)['status'] == 'checkpoint_verified'
        assert json.loads((root / 'restore-verified.json').read_text())['databases_stopped'] is True
    assert calls == [True] and preparation.events.count('capture') == 1


def test_legacy_checkpoint_mode_requires_stopped_restore(preparation):
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    root = upgrade.checkpoint_root(journal)
    checkpoint = root / journal.value['checkpoint']
    native.drill_locked(checkpoint, root, prune_sets=False, upgrade_checkpoint=True)
    journal.value.pop('checkpoint_verification')
    journal.write()
    path = root / 'restore-verified.json'
    receipt = json.loads(path.read_text())
    receipt['databases_stopped'] = False
    path.write_text(json.dumps(receipt))
    with pytest.raises(RuntimeError, match='native_upgrade_checkpoint_unverified'):
        upgrade.checkpoint_receipt(journal)


def test_legacy_checkpoint_mode_rejects_integrity_receipt(preparation):
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    make_integrity_receipt(journal)
    journal.value.pop('checkpoint_verification')
    journal.write()
    (upgrade.checkpoint_root(journal) / 'restore-verified.json').unlink(missing_ok=True)
    with pytest.raises(FileNotFoundError):
        upgrade.checkpoint_receipt(journal)


@pytest.mark.parametrize('mode', [None, False, 'skip', []])
def test_unknown_checkpoint_verification_mode_is_refused(mode):
    with pytest.raises(RuntimeError, match='native_upgrade_checkpoint_unverified'):
        upgrade.checkpoint_verification({'checkpoint_verification': mode})


@pytest.mark.parametrize('field,bad', [('backup_id', 'another-copy'), ('manifest_sha256', '0' * 64),
                                     ('status', 'restore_verified'), ('terminal', False),
                                     ('checkpoint_verification', 'restore')])
def test_integrity_receipt_rejects_invalid_binding(preparation, field, bad):
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    path, receipt = make_integrity_receipt(journal)
    receipt[field] = bad
    path.write_text(json.dumps(receipt))
    with pytest.raises(RuntimeError, match='native_upgrade_checkpoint_unverified'):
        upgrade.checkpoint_receipt(journal)


def test_integrity_receipt_rechecks_current_manifest(preparation):
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    make_integrity_receipt(journal)
    checkpoint = upgrade.checkpoint_root(journal) / journal.value['checkpoint']
    (checkpoint / 'manifest.json').write_text('{"changed":true}')
    with pytest.raises(RuntimeError, match='native_upgrade_checkpoint_mismatch'):
        upgrade.checkpoint_receipt(journal)


def test_integrity_receipt_is_checked_before_migration(reuse_transaction):
    upgrade.prepare('new', TX, target_version=VERSION, previous_version='1.0-1~deb13', reuse_existing=True)
    journal = upgrade.Journal(reuse_transaction.transactions / TX)
    path, receipt = make_integrity_receipt(journal)
    receipt['status'] = 'restore_verified'
    path.write_text(json.dumps(receipt))
    with pytest.raises(RuntimeError, match='native_upgrade_checkpoint_unverified'):
        upgrade.configure_package('new', VERSION)
    assert not any(isinstance(event, list) and 'migrate' in event for event in reuse_transaction.events)
    assert 'restore-checkpoint' not in reuse_transaction.events


@pytest.mark.parametrize('returncode', [0, 17])
def test_upgrade_service_command_and_exit_code(preparation, monkeypatch, capsys, returncode):
    monkeypatch.setattr(upgrade, 'systemd_available', lambda: True, raising=False)
    monkeypatch.setattr(operation_wait, 'coordinator_unit', lambda: None)
    monkeypatch.setattr(operation_wait, 'stall_seconds', lambda: 420)
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(subprocess, 'run', run)
    monkeypatch.setattr(upgrade, 'prepare_package', lambda version: upgrade.prepare(
        'new', TX, target_version=version, previous_version='1.0-1~deb13'))
    # The service's durable result, read back by its waiting package process.
    monkeypatch.setattr(upgrade, 'Journal', lambda path: SimpleNamespace(value={
        'status': 'checkpoint_verified', 'failure_reason_code': 'operation_stalled'}))
    (preparation.transactions / TX).mkdir()
    (preparation.transactions / TX / 'journal.json').write_text('{}')
    monkeypatch.setattr(runtime, 'document', lambda path: {'failure_reason_code': 'operation_stalled'})
    assert upgrade.main(['prepare-package', VERSION]) == returncode
    argv, options = calls[0]
    assert argv[:2] == ['/usr/bin/systemd-run', '--unit=sli-upgrade-' + TX + '.service']
    for value in ('Type=exec', 'WatchdogSec=420', 'NotifyAccess=main', 'RuntimeMaxSec=infinity',
                  'KillMode=control-group'):
        assert '--property=' + value in argv
    assert all(flag in argv for flag in ('--wait', '--pipe', '--collect'))
    assert argv[argv.index('/usr/bin/systemd-cat') + 1:] == [
        '--identifier=sli-upgrade', upgrade.sys.executable, '-I', '-B', upgrade.__file__,
        'prepare', 'new', TX, '--target-version', VERSION, '--previous-version', '1.0-1~deb13']
    assert options['check'] is False and 'timeout' not in options
    assert 'LD_PRELOAD' not in options['env'] and 'PYTHONPATH' not in options['env']
    assert not preparation.events  # Never fence/capture inside dpkg after dispatch.
    assert not any('set-property' in str(call) for call in calls)
    output = capsys.readouterr()
    assert 'sli-upgrade-' + TX + '.service' in output.out
    if returncode:
        assert 'reason_code=operation_stalled' in output.err


def test_prepare_service_reentry_preserves_package_intent(preparation, monkeypatch):
    monkeypatch.setattr(upgrade, 'systemd_available', lambda: True, raising=False)
    monkeypatch.setattr(operation_wait, 'coordinator_unit', lambda: 'sli-upgrade-' + TX + '.service')
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: pytest.fail('recursive systemd-run'))
    assert upgrade.main(['prepare', 'new', TX, '--target-version', VERSION,
                         '--previous-version', '1.0-1~deb13']) == 0
    journal = upgrade.Journal(preparation.transactions / TX)
    assert journal.value['target_version'] == VERSION
    assert journal.value['previous_version'] == '1.0-1~deb13'
    assert journal.value['status'] == 'checkpoint_verified'


def test_prepare_without_systemd_stays_in_process(preparation, monkeypatch):
    monkeypatch.setattr(upgrade, 'systemd_available', lambda: False, raising=False)
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: pytest.fail('systemd unavailable'))
    upgrade.prepare_package(VERSION)
    assert upgrade.package_transaction(VERSION).value['status'] == 'checkpoint_verified'
    assert 'capture' in preparation.events


def test_resume_uses_existing_transaction_service(preparation, monkeypatch):
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    preparation.events.clear()
    monkeypatch.setattr(upgrade, 'systemd_available', lambda: True, raising=False)
    monkeypatch.setattr(operation_wait, 'coordinator_unit', lambda: None)
    monkeypatch.setattr(operation_wait, 'stall_seconds', lambda: 420)
    calls = []
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: calls.append(argv) or SimpleNamespace(returncode=0))
    assert upgrade.resume_package(VERSION)['status'] == 'checkpoint_verified'
    assert '--unit=sli-upgrade-' + journal.path.name + '.service' in calls[0]
    assert calls[0][-2:] == ['resume-package', VERSION]
    assert not preparation.events


def test_configure_uses_checkpoint_transaction_service(preparation, monkeypatch):
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    monkeypatch.setattr(upgrade, 'systemd_available', lambda: True, raising=False)
    monkeypatch.setattr(operation_wait, 'coordinator_unit', lambda: None)
    monkeypatch.setattr(operation_wait, 'stall_seconds', lambda: 420)
    calls = []
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: calls.append(argv) or SimpleNamespace(returncode=0))
    upgrade.configure_package('new', VERSION)
    assert '--unit=sli-upgrade-' + journal.path.name + '.service' in calls[0]
    assert calls[0][-3:] == ['configure-package', 'new', VERSION]


@pytest.mark.parametrize('manager', [False, True])
@pytest.mark.parametrize('returncode', [0, 1])
def test_systemd_availability_checks_manager(tmp_path, monkeypatch, manager, returncode):
    path = tmp_path / 'systemd'
    if manager:
        path.mkdir()
    monkeypatch.setattr(upgrade, 'VOLATILE_UNITS', path)
    calls = []
    monkeypatch.setattr(subprocess, 'run', lambda argv, **kw: calls.append(argv) or
                        SimpleNamespace(returncode=returncode))
    assert upgrade.systemd_available() is (manager and returncode == 0)
    assert bool(calls) is manager


@pytest.mark.parametrize('state', ['stopped', 'active', 'populated'])
def test_killed_prepare_service_recovers_only_after_unit_stopped(preparation, monkeypatch, state):
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    journal.value.update(status='fenced', step='after')
    journal.write()
    preparation.events.clear()
    monkeypatch.setattr(upgrade, 'systemd_available', lambda: True)
    monkeypatch.setattr(operation_wait, 'coordinator_unit', lambda: None)
    monkeypatch.setattr(operation_wait, 'stall_seconds', lambda: 420)
    unit = 'sli-upgrade-' + journal.path.name + '.service'
    monkeypatch.setattr(native, 'CGROUP_ROOT', preparation.transactions.parent / 'cgroups')
    group = '/system.slice/' + unit
    if state == 'populated':
        path = native.CGROUP_ROOT / group.lstrip('/')
        path.mkdir(parents=True)
        (path / 'cgroup.procs').write_text('42\n')
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if argv[0] == '/usr/bin/systemd-run':
            return SimpleNamespace(returncode=134)
        return SimpleNamespace(returncode=0, stdout=(
            'ActiveState=active\nMainPID=42\nResult=success\nControlGroup=\n' if state == 'active' else
            'ActiveState=inactive\nMainPID=0\nResult=watchdog\nControlGroup=' + group + '\n'))

    monkeypatch.setattr(subprocess, 'run', run)
    # Call the already-dispatched entry point, with the trusted previous release.
    assert upgrade.main(['resume-package', VERSION]) == 134
    journal = upgrade.package_transaction(VERSION)
    if state != 'stopped':
        assert journal.value['status'] == 'fenced'
        assert not preparation.events
    else:
        assert journal.value['status'] == 'aborted_before_checkpoint'
        assert journal.value['services_restored'] is True
        assert journal.value['failure_reason_code'] == 'operation_stalled'
        assert 'start-checked' in preparation.events


@pytest.mark.parametrize('status', ['aborted_before_checkpoint', 'migrating', 'candidate_testing', 'recovering', 'committed', 'rolled_back'])
def test_service_death_recovery_never_replays_sql_or_rolls_back_commit(preparation, monkeypatch, status):
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    journal.value.update(status=status, step='before')
    journal.write()
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: SimpleNamespace(
        returncode=0, stdout='ActiveState=inactive\nMainPID=0\nResult=watchdog\nControlGroup=\n'))
    calls = []
    monkeypatch.setattr(upgrade, 'recover_compatible', lambda journal: calls.append(('recover', journal.value.copy())))
    monkeypatch.setattr(install, 'inventory', lambda release: ('accepted', {}, 'digest'))
    monkeypatch.setattr(upgrade, 'finish_committed', lambda journal, candidate: calls.append(('commit', candidate)))
    monkeypatch.setattr(upgrade, 'finish_rollback', lambda journal: calls.append(('rollback', journal.path.name)))
    monkeypatch.setattr(upgrade, 'restart_aborted_prepare', lambda journal: calls.append(('restart', journal.path.name)))
    assert upgrade.recover_service_failure('sli-upgrade-' + journal.path.name + '.service', journal.path.name) == 'operation_stalled'
    assert len(calls) == 1
    if status == 'committed':
        assert calls[0] == ('commit', ('accepted', {}, 'digest'))
    elif status == 'rolled_back':
        assert calls[0][0] == 'rollback'
    elif status == 'aborted_before_checkpoint':
        assert calls[0][0] == 'restart'
    else:
        assert calls[0][0] == 'recover'
        if status == 'migrating':
            assert calls[0][1]['schema_changed'] is True


@pytest.mark.parametrize('error', [FileNotFoundError(), subprocess.TimeoutExpired('systemctl', 10)])
def test_systemd_probe_failure_uses_fallback(tmp_path, monkeypatch, error):
    monkeypatch.setattr(upgrade, 'VOLATILE_UNITS', tmp_path)
    monkeypatch.setattr(subprocess, 'run', lambda *a, **kw: (_ for _ in ()).throw(error))
    assert upgrade.systemd_available() is False


@pytest.fixture
def sealed_recovery(tmp_path, monkeypatch):
    # Model root-owned POSIX metadata on Windows; preserve real file/link types.
    original = Path.lstat
    def lstat(path):
        info = original(path)
        mode = stat.S_IFMT(info.st_mode) | (0o755 if stat.S_ISDIR(info.st_mode) else 0o644)
        return os.stat_result((mode, info.st_ino, info.st_dev, info.st_nlink, 0, 0,
                               info.st_size, info.st_atime, info.st_mtime, info.st_ctime))
    monkeypatch.setattr(Path, 'lstat', lstat)
    monkeypatch.setattr(install, 'trusted', lambda path: path.read_bytes())
    monkeypatch.setattr(upgrade, 'RECOVERY', tmp_path / 'recovery')
    monkeypatch.setattr(install, 'RUNTIMES', tmp_path / 'runtimes')
    root = upgrade.RECOVERY / 'old'
    root.mkdir(parents=True, exist_ok=True)
    manifest = root / 'release/native-runtime.json'
    manifest.parent.mkdir()
    manifest.write_text('{"accepted": true}')
    python = install.RUNTIMES / 'old/bin/python3.14'
    python.parent.mkdir(parents=True)
    python.write_bytes(b'synthetic-python')
    python.chmod(0o755)
    inventory = backup.content_inventory(root, exclude_manifest=False)
    inventory.pop('recovery.json', None)
    value = {'schema_version': 1, 'release': 'old', 'python': str(python),
             'python_sha256': hashlib.sha256(python.read_bytes()).hexdigest(),
             'manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
             'runtime_inventory': upgrade.runtime_inventory(python.parent.parent),
             'content_checksums': inventory}
    (root / 'recovery.json').write_text(json.dumps(value))
    return root, python.parent.parent


@pytest.fixture(params=['coordinator', 'prerm'])
def cleanup(sealed_recovery, request):
    if request.param == 'coordinator':
        return lambda: upgrade.verify_recovery('old')
    body = native_package.scripts('new', VERSION)['prerm']
    source = body.split("<<'SLI_BYTECODE'\n", 1)[1].split('\nSLI_BYTECODE\n', 1)[0]
    namespace = {'__name__': 'embedded_preinstall'}
    exec(compile(source, '<embedded-preinstall>', 'exec'), namespace)
    return lambda: namespace['cleanup_recovery']('old', recovery=upgrade.RECOVERY, runtimes=install.RUNTIMES)


@pytest.fixture
def sealed_bytecode(sealed_recovery):
    seal_path = sealed_recovery[0] / 'recovery.json'
    seal = json.loads(seal_path.read_bytes())
    paths = []
    for root, inventory, prefix in zip(sealed_recovery, ('content_checksums', 'runtime_inventory'),
                                       ('release/deploy/linux', 'lib/python3.14')):
        path = root / prefix / '__pycache__/backup.cpython-314.pyc'
        path.parent.mkdir(parents=True)
        path.write_bytes(b'sealed-bytecode')
        seal[inventory][path.relative_to(root).as_posix()] = {
            'sha256': hashlib.sha256(b'sealed-bytecode').hexdigest(), 'size': len(b'sealed-bytecode')}
        paths.append(path)
    seal_path.write_text(json.dumps(seal))
    return paths


def test_cleanup_preserves_sealed_bytecode_and_removes_only_extras(sealed_recovery, sealed_bytecode, cleanup):
    extras = []
    for path in sealed_bytecode:
        extra = path.with_name('native_preinstall.cpython-313.pyc')
        extra.write_bytes(b'legacy-bytecode')
        extras.append(extra)
    seal = (sealed_recovery[0] / 'recovery.json').read_bytes()
    cleanup()
    assert all(path.read_bytes() == b'sealed-bytecode' for path in sealed_bytecode)
    assert all(not path.exists() for path in extras)
    assert upgrade.verify_recovery('old')[0] == sealed_recovery[0]
    assert (sealed_recovery[0] / 'recovery.json').read_bytes() == seal


@pytest.mark.parametrize('tree', [0, 1])
def test_cleanup_keeps_changed_sealed_bytecode_for_strict_rejection(sealed_bytecode, cleanup, tree):
    path = sealed_bytecode[tree]
    path.write_bytes(b'changed-bytecode')
    code = 'native_recovery_hash_mismatch' if tree == 0 else 'native_recovery_runtime_mismatch'
    with pytest.raises(RuntimeError, match=code):
        cleanup()
        upgrade.verify_recovery('old')
    assert path.read_bytes() == b'changed-bytecode'


def test_runtime_inventory_seals_supplied_bytecode(sealed_recovery):
    root = sealed_recovery[1]
    path = root / 'lib/python3.14/__pycache__/backup.cpython-314.pyc'
    path.parent.mkdir(parents=True)
    path.write_bytes(b'supplied-bytecode')
    inventory = upgrade.runtime_inventory(root)
    assert inventory['lib/python3.14/__pycache__/backup.cpython-314.pyc'] == {
        'sha256': hashlib.sha256(b'supplied-bytecode').hexdigest(), 'size': len(b'supplied-bytecode')}
    assert path.read_bytes() == b'supplied-bytecode'


@pytest.mark.parametrize('tree', [0, 1])
def test_cleanup_validates_all_cache_candidates_before_deleting(sealed_recovery, cleanup, tree):
    root = sealed_recovery[tree]
    extra = root / 'a/__pycache__/extra.pyc'
    invalid = root / 'z/__pycache__/extra.txt'
    for path in (extra, invalid):
        path.parent.mkdir(parents=True)
        path.write_bytes(b'keep')
    with pytest.raises(RuntimeError, match='native_recovery_cache_invalid'):
        cleanup()
    assert extra.read_bytes() == invalid.read_bytes() == b'keep'


@pytest.mark.parametrize('tree', [0, 1])
def test_cleanup_preserves_sealed_empty_cache_directory(sealed_recovery, cleanup, tree):
    root = sealed_recovery[tree]
    cache = root / '__pycache__'
    cache.mkdir()
    (cache / 'extra.pyc').write_bytes(b'legacy-bytecode')
    seal_path = sealed_recovery[0] / 'recovery.json'
    seal = json.loads(seal_path.read_bytes())
    inventory = 'content_checksums' if tree == 0 else 'runtime_inventory'
    seal[inventory]['__pycache__'] = {'type': 'directory'}
    seal_path.write_text(json.dumps(seal))
    # Directory entries are not produced by today's strict inventories; cleanup
    # must nevertheless leave them for that verifier, not silently remove them.
    try:
        cleanup()
    except RuntimeError as error:
        assert str(error) in ('native_recovery_hash_mismatch', 'native_recovery_runtime_mismatch')
    assert cache.is_dir() and not list(cache.iterdir())


@pytest.mark.parametrize('tree', [0, 1])
def test_recovery_removes_legacy_bytecode_before_strict_inventory(sealed_recovery, tree):
    cache = sealed_recovery[tree] / 'nested/__pycache__'
    cache.mkdir(parents=True)
    (cache / 'native_preinstall.cpython-313.pyc').write_bytes(b'legacy-bytecode')
    seal = (sealed_recovery[0] / 'recovery.json').read_bytes()
    assert upgrade.verify_recovery('old')[0] == sealed_recovery[0]
    assert not cache.exists()
    assert (sealed_recovery[0] / 'recovery.json').read_bytes() == seal


def test_package_embeds_cleanup_before_legacy_coordinator(sealed_recovery):
    for root in sealed_recovery:
        cache = root / '__pycache__'
        cache.mkdir()
        (cache / 'native_preinstall.cpython-313.pyc').write_bytes(b'legacy-bytecode')
    scripts = native_package.scripts('new', VERSION)
    for name in ('preinst', 'prerm', 'postinst'):
        body = scripts[name]
        assert body.index('sli_clean_bytecode\n') < body.index(' dispatch ')
        source = body.split("<<'SLI_BYTECODE'\n", 1)[1].split('\nSLI_BYTECODE\n', 1)[0]
        namespace = {'__name__': 'embedded_preinstall'}
        exec(compile(source, '<embedded-preinstall>', 'exec'), namespace)
        namespace['cleanup_recovery']('old', recovery=upgrade.RECOVERY, runtimes=install.RUNTIMES)
        assert all(not (root / '__pycache__').exists() for root in sealed_recovery)
        # A legacy verifier has no cleanup: its original strict seal still matches.
        inventory = backup.content_inventory(sealed_recovery[0], exclude_manifest=False)
        inventory.pop('recovery.json')
        seal = json.loads((sealed_recovery[0] / 'recovery.json').read_bytes())
        assert inventory == seal['content_checksums']
    assert 'upgrade|failed-upgrade)' in scripts['prerm']
    assert f'then target=\'{VERSION}\'' in scripts['prerm']
    assert 'dispatch prepare-package "$target"' in scripts['prerm']


@pytest.mark.parametrize('tree', [0, 1])
@pytest.mark.parametrize('name', ['extra.txt', 'extra.pyc', '__pycache__/extra.txt'])
def test_recovery_refuses_noncache_files(sealed_recovery, tree, name):
    path = sealed_recovery[tree] / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('unsealed')
    with pytest.raises(RuntimeError, match='native_recovery_'):
        upgrade.verify_recovery('old')
    assert path.read_text() == 'unsealed'


@pytest.mark.parametrize('tree', [0, 1])
def test_recovery_refuses_changed_sealed_file(sealed_recovery, tree):
    path = sealed_recovery[tree] / ('release/native-runtime.json' if tree == 0 else 'bin/python3.14')
    path.write_bytes(b'changed')
    with pytest.raises(RuntimeError, match='native_recovery_'):
        upgrade.verify_recovery('old')


def test_bootstrap_refuses_runtime_outside_trusted_prefix(sealed_recovery, tmp_path):
    outside = tmp_path / 'outside/__pycache__'
    outside.mkdir(parents=True)
    marker = outside / 'keep.pyc'
    marker.write_bytes(b'keep')
    path = sealed_recovery[0] / 'recovery.json'
    seal = json.loads(path.read_bytes())
    seal['python'] = str(outside.parent / 'bin/python3.14')
    path.write_text(json.dumps(seal))
    with pytest.raises(RuntimeError, match='native_recovery_cache_invalid'):
        preinstall.cleanup_recovery('old', recovery=upgrade.RECOVERY, runtimes=install.RUNTIMES)
    assert marker.read_bytes() == b'keep'


@pytest.mark.parametrize('tree', [0, 1])
def test_recovery_refuses_cache_symlink_without_touching_target(sealed_recovery, cleanup, tmp_path, monkeypatch, tree):
    outside = tmp_path / 'outside'
    outside.mkdir()
    marker = outside / 'keep.pyc'
    marker.write_bytes(b'keep')
    link = sealed_recovery[tree] / '__pycache__'
    cache_link(link, outside, monkeypatch, directory=True)
    with pytest.raises(RuntimeError):
        cleanup()
    assert link.is_symlink() and marker.read_bytes() == b'keep'


@pytest.mark.parametrize('kind', ['owner', 'writable', 'file_link', 'hardlink'])
def test_recovery_refuses_untrusted_bytecode(sealed_recovery, cleanup, monkeypatch, kind):
    cache = sealed_recovery[0] / '__pycache__'
    cache.mkdir()
    path = cache / 'extra.pyc'
    path.write_bytes(b'keep')
    if kind == 'file_link':
        target = path.with_name('target.pyc')
        target.write_bytes(b'keep')
        path.unlink()
        cache_link(path, target, monkeypatch)
    else:
        original = Path.lstat
        def lstat(item):
            info = original(item)
            if item == (path if kind == 'hardlink' else cache):
                values = list(info)
                if kind == 'hardlink':
                    values[3] = 2
                else:
                    values[4 if kind == 'owner' else 0] = 1000 if kind == 'owner' else info.st_mode | 0o020
                return os.stat_result(values)
            return info
        monkeypatch.setattr(Path, 'lstat', lstat)
    with pytest.raises(RuntimeError):
        cleanup()
    assert path.read_bytes() == b'keep'


def cache_link(path, target, monkeypatch, *, directory=False):
    if os.name != 'nt':
        path.symlink_to(target, target_is_directory=directory)
    else:
        # Windows runner lacks SeCreateSymbolicLinkPrivilege. Model the link
        # boundary here; Linux runs the same assertions against actual links.
        if directory:
            path.mkdir()
        else:
            path.write_bytes(target.read_bytes())
        original = Path.is_symlink
        monkeypatch.setattr(Path, 'is_symlink', lambda item: item == path or original(item))


@pytest.fixture
def preparation(tmp_path, monkeypatch):
    monkeypatch.setattr(upgrade, 'systemd_available', lambda: False)
    transactions = tmp_path / 'transactions'
    transactions.mkdir()
    recovery = tmp_path / 'recovery/old'
    recovery.mkdir(parents=True)
    (recovery / 'recovery.json').write_text('{}')
    events = []

    def atomic(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def capture(path, **kwargs):
        events.append('capture')
        checkpoint = path / 'checkpoint'
        atomic(checkpoint / 'manifest.json', {'consistency_point': {'writers_fenced': True}})
        return checkpoint

    def drill(path, root, *, prune_sets, upgrade_checkpoint):
        assert not prune_sets and upgrade_checkpoint is True
        result = {'status': 'restore_verified', 'backup_id': path.name, 'terminal': True, 'databases_stopped': True,
                  'manifest_sha256': upgrade.digest(path / 'manifest.json')}
        atomic(root / 'restore-verified.json', result)
        return result

    def start(*args):
        # Real startup gate must admit the durable abort before starting units.
        runtime.no_transaction()
        events.append('start-checked')

    monkeypatch.setattr(upgrade, 'TRANSACTIONS', transactions)
    monkeypatch.setattr(runtime, 'TRANSACTIONS', transactions)
    monkeypatch.setattr(runtime, 'STATE', tmp_path / 'state')
    monkeypatch.setattr(runtime, 'release', lambda: (Path('/accepted/old'), {}, 'digest'))
    monkeypatch.setattr(upgrade, 'package_metadata', lambda root: {'version': '1.0-1~deb13'})
    monkeypatch.setattr(upgrade, 'preflight', lambda: (Path('/accepted/old'), recovery))
    monkeypatch.setattr(upgrade, 'operation_lock', lambda root: nullcontext())
    monkeypatch.setattr(upgrade, 'sync_tree', lambda root: None)
    monkeypatch.setattr(upgrade, 'os', SimpleNamespace(O_RDONLY=0, O_DIRECTORY=0, open=lambda *a: 99,
                                                     fsync=lambda fd: None, close=lambda fd: None,
                                                     geteuid=lambda: 0, umask=lambda mode: None))
    monkeypatch.setattr(upgrade, 'ensure_directory', lambda path, *a, **kw: path.mkdir(
        parents=True, exist_ok=kw.get('exist_ok', True)))
    monkeypatch.setattr(install, 'atomic', atomic)
    monkeypatch.setattr(install, 'trusted', lambda path: path.read_bytes())
    monkeypatch.setattr(runtime, 'trusted', lambda path: path.read_bytes())
    monkeypatch.setattr(native, 'ROOT', tmp_path / 'backup')
    monkeypatch.setattr(native, 'DRILLS', tmp_path)
    monkeypatch.setattr(backup, 'size_bytes', lambda path: 1)
    monkeypatch.setattr(upgrade.shutil, 'disk_usage', lambda path: SimpleNamespace(free=100 * 1024**3))
    monkeypatch.setattr(install, 'wait_health', lambda: None)
    monkeypatch.setattr(install, 'backup_schedule', lambda: 'disabled')
    monkeypatch.setattr(upgrade, 'fence', lambda: events.append('fence'))
    monkeypatch.setattr(upgrade, 'stop_application', lambda: events.append('stop-application'))
    monkeypatch.setattr(upgrade, 'file_metadata', lambda: {})
    monkeypatch.setattr(native, 'capture_locked', capture)
    monkeypatch.setattr(native, 'verify', lambda path: (json.loads((path / 'manifest.json').read_text()), None, None))
    monkeypatch.setattr(native, 'drill_locked', drill)
    monkeypatch.setattr(upgrade, 'start_checked', start)
    monkeypatch.setattr(upgrade, 'retained_runtime', lambda path: runtime)
    monkeypatch.setattr(install, 'command', lambda argv, **kw: events.append(argv))
    return SimpleNamespace(events=events, transactions=transactions)


def fail_fence():
    raise runtime.RuntimeErrorCode('native_writers_still_running')


def test_prepare_package_creates_transaction_after_legacy_cache(preparation, sealed_recovery, monkeypatch):
    for root in sealed_recovery:
        cache = root / '__pycache__'
        cache.mkdir()
        (cache / 'native_preinstall.cpython-313.pyc').write_bytes(b'legacy-bytecode')
    monkeypatch.setattr(upgrade.os, 'access', lambda *args: True, raising=False)
    monkeypatch.setattr(upgrade.os, 'X_OK', os.X_OK, raising=False)
    def preflight():
        recovery, _ = upgrade.verify_recovery('old')
        return Path('/accepted/old'), recovery
    monkeypatch.setattr(upgrade, 'preflight', preflight)
    upgrade.prepare_package(VERSION)
    transactions = list(preparation.transactions.iterdir())
    assert len(transactions) == 1
    journal = upgrade.Journal(transactions[0]).value
    assert journal['status'] == 'checkpoint_verified' and journal['target_version'] == VERSION
    assert all(not (root / '__pycache__').exists() for root in sealed_recovery)


@pytest.mark.parametrize('phase', ['preflight', 'fenced'])
def test_prepare_failure_before_checkpoint_restores_previous_services(preparation, monkeypatch, phase):
    if phase == 'fenced':
        monkeypatch.setattr(upgrade, 'fence', fail_fence)
    else:
        original = upgrade.Journal.complete

        def complete(journal, **values):
            if journal.value['status'] == 'preflight':
                fail_fence()
            return original(journal, **values)

        monkeypatch.setattr(upgrade.Journal, 'complete', complete)
    with pytest.raises(RuntimeError, match='native_writers_still_running'):
        upgrade.prepare('new', TX)
    journal = upgrade.Journal(preparation.transactions / TX)
    result = json.loads((journal.path / 'result.json').read_text())
    assert journal.value['status'] == result['status'] == 'aborted_before_checkpoint'
    assert journal.value['step'] == 'after' and result['terminal'] is True
    assert result['reason_code'] == 'native_writers_still_running'
    assert result['services_restored'] is True
    assert 'start-checked' in preparation.events and 'capture' not in preparation.events
    assert ['systemctl', 'start', 'sli.target', 'sli-health.timer'] in preparation.events
    runtime.no_transaction()


def test_repeated_package_prepare_after_abort_allocates_fresh_checkpoint(preparation, monkeypatch):
    fence = upgrade.fence
    monkeypatch.setattr(upgrade, 'fence', fail_fence)
    with pytest.raises(RuntimeError, match='native_writers_still_running'):
        upgrade.prepare_package(VERSION)
    first = upgrade.package_transaction(VERSION)
    monkeypatch.setattr(upgrade, 'fence', fence)
    upgrade.prepare_package(VERSION)
    second = upgrade.package_transaction(VERSION)
    assert second.path != first.path and second.value['status'] == 'checkpoint_verified'
    assert first.value['status'] == 'aborted_before_checkpoint'
    assert preparation.events.count('capture') == 1
    upgrade.check_package(VERSION)


def test_failed_restart_is_reported_and_public_resume_retries_services(preparation, monkeypatch, capsys):
    start = upgrade.start_checked
    monkeypatch.setattr(upgrade, 'fence', fail_fence)
    monkeypatch.setattr(upgrade, 'start_checked', lambda: (_ for _ in ()).throw(RuntimeError('private restart text')))
    assert upgrade.main(['prepare-package', VERSION]) == 1
    result = json.loads((upgrade.package_transaction(VERSION).path / 'result.json').read_text())
    assert result['services_restored'] is False
    assert result['reason_code'] == 'native_writers_still_running'
    output = capsys.readouterr().err
    assert 'reason_code=native_upgrade_restart_failed' in output
    assert f'sli-native-upgrade resume-package {VERSION}' in output
    assert 'private restart text' not in output
    monkeypatch.setattr(upgrade, 'start_checked', start)
    upgrade.resume_package(VERSION)
    result = json.loads((upgrade.package_transaction(VERSION).path / 'result.json').read_text())
    assert result['services_restored'] is True
    assert preparation.events.count('capture') == 0


def test_failure_after_verified_checkpoint_stays_fenced(preparation, monkeypatch):
    upgrade.prepare('new', TX)
    preparation.events.clear()
    monkeypatch.setattr(upgrade, 'fence', fail_fence)
    with pytest.raises(RuntimeError, match='native_writers_still_running'):
        upgrade.prepare('new', TX)
    journal = upgrade.Journal(preparation.transactions / TX)
    result = json.loads((journal.path / 'result.json').read_text())
    assert journal.value['status'] == 'checkpoint_verified'
    assert result['terminal'] is False
    assert 'start-checked' not in preparation.events
    with pytest.raises(runtime.RuntimeErrorCode, match='native_transaction_pending'):
        runtime.no_transaction()


def test_prepare_cli_preserves_safe_reason_and_gives_recovery_command(preparation, monkeypatch, capsys):
    monkeypatch.setattr(upgrade, 'fence', fail_fence)
    assert upgrade.main(['prepare-package', VERSION]) == 1
    output = capsys.readouterr().err
    assert 'reason_code=native_writers_still_running' in output
    assert f'sli-native-upgrade resume-package {VERSION}' in output
    assert 'Recovery' in output and '\u0412\u043e\u0441\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u0438\u0435' in output


@pytest.mark.parametrize('failure', ['fence', 'capture', 'verify'])
def test_private_prepare_error_has_safe_stage_reason_and_aborts(preparation, monkeypatch, failure, capsys):
    owner, attr = (upgrade, 'fence') if failure == 'fence' else (
        native, 'verify' if failure == 'verify' else 'capture_locked')
    monkeypatch.setattr(owner, attr, lambda *a, **kw: (_ for _ in ()).throw(ValueError('private-synthetic-detail')))
    assert upgrade.main(['prepare-package', VERSION]) == 1
    journal = upgrade.package_transaction(VERSION)
    result = json.loads((journal.path / 'result.json').read_text())
    expected = 'native_upgrade_fence_failed' if failure == 'fence' else 'native_upgrade_checkpoint_failed'
    assert result['reason_code'] == expected and result['services_restored'] is True
    assert journal.value['status'] == 'aborted_before_checkpoint'
    output = capsys.readouterr().err
    assert expected in output and 'private-synthetic-detail' not in output
    assert 'private-synthetic-detail' not in (journal.path / 'journal.json').read_text()


def test_repeated_apt_retries_failed_restart_then_prepares(preparation, monkeypatch):
    start, fence = upgrade.start_checked, upgrade.fence
    monkeypatch.setattr(upgrade, 'fence', fail_fence)
    monkeypatch.setattr(upgrade, 'start_checked', lambda: (_ for _ in ()).throw(RuntimeError('injected')))
    with pytest.raises(RuntimeError, match='native_upgrade_restart_failed'):
        upgrade.prepare_package(VERSION)
    first = upgrade.package_transaction(VERSION)
    monkeypatch.setattr(upgrade, 'start_checked', start)
    monkeypatch.setattr(upgrade, 'fence', fence)
    upgrade.prepare_package(VERSION)
    assert upgrade.package_transaction(VERSION).value['status'] == 'checkpoint_verified'
    assert upgrade.Journal(first.path).value['services_restored'] is True


def test_killed_prepare_keeps_closed_gate_until_explicit_resume(preparation, monkeypatch):
    fence = upgrade.fence
    monkeypatch.setattr(upgrade, 'fence', lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        upgrade.prepare_package(VERSION)
    with pytest.raises(RuntimeError, match='native_upgrade_reconciliation_required'):
        upgrade.prepare_package(VERSION)
    with pytest.raises(OSError):
        runtime.no_transaction()
    assert 'start-checked' not in preparation.events
    monkeypatch.setattr(upgrade, 'fence', fence)
    assert upgrade.resume_package(VERSION)['status'] == 'checkpoint_verified'


def test_nonterminal_abort_cannot_open_readiness(preparation):
    path = preparation.transactions / TX
    path.mkdir()
    (path / 'result.json').write_text(json.dumps({
        'schema_version': 1, 'status': 'aborted_before_checkpoint', 'terminal': False}))
    with pytest.raises(runtime.RuntimeErrorCode, match='native_transaction_pending'):
        runtime.no_transaction()


def test_preflight_failure_without_intent_tells_operator_to_retry_apt(preparation, monkeypatch, capsys):
    monkeypatch.setattr(upgrade, 'preflight', lambda: (_ for _ in ()).throw(RuntimeError('native_backup_secret_missing')))
    assert upgrade.main(['prepare-package', VERSION]) == 1
    output = capsys.readouterr().err
    assert 'reason_code=native_backup_secret_missing' in output
    assert 'bash ./install-beta-kit' in output
    assert 'resume-package' not in output
    assert not list(preparation.transactions.iterdir()) and not preparation.events


@pytest.fixture
def reuse_transaction(preparation, tmp_path, monkeypatch):
    """Real prepare/activate/recover state machine; only host/DB I/O is synthetic."""
    old, new = Path('/accepted/old'), tmp_path / 'new'
    (new / 'deploy/linux').mkdir(parents=True)
    (new / 'deploy/linux/native_upgrade.py').write_text('# synthetic new coordinator')
    manifest = {'python': '/accepted/python', 'migration_ledger': [1]}
    state = tmp_path / 'state'
    state.mkdir()
    (state / 'package-install.json').write_text(json.dumps({'release': 'old', 'status': 'configured'}))
    current = [old]
    monkeypatch.setattr(install, 'STATE', state)
    monkeypatch.setattr(install, 'inventory', lambda name: (
        old if name == 'old' else new, dict(manifest), name + '-digest'))
    monkeypatch.setattr(upgrade, 'package_metadata', lambda root: {
        'version': '1.0-1~deb13' if root == old else VERSION})
    monkeypatch.setattr(upgrade, 'preflight', lambda: (current[0], tmp_path / 'recovery/old'))
    monkeypatch.setattr(upgrade, 'validate_reuse_receipt', lambda root: preparation.events.append('receipt'))
    monkeypatch.setattr(upgrade, 'migration_required', lambda *a: True)
    monkeypatch.setattr(native_pg_migrate, 'migrate', lambda root: preparation.events.append(['migrate', str(root)]))
    monkeypatch.setattr(upgrade, 'check_reused_databases', lambda release: preparation.events.append('new-ready'))
    monkeypatch.setattr(runtime, 'stop_writers', lambda: preparation.events.append('stop-writers'))
    monkeypatch.setattr(install, 'wait_health', lambda: pytest.fail('removed application is stopped'))
    monkeypatch.setattr(upgrade, 'verify_recovery', lambda release: (tmp_path / 'recovery/old', {}))
    monkeypatch.setattr(upgrade, 'configure_candidate', lambda *a: preparation.events.append('candidate-units'))
    monkeypatch.setattr(upgrade, 'testing_units', lambda tx=None: None)
    monkeypatch.setattr(upgrade, 'start_checked', lambda *args: preparation.events.append('acceptance'))
    monkeypatch.setattr(install, 'preserve_recovery', lambda *a: preparation.events.append('save-recovery'))
    def switch(root, *args):
        current[0] = root
        preparation.events.append('switch-' + root.name)
    monkeypatch.setattr(upgrade, 'switch', switch)
    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda journal: preparation.events.append('restore-checkpoint'))
    monkeypatch.setattr(upgrade, 'restore_helpers', lambda recovery, *args: preparation.events.append('restore-helpers'))
    monkeypatch.setattr(upgrade, 'restore_agents_unit', lambda recovery: None)
    units = tmp_path / 'units'
    units.mkdir()
    (tmp_path / 'recovery/old/units').mkdir()
    monkeypatch.setattr(upgrade, 'UNITS', units)
    return preparation


def test_reuse_runs_normal_checkpoint_migration_acceptance_commit(reuse_transaction, monkeypatch):
    upgrade.reuse_existing('new')
    journal = upgrade.package_transaction(VERSION)
    events = reuse_transaction.events
    assert journal.value['status'] == 'committed' and journal.value['reuse_existing'] is True
    assert journal.value['coordinator_release'] == 'new'
    assert events.index('stop-writers') < events.index('new-ready') < events.index('fence') < events.index('capture')
    migration = next(i for i, item in enumerate(events) if isinstance(item, list) and 'migrate' in item)
    assert events.index('capture') < migration < events.index('candidate-units') < events.index('acceptance')
    assert events.index('acceptance') < events.index('save-recovery')
    assert not any(isinstance(item, list) and ('ensure' in item or 'sli-bootstrap-pg.service' in item)
                   for item in events)
    result = json.loads((journal.path / 'result.json').read_text())
    assert result['status'] == 'committed' and result['terminal'] is True
    monkeypatch.setattr(install, 'configure_guarded', lambda release: events.append('repeat-acceptance'))
    upgrade.reuse_existing('new')
    assert events.count('capture') == 1 and events[-1] == 'repeat-acceptance'


def test_reuse_failed_acceptance_restores_checkpoint_and_previous_release(reuse_transaction, monkeypatch):
    calls = []
    def acceptance(*args):
        calls.append('acceptance')
        if len(calls) == 1:
            raise RuntimeError('native_install_api_unready')
    monkeypatch.setattr(upgrade, 'start_checked', acceptance)
    with pytest.raises(RuntimeError, match='native_install_api_unready'):
        upgrade.reuse_existing('new')
    journal = upgrade.package_transaction(VERSION)
    assert journal.value['status'] == 'rolled_back'
    events = reuse_transaction.events
    assert events.index('restore-checkpoint') < events.index('switch-old') < events.index('restore-helpers')
    result = json.loads((journal.path / 'result.json').read_text())
    assert result['terminal'] is True and result['status'] == 'rolled_back'
    assert result['accepted_release'] == 'old' and result['reason_code'] == 'native_install_api_unready'
    with pytest.raises(RuntimeError, match='native_upgrade_reconciliation_required'):
        upgrade.reuse_existing('new')


def test_rollback_waits_for_worker_backend_after_units_stop(reuse_transaction, monkeypatch, capsys):
    events = reuse_transaction.events
    clock = [0]
    stopped_at = [None]
    polls = []
    monkeypatch.setattr(install, 'wait_health', lambda: None)
    upgrade.prepare_package(VERSION)
    monkeypatch.setattr(install, 'setup_deadline', nullcontext)
    monkeypatch.setattr(upgrade, 'fence', FENCE)
    monkeypatch.setattr(upgrade, 'stop_application', STOP_APPLICATION)
    monkeypatch.setattr(upgrade, 'wait_restore_databases', lambda: None)
    monkeypatch.setattr(upgrade.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(upgrade.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(native, 'settings', dict)
    monkeypatch.setattr(native, 'environment', lambda values: nullcontext())
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(Path('/unused')))

    def query(sql, parameters=()):
        if not parameters:
            return SimpleNamespace(fetchone=lambda: (1,))  # Legacy one-shot query fails the rollback.
        assert stopped_at[0] is not None
        elapsed = clock[0] - stopped_at[0]
        polls.append(elapsed)
        worker = [('adlog_user', 'fixture-worker')] if 'switch-new' in events and elapsed < 20 else []
        roles = parameters[0] if parameters else ()
        return SimpleNamespace(fetchone=lambda: (1,), fetchall=lambda: [
            row for row in [*worker, ('postgres', 'fixture-maintenance')] if row[0] in roles])

    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **k: nullcontext(SimpleNamespace(execute=query)))

    def stop_writers():
        stopped_at[0] = clock[0]
        events.append('writers-stopped')

    monkeypatch.setattr(runtime, 'stop_writers', stop_writers)
    monkeypatch.setattr(runtime, 'stop_services', lambda *a, **k: None)
    monkeypatch.setattr(upgrade.subprocess, 'run', lambda *a, **k: SimpleNamespace(
        returncode=0, stdout='LoadState=loaded\nActiveState=inactive\nMainPID=0\nControlGroup=\n'))

    def check_runtime(*args):
        if 'switch-old' not in events:
            raise RuntimeError('native_install_api_unready')

    monkeypatch.setattr(upgrade, 'start_checked', check_runtime)
    with pytest.raises(RuntimeError, match='^native_install_api_unready$'):
        upgrade.configure_package('new', VERSION)
    journal = upgrade.package_transaction(VERSION)
    result = json.loads((journal.path / 'result.json').read_text())
    assert result['status'] == 'rolled_back' and result['services_restored'] is True
    assert 0 in polls and max(polls) >= 20
    assert events.index(['systemctl', 'stop', 'sli-backup.service', 'sli-backup-drill.service']) < events.index('writers-stopped')
    assert 'native_upgrade_pg_drain' in capsys.readouterr().out


@pytest.mark.parametrize('problem', [None, 'not-restored', 'receipt-changed', 'terminal-interrupted', 'reopening-failed'])
def test_new_package_finishes_verified_previous_recovery_before_install(reuse_transaction, monkeypatch, problem):
    new_version = '3.0-1~deb13'
    events = reuse_transaction.events
    monkeypatch.setattr(install, 'wait_health', lambda: None)
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    recovery_root = journal.path.parent.parent / 'recovery'
    old_seal = recovery_root / 'old/recovery.json'
    old_seal.write_text(json.dumps({'python': '/accepted/python', 'manifest_sha256': 'old-digest'}))
    journal.value.update(status='candidate_testing', step='before', candidate='new', testing_release='old',
                         schema_changed=True, recovery_in_progress=True, checkpoint_restored=problem != 'not-restored',
                         failure_reason_code='native_upgrade_pg_busy', dotnet_coordinator=True,
                         recovery_sha256=upgrade.digest(old_seal))
    if problem == 'terminal-interrupted':
        journal.value.update(status='rolled_back', step='after', accepted_release='old')
    journal.write()
    if problem == 'terminal-interrupted':
        upgrade.publish(journal, 'rolled_back')
    else:
        upgrade.publish(journal, 'failed', terminal=False, reason_code='native_upgrade_recovery_pending')
    if problem == 'receipt-changed':
        path = upgrade.checkpoint_root(journal) / 'integrity-verified.json'
        path.write_text('{}')
    monkeypatch.setattr(preinstall, 'recovery_required', lambda: True)
    monkeypatch.setattr(upgrade, 'RECOVERY', recovery_root)
    monkeypatch.setattr(upgrade, 'check_checkpoint_space', lambda: events.append('space-checked'))
    monkeypatch.setattr(upgrade, 'restore_checkpoint', lambda *a: pytest.fail('recovery must not replay a restore'))
    monkeypatch.setattr(install, 'trusted_path', lambda path: path)
    old_package_metadata = upgrade.package_metadata
    monkeypatch.setattr(upgrade, 'package_metadata', lambda root: (
        old_package_metadata(root) if root.name == 'old' else {'version': new_version}))

    def subprocess_run(argv, **kwargs):
        if argv[0] == '/usr/bin/dpkg':
            assert argv[1:] == ['--compare-versions', new_version, 'gt', VERSION]
        elif argv[0] == '/usr/bin/dpkg-deb':
            if argv[1] != '--extract':
                assert argv[-1] == 'candidate.deb'
                return SimpleNamespace(stdout=f'sli-release-next\n{new_version}\n')
            root = Path(argv[-1]) / 'opt/sli/releases/next/deploy/linux'
            root.mkdir(parents=True)
            (root / 'native_upgrade.py').write_text('# new kit coordinator')
        else:
            assert argv[:3] == ['/accepted/python', '-I', '-B']
            assert Path(argv[3]).read_text() == '# new kit coordinator'
            assert argv[4:] == ['finish-package-recovery', new_version, journal.path.name]
            events.append('candidate-coordinator')
            upgrade.finish_package_recovery(new_version, journal.path.name)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(upgrade.subprocess, 'run', subprocess_run)
    if problem == 'not-restored':
        upgrade.check_package_space(new_version, 'candidate.deb')
        with pytest.raises(RuntimeError, match='native_transaction_pending'):
            upgrade.prepare_package(new_version)
        assert 'candidate-coordinator' not in events
        return
    if problem == 'receipt-changed':
        with pytest.raises(RuntimeError, match='native_upgrade_checkpoint_unverified'):
            upgrade.check_package_space(new_version, 'candidate.deb')
        assert 'switch-old' not in events
        return
    if problem == 'reopening-failed':
        def fail_schedule(schedule):
            raise RuntimeError('native_install_command_failed')

        with monkeypatch.context() as interrupted:
            interrupted.setattr(install, 'start_backup_schedule', fail_schedule)
            with pytest.raises(RuntimeError, match='native_install_command_failed'):
                upgrade.check_package_space(new_version, 'candidate.deb')
        result = json.loads((journal.path / 'result.json').read_text())
        assert result['terminal'] is False and result['writers_fenced'] is True
        assert result['reason_code'] == 'native_upgrade_recovery_pending'
    upgrade.check_package_space(new_version, 'candidate.deb')
    result = json.loads((journal.path / 'result.json').read_text())
    assert result['status'] == 'rolled_back' and result['terminal'] is True and result['services_restored'] is True
    assert result['accepted_release'] == 'old'
    assert events.index('candidate-coordinator') < events.index('acceptance') < events.index('space-checked')

    monkeypatch.setattr(install, 'setup_deadline', nullcontext)
    upgrade.prepare_package(new_version)
    upgrade.configure_package('new', new_version)
    assert upgrade.package_transaction(new_version).value['status'] == 'committed'
    assert upgrade.package_transaction(VERSION).value['status'] == 'rolled_back'


@pytest.mark.parametrize(('api_starts', 'rollback_query'), [(True, False), (False, False), (False, True)])
def test_package_upgrade_api_readiness_controls_checkpoint_restore(
        reuse_transaction, monkeypatch, capsys, api_starts, rollback_query):
    from urllib.error import URLError

    events = reuse_transaction.events
    clock = [0]
    started = [0]
    probes = []
    runtime_running = False
    previous_ready = False

    def systemctl(argv, **kwargs):
        nonlocal runtime_running
        if argv == ['systemctl', 'start', 'sli-dotnet.target']:
            started[0] = clock[0]
            runtime_running = True
        events.append(argv)

    def urlopen(url, **kwargs):
        nonlocal previous_ready
        release = next(event for event in reversed(events) if isinstance(event, str) and event.startswith('switch-'))
        if release == 'switch-new':
            elapsed = clock[0] - started[0]
            probes.append(elapsed)
            if elapsed < 5 or not api_starts:
                raise URLError(ConnectionRefusedError())
        else:
            previous_ready = True
        return nullcontext(SimpleNamespace(status=200))

    monkeypatch.setattr(install, 'setup_deadline', nullcontext)
    monkeypatch.setattr(install, 'wait_health', lambda: None)
    upgrade.prepare_package(VERSION)
    monkeypatch.setattr(upgrade, 'start_checked', START_CHECKED)
    monkeypatch.setattr(install, 'wait_health', lambda *, check_services: check_services())
    monkeypatch.setattr(install, 'command', systemctl)
    monkeypatch.setattr(install.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(install.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(operation_wait, 'readiness_history', lambda: None)
    monkeypatch.setattr('ssl.create_default_context', lambda **kwargs: object())
    monkeypatch.setattr('urllib.request.urlopen', urlopen)
    monkeypatch.setattr(runtime, 'configuration', lambda: {'health_url': 'https://192.0.2.10:443/api/health/ready'})
    monkeypatch.setattr(runtime, 'selected', lambda config: ('api',))
    monkeypatch.setattr(runtime, 'systemd', lambda service: {'ActiveState': 'active', 'MainPID': '42'})
    monkeypatch.setattr(upgrade.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=1))

    if rollback_query:
        def stop_writers():
            nonlocal runtime_running
            runtime_running = False

        def database_quiet():
            assert not runtime_running
            if previous_ready:
                # A PostgreSQL backend can still be unwinding after its worker exits.
                raise RuntimeError('native_upgrade_pg_busy')
            events.append('database-quiet')

        monkeypatch.setattr(upgrade, 'fence', FENCE)
        monkeypatch.setattr(upgrade, 'stop_application', STOP_APPLICATION)
        monkeypatch.setattr(upgrade, 'unit_state', lambda unit: {'LoadState': 'loaded', 'ActiveState': 'inactive'})
        monkeypatch.setattr(runtime, 'stop_services', lambda *args, **kwargs: None)
        monkeypatch.setattr(runtime, 'stop_writers', stop_writers)
        monkeypatch.setattr(upgrade, 'wait_restore_databases', lambda: None)
        monkeypatch.setattr(upgrade, 'database_quiet', database_quiet)

    if api_starts:
        upgrade.configure_package('new', VERSION)
    else:
        with pytest.raises(install.UnitCommandFailure, match='^native_install_api_unready$'):
            upgrade.configure_package('new', VERSION)

    journal = upgrade.package_transaction(VERSION)
    result = json.loads((journal.path / 'result.json').read_text())
    assert result['terminal'] and result['services_restored']
    assert probes[:3] == [0, 1, 3]
    reasons = [line for line in capsys.readouterr().err.splitlines() if line.startswith('native_upgrade_rollback ')]
    if api_starts:
        assert result['status'] == 'committed' and result['accepted_release'] == 'new'
        assert 'restore-checkpoint' not in events and not reasons
    else:
        assert result['status'] == 'rolled_back' and result['accepted_release'] == 'old'
        assert result['reason_code'] == 'native_install_api_unready'
        assert events.index('restore-checkpoint') < events.index('switch-old')
        assert reasons == ['native_upgrade_rollback reason_code=native_install_api_unready']
        assert previous_ready and runtime_running
        assert ['systemctl', 'enable', '--now', 'sli.target'] in events
        if rollback_query:
            assert events.index('database-quiet') < events.index('restore-checkpoint')


@pytest.fixture
def backup_schedule_fixture(preparation, monkeypatch):
    timer = SimpleNamespace(state='disabled', active=False, condition=True)
    events = preparation.events
    fence = upgrade.fence

    def inspect(argv, **kwargs):
        assert argv[:3] == ['systemctl', 'show', 'sli-backup.timer']
        events.append('backup-schedule-read')
        if timer.state == 'not-found':
            return SimpleNamespace(returncode=1, stdout='LoadState=not-found\n')
        load_state = 'masked' if timer.state == 'masked' else 'loaded'
        return SimpleNamespace(returncode=0, stdout=f'LoadState={load_state}\nUnitFileState={timer.state}\n')

    def stop():
        timer.active = False
        fence()

    def command(argv, **kwargs):
        events.append(argv)
        if 'sli-backup.timer' not in argv or argv[1] == 'stop':
            return
        if timer.state == 'masked':
            raise RuntimeError('synthetic masked timer')
        if argv[1] == 'enable':
            timer.state = 'enabled'
        if argv[1] == 'start' or '--now' in argv:
            timer.active = timer.condition

    monkeypatch.setattr(install.subprocess, 'run', inspect)
    monkeypatch.setattr(install, 'backup_schedule', READ_BACKUP_SCHEDULE)
    monkeypatch.setattr(upgrade, 'fence', stop)
    monkeypatch.setattr(install, 'command', command)
    return timer


@pytest.mark.parametrize(('state', 'condition', 'running'), [
    ('disabled', True, False), ('enabled', True, True),
    ('enabled', False, False), ('masked', True, False), ('not-found', True, False),
])
def test_upgrade_preserves_backup_schedule_and_captures_checkpoint(
        reuse_transaction, backup_schedule_fixture, state, condition, running):
    timer = backup_schedule_fixture
    timer.state, timer.active, timer.condition = state, running, condition
    upgrade.reuse_existing('new')
    journal = upgrade.package_transaction(VERSION)
    assert journal.value['status'] == 'committed' and journal.value['services_restored'] is True
    assert (timer.state, timer.active) == (state, running)
    assert journal.value['backup_schedule'] == state
    events = reuse_transaction.events
    assert events.index('backup-schedule-read') < events.index('fence') < events.index('capture')
    assert events.count('acceptance') == 2
    assert upgrade.checkpoint_receipt(journal)['status'] == 'integrity_verified'


def test_legacy_stopped_timer_stays_disabled_on_package_roll_back(
        reuse_transaction, backup_schedule_fixture, monkeypatch):
    monkeypatch.setattr(install, 'wait_health', lambda: None)
    upgrade.prepare_package(VERSION)
    journal = upgrade.package_transaction(VERSION)
    journal.value.pop('backup_schedule', None)
    journal.write()
    reuse_transaction.events.clear()
    acceptance = upgrade.start_checked

    def fail_candidate(*args):
        if 'restore-checkpoint' not in reuse_transaction.events:
            raise RuntimeError('native_install_api_unready')
        acceptance(*args)

    monkeypatch.setattr(upgrade, 'start_checked', fail_candidate)
    with pytest.raises(RuntimeError, match='native_install_api_unready'):
        upgrade.configure_package('new', VERSION)
    journal = upgrade.package_transaction(VERSION)
    assert journal.value['status'] == 'rolled_back' and journal.value['services_restored'] is True
    assert (backup_schedule_fixture.state, backup_schedule_fixture.active) == ('disabled', False)
    assert reuse_transaction.events.index('backup-schedule-read') < reuse_transaction.events.index('candidate-units')
    assert 'capture' not in reuse_transaction.events


def test_resume_after_fence_failure_preserves_masked_backup(
        preparation, backup_schedule_fixture, monkeypatch):
    backup_schedule_fixture.state = 'masked'
    fence, start = upgrade.fence, upgrade.start_checked

    def failed_fence():
        fence()
        fail_fence()

    monkeypatch.setattr(upgrade, 'fence', failed_fence)
    monkeypatch.setattr(upgrade, 'start_checked', lambda: (_ for _ in ()).throw(RuntimeError('failed readiness')))
    with pytest.raises(RuntimeError, match='native_upgrade_restart_failed'):
        upgrade.prepare_package(VERSION)
    monkeypatch.setattr(upgrade, 'start_checked', start)
    result = upgrade.resume_package(VERSION)
    assert result['services_restored'] is True and result['backup_schedule'] == 'masked'
    assert ['systemctl', 'start', 'sli.target', 'sli-health.timer'] in preparation.events
    assert preparation.events.count('backup-schedule-read') == 1
    assert backup_schedule_fixture.state == 'masked' and not backup_schedule_fixture.active


def test_reuse_prepared_resume_keeps_new_coordinator_identity(reuse_transaction):
    upgrade.prepare('new', TX, target_version=VERSION, previous_version='1.0-1~deb13', reuse_existing=True)
    assert upgrade.resume_package(VERSION)['status'] == 'checkpoint_verified'
    assert reuse_transaction.events.count('capture') == 1


def test_reuse_refuses_stale_previous_version_before_starting_databases(reuse_transaction):
    with pytest.raises(RuntimeError, match='native_upgrade_intent_mismatch'):
        upgrade.prepare('new', TX, target_version=VERSION, previous_version='0.1-1~deb13', reuse_existing=True)
    assert reuse_transaction.events == ['receipt']


def test_reuse_unauthorized_migration_never_starts_databases(reuse_transaction, monkeypatch):
    def refuse(*args):
        raise RuntimeError('native_upgrade_migration_not_authorized')
    monkeypatch.setattr(upgrade, 'migration_required', refuse)
    with pytest.raises(RuntimeError, match='native_upgrade_migration_not_authorized'):
        upgrade.reuse_existing('new')
    assert reuse_transaction.events == ['receipt']


def test_reuse_failed_verification_never_migrates_and_restores_old_services(reuse_transaction, monkeypatch):
    def refuse(*args, **kwargs):
        raise RuntimeError('native_upgrade_checkpoint_unverified')
    monkeypatch.setattr(native, 'verify', refuse)
    with pytest.raises(RuntimeError, match='native_upgrade_checkpoint_unverified'):
        upgrade.reuse_existing('new')
    journal = upgrade.package_transaction(VERSION)
    assert journal.value['status'] == 'aborted_before_checkpoint'
    assert journal.value['services_restored'] is True
    assert 'candidate-units' not in reuse_transaction.events
    assert not any(isinstance(item, list) and 'migrate' in item for item in reuse_transaction.events)


def test_reuse_cli_failure_reports_resumable_version_without_duplicate_launch(reuse_transaction, monkeypatch, capsys):
    root = install.inventory('new')[0]
    monkeypatch.setattr(upgrade, '__file__', str(root / 'deploy/linux/native_upgrade.py'))
    monkeypatch.setattr(upgrade.sys, 'executable', '/accepted/python')
    monkeypatch.setattr(upgrade.sys, 'path', list(upgrade.sys.path))
    def refuse(*args, **kwargs):
        raise RuntimeError('native_upgrade_checkpoint_unverified')
    monkeypatch.setattr(native, 'verify', refuse)
    assert upgrade.main(['reuse-existing', 'new']) == 1
    output = capsys.readouterr().err
    assert f'sudo sli-native-upgrade resume-package {VERSION}' in output
    assert 'launch resume-package' not in output
