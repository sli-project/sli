"""Space budgets use logical DB sizes and compressed sets, never WAL x4."""
import json
import zipfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup_policy as policy, native_host as host
from deploy.linux import native_backup, native_install, native_preinstall, native_runtime, native_upgrade
from deploy.linux import backup, backup_restore_check, restore_existing

GIB = policy.GIB


def test_checkpoint_budget_uses_compressed_copy_and_drill_formula():
    budget = policy.space_estimate(76 * GIB, backup_bytes=16 * GIB)
    assert budget['drill_bytes'] == 32 * GIB + 76 * GIB * 12 // 10 + 10 * GIB
    assert budget['checkpoint_bytes'] == 16 * GIB + budget['drill_bytes']
    assert 149 * GIB < budget['checkpoint_bytes'] < 150 * GIB
    assert budget['checkpoint_bytes'] < (76 * 4 + 1) * GIB / 2


def test_small_first_install_and_clickhouse_already_compressed():
    budget = policy.space_estimate(GIB, expanded_ch_bytes=GIB, files_bytes=GIB)
    assert budget['backup_bytes'] == 3 * GIB
    assert 22 * GIB < budget['checkpoint_bytes'] < 23 * GIB
    assert 14 * GIB < policy.space_estimate(GIB)['checkpoint_bytes'] < 15 * GIB


def test_native_capture_budget_excludes_retained_clickhouse_data(tmp_path, monkeypatch):
    machine = host.Host(tmp_path)
    databases = machine.path(host.MOUNT)
    files = machine.path('/var/lib/sli')
    monkeypatch.setattr(policy, 'tree_bytes', lambda path, **kwargs:
                        4 * GIB if path == databases / 'clickhouse' else 2 * GIB if path == files else 0)
    monkeypatch.setattr(policy, 'last_backup_size', lambda root, **kwargs: 16 * GIB)
    monkeypatch.setattr(machine, 'backup_machine_id', lambda: 'synthetic')
    estimate = machine.backup_space_estimate(tmp_path / 'backups', pg_bytes=10 * GIB)
    # Complete set + file-source copy + reserve.
    assert estimate['capture_bytes'] == (16 + 2 + 1) * GIB


@pytest.mark.parametrize('protected', ['/var/lib/sli/state', '/var/lib/sli/recovery',
                                     '/etc/sli/clickhouse', '/etc/postgresql/18/sli'])
def test_first_capture_refuses_space_missing_protected_companion(tmp_path, monkeypatch, capsys, protected):
    machine = host.Host(tmp_path)
    source, data = machine.path('/mnt/copies'), machine.path(host.MOUNT)
    source.mkdir(parents=True)
    data.mkdir(parents=True)
    monkeypatch.setattr(policy, 'tree_bytes', lambda path, **kwargs:
                        2 * GIB if path == machine.path(protected) else 0)
    monkeypatch.setattr(machine, 'backup_machine_id', lambda: 'synthetic')
    monkeypatch.setattr(machine, 'backup_trusted', lambda path: None)
    monkeypatch.setattr(machine, 'backup_device', lambda path: 1 if path == data else 2)
    monkeypatch.setattr(machine, 'backup_free', lambda path: 3 * GIB // 2)
    with pytest.raises(host.HostError, match='native_backup_root_insufficient_space'):
        machine.validate_backup_root('/mnt/copies')
    assert f'required={3 * GIB} bytes' in capsys.readouterr().out
    assert not list(source.iterdir())


@pytest.mark.parametrize('latest,expected', [(11, 14), (13, 18)])
def test_backup_history_projects_current_companion_without_double_counting_growth(tmp_path, monkeypatch,
                                                                                 latest, expected):
    amounts = {}
    for day, size, companion in [(1, 10, 1), (2, latest, 2)]:
        path = tmp_path / f'2026110{day}T010000.000000Z'
        path.mkdir()
        (path / 'manifest.json').write_text(json.dumps({'status': 'backup_created', 'backup_id': path.name,
                                                       'machine_id': 'synthetic', 'size_bytes': size * GIB}))
        amounts[path] = size * GIB
        amounts[path / 'companion'] = companion * GIB
    monkeypatch.setattr(policy, 'tree_bytes', lambda path, **kwargs: amounts.get(path, 0))
    assert policy.last_backup_size(tmp_path, machine_id='synthetic', companion_bytes=5 * GIB) == expected * GIB


def test_latest_successful_local_manifest_not_foreign_or_failed(tmp_path):
    for day, status, machine, size in [(1, 'backup_created', 'local', 16),
                                       (2, 'backup_created', 'foreign', 2),
                                       (3, 'failed', 'local', 1)]:
        path = tmp_path / f'202610{day:02}T010000.000000Z'
        path.mkdir()
        (path / 'manifest.json').write_text(json.dumps({
            'backup_id': path.name, 'status': status, 'machine_id': machine,
            'size_bytes': size * GIB}))
    assert policy.last_backup_size(tmp_path, machine_id='local') == 16 * GIB


def test_volume_budgets_sum_only_on_same_device(tmp_path):
    root, work = tmp_path / 'copy', tmp_path / 'drill'
    estimate = policy.space_estimate(76 * GIB, backup_bytes=16 * GIB)
    same = policy.space_requirements(root, work, estimate, device=lambda p: 1)
    assert sum(same.values()) == estimate['checkpoint_bytes']
    separate = policy.space_requirements(root, work, estimate, device=lambda p: p)
    assert separate[root] == 2 * 16 * GIB
    assert separate[work] == estimate['drill_bytes'] - 16 * GIB


def test_refusal_shows_bytes_volume_and_old_sets(capsys):
    policy.report_refusal({'reason': 'insufficient_backup_disk_space', 'volume': '/mnt/copies',
                           'required_bytes': 12345, 'free_bytes': 12344})
    message = capsys.readouterr().out
    assert '12345' in message and '12344' in message and '/mnt/copies' in message
    assert 'старые наборы' in message and 'old backup sets' in message


def test_host_admission_uses_capture_only_budget(tmp_path, monkeypatch, capsys):
    machine = host.Host(tmp_path)
    source = machine.path('/mnt/copies')
    source.mkdir(parents=True)
    machine.path(host.MOUNT).mkdir(parents=True)
    budget = policy.space_estimate(76 * GIB, backup_bytes=16 * GIB)
    monkeypatch.setattr(machine, 'backup_trusted', lambda p: None)
    monkeypatch.setattr(machine, 'backup_device', lambda p: 1 if p == machine.path(host.MOUNT) else 2)
    monkeypatch.setattr(machine, 'backup_space_estimate', lambda p: budget)
    monkeypatch.setattr(machine, 'backup_free', lambda p: budget['capture_bytes'])
    assert machine.validate_backup_root('/mnt/copies') == source
    monkeypatch.setattr(machine, 'backup_free', lambda p: budget['capture_bytes'] - 1)
    with pytest.raises(host.HostError, match='native_backup_root_insufficient_space'):
        machine.validate_backup_root('/mnt/copies')
    message = capsys.readouterr().out
    assert str(budget['capture_bytes']) in message and str(source) in message


@pytest.mark.parametrize('early_shortfall,late_shortfall', [(0, 0), (1, 1), (0, 1)])
def test_prepare_and_host_agree_with_real_manifest(tmp_path, monkeypatch, capsys, early_shortfall, late_shortfall):
    machine = host.Host(tmp_path)
    source = machine.path('/mnt/copies')
    root = source / 'native'
    selected = root / '20261031T010000.000000Z'
    selected.mkdir(parents=True)
    (selected / 'manifest.json').write_text(json.dumps({
        'backup_id': selected.name, 'status': 'backup_created', 'size_bytes': 16 * GIB}))
    data = machine.path(host.MOUNT)
    data.mkdir(parents=True)
    monkeypatch.setattr(policy, 'tree_bytes', lambda p, **kw: 76 * GIB if p == data else 0)
    estimate = machine.backup_space_estimate(root)
    free = estimate['capture_bytes'] - early_shortfall
    monkeypatch.setattr(machine, 'backup_trusted', lambda p: None)
    monkeypatch.setattr(machine, 'backup_device', lambda p: 1 if p == data else 2)
    monkeypatch.setattr(machine, 'backup_free', lambda p: free)
    volume_checks = []

    def disk_usage(path):
        volume_checks.append(path)
        return SimpleNamespace(free=free)

    monkeypatch.setattr(policy.shutil, 'disk_usage', disk_usage)
    monkeypatch.setattr(host, 'Host', lambda: machine)
    monkeypatch.setattr(native_backup, 'ROOT', root)
    monkeypatch.setattr(native_backup, 'DRILLS', source / 'restore-check')
    monkeypatch.setattr(native_upgrade, 'TRANSACTIONS', tmp_path / 'transactions')
    monkeypatch.setattr(native_upgrade, 'systemd_available', lambda: False)
    monkeypatch.setattr(native_upgrade, 'operation_lock', lambda p: nullcontext())
    monkeypatch.setattr(native_upgrade, 'preflight', lambda: (Path('/old'), Path('/recovery')))
    monkeypatch.setattr(native_preinstall, 'recovery_required', lambda: True)
    monkeypatch.setattr(native_runtime, 'release', lambda: (Path('/old'), {}, ''))
    monkeypatch.setattr(native_upgrade, 'package_metadata', lambda p: {'version': '1.0-1~deb13'})
    monkeypatch.setattr(native_runtime, 'no_transaction', lambda: None)
    monkeypatch.setattr(native_runtime, 'stop_writers', lambda: pytest.fail('admission must leave writers running'))
    monkeypatch.setattr(native_install, 'command', lambda *args: pytest.fail('admission must not change services'))
    monkeypatch.setattr(native_install, 'wait_health', lambda: None)
    monkeypatch.setattr(native_install, 'backup_schedule', lambda: 'disabled')

    class AdmissionComplete(Exception):
        pass

    def after_admission(*args, **kwargs):
        raise AdmissionComplete

    monkeypatch.setattr(native_upgrade, 'ensure_directory', after_admission)
    if early_shortfall:
        with pytest.raises(host.HostError, match='insufficient_space'):
            machine.validate_backup_root('/mnt/copies')
        with pytest.raises(RuntimeError, match='native_upgrade_insufficient_space'):
            native_upgrade.check_package_space('1.0-2~deb13')
    else:
        assert machine.validate_backup_root('/mnt/copies') == source
        native_upgrade.check_package_space('1.0-2~deb13')
    free = estimate['capture_bytes'] - late_shortfall
    if late_shortfall:
        with pytest.raises(RuntimeError, match='native_upgrade_insufficient_space'):
            native_upgrade.prepare('new', 'a' * 32)
        message = capsys.readouterr().out
        assert message.count(f'required={estimate["capture_bytes"]} bytes') == (3 if early_shortfall else 1)
        assert message.count(f'free={free} bytes') == (3 if early_shortfall else 1)
        assert f'volume={root}' in message
    else:
        with pytest.raises(AdmissionComplete):
            native_upgrade.prepare('new', 'a' * 32)
    assert volume_checks == [root, root]
    assert not (tmp_path / 'transactions').exists()


@pytest.mark.parametrize('installed,version,journal_status,restored,needs_space', [
    (False, '1.0-2~deb13', None, False, False),
    (True, '1.0-1~deb13', None, False, False),
    (True, '1.0-2~deb13', None, False, True),
    (True, '1.0-2~deb13', 'checkpoint_verified', False, False),
    (True, '1.0-2~deb13', 'rolled_back', True, False),
    (True, '1.0-2~deb13', 'aborted_before_checkpoint', False, False),
    (True, '1.0-2~deb13', 'aborted_before_checkpoint', True, True),
    (True, '1.0-2~deb13', 'committed', True, True),
])
def test_early_package_space_is_required_only_for_a_new_checkpoint(
        monkeypatch, installed, version, journal_status, restored, needs_space):
    monkeypatch.setattr(native_preinstall, 'recovery_required', lambda: installed)

    def release():
        assert installed
        return (Path('/old'), {}, '')

    monkeypatch.setattr(native_runtime, 'release', release)
    monkeypatch.setattr(native_upgrade, 'package_metadata', lambda p: {'version': '1.0-1~deb13'})
    journal = None
    if journal_status:
        journal = SimpleNamespace(value={'status': journal_status, 'services_restored': restored})
    monkeypatch.setattr(native_upgrade, 'latest_package_transaction', lambda version: journal)
    checks = []
    monkeypatch.setattr(native_upgrade, 'check_checkpoint_space', lambda: checks.append('checkpoint'))
    native_upgrade.check_package_space(version)
    assert checks == (['checkpoint'] if needs_space else [])


@pytest.mark.parametrize('free,expected', [(20, 'admitted'), (11, 'skipped')])
def test_drill_space_on_separate_work_volume(tmp_path, monkeypatch, free, expected):
    root, work = tmp_path / 'backups', tmp_path / 'work'
    root.mkdir()
    work.mkdir()
    monkeypatch.setattr(policy, 'filesystem', lambda p: 'work' if p.is_relative_to(work) else 'backups')
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda p: SimpleNamespace(
        free=free * GIB if p == work else 50 * GIB))
    result = policy.volume_admission(root, work, {'data': {'device': 'data', 'free_bytes': 2 * GIB}},
                                     32 * GIB, work_required=12 * GIB)
    assert result['status'] == expected
    if expected == 'skipped':
        assert result['volume'] == str(work)
        assert result['required_bytes'] == 12 * GIB and result['free_bytes'] == free * GIB


def test_unavailable_size_is_not_treated_as_empty(tmp_path, monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError('synthetic')
    monkeypatch.setattr(policy.os, 'walk', denied)
    with pytest.raises(PermissionError):
        policy.tree_bytes(tmp_path)


def test_first_capture_estimates_both_live_engines(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(policy, 'filesystem', lambda p: 'backup')
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda p: SimpleNamespace(free=48 * GIB))
    connection = SimpleNamespace(execute=lambda q: SimpleNamespace(fetchone=lambda: (76 * GIB,)))
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext('synthetic'))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a: nullcontext(connection))
    monkeypatch.setattr(backup, 'clickhouse_targets', lambda: [SimpleNamespace(
        query=lambda q: [{'size_bytes': 10 * GIB}])])
    monkeypatch.delenv('SLI_BACKUP_FILES_ROOT', raising=False)
    with pytest.raises(backup.BackupError, match='insufficient_backup_disk_space'):
        backup.backup_output_admission(tmp_path)
    text = capsys.readouterr().out
    assert f'required={87 * GIB} bytes' in text and f'free={48 * GIB} bytes' in text


@pytest.mark.parametrize('shortfall', [0, 1])
def test_known_backup_size_needs_no_database_credentials(tmp_path, monkeypatch, shortfall):
    selected = tmp_path / '20261031T010000.000000Z'
    selected.mkdir()
    backup.write_json(selected / 'manifest.json', {
        'backup_id': selected.name, 'status': 'success', 'size_bytes': 16 * GIB})
    monkeypatch.setattr(policy, 'filesystem', lambda p: 'backup')
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda p: SimpleNamespace(free=17 * GIB - shortfall))
    monkeypatch.setattr(backup, 'pg_passfile', lambda: pytest.fail('known size must not read credentials'))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a: pytest.fail('known size must not connect'))
    monkeypatch.setattr(backup, 'clickhouse_targets', lambda: pytest.fail('known size must not query'))
    if shortfall:
        with pytest.raises(backup.BackupError, match='insufficient_backup_disk_space'):
            backup.backup_output_admission(tmp_path)
    else:
        backup.backup_output_admission(tmp_path)


@pytest.mark.parametrize('override', [False, True])
def test_native_helper_admission_checks_its_restore_work_volume(tmp_path, monkeypatch, override):
    root, data = tmp_path / 'backups', tmp_path / 'data'
    root.mkdir()
    data.mkdir()
    monkeypatch.delenv('SLI_RESTORE_CHECK_ROOT', raising=False)
    if override:
        monkeypatch.setenv('SLI_RESTORE_CHECK_ROOT', str(tmp_path / 'checks'))
    work = policy.work_root(root)
    monkeypatch.setattr(backup, 'native_mode', lambda: True)
    connection = SimpleNamespace(execute=lambda q: SimpleNamespace(
        fetchone=lambda: ({'database_size_bytes': 1024},)))
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext('synthetic'))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a: nullcontext(connection))
    monkeypatch.setattr(backup, 'pg_capacity_paths', lambda p: {'data': str(data)})
    monkeypatch.setattr(host.Host, 'backup_space_estimate', lambda self, p, **kw: policy.space_estimate(1024))
    monkeypatch.setattr(native_backup, 'capture_volume_admission', policy.volume_admission)
    monkeypatch.setattr(policy, 'filesystem', lambda p: (
        'backup' if p.is_relative_to(root) or p.is_relative_to(work) else 'foreign'))
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda p: SimpleNamespace(free=100 * GIB))
    backup.capture_admission(root)
    assert not work.exists()


@pytest.mark.parametrize('kind', ['drill', 'restore'])
def test_clickhouse_refusal_uses_expanded_zip_and_reports_capacity(tmp_path, monkeypatch, capsys, kind):
    selected = tmp_path / '20261031T010000.000000Z'
    selected.mkdir()
    with zipfile.ZipFile(selected / 'history.zip', 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('synthetic', b'x' * 1024)
    component = {'archive': 'history.zip', 'databases': ['synthetic'], 'tables': {'synthetic': {}}}
    target = backup.ClickHouse('history', 'synthetic', 'synthetic', 'SYNTHETIC_PASSWORD')
    monkeypatch.setattr(backup.ClickHouse, 'query', lambda self, q: [
        {'free_space': 2 * GIB if kind == 'drill' and "'default'" in q else 100,
         'path': '/var/lib/clickhouse/restore-check/'}])
    if kind == 'drill':
        result = backup_restore_check.restore_clickhouse(target, selected, component)
        assert result['status'] == 'skipped_insufficient_space' and result['free_bytes'] == 100
    else:
        with pytest.raises(RuntimeError, match='linux_restore_clickhouse_insufficient_space'):
            restore_existing.restore_clickhouse(selected, tmp_path, target, component, replace_existing=False)
    text = capsys.readouterr().out
    assert f'required={GIB + 2048} bytes' in text and 'free=100 bytes' in text


def write_size_manifest(root, day, size, machine='local'):
    selected = root / f'202610{day:02}T010000.000000Z'
    selected.mkdir(parents=True)
    (selected / 'manifest.json').write_text(json.dumps({
        'backup_id': selected.name, 'status': 'backup_created',
        'machine_id': machine, 'size_bytes': size}))
    return selected


def test_manifest_cannot_understate_measured_set_size(tmp_path):
    selected = write_size_manifest(tmp_path, 1, 1)
    (selected / 'payload').write_bytes(b'x' * 4096)
    measured = sum(path.stat().st_size for path in selected.iterdir())
    assert policy.last_backup_size(tmp_path, machine_id='local') == measured


def test_large_native_manifest_requires_complete_local_inventory(tmp_path):
    selected = tmp_path / 'upgrade-checkpoints' / 'tx' / '20261001T010000.000000Z'
    data = selected / 'data' / selected.name
    data.mkdir(parents=True)
    backup.write_json(data / 'manifest.json', {
        'status': 'success', 'components': {'postgres': {}, 'files': {}}})
    companion = selected / 'companion'
    companion.mkdir()
    # Unicode names are escaped by the real JSON writer, which keeps this
    # fixture above 4 MiB with a modest number of small regular files.
    stem = '\u0444' * 65
    for index in range(8700):
        (companion / f'{stem}{index}').write_bytes(b'checkpoint data')
    manifest = {
        'schema_version': 1, 'backup_id': selected.name, 'status': 'backup_created',
        'machine_id': 'a' * 64, 'data_path': data.relative_to(selected).as_posix(),
        'created_at_utc': '2026-10-01T01:00:00+00:00',
        'size_bytes': backup.size_bytes(selected), 'database_size_bytes': 4096,
        'consistency_point': {'writers_fenced': True, 'capture_window_seconds': 1.0, 'mode': 'fenced'},
        'content_checksums': backup.content_inventory(selected),
    }
    path = selected / 'manifest.json'
    backup.write_json(path, manifest)
    raw = path.read_bytes()
    assert len(raw) > 4 * 1024**2
    assert policy.last_backup_size(tmp_path, machine_id='a' * 64) == policy.tree_bytes(selected)
    assert policy.last_backup_size(tmp_path, machine_id='b' * 64) is None

    path.write_bytes(raw[:-50])
    assert policy.last_backup_size(tmp_path, machine_id='a' * 64) is None

    first = manifest['content_checksums'][f'companion/{stem}0']['sha256'].encode('ascii')
    path.write_bytes(raw.replace(first, b'g' * 64, 1))
    assert policy.last_backup_size(tmp_path, machine_id='a' * 64) is None

    path.write_bytes(raw)
    (companion / f'{stem}0').unlink()
    assert policy.last_backup_size(tmp_path, machine_id='a' * 64) is None


@pytest.mark.parametrize('previous,latest,expected', [(15, 16, 17), (16, 15, 15)])
def test_local_history_adds_only_positive_growth(tmp_path, previous, latest, expected):
    write_size_manifest(tmp_path, 1, previous * GIB)
    write_size_manifest(tmp_path / 'upgrade-checkpoints' / 'release', 2, latest * GIB)
    write_size_manifest(tmp_path, 3, 100 * GIB, machine='foreign')
    assert policy.last_backup_size(tmp_path, machine_id='local') == expected * GIB


def test_unmeasurable_set_is_skipped_instead_of_using_manifest(tmp_path, monkeypatch):
    write_size_manifest(tmp_path, 1, 15 * GIB)
    selected = write_size_manifest(tmp_path, 2, 16 * GIB)
    measure = policy.tree_bytes

    def denied(path, **kwargs):
        if path == selected:
            raise PermissionError('synthetic')
        return measure(path, **kwargs)

    monkeypatch.setattr(policy, 'tree_bytes', denied)
    assert policy.last_backup_size(tmp_path, machine_id='local') == 15 * GIB


def test_set_measurement_does_not_follow_symlinks(tmp_path):
    selected = write_size_manifest(tmp_path, 1, 1)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'payload').write_bytes(b'x' * 4096)
    try:
        (selected / 'linked-directory').symlink_to(outside, target_is_directory=True)
        (selected / 'linked-file').symlink_to(outside / 'payload')
    except OSError:
        pytest.skip('symlink creation unavailable')
    assert policy.last_backup_size(tmp_path, machine_id='local') == (selected / 'manifest.json').stat().st_size
