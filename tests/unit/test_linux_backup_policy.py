"""T086 volume refusal, calendar retention and public summary contracts."""
# ruff: noqa: F811 -- imported pytest fixtures are intentionally named as parameters
from __future__ import annotations

import json
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup_policy as policy
from tests.unit.linux_backup_volumes import (
    volume_layout,  # noqa: F401 -- shared fixture
)


@pytest.fixture(autouse=True)
def hermetic_report_domain():
    # This module never loads report/domain settings or opens an application DB.
    yield


def test_defaults_and_invalid_retention(monkeypatch):
    monkeypatch.delenv('SLI_BACKUP_RETENTION', raising=False)
    monkeypatch.delenv('SLI_BACKUP_WEEKLY_RETENTION', raising=False)
    assert policy.retention_settings() == (7, 4)
    monkeypatch.setenv('SLI_BACKUP_WEEKLY_RETENTION', '-1')
    with pytest.raises(ValueError, match='invalid_retention'):
        policy.retention_settings()


def test_calendar_daily_weekly_slots_and_multiple_captures():
    start = datetime(2026, 9, 1, tzinfo=timezone.utc)
    paths = [Path((start + timedelta(days=i, hours=h)).strftime('%Y%m%dT%H%M%S.%fZ'))
             for i in range(55) for h in (1, 2)]
    keep = policy.retained_sets(paths, 7, 4)
    assert len(keep) == 11
    assert all(path.name[9:11] == '02' for path in keep)
    assert set(paths[-14:][1::2]) <= keep
    weekly = sorted(keep - set(paths[-14:][1::2]))
    assert len({datetime.strptime(p.name, '%Y%m%dT%H%M%S.%fZ').replace(tzinfo=timezone.utc).isocalendar()[:2]
                for p in weekly}) == 4
    assert policy.retained_sets(paths, 1, 0) == {paths[-1]}


def test_year_boundary_and_sparse_days():
    paths = [Path(s + 'T020000.000000Z') for s in ('20251221', '20251228', '20260104', '20260112')]
    assert policy.retained_sets(paths, 1, 2) == set(paths[-3:])


@pytest.mark.parametrize('backup_free,data_free,data_device,work_device,clickhouse_device,expected', [
    (0, 50, 'data-device', 'backup-device', 'backup-device', 'insufficient_backup_disk_space'),
    (50, 0, 'data-device', 'backup-device', 'backup-device', 'insufficient_data_disk_space'),
    (50, 50, 'backup-device', 'backup-device', 'backup-device', 'restore_volume_mismatch'),
    (50, 50, 'data-device', 'data-device', 'data-device', 'restore_volume_mismatch'),
    (50, 50, 'data-device', 'other-device', 'other-device', 'restore_volume_mismatch'),
    (50, 50, 'data-device', 'backup-device', 'data-device', 'restore_volume_mismatch'),
    (50, 50, 'data-device', 'backup-device', 'other-device', 'restore_volume_mismatch'),
    (50, 50, 'data-device', 'backup-device', 'backup-device', 'admitted'),
])
def test_admission_checks_both_volumes_without_any_writes(tmp_path, monkeypatch, capsys,
                                                         volume_layout, backup_free, data_free, data_device,
                                                         work_device, clickhouse_device, expected):
    data = tmp_path / 'data'
    data.mkdir()
    sentinel = data / 'PG_VERSION'
    sentinel.write_text('18')
    before = sentinel.stat()
    root = tmp_path / 'backups'
    root.mkdir()
    work = root / '.restore-check'
    volume_layout[data] = data_device
    volume_layout[root] = 'backup-device'
    volume_layout[work] = work_device
    volume_layout[work / 'clickhouse'] = clickhouse_device
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda path: SimpleNamespace(free=backup_free * policy.GIB))
    result = policy.volume_admission(root, work, {'data': {'device': data_device, 'free_bytes': data_free * policy.GIB}},
                                     10 * policy.GIB)
    assert result.get('reason', result['status']) == expected
    if expected != 'admitted':
        policy.report_refusal(result)
        message = capsys.readouterr().out
        assert expected in message and ' / ' in message
    assert not work.exists() and not list(root.iterdir())
    assert sentinel.read_text() == '18' and sentinel.stat().st_mtime_ns == before.st_mtime_ns


def test_default_workspace_and_capacity_unknown_is_not_zero(tmp_path, monkeypatch):
    monkeypatch.delenv('SLI_RESTORE_CHECK_ROOT', raising=False)
    assert policy.work_root(tmp_path) == tmp_path / '.restore-check'
    assert policy.capacity_days(20 * policy.GIB, []) is None
    assert policy.capacity_days(20 * policy.GIB, [2 * policy.GIB, 3 * policy.GIB]) == 6
    assert policy.capacity_days(0, [3 * policy.GIB]) == 0


def test_capture_space_requirements_do_not_reserve_drill(tmp_path):
    estimate = policy.space_estimate(100 * policy.GIB, backup_bytes=10 * policy.GIB,
                                    files_bytes=2 * policy.GIB)
    root, unused = tmp_path / 'backups', tmp_path / 'unavailable-work'
    result = policy.space_requirements(root, unused, estimate, include_drill=False,
        device=lambda path: pytest.fail('capture inspected an unused drill filesystem'))
    assert result == {root: 13 * policy.GIB}
    assert not root.exists() and not unused.exists()


@pytest.mark.parametrize('age,days', [(0, 5), (172801, None)])
def test_public_summary_exposes_only_dates_and_fresh_capacity(tmp_path, monkeypatch, age, days):
    from server.sli.storage.operations_storage import (
        backup_summary,
        load_operations_storage_snapshot,
    )

    path = tmp_path / 'summary.json'
    monkeypatch.setenv('SLI_BACKUP_SUMMARY_PATH', str(path))
    now = datetime.now(timezone.utc)
    path.write_text(json.dumps({'last_backup_at_utc': now.isoformat(), 'last_verified_at_utc': None,
                               'capacity_days': 5, 'observed_at_utc': (now - timedelta(seconds=age)).isoformat(),
                               'private_field': 'must-not-leave-reader'}))
    value = backup_summary()
    assert set(value) == {'last_backup_at_utc', 'last_verified_at_utc', 'capacity_days'}
    assert value['capacity_days'] == days and value['last_verified_at_utc'] is None
    # Backup dates remain visible even without a complete storage footprint.
    assert load_operations_storage_snapshot(tmp_path / 'absent.json')['backups'] == value


@pytest.mark.parametrize('body', ['[]', '{', 'x' * 4097])
def test_malformed_public_summary_never_fabricates_zero(tmp_path, monkeypatch, body):
    from server.sli.storage.operations_storage import backup_summary

    path = tmp_path / 'summary.json'
    path.write_text(body)
    monkeypatch.setenv('SLI_BACKUP_SUMMARY_PATH', str(path))
    assert backup_summary() == {'last_backup_at_utc': None, 'last_verified_at_utc': None, 'capacity_days': None}


def test_refusal_uses_real_restore_entrypoint_before_sandbox_or_source_mutations(tmp_path, monkeypatch,
                                                                              volume_layout):
    pytest.importorskip('psycopg')
    from deploy.linux import backup, restore_sandbox
    from deploy.linux import backup_restore_check as drill

    selected = tmp_path / '20261025T020000.000000Z'
    (selected / 'postgres').mkdir(parents=True)
    (selected / 'manifest.json').write_text(json.dumps({
        'components': {'postgres': {'row_counts': dict.fromkeys(backup.KEY_TABLES, 3),
                                    'database_size_bytes': 10 * policy.GIB}},
        'migration_ledger_max_version': 1,
    }))
    point = {'database_size_bytes': 10 * policy.GIB, 'cluster_id': '123456',
             'postmaster_start': '2026-10-25T00:00:00+00:00', 'data_directory': '/postgres/18/data',
             'tablespaces': [{'oid': 1663, 'location': ''}, {'oid': 1664, 'location': ''}]}
    backup.write_json(tmp_path / '.postgres-capacity.json', backup.pg_capacity_receipt(
        point, {name: {'device': 'ssd', 'free_bytes': 50 * policy.GIB}
                for name in backup.pg_capacity_paths(point)}, observed_at=backup.utc_now().isoformat()))
    volume_layout[tmp_path] = 'backup-device'
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda path: SimpleNamespace(free=0))
    queries = []

    def execute(query, params=()):
        queries.append(str(query))
        value = True if 'advisory' in str(query) else point
        return SimpleNamespace(fetchone=lambda: (value,))

    monkeypatch.setattr(backup, 'backup_lock', lambda *a, **kw: nullcontext())
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext('synthetic'))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **kw: nullcontext(SimpleNamespace(execute=execute)))
    monkeypatch.setattr(restore_sandbox, 'restore', lambda *a: pytest.fail('must not start a sandbox'))
    monkeypatch.setattr(drill, 'cleanup_owned_restores', lambda *a: pytest.fail('must not touch the live cluster'))
    result = drill.restore_check(tmp_path, selected=selected)
    assert result['reason'] == 'insufficient_backup_disk_space'
    assert queries == ['BEGIN READ ONLY', 'SELECT pg_try_advisory_lock(%s)', backup.PG_CAPACITY_SQL, 'SELECT pg_advisory_unlock(%s)']
    assert not (tmp_path / '.restore-check').exists()


def test_failed_capture_never_calls_prune(tmp_path, monkeypatch, volume_layout):
    pytest.importorskip('psycopg')
    from deploy.linux import backup

    monkeypatch.setattr(backup, 'clickhouse_targets', lambda: ())
    monkeypatch.setenv('SLI_DEPLOYMENT_MODE', 'docker')
    volume_layout[tmp_path] = 'backup-device'
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda path: SimpleNamespace(free=0))
    monkeypatch.setattr(backup, 'prune', lambda *a: pytest.fail('must not prune on refusal'))
    with pytest.raises(backup.BackupError, match='insufficient_backup_disk_space'):
        backup.capture_backup(tmp_path, 7, ('postgres',))
    assert not any(path.name.endswith('.partial') for path in tmp_path.iterdir())


@pytest.mark.parametrize('data_device,work_device,allowed', [
    ('data-device', 'backup-device', True),
    ('backup-device', 'backup-device', False),
    ('data-device', 'data-device', False),
    ('data-device', 'other-device', False),
])
def test_installation_validates_physical_volumes_before_creating_directories(tmp_path, monkeypatch,
                                                                           volume_layout,
                                                                           data_device, work_device, allowed):
    pytest.importorskip('psycopg')
    from deploy.linux import installation

    runtime, data, backups, work = (tmp_path / name for name in ('runtime', 'data', 'copies', 'checks'))
    volume_layout.update({data: data_device, backups: 'backup-device', work: work_device})
    environment = {'SLI_BACKUP_DIR': str(backups), 'SLI_DATA_DIR': str(data), 'SLI_RESTORE_CHECK_DIR': str(work)}
    if allowed:
        assert installation.restore_check_directory(runtime, environment) == work
    else:
        with pytest.raises(installation.UpdateError, match='separate_volume'):
            installation.restore_check_directory(runtime, environment)
    assert not any(path.exists() for path in (runtime, data, backups, work))


@pytest.mark.parametrize('child_device', ['backup-device', 'data-device', 'other-device'])
def test_installation_checks_clickhouse_volume_before_creating_child(tmp_path, monkeypatch,
                                                                    volume_layout, child_device):
    pytest.importorskip('cryptography')
    from deploy.linux import installation

    work = tmp_path / 'checks'
    child = work / 'clickhouse'
    volume_layout.update({work: 'backup-device', child: child_device})
    monkeypatch.setattr(installation.os, 'chown', lambda *args: None, raising=False)
    if child_device == 'backup-device':
        installation.prepare_restore_directory(work)
        assert child.is_dir()
    else:
        with pytest.raises(installation.UpdateError, match='separate_volume'):
            installation.prepare_restore_directory(work)
        assert not child.exists()


def test_volume_layout_resolves_declared_paths_through_symlinks(tmp_path, volume_layout):
    """A runner may expose /tmp through a symlink; declared children must still map to their volume."""
    real = tmp_path / 'real'
    real.mkdir()
    link = tmp_path / 'link'
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip('symlinks are not available')
    volume_layout[link / 'copies'] = 'backup-device'
    assert policy.device(link / 'copies' / 'checks') == 'backup-device'
    assert policy.device(real / 'copies') == 'backup-device'
