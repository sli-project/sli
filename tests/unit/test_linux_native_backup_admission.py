"""Portable native drill admission; disposable DBs and POSIX snapshots are faked."""
import json
import shutil
from contextlib import contextmanager, nullcontext
from types import SimpleNamespace

import pytest

from deploy.linux import backup, backup_policy as policy, native_backup as native, native_host
from deploy.linux import native_clickhouse_endpoint as clickhouse, restore_existing, update_checkpoint
from tests.unit.test_linux_native_backup import recovery_set


@pytest.fixture
def drill_storage(tmp_path, monkeypatch):
    root = tmp_path / 'backups'
    selected = recovery_set(root, '20261031T010000.000000Z')
    drills, data = tmp_path / 'drills', tmp_path / 'data'
    data.mkdir()
    events = []
    monkeypatch.setattr(native, 'ROOT', root)
    monkeypatch.setattr(native, 'DRILLS', drills)
    monkeypatch.setattr(native, 'DATA', data)
    monkeypatch.setattr(native_host, 'MOUNT', str(data))
    monkeypatch.setattr(clickhouse, 'database_directory', lambda: '/var/lib/sli-db')
    monkeypatch.setattr(clickhouse, 'site_configuration', dict)
    monkeypatch.setattr(backup, 'backup_lock', lambda root: nullcontext())
    monkeypatch.setattr(backup, 'size_bytes', lambda path: policy.GIB)
    monkeypatch.setattr(native, 'ensure_directory', lambda path, mode, **kw:
                        path.mkdir(parents=True, exist_ok=kw.get('exist_ok', True)))

    @contextmanager
    def snapshot(root, name, **kwargs):
        private = root / '.private'
        shutil.copytree(root / name, private)
        try:
            yield private, None
        finally:
            shutil.rmtree(private)

    @contextmanager
    def databases(work, *, cleanup):
        events.append('start')
        try:
            yield {}
        finally:
            events.append('stopped')
            cleanup['databases_stopped'] = True

    def restore(data, private, manifest, components, *, files_root):
        assert private != selected and data.is_relative_to(private)
        assert components == ('postgres', 'files') and files_root.is_relative_to(drills)
        events.append('restore')

    monkeypatch.setattr(update_checkpoint, 'snapshot', snapshot)
    monkeypatch.setattr(native, 'copy_private', shutil.copytree)
    monkeypatch.setattr(native, 'isolated_databases', databases)
    monkeypatch.setattr(restore_existing, 'restore_components', restore)
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext('synthetic'))
    connection = SimpleNamespace(execute=lambda query: SimpleNamespace(fetchall=list))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a: nullcontext(connection))
    monkeypatch.setattr(native, 'prune', lambda *a: events.append('prune'))
    monkeypatch.setattr(native, 'publish_summary', lambda *a: events.append('summary'))
    return SimpleNamespace(root=root, selected=selected, data=data, drills=drills, events=events)


@pytest.mark.parametrize('checkpoint,backup_root,separate,work_separate,directory,free,expected', [
    # 2 GiB private copies + 1228 B PG + 10 GiB margin,
    # plus the existing 1 GiB live-data reserve for colocated copies.
    (True, False, False, False, True, 13 * policy.GIB + 1228, 'restore_verified'),
    (True, False, False, False, True, 13 * policy.GIB + 1227, 'insufficient_backup_disk_space'),
    (True, False, False, False, True, 0, 'insufficient_data_disk_space'),
    (True, True, True, False, True, 12 * policy.GIB + 1228, 'restore_verified'),
    (True, True, True, False, True, 12 * policy.GIB + 1227, 'insufficient_backup_disk_space'),
    (True, True, True, False, False, 100 * policy.GIB, 'restore_verified'),
    (True, True, False, False, True, 100 * policy.GIB, 'restore_volume_mismatch'),
    (True, False, False, False, False, 100 * policy.GIB, 'restore_volume_mismatch'),
    (True, False, False, True, True, 100 * policy.GIB, 'restore_verified'),
    (False, False, False, False, True, 100 * policy.GIB, 'restore_volume_mismatch'),
    (False, True, True, False, True, 100 * policy.GIB, 'restore_verified'),
], ids=['local-at-capacity', 'local-one-byte-short', 'local-data-full',
        'separate-at-capacity', 'separate-one-byte-short', 'separate-uuid-install',
        'configured-volume-colocated', 'uuid-install-colocated', 'work-on-separate-volume',
        'daily-local-refused', 'daily-separate-verified'])
def test_drill_admits_only_upgrade_local_copy_with_space(drill_storage, monkeypatch, checkpoint,
                                                        backup_root, separate, work_separate,
                                                        directory, free, expected):
    store = drill_storage
    monkeypatch.setattr(clickhouse, 'site_configuration', lambda: {'backup_root': '/mnt/backup'} if backup_root else {})
    monkeypatch.setattr(clickhouse, 'database_directory', lambda: '/var/lib/sli-db' if directory else None)

    def filesystem(path):
        if path == store.data:
            return 'data'
        if work_separate and path.is_relative_to(store.drills):
            return 'other'
        return 'backup' if separate else 'data'

    monkeypatch.setattr(policy, 'filesystem', filesystem)
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda path: SimpleNamespace(free=free))

    def run():
        if checkpoint:
            return native.drill_locked(store.selected, store.root, prune_sets=False, upgrade_checkpoint=True)
        return native.drill()

    if expected == 'restore_verified':
        result = run()
        assert result['terminal'] is True and result['databases_stopped'] is True
        assert store.events == ['start', 'restore', 'stopped'] + ([] if checkpoint else ['prune', 'summary'])
        assert json.loads((store.root / 'restore-verified.json').read_text()) == result
        history = json.loads((store.data / 'backup-status/summary.json').read_text())
        assert history['operation_durations']['drill'] == [max(result['duration_seconds'], 0.001)]
    else:
        with pytest.raises(RuntimeError, match='^native_drill_' + expected + '$'):
            run()
        assert store.events == [] and not store.drills.exists()
        assert not (store.root / 'restore-verified.json').exists()
    result = json.loads((store.root / 'drill-result.json').read_text())
    assert result['terminal'] is True
    assert result['status'] == ('restore_verified' if expected == 'restore_verified' else 'failed')


def test_postgres_only_backup_verifies_without_clickhouse_archives(drill_storage, monkeypatch):
    store = drill_storage
    selected = recovery_set(store.root, '20261031T020000.000000Z', legacy_clickhouse=False)
    monkeypatch.setattr(native, 'capture_volume_admission', lambda *a, **k: {'status': 'admitted'})
    monkeypatch.setattr(policy, 'filesystem', lambda path: 'synthetic')
    result = native.drill_locked(selected, store.root, prune_sets=False, upgrade_checkpoint=True)
    assert result['status'] == 'restore_verified'
    assert result['verified_components'] == ['postgres', 'files']
    assert not list(selected.rglob('*.zip'))
