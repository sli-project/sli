"""Directory storage contracts; synthetic paths only, no real mounts."""
import json

import pytest

from deploy.linux import native_host as host


@pytest.fixture
def directory(tmp_path, monkeypatch):
    machine = host.Host(tmp_path)
    source = machine.path('/var/lib/sli-db')
    source.mkdir(parents=True)
    monkeypatch.setattr(machine, 'backup_trusted', lambda path: None)
    monkeypatch.setattr(machine, 'backup_free', lambda path: 30 * 1024**3)
    monkeypatch.setattr(host, 'run', lambda argv: json.dumps({'filesystems': [
        {'target': '/', 'fstype': 'ext4', 'options': 'rw,relatime'}]}))
    return machine, source


def test_directory_storage_accepts_existing_local_filesystem(directory):
    machine, source = directory
    assert machine.validate_database_directory('/var/lib/sli-db') == source


@pytest.mark.parametrize('filesystem', ['tmpfs', 'nfs', 'overlay', 'btrfs'])
def test_directory_rejects_unsupported_filesystem(directory, monkeypatch, filesystem):
    machine, _ = directory
    monkeypatch.setattr(host, 'run', lambda argv: json.dumps({'filesystems': [
        {'fstype': filesystem, 'options': 'rw'}]}))
    with pytest.raises(host.HostError, match='native_database_filesystem_unsupported'):
        machine.validate_database_directory('/var/lib/sli-db')


def test_directory_refuses_low_space_before_creating_data(directory, monkeypatch):
    machine, source = directory
    monkeypatch.setattr(machine, 'backup_free', lambda path: 19 * 1024**3)
    with pytest.raises(RuntimeError, match='native_database_space_insufficient'):
        machine.validate_database_directory('/var/lib/sli-db')
    assert not list(source.iterdir())


@pytest.mark.parametrize('operation', ['validate_database_directory', 'prepare'])
def test_directory_refuses_readonly_filesystem(directory, monkeypatch, operation):
    machine, _ = directory
    monkeypatch.setattr(host, 'run', lambda argv: json.dumps({'filesystems': [
        {'fstype': 'ext4', 'options': 'ro,relatime'}]}))
    with pytest.raises(host.HostError, match='native_database_filesystem_readonly'):
        if operation == 'prepare':
            machine.prepare(directory='/var/lib/sli-db')
        else:
            machine.validate_database_directory('/var/lib/sli-db')


@pytest.mark.parametrize('path', ['/var/lib/sli', '/srv/sli-db', '/', '/tmp/data', '/var/lib/../data', '/var/lib/x%h'])
def test_directory_refuses_reserved_or_unsafe_paths(directory, path):
    machine, _ = directory
    with pytest.raises(host.HostError, match='native_database_directory_invalid'):
        machine.validate_database_directory(path)


def test_directory_mount_unit_preserves_database_and_backup_paths():
    body = host.directory_mount_unit('/var/lib/sli-db')
    assert 'What=/var/lib/sli-db\n' in body
    assert 'Where=/srv/sli-db\n' in body
    assert 'Options=bind\n' in body
    assert 'RequiresMountsFor=/var/lib/sli-db\n' in body


@pytest.fixture
def prepared_directory(directory, monkeypatch):
    machine, _ = directory
    path = machine.path(host.STATE + '/host-prepared.json')
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({'version': 1, 'mount': '/srv/sli-db', 'uuid': None,
                               'storage_mode': 'directory', 'directory': '/var/lib/sli-db',
                               'clickhouse_mode': 'native'}))
    monkeypatch.setattr(machine, 'validate_receipt_file', lambda path: None)
    monkeypatch.setattr(machine, 'backup_mounted', lambda source, target: False)
    monkeypatch.setattr(machine, 'vendor_guards', lambda: None)
    monkeypatch.setattr(machine, 'clickhouse_mode', lambda: 'native')
    return machine


def test_directory_receipt_rechecks_bind_identity(prepared_directory):
    machine = prepared_directory
    with pytest.raises(host.HostError, match='native_database_mount_mismatch'):
        machine.receipt()


@pytest.mark.parametrize('mounted', [True, False])
def test_directory_receipt_in_readonly_sandbox_still_checks_identity(prepared_directory, monkeypatch, mounted):
    machine = prepared_directory
    monkeypatch.setattr(host, 'run', lambda argv: json.dumps({'filesystems': [
        {'fstype': 'ext4', 'options': 'ro,relatime'}]}))
    monkeypatch.setattr(machine, 'backup_mounted', lambda source, target: mounted)
    monkeypatch.setattr(machine, 'backup_free', lambda path: pytest.fail('receipt must not check free space'))
    if mounted:
        assert machine.receipt()['directory'] == '/var/lib/sli-db'
    else:
        with pytest.raises(host.HostError, match='native_database_mount_mismatch'):
            machine.receipt()


def test_readonly_receipt_still_rejects_untrusted_owner(prepared_directory, monkeypatch):
    machine = prepared_directory
    monkeypatch.setattr(machine, 'backup_trusted', lambda path: (_ for _ in ()).throw(
        host.HostError('native_backup_root_untrusted')))
    with pytest.raises(host.HostError, match='native_backup_root_untrusted'):
        machine.receipt()


def test_readonly_receipt_still_rejects_unsupported_filesystem(prepared_directory, monkeypatch):
    monkeypatch.setattr(host, 'run', lambda argv: json.dumps({'filesystems': [
        {'fstype': 'nfs', 'options': 'ro'}]}))
    with pytest.raises(host.HostError, match='native_database_filesystem_unsupported'):
        prepared_directory.receipt()


def test_local_copy_reserves_live_database_space_and_does_not_admit_restore(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from deploy.linux import backup_policy as policy
    monkeypatch.setattr(policy, 'filesystem', lambda path: 'same-disk')
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda path: SimpleNamespace(free=12 * 1024**3))
    filesystems = {'data': {'device': 'same-disk', 'free_bytes': 12 * 1024**3}}
    root = tmp_path / 'copies'
    required = 12 * 1024**3
    local = policy.local_copy_admission(root, root / 'work', filesystems, required)
    assert local['status'] == 'skipped' and local['required_bytes'] == 13 * 1024**3
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda path: SimpleNamespace(free=20 * 1024**3))
    filesystems['data']['free_bytes'] = 20 * 1024**3
    assert policy.local_copy_admission(root, root / 'work', filesystems, required)['status'] == 'admitted'
    assert policy.volume_admission(root, root / 'work', filesystems, required)['reason'] == 'restore_volume_mismatch'


def test_directory_mode_uses_local_backup_copy_admission(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from deploy.linux import backup_policy as policy
    from deploy.linux import native_backup
    from deploy.linux import native_clickhouse_endpoint as ch
    monkeypatch.setattr(ch, 'database_directory', lambda: '/var/lib/sli-db')
    monkeypatch.setattr(ch, 'site_configuration', dict)
    monkeypatch.setattr(policy, 'filesystem', lambda path: 'same-disk')
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda path: SimpleNamespace(free=30 * 1024**3))
    fs = {'data': {'device': 'same-disk', 'free_bytes': 30 * 1024**3}}
    assert native_backup.capture_volume_admission(tmp_path, tmp_path / 'work', fs, 1024**3)['status'] == 'admitted'
    monkeypatch.setattr(ch, 'site_configuration', lambda: {'backup_root': '/mnt/backup'})
    assert native_backup.capture_volume_admission(tmp_path, tmp_path / 'work', fs, 1024**3)['status'] == 'skipped'


def test_directory_alias_from_receipt_is_validated_before_sandbox_use(tmp_path, monkeypatch):
    from deploy.linux import native_clickhouse_endpoint as ch
    receipt = tmp_path / 'var/lib/sli/state/host-prepared.json'
    receipt.parent.mkdir(parents=True)
    monkeypatch.setattr(ch, 'trusted_text', lambda path: path.read_text())
    receipt.write_text(json.dumps({'storage_mode': 'directory', 'directory': '/var/lib/sli-db'}))
    assert ch.database_directory(tmp_path) == '/var/lib/sli-db'
    receipt.write_text(json.dumps({'storage_mode': 'directory', 'directory': '/var/lib/x%h'}))
    with pytest.raises(ValueError, match='native_database_directory_invalid'):
        ch.database_directory(tmp_path)


def test_capture_admission_accepts_local_directory_copy_without_writing_files(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from deploy.linux import backup
    from deploy.linux import backup_policy as policy
    from deploy.linux import native_clickhouse_endpoint as ch
    monkeypatch.setattr(ch, 'database_directory', lambda: '/var/lib/sli-db')
    monkeypatch.setattr(ch, 'site_configuration', dict)
    monkeypatch.setattr(backup, 'native_mode', lambda: True)
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(tmp_path / 'synthetic-passfile'))
    point = {'database_size_bytes': 1024}
    connection = SimpleNamespace(execute=lambda sql: SimpleNamespace(fetchone=lambda: [point]))
    monkeypatch.setattr(backup, 'pg_connect', lambda path: nullcontext(connection))
    monkeypatch.setattr(backup, 'pg_capacity_paths', lambda point: {'data': tmp_path})
    monkeypatch.setattr(policy, 'filesystem', lambda path: 'one-disk')
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda path: SimpleNamespace(free=30 * 1024**3))
    backup.capture_admission(tmp_path)
    assert not list(tmp_path.iterdir())
