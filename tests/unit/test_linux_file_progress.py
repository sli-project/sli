"""Real file work renews the watch before a large stage has completed."""
import hashlib
import io
import json
import os
import shutil
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup, operation_wait as operation, restore_existing as restore


@pytest.fixture
def progress(monkeypatch):
    calls = []
    monkeypatch.setattr(operation, 'made_progress', lambda: calls.append(True))
    return calls


def payload(root):
    root.mkdir()
    (root / 'nested').mkdir()
    for name in ('one', 'nested/two', 'nested/three'):
        (root / name).write_bytes(b'x' * (2 * 1024**2 + 1))
    return root


def test_copy_stream_reports_written_blocks_before_eof(progress):
    target = io.BytesIO()
    sizes = []
    source = io.BytesIO(b'x' * (2 * 1024**2 + 1))
    original = operation.made_progress

    def observe():
        sizes.append(target.tell())
        original()

    operation.made_progress = observe
    operation.copy_stream(source, target)
    assert sizes == [1024**2, 2 * 1024**2, 2 * 1024**2 + 1]
    assert len(progress) == 3


def test_hash_reports_consumed_blocks_before_eof(monkeypatch):
    data = b'x' * (2 * 256 * 1024 + 1)
    source = io.BytesIO(data)
    offsets = []
    monkeypatch.setattr(operation, 'made_progress', lambda: offsets.append(source.tell()))
    assert operation.hash_stream(source, operation.InventoryProgress()) == hashlib.sha256(data).hexdigest()
    assert offsets == [256 * 1024, 2 * 256 * 1024, len(data)]


def test_copy_tree_reports_empty_directories_during_walk(tmp_path, monkeypatch):
    source, target = tmp_path / 'source', tmp_path / 'target'
    for name in ('one', 'two', 'three'):
        (source / name).mkdir(parents=True)
    seen = []
    monkeypatch.setattr(operation, 'made_progress', lambda: seen.append(len(list(target.rglob('*')))))
    operation.copy_tree(source, target)
    assert len(seen) == 4
    assert seen[0] == 0 and 0 < seen[-1] < 3
    assert len(list(target.iterdir())) == 3


@pytest.mark.skipif(os.name != 'posix', reason='fd-relative Linux deletion')
def test_remove_tree_pins_directories_if_root_is_replaced(tmp_path, monkeypatch):
    tree = payload(tmp_path / 'tree')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'keep').write_bytes(b'keep')
    walk = os.fwalk

    def replaced(*args, **kwargs):
        iterator = walk(*args, **kwargs)
        first = next(iterator)
        tree.rename(tmp_path / 'moved')
        tree.symlink_to(outside, target_is_directory=True)
        yield first
        yield from iterator

    monkeypatch.setattr(os, 'fwalk', replaced)
    with pytest.raises(OSError):
        operation.remove_tree(tree)
    assert (outside / 'keep').read_bytes() == b'keep'


@pytest.mark.parametrize('metadata', [False, True])
def test_copy_reports_blocks_and_keeps_metadata_contract(tmp_path, monkeypatch, metadata):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.write_bytes(b'x' * (2 * 1024**2 + 1))
    source.chmod(0o640)
    os.utime(source, ns=(1234567890000000000, 1234567890000000000))
    sizes = []
    monkeypatch.setattr(operation, 'made_progress', lambda: sizes.append(target.stat().st_size))
    copier = operation.copy2 if metadata else operation.copy_file
    copier(source, target)
    assert any(0 < size < source.stat().st_size for size in sizes)
    assert len(sizes) >= 3
    assert target.read_bytes() == source.read_bytes()
    if metadata:
        assert target.stat().st_mode == source.stat().st_mode
        assert target.stat().st_mtime_ns == source.stat().st_mtime_ns
    with pytest.raises(shutil.SameFileError):
        copier(source, source)


def test_remove_tree_reports_actual_removals_and_does_not_follow_links(tmp_path, monkeypatch):
    tree = payload(tmp_path / 'tree')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'keep').write_bytes(b'keep')
    if os.name == 'posix':
        (tree / 'link').symlink_to(outside, target_is_directory=True)
    remaining = []
    monkeypatch.setattr(operation, 'made_progress', lambda: remaining.append(len(list(tree.rglob('*')))
                        if tree.exists() else 0))
    operation.remove_tree(tree)
    assert not tree.exists()
    assert (outside / 'keep').read_bytes() == b'keep'
    assert len(remaining) >= 5
    assert remaining[0] > remaining[-1] == 0
    if os.name == 'posix':
        link = tmp_path / 'root-link'
        link.symlink_to(outside, target_is_directory=True)
        with pytest.raises(OSError):
            operation.remove_tree(link)
        assert (outside / 'keep').exists()


@pytest.mark.parametrize('nested', [False, True])
def test_files_inventory_reports_hash_blocks(tmp_path, monkeypatch, nested):
    root = tmp_path / 'files'
    root.mkdir()
    directory = root / 'nested' if nested else root
    directory.mkdir(exist_ok=True)
    data = b'x' * (2 * 1024**2 + 1)
    (directory / 'payload').write_bytes(data)
    reads = []
    monkeypatch.setattr(operation, 'made_progress', lambda: reads.append(True))
    inventory = restore.files_inventory(root, set())
    assert len(reads) >= 9
    assert inventory[('nested/' if nested else '') + 'payload'] == {
        'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}


def test_restore_reports_each_validation_deletion_copy_and_readback(tmp_path, monkeypatch):
    source = tmp_path / 'set'
    source.mkdir()
    payload(source / 'files')
    target = payload(tmp_path / 'target')
    phase, observations = ['validation'], {}
    monkeypatch.setenv('SLI_DEPLOYMENT_MODE', 'docker')
    monkeypatch.setattr(operation, 'made_progress', lambda: observations.setdefault(phase[0], []).append(True))
    inventory = backup.content_inventory
    files_inventory = restore.files_inventory

    def hash_tree(path, **kwargs):
        previous = phase[0]
        phase[0] = 'source_hash' if path == source / 'files' else previous
        try:
            return inventory(path, **kwargs)
        finally:
            phase[0] = previous

    def hash_files(path, preserved):
        previous = phase[0]
        phase[0] = 'destination_hash' if path == target else 'expected_hash'
        try:
            return files_inventory(path, preserved)
        finally:
            phase[0] = previous

    monkeypatch.setattr(backup, 'content_inventory', hash_tree)
    monkeypatch.setattr(restore, 'files_inventory', hash_files)
    # Observe operations from their real filesystem side effects, including
    # individual files copied/removed before the next tree has completed.
    original_copy = operation.copy2
    original_remove = operation.remove_tree

    def copy(*args, **kwargs):
        phase[0] = 'copy'
        return original_copy(*args, **kwargs)

    def remove(*args, **kwargs):
        phase[0] = 'remove'
        return original_remove(*args, **kwargs)

    monkeypatch.setattr(operation, 'copy2', copy)
    monkeypatch.setattr(operation, 'remove_tree', remove)
    restore.restore_files(source, target, replace_existing=True)
    for name in ('source_hash', 'destination_hash', 'expected_hash', 'copy', 'remove'):
        assert len(observations.get(name, [])) > 1, name
    assert (target / 'nested/two').read_bytes() == b'x' * (2 * 1024**2 + 1)


@pytest.mark.parametrize('stage', ['readable', 'capture'])
def test_clickhouse_archive_copy_reports_blocks(tmp_path, monkeypatch, progress, stage):
    archive_root = tmp_path / 'archives'
    archive_root.mkdir()
    staging = tmp_path / 'set'
    staging.mkdir()
    source = staging / 'history.zip'
    data = b'x' * (2 * 1024**2 + 1)
    source.write_bytes(data)
    target = backup.ClickHouse('history', 'synthetic.invalid', 'synthetic', 'unused', archive_root=archive_root)
    monkeypatch.setattr(backup.ClickHouse, 'backup_disk_path', lambda self, path: str(path))

    def capture(self, directory):
        (directory / 'history.zip').write_bytes(data)
        return {'size_bytes': len(data)}

    monkeypatch.setattr(backup.ClickHouse, 'capture_archive', capture)
    if stage == 'readable':
        with target.readable_archive(source, staging) as path:
            assert len(progress) >= 3
            assert Path(path).read_bytes() == data
    else:
        target.backup(staging)
        assert len(progress) >= 3
        assert source.read_bytes() == data


@pytest.mark.skipif(os.name != 'posix', reason='descriptor-based Linux snapshots')
def test_backup_files_reports_snapshot_copy_and_cleanup(tmp_path, monkeypatch):
    from deploy.linux import update_checkpoint

    source = payload(tmp_path / 'source')
    root = tmp_path / 'backups'
    root.mkdir()
    destination = root / 'files'
    monkeypatch.setenv('SLI_BACKUP_ROOT', str(root))
    monkeypatch.setenv('SLI_BACKUP_FILES_ROOT', str(source))
    seen = []

    def observe():
        seen.append(sum(path.stat().st_size for path in destination.rglob('*') if path.is_file()))

    monkeypatch.setattr(operation, 'made_progress', observe)
    backup.backup_files(destination)
    total = 3 * (2 * 1024**2 + 1)
    assert seen.count(0) >= 9  # Snapshot blocks before the second copy begins.
    assert sum(0 < size < total for size in seen) >= 6
    assert len(seen) > 18  # Includes private snapshot cleanup.
    assert backup.content_inventory(destination) == backup.content_inventory(source)
    assert not list(root.glob('sli-checkpoint-*'))
    # A standalone snapshot caller must also report actual cleanup progress.
    calls = []
    monkeypatch.setattr(operation, 'made_progress', lambda: calls.append(True))
    with update_checkpoint.snapshot(source.parent, source.name, temporary_root=root,
                                    progress=operation.made_progress):
        copied = len(calls)
    assert len(calls) > copied + 3


def test_capture_hashes_report_progress_before_publication(tmp_path, monkeypatch, progress):
    monkeypatch.setattr(backup, 'clickhouse_targets', lambda: ())
    monkeypatch.setattr(backup, 'backup_files', lambda path: (payload(path), {'size_bytes': 6291459})[1])
    monkeypatch.setattr(backup, 'prune', lambda *a: None)
    monkeypatch.setattr(operation, 'history_path', lambda: tmp_path / 'summary.json')
    monkeypatch.setattr(operation, 'record_success', lambda *a, **kw: None)
    original = backup.publish_backup

    def publish(staging, final):
        assert len(progress) >= 27
        original(staging, final)

    monkeypatch.setattr(backup, 'publish_backup', publish)
    path = backup.capture_backup(tmp_path, 1, ('files',))
    assert (path / 'manifest.json').is_file()


def test_integrity_hash_and_zip_crc_each_report_blocks(tmp_path, monkeypatch, progress):
    import zipfile

    from deploy.linux import backup_restore_check as drill

    root = tmp_path / 'set'
    root.mkdir()
    (root / 'postgres').mkdir()
    (root / 'postgres/toc.dat').write_bytes(b'x' * (2 * 1024**2 + 1))
    for name in ('history', 'warm'):
        with zipfile.ZipFile(root / (name + '.zip'), 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('.backup', '<backup/>')
            archive.writestr('data', b'x' * (2 * 1024**2 + 1))
    manifest = {'status': 'success', 'backup_id': 'set',
                'components': {'postgres': {}, 'history': {'archive': 'history.zip', 'databases': ['synthetic']},
                               'warm': {'archive': 'warm.zip', 'databases': ['synthetic']}},
                'content_checksums': backup.content_inventory(root)}
    (root / 'manifest.json').write_text(json.dumps(manifest))
    monkeypatch.setattr(backup, 'default_components', lambda: ('postgres', 'history', 'warm'))
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(None))

    def pg_tool(*a, **kw):
        assert len(progress) >= 9
        progress.clear()

    monkeypatch.setattr(backup, 'pg_tool', pg_tool)
    assert drill.integrity_check(root) == {'status': 'verified'}
    assert len(progress) >= 18  # Expanded ZIP data, not just compressed hashes.


def test_restore_permissions_report_per_entry(tmp_path, monkeypatch, progress):
    from deploy.linux import native_runtime as runtime

    root = payload(tmp_path / 'data')
    monkeypatch.setattr(runtime.os, 'chown', lambda *a: None, raising=False)
    monkeypatch.setattr(runtime, 'ensure_directory', lambda *a, **kw: a[0].mkdir(exist_ok=True))
    runtime.restore_data_permissions(root, 123)
    assert len(progress) >= 4


def test_checkpoint_metadata_reports_each_collected_entry(tmp_path, monkeypatch, progress):
    from deploy.linux import native_backup as native, native_upgrade as upgrade

    root = payload(tmp_path / 'data')
    state = root / 'state'
    state.mkdir()
    (state / 'receipt').write_text('synthetic')
    monkeypatch.setattr(native, 'DATA', root)
    monkeypatch.setattr(native, 'STATE', state)
    inventory = upgrade.file_metadata()
    assert len(progress) == len(inventory) == 5
    assert set(inventory) == {'files/one', 'files/nested', 'files/nested/two',
                              'files/nested/three', 'state/receipt'}


@pytest.mark.parametrize('defect', ['owner', 'writable', 'link'])
def test_streamed_recovery_digest_keeps_trusted_path_rejections(tmp_path, monkeypatch, defect):
    from deploy.linux import native_install as install, native_upgrade as upgrade

    path = tmp_path / 'payload'
    path.write_bytes(b'synthetic')
    monkeypatch.setattr(Path, 'lstat', lambda item: SimpleNamespace(
        st_uid=123 if defect == 'owner' and item == path else 0,
        st_mode=0o100622 if defect == 'writable' and item == path else 0o100600))
    monkeypatch.setattr(Path, 'is_symlink', lambda item: defect == 'link' and item == path)
    for read in (install.trusted, lambda item: upgrade.digest(item, progress=True)):
        with pytest.raises(RuntimeError, match='native_install_untrusted_path'):
            read(path)


@pytest.mark.skipif(os.name != 'posix', reason='directory fsync and descriptor snapshots')
def test_recovery_hash_and_durability_report_during_work(tmp_path, monkeypatch, progress):
    from deploy.linux import native_install as install, native_upgrade as upgrade

    root = payload(tmp_path / 'recovery')
    # Only the root ownership policy is replaced; hashing and I/O stay real.
    monkeypatch.setattr(install, 'trusted_path', lambda path: path)
    assert upgrade.digest(root / 'one', progress=True) == hashlib.sha256(b'x' * (2 * 1024**2 + 1)).hexdigest()
    assert len(progress) >= 9
    progress.clear()
    upgrade.sync_tree(root)
    assert len(progress) >= 5
