import zipfile
from pathlib import Path

import pytest

from server.sli.storage import runtime_storage as storage


pytestmark = pytest.mark.posix_only


@pytest.fixture
def planned(tmp_path):
    raw = tmp_path / 'raw'
    raw.mkdir()
    src = raw / 'sample.json'
    src.write_bytes(b'original bytes')
    plan = storage.build_raw_cleanup_plan(raw_dir=raw, archive_dir=tmp_path / 'archive',
                                          older_than_days=0, archive_mode='zip')
    return src, plan


def run(plan):
    return storage.apply_raw_cleanup_plan(plan, apply=True, write_metadata=False)


def test_close_failure_keeps_sources(planned, monkeypatch):
    src, plan = planned
    close = zipfile.ZipFile.close

    def fail_close(zf):
        writing = zf.mode == 'w' and zf.fp is not None
        close(zf)
        if writing:
            raise OSError('injected close failure')

    monkeypatch.setattr(zipfile.ZipFile, 'close', fail_close)
    result = run(plan)
    assert src.read_bytes() == b'original bytes'
    assert result['errors']
    assert not result['archived']


def test_success_verified_archive(planned):
    src, plan = planned
    result = run(plan)
    assert not result['errors']
    assert not src.exists()
    with zipfile.ZipFile(result['zip_path']) as zf:
        assert zf.testzip() is None
        assert zf.read('sample.json') == b'original bytes'
    assert len(result['archived']) == 1


def test_change_since_plan_keeps_source(planned):
    src, plan = planned
    src.write_bytes(b'changed bytes')
    result = run(plan)
    assert src.read_bytes() == b'changed bytes'
    assert result['errors']
    assert not result['archived']


@pytest.mark.parametrize('operation', ['fsync', 'link'])
def test_publication_failure_keeps_sources(planned, monkeypatch, operation):
    src, plan = planned

    def fail(*args, **kwargs):
        raise OSError('injected publication failure')

    monkeypatch.setattr(storage.os, operation, fail)
    result = run(plan)
    assert src.read_bytes() == b'original bytes'
    assert result['errors']
    assert not result['archived']


def test_existing_destination_preserved(planned):
    _src, plan = planned
    destination = Path(plan['zip_path'])
    destination.parent.mkdir()
    destination.write_bytes(b'existing archive')
    result = run(plan)
    assert destination.read_bytes() == b'existing archive'
    assert result['zip_path'] != str(destination)
    assert not result['errors']


def test_source_symlink_rejected(planned, tmp_path):
    src, plan = planned
    outside = tmp_path / 'outside'
    outside.write_bytes(b'outside data')
    src.unlink()
    src.symlink_to(outside)
    result = run(plan)
    assert src.is_symlink()
    assert outside.read_bytes() == b'outside data'
    assert result['errors']


def test_crc_failure_keeps_sources(planned, monkeypatch):
    src, plan = planned

    def bad_crc(self, size=-1):
        raise zipfile.BadZipFile('injected bad CRC')

    monkeypatch.setattr(zipfile.ZipExtFile, 'read', bad_crc)
    result = run(plan)
    assert src.read_bytes() == b'original bytes'
    assert result['errors']
    assert not result['archived']
    assert not Path(plan['zip_path']).exists()


def test_directory_sync_failure_keeps_sources_and_published_archive(planned, monkeypatch):
    src, plan = planned
    fsync = storage.os.fsync
    calls = 0

    def fail_directory(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError('injected directory fsync failure')
        return fsync(fd)

    monkeypatch.setattr(storage.os, 'fsync', fail_directory)
    result = run(plan)
    assert src.read_bytes() == b'original bytes'
    assert result['errors']
    assert not result['archived']
    with zipfile.ZipFile(plan['zip_path']) as zf:
        assert zf.read('sample.json') == b'original bytes'


def test_change_after_verification_keeps_new_source(planned, monkeypatch):
    src, plan = planned
    fsync = storage.os.fsync

    def mutate(fd):
        src.write_bytes(b'new bytes')
        return fsync(fd)

    monkeypatch.setattr(storage.os, 'fsync', mutate)
    result = run(plan)
    assert src.read_bytes() == b'new bytes'
    assert result['errors']
    assert not result['archived']
    with zipfile.ZipFile(result['zip_path']) as zf:
        assert zf.read('sample.json') == b'original bytes'


def test_destination_race_does_not_overwrite(planned, monkeypatch):
    _src, plan = planned
    link = storage.os.link
    raced = False

    def race(source, target):
        nonlocal raced
        if not raced:
            raced = True
            Path(target).write_bytes(b'other owner')
        return link(source, target)

    monkeypatch.setattr(storage.os, 'link', race)
    result = run(plan)
    assert Path(plan['zip_path']).read_bytes() == b'other owner'
    assert result['zip_path'] != plan['zip_path']
    assert not result['errors']


def test_replaced_staging_path_is_not_removed(planned, monkeypatch):
    src, plan = planned
    fsync = storage.os.fsync
    replaced = None

    def replace(fd):
        nonlocal replaced
        if replaced is None:
            replaced = next(Path(plan['archive_dir']).glob('.raw-archive-*.tmp'))
            replaced.unlink()
            replaced.write_bytes(b'other owner')
        return fsync(fd)

    monkeypatch.setattr(storage.os, 'fsync', replace)
    result = run(plan)
    assert src.read_bytes() == b'original bytes'
    assert result['errors']
    assert replaced.read_bytes() == b'other owner'
    assert not result['archived']


def test_later_source_failure_keeps_entire_batch(planned):
    src, plan = planned
    second = src.with_name('second.json')
    second.write_bytes(b'second bytes')
    plan = storage.build_raw_cleanup_plan(raw_dir=src.parent,
                                         archive_dir=Path(plan['archive_dir']),
                                         older_than_days=0, archive_mode='zip')
    second.unlink()
    result = run(plan)
    assert src.read_bytes() == b'original bytes'
    assert result['errors']
    assert not result['archived']


def test_outside_source_rejected(planned, tmp_path):
    src, plan = planned
    outside = tmp_path / 'outside.json'
    outside.write_bytes(b'outside bytes')
    plan['candidates'][0]['path'] = str(outside)
    plan['candidates'][0]['source_identity'] = storage._raw_source_identity(outside.stat())
    result = run(plan)
    assert outside.read_bytes() == b'outside bytes'
    assert src.exists()
    assert result['errors']
    assert not result['archived']


def test_dry_run_does_not_create_archive(planned):
    src, plan = planned
    result = storage.apply_raw_cleanup_plan(plan, apply=False, write_metadata=False)
    assert src.read_bytes() == b'original bytes'
    assert not Path(plan['archive_dir']).exists()
    assert not result['errors']
    assert not result['archived']
