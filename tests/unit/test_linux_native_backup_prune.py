"""Portable retention regressions: real files/hashes, no host or database access."""
import json
import sys
from contextlib import nullcontext
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from deploy.linux import backup, native_backup as native, native_backup_settings, native_host, native_runtime


def write_set(root, stamp):
    path = root / stamp
    data = path / 'data' / stamp
    data.mkdir(parents=True)
    (data / 'payload').write_bytes(b'synthetic')
    backup.write_json(data / 'manifest.json', {
        'status': 'success', 'components': {name: {} for name in backup.COMPONENTS},
        'content_checksums': backup.content_inventory(data),
    })
    backup.write_json(path / 'manifest.json', {
        'schema_version': 1, 'status': 'backup_created', 'backup_id': stamp,
        'data_path': 'data/' + stamp, 'content_checksums': backup.content_inventory(path),
    })
    return path


@pytest.fixture
def capture_host(tmp_path, monkeypatch):
    root, data = tmp_path / 'backups', tmp_path / 'data'
    root.mkdir()
    data.mkdir()
    monkeypatch.setattr(native, 'ROOT', root)
    monkeypatch.setattr(native, 'DATA', data)
    monkeypatch.setattr(native, 'settings', lambda: {})
    monkeypatch.setattr(native, 'ensure_directory', lambda path, mode, **kw:
                        path.mkdir(parents=True, exist_ok=kw.get('exist_ok', True)))
    monkeypatch.setattr(backup, 'backup_lock', lambda root: nullcontext())
    monkeypatch.setattr(backup, 'capture_admission', lambda root, *, regular: None)
    monkeypatch.setattr(native_backup_settings, 'read_policy', lambda: {'enabled': True})
    monkeypatch.setattr(native_backup_settings, 'selected_storage',
                        lambda state, *, create: nullcontext((root, lambda: None)))
    monkeypatch.setattr(backup, 'utc_now', lambda: datetime(2026, 10, 31, tzinfo=timezone.utc))
    monkeypatch.setattr(native_host, 'administrative_lock', nullcontext)
    monkeypatch.setattr(native_host, 'Host', lambda: SimpleNamespace(
        receipt=lambda: None, require_backup_mount=lambda: None, backup_machine_id=lambda: 'synthetic-machine'))
    monkeypatch.setattr(native_runtime, 'no_transaction', lambda: None)
    release = tmp_path / 'release'
    monkeypatch.setattr(native_runtime, 'release', lambda: (release, {}, 'synthetic-digest'))
    monkeypatch.setattr(native_runtime, 'document', lambda path: {
        'release': str(release), 'manifest_sha256': 'synthetic-digest'})

    def capture(data_root, retention, *, components, writers_fenced):
        assert writers_fenced is False
        source = write_set(data_root.parent / 'fake', '20261031T000000.000000Z')
        target = data_root / source.name
        (source / 'data' / source.name).rename(target)
        native.shutil.rmtree(source.parent)
        return target

    monkeypatch.setattr(backup, 'run_backup', capture)
    monkeypatch.setattr(native, 'companion', lambda path: path.mkdir())
    # Fake CLI privileges without changing the history reader's actual file owner.
    monkeypatch.setattr(native, 'os', SimpleNamespace(**(vars(native.os) | {
        'geteuid': lambda: 0, 'umask': lambda mode: None})))
    monkeypatch.setattr(native.signal, 'signal', lambda *args: None)
    monkeypatch.setenv('SLI_BACKUP_RETENTION', '1')
    monkeypatch.setenv('SLI_BACKUP_WEEKLY_RETENTION', '0')
    journal = []
    monkeypatch.setitem(sys.modules, 'syslog', SimpleNamespace(
        openlog=lambda name: None, LOG_WARNING=4,
        syslog=lambda priority, message: journal.append((priority, message))))
    return root, data, journal


@pytest.mark.parametrize('corruption', ['payload', 'json', 'missing_manifest', 'structure', 'hardlink'])
def test_capture_preserves_untrusted_old_set_and_reports_warning(capture_host, capsys, corruption):
    root, data, journal = capture_host
    old = write_set(root, '20261029T141917.000000Z')
    disposable = write_set(root, '20261030T010000.000000Z')
    if corruption == 'payload':
        (old / 'data' / old.name / 'payload').write_bytes(b'private-corruption-canary')
    elif corruption == 'json':
        (old / 'manifest.json').write_text('private-corruption-canary')
    elif corruption == 'missing_manifest':
        (old / 'manifest.json').unlink()
    elif corruption == 'structure':
        (old / 'manifest.json').write_text('[]')
    else:
        native.os.link(old / 'manifest.json', old / 'linked-manifest')
    before = {p.relative_to(old): p.read_bytes() for p in old.rglob('*') if p.is_file()}

    assert native.main(['capture']) == 0

    result = json.loads((root / 'last-result.json').read_text())
    assert result['status'] == 'backup_created' and result['terminal'] is True
    native.verify(root / result['backup_id'])
    assert {p.relative_to(old): p.read_bytes() for p in old.rglob('*') if p.is_file()} == before
    assert old.is_dir() and not disposable.exists()
    warning = {'reason_code': 'native_backup_old_set_untrusted', 'backup_id': old.name}
    assert result['warnings'] == [warning]
    summary = json.loads((data / 'backup-status/summary.json').read_text())
    assert summary['warnings'] == [warning]
    assert summary['last_backup_at_utc'] == '2026-10-31T00:00:00+00:00'
    output = capsys.readouterr()
    assert 'native_backup_complete' in output.out and not output.err
    assert 'reason_code=native_backup_old_set_untrusted' in output.out and old.name in output.out
    assert len(journal) == 1 and journal[0][0] == 4
    assert 'native_backup_old_set_untrusted' in journal[0][1] and old.name in journal[0][1]
    assert 'private-corruption-canary' not in output.out + output.err + journal[0][1]


def test_capture_rejects_corrupt_new_set_before_pruning(capture_host, monkeypatch, capsys):
    root, _, journal = capture_host
    old = write_set(root, '20261029T141917.000000Z')
    write_json = backup.write_json

    def corrupt_after_manifest(path, value):
        write_json(path, value)
        if path.name == 'manifest.json' and value.get('status') == 'backup_created':
            (path.parent / 'unexpected').write_text('synthetic-corruption')

    monkeypatch.setattr(backup, 'write_json', corrupt_after_manifest)
    assert native.main(['capture']) == 1
    assert json.loads((root / 'last-result.json').read_text())['status'] == 'failed'
    assert old.exists() and not journal
    assert 'reason_code=native_backup_hash_mismatch' in capsys.readouterr().err


@pytest.mark.parametrize('action', ['capture', 'drill'])
@pytest.mark.parametrize('code', ['native_backup_hash_mismatch', 'native_drill_ledger_mismatch',
                                 'native_future_failure_123'])
def test_cli_preserves_native_reason_codes(capture_host, monkeypatch, capsys, action, code):
    def fail():
        raise RuntimeError(code)

    monkeypatch.setattr(native, action, fail)
    assert native.main([action]) == 1
    assert f'reason_code={code}' in capsys.readouterr().err


@pytest.mark.parametrize('message', ['private-credential-value', 'native_error\nprivate-credential-value',
                                    'native_error private-credential-value', 'native_error;' + 'x' * 200])
def test_cli_does_not_disclose_arbitrary_exception_text(capture_host, monkeypatch, capsys, message):
    def fail():
        raise RuntimeError(message)

    monkeypatch.setattr(native, 'capture', fail)
    assert native.main(['capture']) == 1
    assert capsys.readouterr().err == 'native_backup_failed\n'
