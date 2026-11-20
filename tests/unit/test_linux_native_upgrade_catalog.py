"""Portable retained-coordinator diagnostics contracts; no host operations."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import native_diagnostics, native_install as install, native_upgrade as upgrade


@pytest.mark.parametrize('catalog_present', [True, False])
@pytest.mark.parametrize('error,expected', [
    (RuntimeError('native_install_api_unready'), 'native_install_api_unready'),
    (RuntimeError('password=synthetic-private-value'), 'native_upgrade_failed'),
    (ValueError('password=synthetic-private-value'), 'native_upgrade_failed'),
    (OSError('password=synthetic-private-value'), 'native_upgrade_failed'),
])
def test_retained_coordinator_publishes_failure_with_legacy_or_absent_catalog(
        tmp_path, monkeypatch, capsys, catalog_present, error, expected):
    saved = tmp_path / 'saved'
    helpers = saved / 'release/deploy/linux'
    helpers.mkdir(parents=True)
    installed = tmp_path / 'installed'
    installed.mkdir()
    # Synthetic accepted helper snapshot, following the restore_helpers tests.
    names = ('native_host.py', 'native_runtime.py', 'native_install.py', 'native_backup.py',
             'native_upgrade.py', 'native_clickhouse_endpoint.py', 'native_preinstall.py',
             'native_pins.json', 'secrets-manifest.json', 'backup_policy.py', 'operation_wait.py')
    for name in names:
        (helpers / name).write_text('# accepted helper\n', encoding='utf-8')
        (installed / name).write_text('# candidate helper\n', encoding='utf-8')
    retained_path = installed / 'native_upgrade.py'
    retained_bytes = Path(upgrade.__file__).read_bytes()
    retained_path.write_bytes(retained_bytes)
    # This repository's pre-#1054 catalog has no upgrade fallback entry.
    assert 'native_upgrade_failed' not in native_diagnostics.MESSAGES
    if catalog_present:
        (installed / 'native_diagnostics.py').write_bytes(Path(native_diagnostics.__file__).read_bytes())

    monkeypatch.setattr(upgrade, 'RUNTIME_HELPER', installed / 'native_runtime.py')

    def trusted(path):
        assert path.is_relative_to(helpers)
        return path.read_bytes()

    monkeypatch.setattr(install, 'trusted', trusted)
    upgrade.restore_helpers(saved, preserve_coordinator=True)
    assert retained_path.read_bytes() == retained_bytes
    assert (installed / 'native_runtime.py').read_bytes() == (helpers / 'native_runtime.py').read_bytes()
    assert (installed / 'native_diagnostics.py').exists() is catalog_present
    spec = importlib.util.spec_from_file_location('retained_upgrade_catalog_test', retained_path)
    retained = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(retained)
    assert retained.failure_code(error) == expected
    if expected != 'native_upgrade_failed':
        assert retained.failure_message(expected) == 'The candidate API did not become ready.'
    else:
        assert retained.failure_message(expected) == (
            'The native upgrade could not be completed; inspect its transaction result.')

    transaction = tmp_path / ('a' * 32)
    transaction.mkdir()
    journal = SimpleNamespace(path=transaction, value={'failure_reason_code': expected})

    def atomic(path, value):
        # Only replace POSIX durability/ownership; exercise the real publication.
        assert path == transaction / 'result.json'
        path.write_text(json.dumps(value), encoding='utf-8')

    monkeypatch.setattr(install, 'atomic', atomic)
    for status, terminal, reason in [('failed', False, expected), ('rolled_back', True, None)]:
        retained.publish(journal, status, terminal=terminal, reason_code=reason)
        text = (transaction / 'result.json').read_text(encoding='utf-8')
        result = json.loads(text)
        assert result['transaction'] == transaction.name
        assert result['status'] == status and result['terminal'] is terminal
        assert result['reason_code'] == expected
        assert result['message'] == retained.failure_message(expected)
        assert 'synthetic-private-value' not in text

    monkeypatch.setattr(retained.os, 'geteuid', lambda: 0, raising=False)

    def fail(*args):
        raise error

    monkeypatch.setattr(retained, 'prepare_package', fail)
    assert retained.main(['prepare-package', '2.0-1~deb13']) == 1
    output = capsys.readouterr().err
    assert f'reason_code={expected}' in output
    assert 'synthetic-private-value' not in output and 'Traceback' not in output
