import json
import subprocess
from types import SimpleNamespace

import pytest

from deploy.linux import native_install as install
from deploy.linux import native_setup as setup
from deploy.linux import operation_wait as operation


@pytest.mark.parametrize('program,shown,hidden', [
    ('/usr/bin/systemctl', ['Unit sli-x.service not loaded.'], []),
    ('/usr/bin/psql', ['native_existing_configuration_conflict: /usr/lib/systemd/system/sli-ready.service'],
     ['DETAIL:  Failing row contains (secret-value).']),
])
def test_failed_command_reports_codes_but_not_foreign_stderr(monkeypatch, capsys, program, shown, hidden):
    stderr = '\n'.join(['native_existing_configuration_conflict: /usr/lib/systemd/system/sli-ready.service',
                        'DETAIL:  Failing row contains (secret-value).', 'Unit sli-x.service not loaded.'])
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=1, stderr=stderr.encode()))
    with pytest.raises(RuntimeError, match='native_install_command_failed'):
        install.command([program, '--password=never-logged'])
    err = capsys.readouterr().err
    assert all(line in err for line in shown)
    assert not any(line in err for line in hidden)
    assert 'never-logged' not in err


def test_postinst_staging_names_missing_runtime_and_can_retry(tmp_path, monkeypatch, capsys):
    releases, runtimes, state = [tmp_path / name for name in ('releases', 'runtimes', 'state')]
    root = releases / 'beta'
    root.mkdir(parents=True)
    state.mkdir()
    python = runtimes / 'test-runtime' / 'bin/python3.14'
    manifest = {'schema_version': 1, 'migration_ledger': [1], 'roles': [1], 'plugins': {'test': 1},
                'python': str(python), 'python_sha256': install.hashlib.sha256(b'synthetic executable').hexdigest()}
    (root / 'native-runtime.json').write_text(json.dumps(manifest))
    monkeypatch.setattr(install, 'RELEASES', releases)
    monkeypatch.setattr(install, 'RUNTIMES', runtimes)
    monkeypatch.setattr(install, 'STATE', state)
    monkeypatch.setattr(install.os, 'geteuid', lambda: 0, raising=False)
    monkeypatch.setattr(install.os, 'umask', lambda mode: None)
    monkeypatch.setattr(install.os, 'access', lambda path, mode: True)
    monkeypatch.setattr(install, 'trusted', lambda path: path.read_bytes())
    monkeypatch.setattr(install, 'atomic', lambda path, record: path.write_text(json.dumps(record)))
    assert install.main(['stage', 'beta']) == 1
    message = capsys.readouterr().err
    assert str(python) in message
    assert 'sudo apt install --reinstall ./sli-runtime-test-runtime_*_amd64.deb' in message
    assert 'sudo dpkg --configure -a' in message
    assert not (state / 'pending-release.json').exists()

    python.parent.mkdir(parents=True)
    python.write_bytes(b'modified executable')
    assert install.main(['stage', 'beta']) == 1
    assert 'modified or not executable' in capsys.readouterr().err
    assert not (state / 'pending-release.json').exists()

    python.write_bytes(b'synthetic executable')
    assert install.main(['stage', 'beta']) == 0
    assert json.loads((state / 'pending-release.json').read_text())['release'] == 'beta'


def test_setup_surfaces_only_validated_unit_paths_from_child(tmp_path, monkeypatch, capsys):
    prefix = 'native_existing_configuration_conflict: '
    unit = '/etc/systemd/system/sli-postgresql.service.d'
    rejected = [prefix + '/etc/sli/secrets/private', prefix + unit + ' extra', 'untrusted statement']
    monkeypatch.setattr(operation, 'wait_process', lambda *args: None)

    def failed_child(lines, *, expected):
        def popen(*args, stderr, **kwargs):
            stderr.write('\n'.join(lines).encode())
            return SimpleNamespace(returncode=1)

        monkeypatch.setattr(operation.subprocess, 'Popen', popen)
        with pytest.raises(RuntimeError, match=expected) as caught:
            operation.setup_command(['/usr/sbin/sli-native-install', 'configure', 'beta'], cwd=tmp_path,
                                    env={}, watch=None, failure_codes=setup.diagnostics.COMMAND_FAILURES,
                                    diagnose_failure=setup.diagnose_install_failure)
        setup.diagnostics.failure(caught.value)
        message = capsys.readouterr().err
        assert all(line not in message for line in rejected)
        return message

    assert unit not in failed_child(rejected, expected='native_setup_install_failed')
    message = failed_child([*rejected, prefix + unit], expected='native_existing_configuration_conflict')
    assert unit in message and 'sudo sh -c' in message
    known = 'native_command_failed: systemctl reset-failed sli-clickhouse-history.service'
    assert known in failed_child([*rejected, known], expected=known)
