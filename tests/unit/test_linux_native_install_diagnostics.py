import json
import subprocess
from types import SimpleNamespace

import pytest

from deploy.linux import native_install as install
from deploy.linux import native_host as host
from deploy.linux import native_setup as setup
from deploy.linux import operation_wait as operation


@pytest.mark.parametrize('outcomes', [(1, 2, 0), (1, 1)])
def test_bootstrap_waits_for_postgres_before_sql(monkeypatch, outcomes):
    pending = iter(outcomes)
    ticks = iter([0, 0, 60 if outcomes[-1] else 1])
    probes = []

    def pg_isready(argv, **kwargs):
        probes.append(argv)
        return SimpleNamespace(returncode=next(pending), stderr='')

    def psql(argv, **kwargs):
        assert len(probes) == len(outcomes) and outcomes[-1] == 0
        assert argv[0] == 'psql'
        raise RuntimeError('sql-reached')

    monkeypatch.setattr(subprocess, 'run', pg_isready)
    monkeypatch.setattr(host, 'run', psql)
    monkeypatch.setattr(host, 'time', SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda seconds: None))
    reason = 'sql-reached' if outcomes[-1] == 0 else 'native_postgres_bootstrap_unready'
    with pytest.raises(RuntimeError, match=reason):
        host.bootstrap_pg()
    assert len(probes) == len(outcomes)


@pytest.mark.parametrize('sensitive_input', [False, True])
def test_host_journals_sanitized_command_stderr(monkeypatch, capsys, sensitive_input):
    cause = 'psql: FATAL: the database system is starting up'
    stderr = '\n'.join([cause, 'Password: test-value-a', 'token=test-value-b',
                        'DETAIL: Failing row contains (test-value-c)',
                        *(['test-unlabelled-query-fragment'] if sensitive_input else [])])
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(
        returncode=1, stdout='test-private-stdout', stderr=stderr))
    journal = []
    monkeypatch.setattr(setup.diagnostics, 'log_code', journal.append)
    with pytest.raises(host.HostError, match='native_command_failed') as caught:
        host.run(['psql'], sensitive_input=sensitive_input)
    setup.diagnostics.failure(caught.value)
    logged = '\n'.join(journal)
    assert '[redacted' in logged
    assert (cause in logged) is not sensitive_input
    assert 'test-' not in logged
    assert capsys.readouterr().err.strip() == 'native_command_failed: psql'


@pytest.mark.parametrize('argv,shown', [
    (['/usr/bin/systemctl', 'stop', 'sli-x.service'], 'Unit sli-x.service not loaded.'),
    (['/usr/bin/psql', '--password=never-logged'],
     'native_existing_configuration_conflict: /usr/lib/systemd/system/sli-ready.service'),
])
def test_failed_command_reports_codes_but_not_foreign_stderr(monkeypatch, capsys, argv, shown):
    stderr = '\n'.join([
        'native_existing_configuration_conflict: /usr/lib/systemd/system/sli-ready.service',
        'DETAIL:  Failing row contains (secret-value).',
        'Unit sli-other.service not loaded.',
        'Unit sli-x.service not loaded.',
    ])
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=1, stderr=stderr.encode()))
    with pytest.raises(RuntimeError, match='native_install_command_failed'):
        install.command(argv)
    err = capsys.readouterr().err
    assert shown in err
    assert 'secret-value' not in err
    assert 'Unit sli-other.service not loaded.' not in err
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
