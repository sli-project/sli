"""Machine-local progress budgets; no database or wall-clock sleeps."""
import json
import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import operation_wait as operation
from deploy.linux.native_clickhouse_endpoint import parse_site


@pytest.fixture(autouse=True)
def synthetic_native_rate(monkeypatch):
    monkeypatch.setattr(operation, 'native_rate', lambda path: 1024**2)


def test_slow_operation_with_progress_survives_old_deadline(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    watch = operation.Watch('postgres_dump', minimum=21600, size=500 * 1024**3, stall=900)
    for tick in range(1, 1000):
        clock[0] = tick * 30
        watch.check(tick)
    assert clock[0] > 21600


def test_portable_watch_keeps_live_work_past_its_estimate(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    watch = operation.Watch('postgres_restore', minimum=60, stall=90)
    for tick in range(1, 11):
        clock[0] = tick * 30
        watch.check(tick)
    assert clock[0] > watch.limit


def test_portable_estimate_uses_measured_machine_rate(monkeypatch):
    monkeypatch.setattr(operation, 'native_rate', lambda path: 100)
    slow = operation.Watch('postgres_restore', minimum=0, size=1000)
    monkeypatch.setattr(operation, 'native_rate', lambda path: 1000)
    fast = operation.Watch('postgres_restore', minimum=0, size=1000)
    assert slow.limit > fast.limit


@pytest.mark.parametrize('error', [PermissionError('unavailable'), RuntimeError('native_operation_rate_unavailable')])
def test_portable_rate_measurement_failure_uses_previous_estimate(monkeypatch, error):
    def unavailable(path):
        raise error
    monkeypatch.setattr(operation, 'native_rate', unavailable)
    watch = operation.Watch('postgres_restore', minimum=0, size=2 * 1024**2)
    assert watch.limit == 6
    with pytest.raises(type(error)):
        operation.Watch('postgres_restore', minimum=0, size=1024, native=True)


def test_zero_size_native_watch_reports_stall_instead_of_total_deadline(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    watch = operation.Watch('postgres_restore', minimum=0, native=True, stall=60)
    clock[0] = 60
    with pytest.raises(operation.OperationTimeout, match='^operation_stalled$'):
        watch.check(0)


def test_stall_reports_only_safe_code_and_numeric_timing(monkeypatch, capsys):
    clock = [0.0]
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    watch = operation.Watch('postgres_restore', minimum=21600, stall=900)
    watch.check(12)
    clock[0] = 900
    with pytest.raises(operation.OperationTimeout, match='operation_stalled') as caught:
        watch.check(12)
    assert caught.value.detail['step'] == 'postgres_restore'
    assert caught.value.detail['last_progress_seconds_ago'] == 900
    assert 'Нет прогресса' in capsys.readouterr().err


def test_history_uses_last_five_successes_and_survives_other_summary_fields(tmp_path):
    path = tmp_path / 'summary.json'
    path.write_text(json.dumps({'capacity_days': 4}))
    for seconds in [999999, 10, 20, 30, 40, 50]:
        operation.record_success(path, 'postgres_dump', seconds)
    watch = operation.Watch('postgres_dump', minimum=60, history=path)
    assert watch.limit == 90
    assert watch.usual == 30
    assert json.loads(path.read_text())['capacity_days'] == 4


def test_history_follows_explicit_backup_root_before_environment(tmp_path, monkeypatch):
    monkeypatch.delenv('SLI_DEPLOYMENT_MODE', raising=False)
    monkeypatch.setenv('SLI_BACKUP_ROOT', str(tmp_path / 'configured'))
    assert operation.history_path() == tmp_path / 'configured/.status/summary.json'
    assert operation.history_path(tmp_path / 'actual') == tmp_path / 'actual/.status/summary.json'
    monkeypatch.setenv('SLI_DEPLOYMENT_MODE', 'native')
    assert operation.history_path(tmp_path) == Path('/var/lib/sli/backup-status/summary.json')


@pytest.mark.parametrize('failure', ['mkdir', 'mkstemp', 'replace', 'unlink'])
def test_successful_pg_tool_survives_unwritable_history(tmp_path, monkeypatch, capsys, failure):
    from deploy.linux import backup

    path = tmp_path / '.status/summary.json'
    process = Process([0], finishes=0)
    monkeypatch.setattr(backup.subprocess, 'Popen', lambda *a, **kw: process)
    monkeypatch.setattr(backup, 'pg_environment', lambda _: {})

    def unavailable(*args, **kwargs):
        raise PermissionError('private path and diagnostic')

    owner = {'mkdir': Path, 'mkstemp': operation.tempfile, 'replace': operation.os, 'unlink': Path}[failure]
    monkeypatch.setattr(owner, failure, unavailable)
    watch = operation.Watch('postgres_restore', minimum=60, history=path, stall=60)
    assert backup.pg_tool(['pg_restore'], tmp_path / 'unused', watch=watch, progress=lambda: 1) is None
    assert process.reaped and process.returncode == 0
    assert capsys.readouterr().err.strip() == 'native_operation_history_unavailable'


@pytest.mark.parametrize('contents', ['{', '[]', '{"operation_durations":{"postgres_restore":"invalid"}}'])
def test_corrupt_history_uses_minimum(tmp_path, contents):
    path = tmp_path / 'summary.json'
    path.write_text(contents)
    watch = operation.Watch('postgres_restore', minimum=60, history=path, stall=60)
    assert watch.usual == 0 and watch.limit == 60


def test_unreadable_history_uses_minimum(tmp_path, monkeypatch, capsys):
    def unavailable(*args, **kwargs):
        raise PermissionError('private path and diagnostic')

    monkeypatch.setattr(Path, 'open', unavailable)
    watch = operation.Watch('postgres_restore', minimum=60, history=tmp_path / 'summary.json', stall=60)
    assert watch.usual == 0 and watch.limit == 60
    assert capsys.readouterr().err.strip() == 'native_operation_history_unavailable'


@pytest.mark.parametrize('link_parent', [False, True])
def test_linked_history_is_neither_read_nor_written(tmp_path, monkeypatch, capsys, link_parent):
    path = tmp_path / '.status/summary.json'
    path.parent.mkdir()
    original = '{"operation_durations":{"postgres_restore":[900]}}'
    path.write_text(original)
    linked = path.parent if link_parent else path
    is_symlink = Path.is_symlink
    monkeypatch.setattr(Path, 'is_symlink', lambda item: item == linked or is_symlink(item))
    watch = operation.Watch('postgres_restore', minimum=60, history=path, stall=60)
    assert watch.usual == 0 and watch.limit == 60
    watch.success()
    assert path.read_text() == original
    assert set(capsys.readouterr().err.splitlines()) == {'native_operation_history_untrusted'}


def test_foreign_owned_history_is_neither_read_nor_written(tmp_path, monkeypatch, capsys):
    path = tmp_path / 'summary.json'
    original = '{"operation_durations":{"postgres_restore":[900]}}'
    path.write_text(original)
    lstat = Path.lstat
    monkeypatch.setattr(operation.os, 'geteuid', lambda: 1001, raising=False)

    def foreign_owner(item, *args, **kwargs):
        info = lstat(item, *args, **kwargs)
        return SimpleNamespace(st_uid=1002, st_mode=info.st_mode) if item == path else info

    monkeypatch.setattr(Path, 'lstat', foreign_owner)
    watch = operation.Watch('postgres_restore', minimum=60, history=path, stall=60)
    assert watch.usual == 0 and watch.limit == 60
    watch.success()
    assert path.read_text() == original
    assert set(capsys.readouterr().err.splitlines()) == {'native_operation_history_untrusted'}


def test_history_outliers_are_rejected_against_work_estimate(tmp_path):
    path = tmp_path / 'summary.json'
    path.write_text(json.dumps({'operation_durations': {'postgres_restore': [10**400, 10**400, 10**400]}}))
    watch = operation.Watch('postgres_restore', minimum=60, history=path, stall=60)
    assert watch.usual == 0
    assert watch.limit == 60
    operation.record_success(path, 'postgres_restore', 10**9)
    assert max(operation.samples(path, 'postgres_restore')) <= 604800


@pytest.mark.parametrize('value', [0, 181, True, '15', 1.5])
def test_site_stall_override_rejects_invalid_values(value):
    encoded = json.dumps(value).lower()
    if isinstance(value, str):
        encoded = json.dumps(value)
    with pytest.raises(ValueError, match='native_site_operation_stall_invalid'):
        parse_site('operation_stall_minutes = ' + encoded)


def test_site_override_is_used_by_watch(monkeypatch):
    from deploy.linux import native_clickhouse_endpoint as endpoint
    monkeypatch.setattr(endpoint, 'site_configuration', lambda: parse_site('operation_stall_minutes = 25'))
    assert operation.Watch('postgres_dump', minimum=21600).stall == 1500
    assert operation.Watch('migration', minimum=21600).stall == 1500


def test_size_and_history_cannot_disable_silence_limit(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    watch = operation.Watch('migration', minimum=21600)
    assert watch.stall == 1800
    clock[0] = watch.limit
    with pytest.raises(operation.OperationTimeout, match='operation_stalled'):
        watch.check(1)


class Process:
    pid = 12345
    def __init__(self, clock, *, finishes=100, code=0):
        self.clock, self.finishes, self.code = clock, finishes, code
        self.returncode = None
        self.killed = False
        self.reaped = False

    def poll(self):
        if self.clock[0] >= self.finishes:
            self.returncode = self.code
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None and timeout is not None:
            self.clock[0] += timeout
            if self.poll() is None:
                raise subprocess.TimeoutExpired('synthetic', timeout)
        self.reaped = self.returncode is not None
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


@pytest.mark.parametrize('progressing', [True, False])
def test_pg_tool_observes_progress_and_reaps_stalled_child(tmp_path, monkeypatch, progressing):
    from deploy.linux import backup
    clock = [0.0]
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    process = Process(clock, finishes=300 if progressing else 100000)
    monkeypatch.setattr(operation.os, 'killpg', lambda *a: process.kill(), raising=False)
    captured = {}

    def popen(argv, **kwargs):
        captured.update(kwargs)
        return process

    monkeypatch.setattr(backup.subprocess, 'Popen', popen)
    monkeypatch.setattr(backup, 'pg_environment', lambda _: {'PGPASSFILE': 'synthetic'})
    path = tmp_path / 'summary.json'
    watch = operation.Watch('postgres_restore', minimum=10000, history=path, stall=90)
    run = lambda: backup.pg_tool(['pg_restore'], tmp_path / 'unused', watch=watch,
                                progress=lambda: clock[0] if progressing else 0)
    if progressing:
        run()
        assert operation.samples(path, 'postgres_restore') == [300]
    else:
        with pytest.raises(operation.OperationTimeout, match='operation_stalled'):
            run()
        assert not path.exists() and process.killed
    assert process.reaped
    assert captured['env']['PGAPPNAME'].startswith('sli_op_')
    assert 'statement_timeout=0' in captured['env']['PGOPTIONS']


@pytest.mark.parametrize('progressing', [True, False])
def test_clickhouse_restore_tracks_counters_and_cancels_exact_query(tmp_path, monkeypatch, progressing):
    from deploy.linux import backup
    clock, statements, submitted = [0.0], [], []
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(operation, 'history_path', lambda: tmp_path / 'summary.json')

    class Future:
        def done(self):
            return False

        def result(self, timeout):
            if timeout == 35 or progressing and clock[0] >= 2100:
                return [{'status': 'RESTORED'}]
            clock[0] += timeout
            raise backup.FutureTimeout()

    class Executor:
        def __init__(self, **kwargs):
            pass

        def submit(self, function, statement, **kwargs):
            submitted.append((statement, kwargs['query_id']))
            return Future()

        def shutdown(self, **kwargs):
            pass

    def query(self, statement, **kwargs):
        statements.append(statement)
        if 'system.backups' in statement:
            return [{'bytes_read': clock[0] if progressing else 0}]
        return []

    monkeypatch.setattr(backup, 'ThreadPoolExecutor', Executor)
    monkeypatch.setattr(backup.ClickHouse, '_query', query)
    target = backup.ClickHouse('history', 'synthetic.invalid', 'synthetic', 'unused',
                              timeout=1800, operation_size=1024**3)
    run = lambda: target.query('RESTORE DATABASE `synthetic` FROM Disk(\'backups\', \'synthetic.zip\') SETTINGS max_threads=2')
    if progressing:
        assert run() == [{'status': 'RESTORED'}]
        assert clock[0] > 1800
        assert not any(q.startswith('KILL') for q in statements)
    else:
        with pytest.raises(operation.OperationTimeout, match='operation_stalled'):
            run()
        assert statements[-1] == "KILL QUERY WHERE query_id='" + submitted[0][1] + "' SYNC"
        assert operation.samples(tmp_path / 'summary.json', 'history_restore') == []
    assert "id='" + submitted[0][1] + "'" in submitted[0][0]


def test_clickhouse_restore_uses_supervised_read_instead_of_elapsed_sql_limit(tmp_path, monkeypatch):
    from urllib.parse import parse_qs, urlsplit

    from deploy.linux import backup
    from deploy.linux import backup_restore_check as drill

    requests, timeouts, reads = [], [], []
    monkeypatch.setattr(operation.time, 'monotonic', lambda: 5)
    monkeypatch.setattr(operation, 'history_path', lambda: tmp_path / 'summary.json')
    monkeypatch.setattr(backup, 'read_secret', lambda _: 'synthetic')
    monkeypatch.setattr(backup.ClickHouse, 'statistics', lambda *a: {})
    connection = SimpleNamespace(
        sock=SimpleNamespace(settimeout=reads.append),
        request=lambda method, endpoint, **kw: requests.append((endpoint, kw['body'].decode())),
        getresponse=lambda: SimpleNamespace(status=200, read=lambda _: b'{"data":[{"status":"RESTORED"}]}'),
        close=lambda: None,
    )
    def connect(*args, **kwargs):
        timeouts.append(kwargs['timeout'])
        return connection
    monkeypatch.setattr(backup.http.client, 'HTTPConnection', connect)
    target = backup.ClickHouse('history', 'synthetic.invalid', 'synthetic', 'unused',
                              timeout=drill.RESTORE_TIMEOUT, operation_size=100 * 1024**3)
    result = drill.verify_clickhouse_archive(target, ['fixture'], {'fixture': {}}, None,
                                            'synthetic/history.zip', 0)
    assert result['status'] == 'verified'
    endpoint, statement = next(item for item in requests if item[1].startswith('RESTORE'))
    query = parse_qs(urlsplit(endpoint).query)
    assert query['max_execution_time'] == ['0']
    assert query['query_id'][0].startswith('sli_backup_query_')
    assert 'max_execution_time=0' in statement
    # The trailing DROP is a separate bounded control request.
    assert timeouts == [operation.POLL_SECONDS, 30] and reads == [None]


@pytest.mark.skipif(__import__('sys').platform != 'linux', reason='Linux HTTP worker uses POSIX socket cancellation')
def test_clickhouse_cancel_unblocks_owned_socket_read():
    import socket
    from concurrent.futures import ThreadPoolExecutor
    from deploy.linux import backup

    reader, writer = socket.socketpair()
    try:
        with ThreadPoolExecutor(max_workers=1) as worker:
            pending = worker.submit(reader.recv, 1)
            backup.ClickHouse.cancel_transport({'socket': reader})
            assert pending.result(timeout=2) == b''
    finally:
        reader.close()
        writer.close()


def test_clickhouse_failed_server_cancel_closes_worker_and_requires_cleanup(tmp_path, monkeypatch):
    from deploy.linux import backup
    clock, cancelled = [0.0], []
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(operation, 'history_path', lambda: tmp_path / 'summary.json')

    class Future:
        def done(self):
            return bool(cancelled)

        def result(self, timeout):
            if cancelled:
                raise OSError('closed')
            clock[0] += 1000
            raise backup.FutureTimeout()

    class Executor:
        def __init__(self, **kwargs):
            pass

        def submit(self, *args, **kwargs):
            return Future()

        def shutdown(self, **kwargs):
            pass

    def query(self, statement, **kwargs):
        if statement.startswith('KILL '):
            raise OSError('unavailable')
        return []

    monkeypatch.setattr(backup, 'ThreadPoolExecutor', Executor)
    monkeypatch.setattr(backup.ClickHouse, '_query', query)
    monkeypatch.setattr(backup.ClickHouse, 'cancel_transport', staticmethod(lambda _: cancelled.append(True)))
    target = backup.ClickHouse('history', 'synthetic.invalid', 'synthetic', 'unused')
    with pytest.raises(RuntimeError, match='^linux_backup_restore_cleanup_required$'):
        target.query('RESTORE DATABASE `synthetic` FROM Disk(\'backups\', \'synthetic.zip\')')
    assert cancelled == [True]


@pytest.mark.parametrize('progressing', [True, False])
def test_migration_process_has_per_statement_progress_budget(tmp_path, monkeypatch, progressing):
    from deploy.linux import backup, migrate
    clock, captured = [0.0], {}
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(operation, 'history_path', lambda: tmp_path / 'summary.json')
    connection = SimpleNamespace(execute=lambda *_: SimpleNamespace(fetchone=lambda: (1024**3,)))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **kw: nullcontext(connection))
    monkeypatch.setattr(operation, 'postgres_probe', lambda *a: clock[0] if progressing else 0)
    process = Process(clock, finishes=2400 if progressing else 100000)

    def popen(argv, **kwargs):
        captured.update(argv=argv, **kwargs)
        return process

    monkeypatch.setattr(migrate.subprocess, 'Popen', popen)
    monkeypatch.setenv('PGPASSWORD', 'must-not-inherit')
    run = lambda: migrate.run_sql([tmp_path / '123_synthetic.sql'], passfile=tmp_path / 'passfile', atomic=True)
    if progressing:
        run()
        assert operation.samples(tmp_path / 'summary.json', 'migration') == [2400]
    else:
        with pytest.raises(operation.OperationTimeout, match='operation_stalled'):
            run()
        assert clock[0] == 1800
        assert not (tmp_path / 'summary.json').exists()
    assert process.reaped and process.killed != progressing
    assert '--single-transaction' in captured['argv']
    assert 'PGPASSWORD' not in captured['env']


def test_api_readiness_survives_old_sixty_second_limit(monkeypatch):
    from urllib.error import URLError
    from deploy.linux import native_install as install
    import ssl
    clock = [0.0]
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(operation.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(ssl, 'create_default_context', lambda **kw: object())
    monkeypatch.setattr(operation, 'readiness_history', lambda: None)

    def urlopen(*args, **kwargs):
        if clock[0] < 180:
            raise URLError(ConnectionRefusedError())
        return nullcontext(SimpleNamespace(status=200))

    monkeypatch.setattr('urllib.request.urlopen', urlopen)
    install.wait_api({'health_url': 'https://synthetic.invalid/ready'})
    assert clock[0] == 180


def test_workers_timeout_names_unready_component_without_exception_text(monkeypatch, capsys):
    from deploy.linux import native_install as install, native_runtime as runtime
    clock = [0.0]
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(operation.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(operation, 'readiness_history', lambda: None)
    def unavailable(*args, **kwargs):
        raise RuntimeError('private text must stay private')
    monkeypatch.setattr(install, 'command', unavailable)
    monkeypatch.setattr(runtime, 'configuration', lambda: {})
    monkeypatch.setattr(runtime, 'selected', lambda _: ('api', 'entity-state'))
    monkeypatch.setattr(runtime, 'healthy_service', lambda name: name == 'api')
    with pytest.raises(RuntimeError, match='native_install_workers_unhealthy'):
        install.wait_health()
    diagnostic = capsys.readouterr().err
    assert 'entity-state' in diagnostic and 'operation' in diagnostic
    assert 'private text' not in diagnostic


def test_shrinking_file_is_not_progress(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    watch = operation.Watch('postgres_dump', minimum=21600, stall=900)
    watch.check(100)
    clock[0] = 899
    watch.check(99)
    clock[0] = 900
    with pytest.raises(operation.OperationTimeout, match='operation_stalled'):
        watch.check(98)


def test_systemd_safety_budget_uses_measured_dataset(tmp_path, monkeypatch):
    from deploy.linux import backup_policy, native_backup, native_host
    monkeypatch.setattr(native_backup, 'DATA', tmp_path)
    monkeypatch.setattr(native_host.Host, 'backup_space_estimate',
                        lambda *a: backup_policy.space_estimate(76 * 1024**3, backup_bytes=16 * 1024**3))
    monkeypatch.setattr(native_backup.shutil, 'disk_usage', lambda _: pytest.fail('disk capacity is not data'))
    budget = native_backup.systemd_budget(tmp_path)
    assert budget == 184 * 1024 + 1800
    assert 'TimeoutStartSec=12h' in native_backup.units()['sli-backup.service']
    operation.record_success(tmp_path / 'backup-status/summary.json', 'drill', 100000000)
    assert native_backup.systemd_budget(tmp_path) == budget


def test_native_migration_preserves_fixed_failure_code(tmp_path, monkeypatch, capsys):
    from deploy.linux import backup, native_install
    connection = SimpleNamespace(execute=lambda *_: SimpleNamespace(fetchone=lambda: (1024,)))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **kw: nullcontext(connection))
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(tmp_path / 'synthetic'))
    monkeypatch.setattr(operation, 'history_path', lambda: tmp_path / 'summary.json')

    def popen(argv, **kwargs):
        kwargs['stderr'].write(b'private diagnostic\noperation_stalled\n')
        return Process([0], finishes=0, code=1)

    monkeypatch.setattr(native_install.subprocess, 'Popen', popen)
    with pytest.raises(RuntimeError, match='^operation_stalled$'):
        native_install.command(['python', '-m', 'deploy.linux.entrypoint', 'migrate'], env={'PATH': ''})
    assert 'private' not in capsys.readouterr().err
    assert not (tmp_path / 'summary.json').exists()


def test_stdlib_setup_loads_installed_operation_helper_without_import_path():
    import sys
    from pathlib import Path
    from deploy.linux import native_package
    path = Path(native_package.__file__).with_name('native_install.py')
    code = ('import importlib.util,sys; '
            'spec=importlib.util.spec_from_file_location("sli_install",sys.argv[1]); '
            'module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); '
            'print(module.operations().Watch("api_ready",minimum=3600).stall)')
    result = subprocess.run([sys.executable, '-I', '-c', code, str(path)],
                            capture_output=True, text=True, timeout=15, check=True)
    assert result.stdout.strip() == '900'
    assert 'operation_wait.py' in native_package.HELPERS


def test_clickhouse_capture_budget_uses_database_bytes_before_compression(tmp_path, monkeypatch):
    from deploy.linux import backup
    source_size = 500 * 1024**3
    monkeypatch.setattr(operation, 'history_path', lambda: tmp_path / '.status/summary.json')
    monkeypatch.setattr(backup.ClickHouse, 'backup_disk_path', lambda *a: 'synthetic/history.zip')
    monkeypatch.setattr(backup.ClickHouse, 'statistics', lambda *a: {})

    def query(self, statement, **kwargs):
        if 'sum(bytes_on_disk)' in statement:
            return [{'bytes': source_size}]
        if statement.startswith('SELECT version'):
            return [{'version': 'synthetic'}]
        if 'system.databases' in statement:
            return [{'name': 'synthetic'}]
        if statement.startswith('BACKUP'):
            (tmp_path / 'history.zip').write_bytes(b'compressed')
            return [{'status': 'BACKUP_CREATED'}]
        pytest.fail('unexpected query')

    monkeypatch.setattr(backup.ClickHouse, '_query', query)
    result = backup.ClickHouse('history', 'synthetic.invalid', 'synthetic', 'unused').capture_archive(tmp_path)
    assert result['database_size_bytes'] == source_size
    assert result['size_bytes'] == 10
