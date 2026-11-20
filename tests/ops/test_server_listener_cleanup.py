from types import SimpleNamespace

import pytest

# isort: split
from scripts.maintenance import server_control as module


def test_ss_ignores_unrelated_ports_and_handles_ipv6(monkeypatch):
    output = ('LISTEN 0 128 127.0.0.1:22 0.0.0.0:* users:(("ssh",pid=9,fd=3))\n'
              'LISTEN 0 128 [::]:8080 [::]:* users:(("python",pid=42,fd=4))\n')
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0, stdout=output, stderr=''))
    assert module._listening_pids(8080) == [42]
    assert module._listening_pids(8081) == []


def test_lsof_only_parses_machine_records(monkeypatch):
    def run(command, **kwargs):
        if command[0] == 'ss':
            raise FileNotFoundError('ss')
        return SimpleNamespace(returncode=0, stdout='p42\nf3\nn[::1]:8080\np9\nf4\nn127.0.0.1:22\n', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', run)
    assert module._listening_pids(8080) == [42]


@pytest.mark.parametrize('fallback', ['missing', 'empty'])
def test_hidden_ss_owner_is_not_a_free_port(monkeypatch, fallback):
    def run(command, **kwargs):
        if command[0] == 'ss':
            return SimpleNamespace(returncode=0, stdout='LISTEN 0 128 [::]:8080 [::]:*\n', stderr='')
        if fallback == 'missing':
            raise FileNotFoundError('lsof')
        return SimpleNamespace(returncode=1, stdout='', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', run)
    with pytest.raises(RuntimeError, match='unavailable'):
        module._listening_pids(8080)
    assert module.stop(target_port=8080)['status'] == 'failed'


def test_no_inventory_is_unknown(monkeypatch):
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))
    with pytest.raises(RuntimeError, match='unavailable'):
        module._listening_pids(8080)


def test_empty_successful_ss_is_free(monkeypatch):
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0, stdout='', stderr=''))
    assert module._listening_pids(8080) == []


@pytest.mark.parametrize('outcome', ['ok', 'kill_failed', 'wait_failed'])
def test_failed_start_cleanup_runs_after_operation_deadline(monkeypatch, outcome):
    clock = [0.0]
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    deadline = module.OperationDeadline(1)
    waits = []
    process = SimpleNamespace(pid=42, poll=lambda: None)
    def wait(timeout):
        waits.append(timeout)
        if outcome == 'wait_failed':
            raise module.subprocess.TimeoutExpired('owned-child', timeout)
        return -1
    process.wait = wait
    def spawn(*a, **k):
        clock[0] = 2.0
        return process, {'pid': 42}, 0
    monkeypatch.setattr(module, '_spawn', spawn)
    monkeypatch.setattr(module, '_list_processes', lambda d: d.remaining(stage='inventory'))
    monkeypatch.setattr(module, '_runtime_log_path', lambda: None)
    monkeypatch.setattr(module, '_read_log_delta', lambda *a: '')
    calls = []
    def kill(pid, cleanup_deadline):
        calls.append((pid, cleanup_deadline.remaining()))
        return {'pid': pid, 'exit_code': 1 if outcome == 'kill_failed' else 0}
    monkeypatch.setattr(module, '_terminate_pid_tree', kill)
    result = module._start_verified_runtime('synthetic', url='http://invalid', timeout=1,
        target_port=8080, insecure=False, deadline=deadline, build_id_prefix='test', require_exclusive_port_owner=True)
    assert result['failure_reason'] == 'deadline_exceeded'
    assert calls and calls[0][0] == 42 and calls[0][1] > 0
    cleanup = result['failed_start_cleanup']
    assert cleanup['status'] == ('ok' if outcome == 'ok' else 'failed')
    assert cleanup['termination_verified'] is (outcome != 'wait_failed')
    assert waits and 0 < waits[0] <= module.FAILED_START_CLEANUP_SECONDS


def test_windows_cleanup_executes_taskkill_with_fresh_budget(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    deadline = module.OperationDeadline(1)
    clock[0] = 2.0
    monkeypatch.setattr(module, 'os', SimpleNamespace(name='nt'))
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs['timeout']))
        return SimpleNamespace(returncode=0, stdout='synthetic success', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', run)
    cleanup_deadline = module.OperationDeadline(module.FAILED_START_CLEANUP_SECONDS)
    assert module._terminate_pid_tree(42, cleanup_deadline)['exit_code'] == 0
    assert calls[0][0] == ['taskkill', '/PID', '42', '/T', '/F']
    assert 0 < calls[0][1] <= module.FAILED_START_CLEANUP_SECONDS
    with pytest.raises(module.OperationDeadlineExceeded):
        deadline.remaining()


def test_ss_command_filters_requested_local_port(monkeypatch):
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', run)
    assert module._listening_pids(8080) == []
    assert calls == [['ss', '-H', '-ltnp', 'sport', '=', ':8080']]


@pytest.mark.parametrize('output', ['n[::]:8080\n', 'p42\nf3\nn[::]:8080\np9\nf4\nn[::]:8080\n'])
def test_lsof_missing_and_multiple_owners(monkeypatch, output):
    def run(command, **kwargs):
        if command[0] == 'ss':
            raise FileNotFoundError()
        assert '-a' in command and '-Fpfn' in command
        return SimpleNamespace(returncode=0, stdout=output, stderr='')
    monkeypatch.setattr(module.subprocess, 'run', run)
    if output.startswith('n'):
        with pytest.raises(RuntimeError, match='unavailable'):
            module._listening_pids(8080)
    else:
        assert module._listening_pids(8080) == [9, 42]


def test_inventory_timeout_is_not_suppressed(monkeypatch):
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: (_ for _ in ()).throw(module.subprocess.TimeoutExpired('ss', 1)))
    with pytest.raises(module.subprocess.TimeoutExpired):
        module._listening_pids(8080)


@pytest.mark.parametrize('output', ['malformed\n', 'LISTEN 0 128 [::]:8080 [::]:* users:(("x",pid=0,fd=1))\n'])
def test_unparseable_or_hidden_owner_fails_closed(monkeypatch, output):
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0, stdout=output, stderr=''))
    with pytest.raises(RuntimeError, match='unavailable'):
        module._listening_pids(8080)


def test_taskkill_timeout_is_reported_without_fallback_foreign_kill(monkeypatch):
    monkeypatch.setattr(module, 'os', SimpleNamespace(name='nt'))
    def run(command, **kwargs):
        raise module.subprocess.TimeoutExpired(command, kwargs['timeout'])
    monkeypatch.setattr(module.subprocess, 'run', run)
    result = module._terminate_pid_tree(42, module.OperationDeadline(15))
    assert result['pid'] == 42
    assert result['error_type'] == 'TimeoutExpired'


@pytest.mark.parametrize('output', [
    'LISTEN 0 128 nonsense [::]:* users:(("x",pid=42,fd=1))\n',
    'LISTEN 0 128 [invalid]:8080 [::]:* users:(("x",pid=42,fd=1))\n',
])
def test_ss_invalid_local_endpoint_cannot_look_free(monkeypatch, output):
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0, stdout=output, stderr=''))
    with pytest.raises(RuntimeError, match='unavailable'):
        module._listening_pids(8080)


@pytest.mark.parametrize('output', [
    'p42\nf3\nn[::]:8080\np9\n',
    'p42\nf3\nn[::]:8080\nf4\n',
    'p42\nf3\nnnonsense\n',
    'p42\nn[::]:8080\n',
])
def test_lsof_requires_each_process_and_file_complete(monkeypatch, output):
    def run(command, **kwargs):
        if command[0] == 'ss':
            raise FileNotFoundError()
        return SimpleNamespace(returncode=0, stdout=output, stderr='')
    monkeypatch.setattr(module.subprocess, 'run', run)
    with pytest.raises(RuntimeError, match='unavailable'):
        module._listening_pids(8080)


@pytest.mark.parametrize('endpoint', ['127.0.0.1:8080', '[::1]:8080', ':::8080', '*:8080', '[fe80::1%eth0]:8080'])
def test_ss_valid_endpoint_forms(monkeypatch, endpoint):
    output = f'LISTEN 0 128 {endpoint} *:* users:(("x",pid=42,fd=1))\n'
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0, stdout=output, stderr=''))
    assert module._listening_pids(8080) == [42]


def test_lsof_complete_unrelated_ports_are_filtered(monkeypatch):
    def run(command, **kwargs):
        if command[0] == 'ss':
            raise FileNotFoundError()
        return SimpleNamespace(returncode=0, stdout='p42\nf3\nn*:22\nf4\nn[::1]:9090\n', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', run)
    assert module._listening_pids(8080) == []


def test_lsof_multiple_files_for_same_process(monkeypatch):
    def run(command, **kwargs):
        if command[0] == 'ss':
            raise FileNotFoundError()
        return SimpleNamespace(returncode=0, stdout='p42\nf3\nn*:8080\nf4\nn[::1]:8080\n', stderr='')
    monkeypatch.setattr(module.subprocess, 'run', run)
    assert module._listening_pids(8080) == [42]
