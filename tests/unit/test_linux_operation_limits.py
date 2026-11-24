"""Native work estimates and watchdogs; synthetic sizes, clock and services."""
import hashlib
import json
import os
import socket
import stat
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup_policy, native_backup, native_host, operation_wait as operation
from deploy.linux import native_runtime

GIB = 1024**3


@pytest.mark.parametrize('rate,expected', [(1024**2, 190216), (32 * 1024**2, 7688)])
def test_systemd_budget_uses_work_not_disk_capacity(tmp_path, monkeypatch, rate, expected):
    estimate = backup_policy.space_estimate(76 * GIB, backup_bytes=16 * GIB)
    monkeypatch.setattr(native_host.Host, 'backup_space_estimate', lambda *a: estimate)
    monkeypatch.setattr(operation, 'native_rate', lambda path: rate)
    monkeypatch.setattr(operation, 'machine_id', lambda: 'local')
    monkeypatch.setattr(native_backup, 'DATA', tmp_path)
    monkeypatch.setattr(native_backup.shutil, 'disk_usage', lambda _: pytest.fail('capacity is not work'))
    assert native_backup.systemd_budget(tmp_path) == expected


@pytest.mark.parametrize('conflict,reason', [
    (None, None),
    ('unsealed-timeout', 'native_existing_configuration_conflict'),
    ('other-field', 'native_existing_configuration_conflict'),
    ('bad-seal', 'native_existing_configuration_conflict'),
    ('bad-recovery-copy', 'native_existing_configuration_conflict'),
    ('unselected-release', 'native_existing_configuration_conflict'),
    ('no-seal', 'native_existing_configuration_conflict'),
    ('owner', 'native_existing_configuration_permissions'),
    ('group', 'native_existing_configuration_permissions'),
    ('mode', 'native_existing_configuration_permissions'),
    ('symlink', 'native_symlink_forbidden'),
])
def test_backup_configure_keeps_only_accepted_start_timeout(tmp_path, monkeypatch, conflict, reason):
    machine = native_host.Host(tmp_path)
    budget = 1864
    attributes = {}
    initial_write = machine.write
    file_stat = Path.stat
    is_symlink = Path.is_symlink

    def write(name, body, mode):
        if name == native_backup.HELPER:
            return
        path = machine.path(name)
        if path.exists():
            return initial_write(name, body, mode)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body.encode())
        attributes[path] = dict(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | mode)

    def simulated_stat(path, **kwargs):
        if path in attributes:
            return SimpleNamespace(**attributes[path])
        return file_stat(path, **kwargs)

    def simulated_symlink(path):
        return stat.S_ISLNK(attributes[path]['st_mode']) if path in attributes else is_symlink(path)

    monkeypatch.setattr(Path, 'stat', simulated_stat)
    monkeypatch.setattr(Path, 'is_symlink', simulated_symlink)
    monkeypatch.setattr(native_host, 'Host', lambda: machine)
    monkeypatch.setattr(native_host, 'grp', SimpleNamespace(getgrnam=lambda _: SimpleNamespace(gr_gid=0)))
    monkeypatch.setattr(native_host, 'ensure_directory', lambda *args: None)
    monkeypatch.setattr(machine, 'require_backup_mount', lambda: None)
    monkeypatch.setattr(machine, 'backup_space_estimate', lambda root: {'capture_bytes': 1})
    monkeypatch.setattr(machine, 'directory', lambda *args: None)
    monkeypatch.setattr(machine, 'write', write)
    monkeypatch.setattr(native_backup, 'systemd_budget', lambda path: budget)
    monkeypatch.setattr(native_backup, 'capture_volume_admission', lambda *args, **kw: {'status': 'admitted'})
    monkeypatch.setattr(native_backup, 'command', lambda argv: None)
    monkeypatch.setattr(native_backup.shutil, 'disk_usage', lambda path: SimpleNamespace(free=GIB))
    monkeypatch.setattr(backup_policy, 'filesystem', lambda path: 1)
    monkeypatch.setattr(backup_policy, 'retention_settings', lambda: (7, 4))
    monkeypatch.setattr(operation, 'stall_seconds', lambda: 1800)

    state = tmp_path / 'state'
    selected = tmp_path / 'opt/sli/releases/accepted'
    recovery = tmp_path / 'recovery' / selected.name
    monkeypatch.setattr(native_runtime, 'STATE', state)
    monkeypatch.setattr(native_runtime, 'RECOVERY', recovery.parent)
    monkeypatch.setattr(native_runtime, 'trusted', Path.read_bytes)
    monkeypatch.setattr(native_runtime, 'release', lambda: (selected, {}, 'f' * 64))
    native_backup.configure()
    native_backup.configure()  # Exact existing files need no accepted receipt.

    units = [machine.path('/usr/lib/systemd/system/' + name) for name in
             ('sli-backup.service', 'sli-backup-drill.service', 'sli-backup.timer')]
    override = tmp_path / 'etc/systemd/system/sli-backup.service.d/operator.conf'
    override.parent.mkdir(parents=True)
    override.write_bytes(b'[Service]\nTimeoutStartSec=90\n')
    state.mkdir()
    receipt = {'schema_version': 1, 'release': str(selected), 'manifest_sha256': 'f' * 64}
    (state / 'installed.json').write_text(json.dumps(receipt))
    (recovery / 'units').mkdir(parents=True)
    inventory = {}
    protected = [override, state / 'installed.json']
    for unit in units:
        body = unit.read_bytes()
        saved = recovery / 'units' / unit.name
        saved.write_bytes(body)
        inventory[f'units/{unit.name}'] = {'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body)}
        protected.append(saved)
    seal = recovery / 'recovery.json'
    saved_receipt = {**receipt, 'release': selected.name, 'content_checksums': inventory}
    if conflict == 'bad-seal':
        inventory['units/sli-backup.service']['sha256'] = '0' * 64
    if conflict == 'bad-recovery-copy':
        (recovery / 'units/sli-backup.service').write_bytes(b'changed after sealing')
    if conflict == 'unselected-release':
        (state / 'installed.json').write_text(json.dumps({**receipt, 'release': str(tmp_path / 'different')}))
    if conflict != 'no-seal':
        seal.write_text(json.dumps(saved_receipt))
        protected.append(seal)

    target = units[0]
    if conflict == 'unsealed-timeout':
        target.write_bytes(target.read_bytes().replace(b'TimeoutStartSec=1864', b'TimeoutStartSec=1865'))
    if conflict == 'other-field':
        target.write_bytes(target.read_bytes().replace(b'KillMode=control-group', b'KillMode=process'))
    if conflict == 'owner':
        attributes[target]['st_uid'] = 1001
    if conflict == 'group':
        attributes[target]['st_gid'] = 1001
    if conflict == 'mode':
        attributes[target]['st_mode'] = stat.S_IFREG | 0o664
    if conflict == 'symlink':
        attributes[target]['st_mode'] = stat.S_IFLNK | 0o777

    original = {path: path.read_bytes() for path in (*units, *protected)}
    for budget in (1928, 1960):
        if reason is None:
            native_backup.configure()
        else:
            with pytest.raises(RuntimeError, match=reason):
                native_backup.configure()
        assert {path: path.read_bytes() for path in original} == original


@pytest.mark.parametrize('samples', [
    [10**400],
    [{'machine_id': 'foreign', 'size_bytes': GIB, 'seconds': 1000}],
    [{'machine_id': 'local', 'size_bytes': GIB, 'seconds': 10**100}],
    [{'machine_id': 'local', 'size_bytes': 1, 'seconds': 2000}],
    [{'machine_id': 'local', 'size_bytes': 10**400, 'seconds': 1000}],
])
def test_bad_history_cannot_inflate_native_budget(tmp_path, monkeypatch, samples):
    path = tmp_path / 'summary.json'
    path.write_text(json.dumps({'operation_samples': {'capture': samples}}))
    monkeypatch.setattr(operation, 'machine_id', lambda: 'local')
    monkeypatch.setattr(operation, 'native_rate', lambda path: 1024**2)
    watch = operation.Watch('capture', minimum=43200, size=GIB, history=path, native=True, work_path=tmp_path)
    assert watch.usual == 0
    assert watch.limit == 1024 + 1800


def test_native_slow_progress_survives_estimate(tmp_path, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(operation, 'native_rate', lambda path: 1024**2)
    watch = operation.Watch('capture', minimum=1, size=1024, stall=90, native=True, work_path=tmp_path)
    watch.check(0)
    for tick in range(1, 100):
        clock[0] = tick * 30
        watch.check(tick)
    assert clock[0] > watch.limit
    clock[0] += 90
    with pytest.raises(operation.OperationTimeout):
        watch.check(99)


@pytest.mark.skipif(os.name != 'posix', reason='POSIX interval timer; Linux container')
def test_apt_watchdog_interrupts_blocked_step_and_disarms_before_recovery(monkeypatch):
    handlers, timers, clock = {}, [], [0.0]
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(operation.signal, 'signal', lambda number, handler: handlers.setdefault(number, handler))
    monkeypatch.setattr(operation.signal, 'getsignal', lambda number: None)
    monkeypatch.setattr(operation.signal, 'setitimer', lambda *args: timers.append(args))
    watch = operation.Watch('setup', minimum=180, stall=90)
    with pytest.raises(operation.OperationTimeout, match='operation_stalled'):
        with operation.deadline(watch):
            clock[0] = 90
            handlers[operation.signal.SIGALRM](None, None)
    assert timers[-1][1] == 0


def test_apt_setup_timeout_reaches_existing_rollback(monkeypatch, tmp_path):
    from deploy.linux import native_install as install, native_runtime as runtime, native_upgrade as upgrade
    events = []
    journal = SimpleNamespace(path=tmp_path / ('0' * 32), value={'target_version': '1', 'created_at_utc': 'today',
                                    'status': 'checkpoint_verified'}, write=lambda: None)
    monkeypatch.setattr(upgrade, 'TRANSACTIONS', tmp_path)
    (tmp_path / 'tx').mkdir()
    monkeypatch.setattr(upgrade, 'Journal', lambda path: journal)
    monkeypatch.setattr(upgrade, 'operation_lock', lambda path: nullcontext())
    monkeypatch.setattr(upgrade, 'run_service', lambda *args: False)  # In-process path under test.
    monkeypatch.setattr(install, 'inventory', lambda release: None)
    monkeypatch.setattr(runtime, 'no_transaction', lambda: None)
    monkeypatch.setattr(install, 'setup_deadline', lambda: nullcontext())
    monkeypatch.setattr(install, 'backup_schedule', lambda: 'disabled')

    def blocked(*args):
        raise operation.OperationTimeout('operation_stalled', {})

    monkeypatch.setattr(upgrade, 'activate', blocked)
    monkeypatch.setattr(upgrade, 'recover_compatible', lambda value: events.append('old-services-started'))
    with pytest.raises(operation.OperationTimeout, match='operation_stalled'):
        upgrade.configure_package('candidate', '1')
    assert events == ['old-services-started']
    assert journal.value['failure_reason_code'] == 'operation_stalled'


def test_native_history_is_scaled_by_work_and_survives_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(operation, 'machine_id', lambda: 'local')
    monkeypatch.setattr(operation, 'native_rate', lambda path: 1024**2)
    path = tmp_path / 'summary.json'
    operation.record_success(path, 'capture', 1200, size=GIB)
    watch = operation.Watch('capture', minimum=0, size=2 * GIB, history=path,
                            native=True, work_path=tmp_path)
    assert watch.usual == 2400
    assert watch.limit == 4200


def test_history_read_is_bounded(tmp_path):
    path = tmp_path / 'summary.json'
    path.write_bytes(b' ' * (operation.MAX_HISTORY_BYTES + 1))
    assert operation.read_history(path) == {}


def test_legacy_native_durations_cannot_be_imported_from_another_machine(tmp_path, monkeypatch):
    monkeypatch.setenv('SLI_DEPLOYMENT_MODE', 'native')
    monkeypatch.setattr(operation, 'machine_id', lambda: 'local')
    path = tmp_path / 'summary.json'
    path.write_text(json.dumps({'operation_machine_id': 'foreign',
                                'operation_durations': {'migration': [50], 'capture': [50]}}))
    assert operation.samples(path, 'migration', maximum=60) == []
    operation.record_success(path, 'migration', 20)
    assert operation.samples(path, 'migration', maximum=60) == [20]
    assert operation.samples(path, 'capture', maximum=60) == []


@pytest.mark.skipif(os.name != 'posix', reason='POSIX writable-mode check')
def test_writable_history_is_neither_read_nor_replaced(tmp_path):
    path = tmp_path / 'summary.json'
    original = '{"operation_durations":{"capture":[50]}}'
    path.write_text(original)
    path.chmod(0o666)
    assert operation.read_history(path) == {}
    operation.record_success(path, 'capture', 20)
    assert path.read_text() == original


def test_progress_notifies_watchdog_only_at_intervals(monkeypatch):
    clock, sent = [0.0], []
    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(operation, '_watchdog_last', None)
    monkeypatch.setattr(operation, 'progress_fds', lambda: ())
    monkeypatch.setenv('NOTIFY_SOCKET', '@sli-test-watchdog')
    monkeypatch.setenv('WATCHDOG_PID', str(os.getpid()))
    monkeypatch.setattr(operation.subprocess, 'run', lambda *a, **kw: pytest.fail('no set-property'))
    monkeypatch.setattr(socket, 'AF_UNIX', getattr(socket, 'AF_UNIX', 1), raising=False)

    def connect(family, kind):
        assert (family, kind) == (socket.AF_UNIX, socket.SOCK_DGRAM)
        return nullcontext(SimpleNamespace(settimeout=lambda seconds: None,
                           sendto=lambda payload, address: sent.append((payload, address))))

    monkeypatch.setattr(socket, 'socket', connect)
    operation.made_progress()
    clock[0] = 4.9
    operation.made_progress()
    assert sent == [(b'WATCHDOG=1', '\0sli-test-watchdog')]
    clock[0] = 5
    operation.made_progress()
    clock[0] = 36
    operation.made_progress()
    assert sent == [(b'WATCHDOG=1', '\0sli-test-watchdog')] * 3


@pytest.mark.parametrize('notify', [None, '/unused-notify-socket'])
def test_watchdog_without_socket_or_in_child_is_noop(monkeypatch, notify):
    monkeypatch.delenv('NOTIFY_SOCKET', raising=False)
    if notify:
        monkeypatch.setenv('NOTIFY_SOCKET', notify)
        monkeypatch.setenv('WATCHDOG_PID', str(os.getpid() + 1))
    monkeypatch.setattr(socket, 'socket', lambda *a: pytest.fail('not the notifying coordinator'))
    monkeypatch.setattr(operation.subprocess, 'run', lambda *a, **kw: pytest.fail('no set-property'))
    operation.made_progress()


def test_native_settings_preserve_watchdog_identity_without_inherited_secrets(monkeypatch):
    from deploy.linux import native_clickhouse_endpoint as endpoint, native_install
    monkeypatch.setattr(endpoint, 'configured_mode', lambda: 'native')
    expected = {'NOTIFY_SOCKET': '@sli-test', 'WATCHDOG_PID': str(os.getpid()),
                'WATCHDOG_USEC': '1800000000', 'INVOCATION_ID': 'a' * 32}
    for key, value in expected.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv('PGPASSWORD', 'synthetic-untrusted')
    for settings in (native_backup.settings(), native_install.environment()):
        assert all(settings.get(key) == value for key, value in expected.items())
        assert 'PGPASSWORD' not in settings
        with native_backup.environment(settings):
            assert os.environ['NOTIFY_SOCKET'] == '@sli-test'


@pytest.mark.parametrize('action', ['backup', 'upgrade'])
def test_exec_launch_preserves_coordinator_watchdog_environment(tmp_path, monkeypatch, action):
    from pathlib import Path
    from deploy.linux import native_upgrade
    target = native_backup if action == 'backup' else native_upgrade
    helper = tmp_path / 'native_runtime.py'
    helper.write_text(
        'from pathlib import Path\nimport hashlib\n'
        "def release(): return Path('/accepted/old'), {'python':'/accepted/python'}, 'digest'\n"
        "def trusted(path): return b'coordinator'\n"
        "def document(path): return {'python':'/accepted/python', 'manifest_sha256':'digest', "
        "'content_checksums':{'release/deploy/linux/native_upgrade.py': "
        "{'sha256':hashlib.sha256(b'coordinator').hexdigest()}}}\n")
    monkeypatch.setattr(target, 'RUNTIME_HELPER', helper)
    original = Path.lstat
    monkeypatch.setattr(Path, 'lstat', lambda path: SimpleNamespace(st_uid=0, st_mode=0o100755)
                        if path in (helper, *helper.parents) else original(path))
    monkeypatch.setattr(target.os, 'chdir', lambda path: None)
    monkeypatch.setattr(sys, 'dont_write_bytecode', sys.dont_write_bytecode)
    calls = []
    monkeypatch.setattr(target.os, 'execve', lambda *args: calls.append(args))
    expected = {'NOTIFY_SOCKET': '@sli-test', 'WATCHDOG_PID': str(os.getpid()),
                'WATCHDOG_USEC': '1800000000', 'INVOCATION_ID': 'a' * 32}
    backup_options = {'SLI_RESTORE_CHECK_ROOT': '/test/restore-check',
                      'SLI_BACKUP_RETENTION': '7', 'SLI_BACKUP_WEEKLY_RETENTION': '4'}
    for key, value in (expected | backup_options).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv('PYTHONPATH', 'untrusted')
    monkeypatch.setenv('LD_PRELOAD', 'untrusted')
    if action == 'backup':
        target.launch('drill')
        expected_argv = ['/usr/bin/unshare', '--mount', '--propagation', 'private', '--',
                         '/accepted/python', '-B', '-m', 'deploy.linux.native_backup', 'drill']
        expected.update(backup_options)
    else:
        target.launch('new', 'b' * 32)
        script = Path('/var/lib/sli/recovery/old/release/deploy/linux/native_upgrade.py')
        expected_argv = ['/accepted/python', '-I', '-B', str(script), 'prepare', 'new', 'b' * 32]
    assert calls == [(expected_argv[0], expected_argv, {
        'PATH': '/usr/lib/postgresql/18/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1', **expected,
    })]


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux UNIX datagram/abstract sockets')
@pytest.mark.parametrize('abstract', [False, True])
def test_watchdog_reaches_real_notify_socket(monkeypatch, abstract):
    import secrets
    import tempfile
    # sockaddr_un paths are short even when the checkout/basetemp path is long.
    with tempfile.TemporaryDirectory(prefix='sli-wd-', dir='/tmp') as folder:
        address = '\0sli-watchdog-' + secrets.token_hex(8) if abstract else folder + '/notify'
        monkeypatch.setenv('NOTIFY_SOCKET', '@' + address[1:] if abstract else address)
        monkeypatch.setenv('WATCHDOG_PID', str(os.getpid()))
        monkeypatch.setattr(operation, '_watchdog_last', None)
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
            receiver.bind(address)
            receiver.settimeout(0.1)
            operation.made_progress()
            assert receiver.recv(1024) == b'WATCHDOG=1'
            operation.made_progress()
            with pytest.raises(socket.timeout):
                receiver.recv(1024)


@pytest.mark.parametrize('minutes,expected', [(None, 1800), (25, 1500)])
def test_coordinator_units_and_native_watch_share_stall(monkeypatch, minutes, expected):
    from deploy.linux import native_clickhouse_endpoint as endpoint
    monkeypatch.setattr(endpoint, 'site_configuration', lambda: {} if minutes is None else
                        {'operation_stall_minutes': minutes})
    for name in ('sli-backup.service', 'sli-backup-drill.service'):
        body = native_backup.units()[name]
        assert f'WatchdogSec={expected}\n' in body
        assert 'NotifyAccess=main\n' in body
        assert 'RuntimeMaxSec=infinity\n' in body
    assert operation.Watch('capture', minimum=0, native=True).stall == expected


@pytest.mark.parametrize('invocation,cgroup,expected', [
    ('a' * 32, '0::/system.slice/sli-backup-drill.service\n', 'sli-backup-drill.service'),
    ('b' * 32, '0::/system.slice/sli-upgrade-capture-123.service\n', 'sli-upgrade-capture-123.service'),
    ('c' * 32, '0::/user.slice/user@1000.service/app.slice/run-drill.service\n', 'run-drill.service'),
    ('', '0::/system.slice/ssh.service\n', None),
    ('d' * 32, '0::/user.slice/session-1.scope\n', None),
    ('d' * 32, '0::/system.slice/bad name.service\n', None),
])
def test_coordinator_identity_comes_from_own_service(monkeypatch, invocation, cgroup, expected):
    from pathlib import Path
    monkeypatch.setenv('INVOCATION_ID', invocation)
    def read(path, **kwargs):
        assert path == Path('/proc/self/cgroup')
        return cgroup
    monkeypatch.setattr(Path, 'read_text', read)
    assert operation.coordinator_unit() == expected


@pytest.mark.skipif(os.name != 'posix', reason='POSIX signal and pipe supervision; Linux container')
def test_real_blocked_apt_step_times_out():
    watch = operation.Watch('setup', minimum=1, stall=0.02, native=True)
    with pytest.raises(operation.OperationTimeout):
        with operation.deadline(watch):
            operation.signal.pause()
    assert operation.signal.getitimer(operation.signal.ITIMER_REAL) == (0, 0)


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process groups and pass_fds; Linux container')
@pytest.mark.parametrize('progressing', [False, True])
def test_setup_parent_observes_only_child_progress_and_reaps(tmp_path, monkeypatch, progressing):
    import sys
    monkeypatch.setattr(operation, 'POLL_SECONDS', 0.02)
    watch = operation.Watch('setup', minimum=0, stall=0.3, native=True)
    # Repeated diagnostic prose is not progress. Only the inherited pipe is.
    code = ('import os,time; fd=int(os.environ["SLI_OPERATION_PROGRESS_FD"]); '
            '[(os.write(fd,b".") if ' + repr(progressing) + ' else print("noise",flush=True), '
            'time.sleep(.05)) for _ in range(20)]')
    call = lambda: operation.setup_command([sys.executable, '-c', code], cwd=tmp_path, env=dict(os.environ), watch=watch)
    if progressing:
        call()
    else:
        with pytest.raises(operation.OperationTimeout):
            call()


@pytest.mark.parametrize('valid', [True, False])
@pytest.mark.parametrize('report', [
    'native_command_failed: systemctl list-unit-files',
    'native_command_failed: systemctl stop sli-clickhouse-history.service',
])
def test_setup_parent_relays_only_exact_command_failure(tmp_path, monkeypatch, capsys, valid, report):
    from deploy.linux import native_diagnostics

    def child(argv, *, stderr, **kwargs):
        message = report if valid else report + ' synthetic-private-argument'
        stderr.write(('synthetic-private-output\n' + message + '\n').encode())
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(operation.os, 'set_blocking', lambda *args: None)
    monkeypatch.setattr(operation.subprocess, 'Popen', child)
    monkeypatch.setattr(operation, 'wait_process', lambda *args: None)
    with pytest.raises(RuntimeError) as error:
        operation.setup_command(['synthetic-install'], cwd=tmp_path, env={}, watch=None,
                                failure_codes=native_diagnostics.COMMAND_FAILURES)
    native_diagnostics.failure(error.value)
    stderr = capsys.readouterr().err
    if valid:
        assert stderr == report + '\n'
    else:
        assert 'SLI could not finish its first start' in stderr
        assert 'synthetic-private' not in stderr


@pytest.mark.parametrize('backup_schedule', ['enabled', 'disabled', 'masked'])
def test_timed_out_accepted_reinstall_restarts_services(tmp_path, monkeypatch, backup_schedule):
    from deploy.linux import native_install as install, native_runtime as runtime, native_upgrade as upgrade
    root, state = tmp_path / 'release', tmp_path / 'state'
    root.mkdir()
    state.mkdir()
    accepted = {'status': 'configured', 'release': 'release'}
    (state / 'package-install.json').write_text(json.dumps(accepted))
    (state / 'installed.json').write_text(json.dumps({'release': str(root), 'manifest_sha256': 'digest'}))
    monkeypatch.setattr(install, 'STATE', state)
    monkeypatch.setattr(install, 'CURRENT', root)
    monkeypatch.setattr(install, 'trusted', lambda path: path.read_bytes())
    monkeypatch.setattr(install, 'inventory', lambda release: (root, {}, 'digest'))
    monkeypatch.setattr(install, 'setup_deadline', lambda: nullcontext())
    monkeypatch.setattr(install, 'atomic', lambda path, value: path.write_text(json.dumps(value)))
    monkeypatch.setattr(runtime, 'no_transaction', lambda: None)
    events = []
    monkeypatch.setattr(upgrade, 'start_checked', lambda: events.append('healthy'))
    monkeypatch.setattr(install, 'backup_schedule', lambda: backup_schedule)
    monkeypatch.setattr(install, 'command', lambda argv, **kw: events.append(argv))

    def blocked(release):
        (state / 'package-install.json').write_text('{"status":"failed"}')
        raise operation.OperationTimeout('operation_stalled', {})

    monkeypatch.setattr(install, 'configure', blocked)
    with pytest.raises(operation.OperationTimeout, match='operation_stalled'):
        install.configure_guarded('release')
    assert json.loads((state / 'package-install.json').read_text()) == accepted
    expected = ['healthy', ['systemctl', 'enable', '--now', 'sli.target']]
    if backup_schedule == 'enabled':
        expected.append(['systemctl', 'start', 'sli-backup.timer'])
    assert events == expected
