"""Native recovery-set contracts; DB/systemd operations use fakes only."""
import json
import os
import zipfile
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup, native_backup_settings, native_host, native_runtime, restore_existing
from deploy.linux import native_backup as native

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='POSIX ownership, fcntl, fsync and cgroups; portable EXTCH tests run separately')


@pytest.fixture(autouse=True)
def native_clickhouse_mode(monkeypatch):
    from deploy.linux import operation_wait
    monkeypatch.setattr(operation_wait, 'native_rate', lambda path: 1024**2)
    # Temporary-root lifecycle fakes do not provision real system ownership.
    def directory(path, mode=0o755, *owners, **options):
        path.mkdir(mode=mode, parents=True, exist_ok=options.get('exist_ok', True))

    monkeypatch.setattr(native, 'ensure_directory', directory)
    monkeypatch.setattr(native_host.clickhouse, 'configured_mode', lambda root=Path('/'): 'native')


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def recovery_set(root, stamp, *, legacy_clickhouse=True):
    path = root / stamp
    data = path / 'data' / stamp
    data.mkdir(parents=True)
    names = ('postgres/toc.dat', 'roles.sql', 'files/evidence/item') + (('history.zip', 'warm.zip') if legacy_clickhouse else ())
    components = backup.COMPONENTS if legacy_clickhouse else ('postgres', 'files')
    for name in names:
        file = data / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(b'synthetic')
        if file.suffix == '.zip':
            with zipfile.ZipFile(file, 'w') as archive:
                archive.writestr('synthetic', b'archive-data')
    write(data / 'manifest.json', {'status': 'success', 'backup_id': stamp,
          'components': {name: ({'database_size_bytes': 1024} if name == 'postgres' else {}) for name in components},
          'content_checksums': backup.content_inventory(data)})
    write(path / 'companion/state/installed.json', {'migration_ledger': []})
    write(path / 'manifest.json', {'schema_version': 1, 'status': 'backup_created',
          'backup_id': stamp, 'data_path': 'data/' + stamp, 'content_checksums': backup.content_inventory(path)})
    return path


@pytest.fixture
def storage(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, 'capture_admission', lambda root, **kwargs: None)
    root = tmp_path / 'backups'
    root.mkdir()
    status_data = tmp_path / 'status-data'
    status_data.mkdir()
    monkeypatch.setattr(native, 'DATA', status_data)
    drills = tmp_path / 'drills'
    drills.mkdir()
    monkeypatch.setattr(native, 'ROOT', root)
    monkeypatch.setattr(native, 'DRILLS', drills)
    from deploy.linux import backup_policy
    data = tmp_path / 'ssd'
    data.mkdir()
    monkeypatch.setattr(native_host, 'MOUNT', str(data))
    monkeypatch.setattr(backup_policy, 'filesystem', lambda path: 'ssd' if path == data else 'hdd')
    monkeypatch.setattr(backup_policy.shutil, 'disk_usage', lambda path: SimpleNamespace(
        free=100 * 1024**3, total=200 * 1024**3))
    monkeypatch.setattr(native_host, 'administrative_lock', nullcontext)
    monkeypatch.setattr(native_backup_settings, 'read_policy',
                        lambda: {'enabled': True, 'identity': {'uuid': 'fixture-volume'}})
    monkeypatch.setattr(native_backup_settings, 'selected_storage',
                        lambda state, **options: nullcontext((root, lambda: None)))
    return root


def test_timer_and_service_contract():
    units = native.units()
    assert 'OnCalendar=*-*-* 02:00:00' in units['sli-backup.timer']
    assert 'Persistent=true' in units['sli-backup.timer']
    assert 'PartOf=sli.target' in units['sli-backup.service']
    assert 'launch scheduled-capture' in units['sli-backup.service']
    assert 'UMask=0077' in units['sli-backup.service']
    assert 'KillMode=control-group' in units['sli-backup.service']


@pytest.mark.parametrize('backup_gib,data_gib,accepted', [(7, 100, True), (5, 100, False), (100, 0, False)])
def test_configure_admits_capture_without_optional_drill_workspace(storage, monkeypatch,
                                                                  backup_gib, data_gib, accepted):
    from deploy.linux import backup_policy as policy

    files, events = {}, []
    data = Path(native_host.MOUNT)
    estimate = policy.space_estimate(10 * policy.GIB, backup_bytes=5 * policy.GIB)
    monkeypatch.setattr(policy.shutil, 'disk_usage', lambda path: SimpleNamespace(
        free=(data_gib if Path(path) == data else backup_gib) * policy.GIB))
    monkeypatch.setattr(native, 'capture_volume_admission', policy.volume_admission)

    def directory(path, *args):
        if Path(path) == native.DRILLS:
            raise PermissionError('optional drill workspace is unavailable')
        events.append('directory')

    machine = SimpleNamespace(require_backup_mount=lambda: events.append('mount-checked'),
        backup_space_estimate=lambda root: estimate, directory=directory,
        path=lambda path: storage / path.lstrip('/'),
        write=lambda path, body, *args: files.update({str(path): body}))
    monkeypatch.setattr(native_host, 'Host', lambda: machine)
    monkeypatch.setattr(native, 'systemd_budget', lambda path: 300)
    monkeypatch.setattr(native, 'command', lambda argv, **kwargs: events.append(argv))
    if accepted:
        native.configure()
        assert events[0] == 'mount-checked'
        assert '/usr/lib/systemd/system/sli-backup-drill.service' in files
    else:
        with pytest.raises(RuntimeError, match='native_backup_separate_volume_required'):
            native.configure()
        assert events == ['mount-checked'] and not files


def test_budget_does_not_probe_optional_drill_volume(storage, monkeypatch):
    from deploy.linux import backup_policy as policy, operation_wait

    estimate = policy.space_estimate(10 * policy.GIB, backup_bytes=5 * policy.GIB)
    monkeypatch.setattr(native_host.Host, 'backup_space_estimate', lambda self, root: estimate)
    def rate(path):
        if Path(path) == native.DRILLS:
            pytest.fail('configuration probed the unavailable optional drill volume')
        return 1024**2
    monkeypatch.setattr(operation_wait, 'native_rate', rate)
    assert native.systemd_budget(Path(native_host.MOUNT)) > 0


@pytest.mark.parametrize('name', ['data/20261017T010000.000000Z/postgres/toc.dat',
                                    'companion/state/installed.json', 'data/20261017T010000.000000Z/manifest.json'])
def test_hash_readback_rejects_any_changed_component(storage, name):
    path = recovery_set(storage, '20261017T010000.000000Z')
    native.verify(path)
    (path / name).write_text('tampered')
    with pytest.raises(RuntimeError, match='hash_mismatch'):
        native.verify(path)


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'extra_file', 'missing_file'])
def test_readback_refuses_unsafe_or_inexact_inventory(storage, kind):
    path = recovery_set(storage, '20261017T010000.000000Z')
    if kind == 'symlink':
        (path / 'extra').symlink_to(path / 'manifest.json')
    elif kind == 'hardlink':
        os.link(path / 'manifest.json', path / 'extra')
    elif kind == 'extra_file':
        (path / 'extra').write_text('unexpected')
    else:
        (path / 'companion/state/installed.json').unlink()
    with pytest.raises((RuntimeError, ValueError)):
        native.verify(path)


def test_retention_one_keeps_last_drill_and_external_checkpoints(storage, monkeypatch):
    from deploy.linux import operation_wait

    old = recovery_set(storage, '20261017T010000.000000Z')
    discard = recovery_set(storage, '20261017T020000.000000Z')
    remaining = []
    monkeypatch.setattr(operation_wait, 'made_progress', lambda: remaining.append(len(list(discard.rglob('*')))))
    new = recovery_set(storage, '20261017T030000.000000Z')
    checkpoint = storage / 'update-checkpoints/operation'
    checkpoint.mkdir(parents=True)
    write(storage / 'restore-verified.json', {'backup_id': old.name})
    native.prune(new)
    assert old.exists() and new.exists() and checkpoint.exists() and not discard.exists()
    assert len(set(remaining)) > 3  # Progress between actual entry removals.
    write(storage / 'restore-verified.json', {'backup_id': new.name})
    native.prune(new)
    assert not old.exists() and checkpoint.exists()


def test_failed_new_readback_never_prunes(storage):
    old = recovery_set(storage, '20261017T010000.000000Z')
    new = recovery_set(storage, '20261017T030000.000000Z')
    (new / 'unexpected').write_text('bad')
    with pytest.raises(RuntimeError):
        native.prune(new)
    assert old.exists()


def test_companion_copies_only_online_secrets_and_preserves_source(tmp_path, monkeypatch):
    from deploy.linux import native_install
    config = tmp_path / 'etc'
    data = tmp_path / 'data'
    state = data / 'state'
    for directory in (config / 'secrets', config / 'clickhouse', state, data / 'recovery'):
        directory.mkdir(parents=True)
    for name in ('runtime.json', 'site.toml'):
        (config / name).write_text('configuration')
    write(config / 'runtime.json', {'agents': True})
    inventory = json.loads(Path(native.__file__).with_name('secrets-manifest.json').read_text())
    for name in inventory['secrets']:
        (config / 'secrets' / name).write_text('synthetic-value')
    master_canary = b'synthetic-ad-kek-exclusion-canary'
    master_path = config / 'secrets/ad_credentials_master_key'
    master_path.write_bytes(master_canary)
    monkeypatch.setattr(native, 'CONFIG', config)
    monkeypatch.setattr(native, 'DATA', data)
    monkeypatch.setattr(native, 'STATE', state)
    monkeypatch.setattr(native_install, 'trusted', lambda path: path.read_bytes())
    monkeypatch.setattr(native, 'command', lambda argv: b'sli\t1.0\tamd64\n')
    original = native.copy_private
    def copy(source, destination):
        if str(source).startswith('/etc/postgresql'):
            destination.mkdir()
        else:
            original(source, destination)
    monkeypatch.setattr(native, 'copy_private', copy)
    dest = tmp_path / 'companion'
    native.companion(dest)
    assert not (dest / 'secrets/agent_root_key').exists()
    assert not (dest / 'secrets/ad_credentials_master_key').exists()
    assert (dest / 'secrets/agent_issuer_key').read_text() == 'synthetic-value'
    assert (config / 'secrets/agent_root_key').read_text() == 'synthetic-value'
    assert all(file.stat().st_mode & 0o077 == 0 for file in (dest / 'secrets').iterdir())
    assert (dest / 'packages.tsv').is_file()
    # Inspect the companion actually produced by the helper, rather than only
    # the inventory allowlist. This is a fake-host unit, not an installed backup.
    from scripts.maintenance.ad_gpo_pilot_acceptance import scan_canary
    assert all(scan_canary(file, master_canary) == 'passed' for file in dest.rglob('*') if file.is_file())
    assert master_path.read_bytes() == master_canary


@pytest.mark.parametrize('notification', ['absent', 'present', 'broken_link'])
def test_optional_notification_secrets_follow_fresh_install_import_contract(tmp_path, monkeypatch, notification):
    from deploy.linux import native_install

    config = tmp_path / 'etc'
    (config / 'secrets').mkdir(parents=True)
    write(config / 'runtime.json', {'agents': False})
    inventory = json.loads(Path(native.__file__).with_name('secrets-manifest.json').read_text())
    for name, spec in inventory['secrets'].items():
        if spec['group'] in {'core', 'tls'}:
            (config / 'secrets' / name).write_text('synthetic')
    path = config / 'secrets/notification_smtp_password'
    if notification == 'present':
        path.write_text('synthetic-notification')
    elif notification == 'broken_link':
        path.symlink_to('missing')
    monkeypatch.setattr(native, 'CONFIG', config)
    monkeypatch.setattr(native_install, 'trusted', lambda path: path.read_bytes())
    if notification == 'broken_link':
        with pytest.raises(FileNotFoundError):
            native.secret_sources()
    else:
        sources = native.secret_sources()
        assert ('notification_smtp_password' in sources) == (notification == 'present')
        assert sources['postgres_password'].read_text() == 'synthetic'


@pytest.mark.parametrize('kind', ['missing', 'broken_optional_link'])
def test_online_secret_preflight_refuses_missing_or_broken_credentials(tmp_path, monkeypatch, kind):
    from deploy.linux import native_install

    config = tmp_path / 'etc'
    (config / 'secrets').mkdir(parents=True)
    write(config / 'runtime.json', {'agents': False})
    inventory = {'secrets': {'runtime_password': {'group': 'runtime'}, 'agent_issuer_key': {'group': 'agents'},
                             'agent_root_key': {'group': 'offline'}}}
    def trusted(path):
        return json.dumps(inventory).encode() if path.name == 'secrets-manifest.json' else path.read_bytes()
    monkeypatch.setattr(native, 'CONFIG', config)
    monkeypatch.setattr(native_install, 'trusted', trusted)
    if kind == 'broken_optional_link':
        (config / 'secrets/runtime_password').write_text('synthetic-value')
        (config / 'secrets/agent_issuer_key').symlink_to('missing')
    with pytest.raises((RuntimeError, FileNotFoundError)):
        native.secret_sources()


@pytest.fixture
def drill_fakes(storage, monkeypatch):
    path = recovery_set(storage, '20261017T010000.000000Z')
    events = []
    @contextmanager
    def databases(work, *, cleanup):
        events.append('start-isolated')
        try:
            yield native.settings() | {'SLI_PG_PORT': '55432'}
        finally:
            events.append('stopped')
            cleanup['databases_stopped'] = True
    monkeypatch.setattr(native, 'isolated_databases', databases)
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(Path('/unused')))
    conn = SimpleNamespace(execute=lambda query: SimpleNamespace(fetchall=list))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a: nullcontext(conn))
    def restore(data, root, manifest, components, *, files_root):
        assert os.environ['SLI_PG_PORT'] == '55432'
        assert data.is_relative_to(root) and root != path
        assert backup.content_inventory(data) == manifest['content_checksums']
        assert components == ("postgres", "files") and files_root.is_relative_to(native.DRILLS)
        events.append('restore')
    monkeypatch.setattr(restore_existing, 'restore_components', restore)
    return SimpleNamespace(path=path, events=events)


def test_drill_private_snapshot_terminal_only_after_cleanup(drill_fakes, storage, monkeypatch):
    from deploy.linux import backup_restore_check
    from deploy.linux import operation_wait

    removals = []
    monkeypatch.setattr(operation_wait, 'made_progress', lambda: removals.append(
        sum(1 for _ in native.DRILLS.rglob('*'))))

    # The native service provisions its own disposable cluster; it must not
    # depend on the Docker-style shared-server capacity publisher/admission.
    monkeypatch.setattr(backup_restore_check, 'restore_check', lambda *a, **kw:
                        pytest.fail('native drill entered shared-server restore check'))
    monkeypatch.setattr(backup_restore_check, 'postgres_admission', lambda *a, **kw:
                        pytest.fail('native drill requires shared-server capacity receipt'))
    original = native.copy_private
    def copy(source, destination):
        assert 'stopped' not in drill_fakes.events
        original(source, destination)
    monkeypatch.setattr(native, 'copy_private', copy)
    native.drill()
    assert not (storage / '.postgres-capacity.json').exists()
    assert drill_fakes.events == ['start-isolated', 'restore', 'stopped']
    result = json.loads((storage / 'drill-result.json').read_text())
    assert result['status'] == 'restore_verified' and result['terminal'] and result['databases_stopped']
    assert result == json.loads((storage / 'restore-verified.json').read_text())
    assert len(set(removals)) > 3


def test_explicit_drill_creates_private_workspace_on_demand(drill_fakes, storage):
    assert not list(native.DRILLS.iterdir())
    native.DRILLS.rmdir()
    native.drill()
    assert native.DRILLS.stat().st_mode & 0o777 == 0o711
    assert not list(native.DRILLS.iterdir())
    assert json.loads((storage / 'restore-verified.json').read_text())['status'] == 'restore_verified'


@pytest.mark.parametrize('failure', ['restore', 'ledger', 'cleanup', 'tamper'])
def test_drill_failure_never_advances_last_recoverable_receipt(drill_fakes, storage, monkeypatch, failure):
    receipt = {'backup_id': '20261016T010000.000000Z'}
    write(storage / 'restore-verified.json', receipt)
    if failure == 'restore':
        monkeypatch.setattr(restore_existing, 'restore_components', lambda *a, **k: native.require(False))
    elif failure == 'ledger':
        conn = SimpleNamespace(execute=lambda query: SimpleNamespace(fetchall=lambda: [(1, 'x', 'sha')]))
        monkeypatch.setattr(backup, 'pg_connect', lambda *a: nullcontext(conn))
    elif failure == 'cleanup':
        @contextmanager
        def databases(work, *, cleanup):
            yield native.settings() | {'SLI_PG_PORT': '55432'}
            raise RuntimeError('cleanup failed')
        monkeypatch.setattr(native, 'isolated_databases', databases)
    else:
        (drill_fakes.path / 'companion/state/installed.json').write_text('tampered')
    with pytest.raises(RuntimeError):
        native.drill()
    assert json.loads((storage / 'restore-verified.json').read_text()) == receipt
    result = json.loads((storage / 'drill-result.json').read_text())
    assert result['terminal'] and result['status'] == 'failed'


def test_cleanup_attempts_all_units_and_rejects_live_process(monkeypatch):
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        if argv[1] == 'show':
            return b'ActiveState=active\nMainPID=42\n'
        return b''
    monkeypatch.setattr(native, 'command', command)
    with pytest.raises(RuntimeError, match='cleanup_failed'):
        native.stop_drill(['first.service', 'second.service'])
    assert [c[2] for c in calls if c[1] == 'stop'] == ['second.service', 'first.service']


def test_cleanup_checks_child_cgroups(tmp_path, monkeypatch):
    parent = tmp_path / 'system.slice/test.service'
    child = parent / 'child'
    child.mkdir(parents=True)
    (parent / 'cgroup.procs').write_text('')
    (child / 'cgroup.procs').write_text('42\n')
    monkeypatch.setattr(native, 'CGROUP_ROOT', tmp_path)
    monkeypatch.setattr(native, 'command', lambda *a, **k:
                        b'ActiveState=inactive\nMainPID=0\nControlGroup=/system.slice/test.service\n')
    with pytest.raises(RuntimeError, match='cleanup_failed'):
        native.stop_drill(['test.service'])


def test_database_provisioning_never_selects_live_ports_or_paths(tmp_path, monkeypatch):
    import pwd
    from deploy.linux import operation_wait
    meminfo = tmp_path / 'meminfo'
    meminfo.write_text(f'MemAvailable: {12 * 1024**2} kB\n')
    monkeypatch.setattr(native, 'MEMINFO', meminfo, raising=False)
    monkeypatch.setattr(operation_wait, 'coordinator_unit', lambda: None)
    monkeypatch.setattr(native, 'systemd_budget', lambda path: 2500)
    work = tmp_path / 'isolated'
    work.mkdir()
    monkeypatch.setattr(pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
    monkeypatch.setattr(native.os, 'chown', lambda *a: None)
    calls = []
    def command(argv, **kwargs):
        calls.append(argv)
        return b'ActiveState=inactive\nMainPID=0\nControlGroup=\n' if argv[1] == 'show' else b''
    monkeypatch.setattr(native, 'command', command)
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(Path('/unused')))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **k: nullcontext(SimpleNamespace(execute=lambda q: None)))
    monkeypatch.setattr(backup.ClickHouse, 'query', lambda *a: [{'1': 1}])
    with native.isolated_databases(work) as env:
        assert env['SLI_PG_PORT'] == '55432'
        assert env['SLI_HELPER_RUNTIME_ROOT'] == str(work / 'helpers')
        targets = backup.clickhouse_targets()
        assert targets == ()
        assert not any('CLICKHOUSE' in key for key in env)
    starts = [c for c in calls if c[0] == 'systemd-run']
    assert starts and all(any(arg.startswith('--property=RuntimeMaxSec=')
                             and int(arg.split('=')[-1]) >= 43200 for arg in c) for c in starts)
    assert '--property=SuccessExitStatus=143' not in starts[0]
    assert all(not any('clickhouse' in arg or 'docker' in arg for arg in call) for call in starts)
    assert len([c for c in calls if c[:2] == ['systemctl', 'stop']]) == len(starts)



def test_launcher_works_without_import_path_and_drops_inherited_environment(tmp_path, monkeypatch):
    helper = tmp_path / 'native_runtime.py'
    helper.write_text("from pathlib import Path\n"
                      "def release(): return Path('/accepted'), {'python':'/accepted/python'}, 'sha'\n"
                      "def trusted(path): assert str(path) == '/accepted/deploy/linux/native_backup.py'\n")
    monkeypatch.setattr(native, 'RUNTIME_HELPER', helper)
    original = Path.lstat
    monkeypatch.setattr(Path, 'lstat', lambda path: SimpleNamespace(st_uid=0, st_mode=0o100755)
                        if path in (helper, *helper.parents) else original(path))
    calls = []
    monkeypatch.setattr(native.os, 'chdir', lambda path: calls.append(('cwd', path)))
    monkeypatch.setattr(native.os, 'execve', lambda *args: calls.append(('exec', args)))
    monkeypatch.setenv('LD_PRELOAD', 'untrusted')
    monkeypatch.setenv('PYTHONPATH', 'untrusted')
    monkeypatch.setenv('NOTIFY_SOCKET', '@sli-test')
    monkeypatch.setenv('INVOCATION_ID', 'a' * 32)
    monkeypatch.setenv('WATCHDOG_PID', str(os.getpid()))
    monkeypatch.setenv('WATCHDOG_USEC', '1800000000')
    native.launch('drill')
    executable, argv, env = calls[-1][1]
    assert executable == '/usr/bin/unshare'
    assert argv == ['/usr/bin/unshare', '--mount', '--propagation', 'private', '--',
                    '/accepted/python', '-B', '-m', 'deploy.linux.native_backup', 'drill']
    assert set(env) == {'PATH', 'LC_ALL', 'PYTHONDONTWRITEBYTECODE',
                        'NOTIFY_SOCKET', 'INVOCATION_ID', 'WATCHDOG_PID', 'WATCHDOG_USEC'}
    assert env['NOTIFY_SOCKET'] == '@sli-test'
    assert env['INVOCATION_ID'] == 'a' * 32


def test_launcher_refuses_symlink_before_import(tmp_path, monkeypatch):
    source = tmp_path / 'code'
    source.write_text('raise AssertionError("must not execute")')
    link = tmp_path / 'native_runtime.py'
    link.symlink_to(source)
    monkeypatch.setattr(native, 'RUNTIME_HELPER', link)
    with pytest.raises(RuntimeError, match='untrusted_launcher'):
        native.launch('capture')


def test_settings_ignore_inherited_inline_secrets(monkeypatch):
    monkeypatch.setenv('SLI_PG_ADMIN_PASSWORD', 'synthetic-inherited-value')
    before = dict(os.environ)
    with native.environment(native.settings()):
        assert 'SLI_PG_ADMIN_PASSWORD' not in os.environ
        assert 'SLI_PG_ADMIN_PASSWORD_FILE' in os.environ
        assert backup.postgres_target().port == 5432
        assert backup.clickhouse_targets() == ()
    assert dict(os.environ) == before


@pytest.fixture
def capture_fakes(storage, tmp_path, monkeypatch):
    data = tmp_path / 'data'
    data.mkdir()
    (data / 'raw_files').mkdir()
    (data / 'raw_files/item').write_bytes(b'synthetic-evidence')
    (data / 'service-heartbeat.json').write_text('synthetic-heartbeat')
    (data / 'drills').mkdir()
    (data / 'drills/ignored').write_text('must not recurse')
    monkeypatch.setattr(native, 'DATA', data)
    monkeypatch.setattr(native_host, 'Host', lambda: SimpleNamespace(
        receipt=lambda: None, require_backup_mount=lambda: None, backup_machine_id=lambda: 'synthetic-machine'))
    monkeypatch.setattr(native_runtime, 'no_transaction', lambda: None)
    monkeypatch.setattr(native_runtime, 'release', lambda: (Path('/accepted'), {}, 'sha'))
    monkeypatch.setattr(native_runtime, 'document', lambda path: {'release': '/accepted', 'manifest_sha256': 'sha'})
    def capture(root, retention, *, components, writers_fenced):
        assert retention == 1 and components == ("postgres", "files")
        assert os.environ['SLI_DEPLOYMENT_MODE'] == 'native'
        source = Path(os.environ['SLI_BACKUP_FILES_ROOT'])
        assert (source / 'raw_files/item').is_file() and not (source / 'drills').exists()
        assert (source / 'service-heartbeat.json').read_text() == 'synthetic-heartbeat'
        path = recovery_set(root.parent / 'fake', '20261017T010000.000000Z')
        actual = root / path.name
        __import__('shutil').move(str(path / 'data' / path.name), actual)
        __import__('shutil').rmtree(root.parent / 'fake')
        return actual
    monkeypatch.setattr(backup, 'run_backup', capture)
    def companion(destination):
        write(destination / 'state/installed.json', {'migration_ledger': []})
    monkeypatch.setattr(native, 'companion', companion)
    return data


def test_capture_publishes_full_set_without_claiming_restore(storage, capture_fakes, monkeypatch):
    from deploy.linux import operation_wait

    removals = []
    original = operation_wait.remove_tree

    def remove(path):
        calls = []
        if path.name == 'file-source':
            monkeypatch.setattr(operation_wait, 'made_progress', lambda: calls.append(
                sum(1 for _ in path.rglob('*'))))
        try:
            original(path)
        finally:
            if path.name == 'file-source':
                monkeypatch.setattr(operation_wait, 'made_progress', progress)
                removals.extend(calls)

    progress = operation_wait.made_progress
    monkeypatch.setattr(operation_wait, 'remove_tree', remove)
    path = native.capture()
    manifest, _, _ = native.verify(path)
    assert manifest['status'] == 'backup_created'
    assert manifest['machine_id'] == 'synthetic-machine'
    assert manifest['consistency_point']['writers_fenced'] is False
    assert not (storage / 'restore-verified.json').exists()
    result = json.loads((storage / 'last-result.json').read_text())
    assert result['terminal'] and result['status'] == 'backup_created'
    assert len(set(removals)) > 1 and removals[-1] == 0


def test_upgrade_capture_has_separate_namespace_and_never_prunes_scheduled_sets(storage, capture_fakes, monkeypatch):
    checkpoint_root = storage / 'update-checkpoints'
    checkpoint_root.mkdir()
    monkeypatch.setattr(native_runtime, 'no_transaction', lambda: (_ for _ in ()).throw(AssertionError('pending upgrade is expected')))
    monkeypatch.setattr(native, 'prune', lambda path: (_ for _ in ()).throw(AssertionError('checkpoint must be protected')))
    from deploy.linux import operation_wait
    monkeypatch.setattr(operation_wait, 'Watch', lambda *a, **k: pytest.fail('fenced capture needs no window'))
    with backup.backup_lock(storage):
        path = native.capture_locked(checkpoint_root, writers_fenced=True)
    manifest, _, _ = native.verify(path)
    assert path.parent == checkpoint_root
    assert manifest['consistency_point']['writers_fenced'] is True
    assert manifest['consistency_point']['mode'] == 'fenced'
    assert not (storage / 'last-result.json').exists()


def test_upgrade_drill_verifies_exact_checkpoint_without_scheduled_retention(drill_fakes, storage, monkeypatch):
    monkeypatch.setattr(native, 'prune', lambda path: (_ for _ in ()).throw(AssertionError('checkpoint must be protected')))
    with backup.backup_lock(storage):
        result = native.drill_locked(drill_fakes.path, storage, prune_sets=False)
    assert result['backup_id'] == drill_fakes.path.name
    assert result['status'] == 'restore_verified' and result['databases_stopped']


@pytest.mark.parametrize('failure', ['data', 'companion', 'operation_stall', 'capture_window'])
def test_capture_failure_preserves_previous_and_never_publishes(storage, capture_fakes, monkeypatch, failure):
    old = recovery_set(storage, '20261017T010000.000000Z')
    if failure == 'data':
        monkeypatch.setattr(backup, 'run_backup', lambda *a, **k: native.require(False))
    elif failure == 'companion':
        monkeypatch.setattr(native, 'companion', lambda *a: native.require(False))
    elif failure == 'capture_window':
        from deploy.linux import operation_wait
        monkeypatch.setattr(operation_wait, 'Watch', lambda *a, **k: SimpleNamespace(limit=-1))
    else:
        from deploy.linux import operation_wait
        def stalled(*args, **kwargs):
            raise operation_wait.OperationTimeout('operation_stalled', {'step': 'postgres_dump'})
        monkeypatch.setattr(backup, 'run_backup', stalled)
    with pytest.raises(RuntimeError):
        native.capture()
    assert old.exists()
    assert [p for p in storage.iterdir() if backup.BACKUP_NAME.fullmatch(p.name)] == [old]
    assert json.loads((storage / 'last-result.json').read_text())['status'] == 'failed'


def test_drill_insufficient_disk_is_terminal_before_provisioning(drill_fakes, storage, monkeypatch):
    monkeypatch.setattr(native.shutil, 'disk_usage', lambda path: SimpleNamespace(free=0))
    with pytest.raises(RuntimeError, match='insufficient_data_disk_space'):
        native.drill()
    assert drill_fakes.events == []
    assert json.loads((storage / 'drill-result.json').read_text())['terminal']


def test_capture_preflight_failure_records_terminal_without_touching_previous(storage, capture_fakes, monkeypatch):
    old = recovery_set(storage, '20261017T010000.000000Z')
    monkeypatch.setattr(native_runtime, 'document', lambda path: {'release': '/different'})
    with pytest.raises(RuntimeError, match='registry_mismatch'):
        native.capture()
    assert old.exists() and not list(storage.glob('.*.partial'))
    assert json.loads((storage / 'last-result.json').read_text())['status'] == 'failed'


def test_service_sigterm_unwinds_isolated_database_cleanup(drill_fakes, storage, monkeypatch, capsys):
    handlers = {}
    monkeypatch.setattr(native.signal, 'signal', lambda number, handler: handlers.update({number: handler}))
    monkeypatch.setattr(native.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(native.os, 'umask', lambda mode: None)
    def terminate(*args, **kwargs):
        handlers[native.signal.SIGTERM](native.signal.SIGTERM, None)
    monkeypatch.setattr(restore_existing, 'restore_components', terminate)
    assert native.main(['drill']) == 1
    assert drill_fakes.events == ['start-isolated', 'stopped']
    assert json.loads((storage / 'drill-result.json').read_text())['status'] == 'failed'
    assert capsys.readouterr().err == 'native_backup_failed\n'


@pytest.mark.parametrize('pending', [True, False])
def test_cli_pending_upgrade_explains_refusal_without_disclosing_errors(monkeypatch, capsys, pending):
    monkeypatch.setattr(native.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(native.os, 'umask', lambda mode: None)

    def refused():
        raise native_runtime.RuntimeErrorCode('native_transaction_pending' if pending else 'private-credential-value')

    monkeypatch.setattr(native, 'capture', refused)
    assert native.main(['capture']) == 1
    output = capsys.readouterr().err
    assert 'private-credential-value' not in output
    if pending:
        assert 'upgrade transaction is pending' in output
        assert 'reason_code=native_transaction_pending' in output
    else:
        assert output == 'native_backup_failed\n'
