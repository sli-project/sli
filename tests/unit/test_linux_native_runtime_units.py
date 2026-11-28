import json
import os
from pathlib import Path, PurePosixPath

import pytest

from deploy.linux import native_runtime as runtime
from deploy.linux import native_host, native_install, native_upgrade


@pytest.mark.parametrize("radius_pilot", [False, True])
def test_beta_units_cannot_configure_retired_event_reads(radius_pilot):
    config = dict(profiles=['light', 'heavy', 'long'], radius_pilot=radius_pilot, bind='192.0.2.1',
                  health_url='https://192.0.2.1:8443/api/health/ready')
    for service in runtime.selected(config):
        env, _ = runtime.environment(service, config, dotnet=True)
        assert not any('ShortEventReads' in name for name in env)
        command = runtime.DOTNET_COMMANDS[service]
        assert not command or command[0] not in ('collection-worker', 'legacy-post-collection-worker',
                                               'radius-accounting-worker')
    assert not any('ShortEventReads' in name for name in native_install.environment())


def test_beta_excludes_services_even_when_all_profiles_enabled(monkeypatch):
    monkeypatch.setattr(runtime.clickhouse, 'configured_mode', lambda: 'native')
    config = dict(profiles=['light', 'heavy', 'long'], radius_pilot=False, bind='192.0.2.1',
                  health_url='https://192.0.2.1:8443/api/health/ready')
    expected = {'api', 'post-collection', 'semantic', 'entity-state', 'storage-lifecycle',
                'ad-snapshot-manifest-coordinator', 'notification-delivery', 'notification-setup',
                'executor-light', 'executor-heavy', 'executor-long'}
    assert set(runtime.selected(config)) == expected
    for release in ('previous', 'candidate'):
        rendered = runtime.dotnet_units(release, config)
        assert set(rendered) == {'sli-dotnet.target', *map(runtime.dotnet_unit_name, expected)}
        assert 'Requires=sli-dotnet.target\n' in runtime.units(config)['sli.target']
        assert all('python3' not in body for body in rendered.values())
        assert all(' launch ' not in body for name, body in runtime.units(config).items()
                   if name != 'sli-backup-settings.service')
        for excluded in ('what-where-when', 'remote-access', 'report-producer'):
            with pytest.raises(runtime.RuntimeErrorCode, match='native_profile_disabled'):
                runtime.dotnet_unit(release, config, excluded)


def test_upgrade_starts_and_checks_only_dotnet_beta_services(monkeypatch):
    from types import SimpleNamespace

    config = {'profiles': ['light', 'heavy'], 'radius_pilot': False}
    calls, probes = [], []
    monkeypatch.setattr(runtime, 'configuration', lambda: config)
    monkeypatch.setattr(runtime, 'systemd', lambda service: probes.append(service) or {
        'ActiveState': 'active', 'MainPID': '42'})
    monkeypatch.setattr(native_install, 'command', lambda argv, **kw: calls.append(argv))
    monkeypatch.setattr(native_install, 'wait_api', lambda settings, **kwargs: calls.append('api-ready'))

    def wait_health(*, check_services):
        calls.append('workers-ready')
        check_services()

    monkeypatch.setattr(native_install, 'wait_health', wait_health)
    monkeypatch.setattr(native_upgrade.subprocess, 'run', lambda argv, **kw: SimpleNamespace(returncode=0))
    native_upgrade.start_checked()
    assert calls[0] == ['systemctl', 'reset-failed', 'sli-ready.service', 'sli-health.service',
                        *map(runtime.dotnet_unit_name, runtime.selected(config))]
    assert calls[1:] == [['systemctl', 'start', 'sli-ready.service'],
                         ['systemctl', 'start', 'sli-dotnet.target'], 'api-ready', 'workers-ready']
    assert probes == list(runtime.selected(config))
    # A failed transition can still restore a retained pre-.NET runtime catalog.
    calls.clear()
    accepted = SimpleNamespace(configuration=lambda: config, selected=lambda settings: ('api',),
                               unit_name=lambda service: 'sli-api.service', systemd=runtime.systemd)
    native_upgrade.start_checked(accepted)
    assert calls[0] == ['systemctl', 'reset-failed', 'sli-ready.service', 'sli-health.service', 'sli-api.service']
    assert calls[2] == ['systemctl', 'start', 'sli-runtime.target']


@pytest.mark.parametrize('loaded', [True, False])
def test_stop_writers_accepts_absent_units_but_rejects_query_errors(monkeypatch, loaded):
    from types import SimpleNamespace

    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=1, stdout='LoadState=' + ('loaded' if loaded else 'not-found'))
    monkeypatch.setattr(runtime.subprocess, 'run', run)
    if loaded:
        with pytest.raises(runtime.RuntimeErrorCode, match='native_systemd_query_failed'):
            runtime.stop_writers()
    else:
        assert runtime.stop_writers()
        assert ['systemctl', 'stop', 'sli-dotnet.target',
                *map(runtime.dotnet_unit_name, (*runtime.SERVICES, *runtime.DOTNET_ONLY_SERVICES))] in calls


def test_health_probes_dotnet_api_at_configured_site_url(monkeypatch):
    import ssl
    from contextlib import nullcontext
    from types import SimpleNamespace
    from deploy.linux import healthcheck

    url = 'https://192.0.2.20:9443/api/health/ready'
    requests, units = [], []
    monkeypatch.setattr(runtime, 'ready', lambda: True)
    monkeypatch.setattr(runtime, 'configuration', lambda: {'health_url': url})
    monkeypatch.setattr(runtime, 'selected', lambda config: ('api',))
    monkeypatch.setattr(native_host, 'credential', lambda name: 'synthetic-only')
    monkeypatch.setenv('CREDENTIALS_DIRECTORY', '/synthetic/delivered')
    for setting in ('ADLOG_PG_DSN', 'ADLOG_PG_PASSWORD_FILE', 'SLI_TLS_CA_FILE', 'SLI_HEALTH_URL'):
        monkeypatch.setenv(setting, '')
    monkeypatch.setattr(runtime, 'process_start', lambda pid: 95.0)
    monkeypatch.setattr(runtime.time, 'monotonic', lambda: 100.0)
    def show(argv, **kwargs):
        units.append(argv[2])
        return SimpleNamespace(returncode=0, stdout='LoadState=loaded\nActiveState=active\nSubState=running\n'
                               'MainPID=42\nExecMainStartTimestampMonotonic=95000000\nInvocationID=' + 'a' * 32 +
                               '\nNRestarts=0\nControlGroup=/sli.slice/sli-dotnet-api.service\n')
    monkeypatch.setattr(runtime.subprocess, 'run', show)
    monkeypatch.setattr(ssl, 'create_default_context', lambda **kw: object())
    monkeypatch.setattr(healthcheck, 'urlopen', lambda address, **kw: requests.append(address) or
                        nullcontext(SimpleNamespace(status=200)))
    assert runtime.health()
    assert requests == [url]
    assert units == ['sli-dotnet-api.service', 'sli-dotnet-api.service']


@pytest.mark.parametrize('action,tampered', [('configure-package', False), ('resume-package', False),
                                          ('resume-package', True)])
def test_upgrade_dispatches_verified_candidate_and_pins_resumption(tmp_path, monkeypatch, action, tampered):
    import hashlib
    from types import SimpleNamespace

    helper = tmp_path / 'usr/lib/sli/native_runtime.py'
    candidate = tmp_path / 'releases/new'
    transactions = tmp_path / 'transactions'
    transaction = transactions / ('a' * 32)
    transaction.mkdir(parents=True)
    body = b'synthetic-coordinator'
    journal = dict(target_version='2.0-1~deb13', created_at_utc='2026-11-13',
                   dotnet_coordinator=True, coordinator_release='new',
                   coordinator_manifest_sha256='manifest',
                   coordinator_sha256='0' * 64 if tampered else hashlib.sha256(body).hexdigest())
    loaded_runtime = SimpleNamespace(document=lambda path: journal if path.name == 'journal.json'
                                     else {'version': '2.0-1~deb13'}, trusted=lambda path: body)
    loaded_install = SimpleNamespace(inventory=lambda release: (candidate, {'python': '/pinned/python'}, 'manifest'),
                                     environment=lambda: {'PATH': '/usr/bin:/bin'})
    def spec(name, path):
        source = loaded_runtime if path == helper else loaded_install
        return SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: vars(module).update(vars(source))))
    real_lstat = Path.lstat
    trusted_paths = {helper, *helper.parents}
    monkeypatch.setattr(Path, 'lstat', lambda path: SimpleNamespace(st_uid=0, st_mode=0o100644)
                        if path in trusted_paths else real_lstat(path))
    monkeypatch.setattr(Path, 'is_symlink', lambda path: False)
    monkeypatch.setattr(native_upgrade, '__file__', str(helper.with_name('native_upgrade.py')))
    monkeypatch.setattr(native_upgrade, 'RUNTIME_HELPER', helper)
    monkeypatch.setattr(native_upgrade, 'TRANSACTIONS', transactions)
    monkeypatch.setattr(native_upgrade, 'RECOVERY', tmp_path / 'recovery')
    monkeypatch.setattr(native_upgrade.importlib.util, 'spec_from_file_location', spec)
    monkeypatch.setattr(native_upgrade.importlib.util, 'module_from_spec', lambda spec: SimpleNamespace())
    calls = []
    monkeypatch.setattr(native_upgrade.os, 'execve', lambda *args: calls.append(args))
    arguments = ['new', '2.0-1~deb13'] if action == 'configure-package' else ['2.0-1~deb13']
    if tampered:
        with pytest.raises(RuntimeError, match='native_reuse_coordinator_mismatch'):
            native_upgrade.launch(None, None, action=action, arguments=arguments)
        assert not calls
    else:
        native_upgrade.launch(None, None, action=action, arguments=arguments)
        assert calls == [('/pinned/python', ['/pinned/python', '-I', '-B',
                          str(candidate / 'deploy/linux/native_upgrade.py'), action, *arguments],
                          {'PATH': '/usr/bin:/bin'})]


def test_report_producer_install_upgrade_and_rollback_inventory():
    assert 'sli-report' in native_host.ACCOUNTS
    assert native_install.environment()['SLI_REPORT_PRODUCER_PG_PASSWORD_FILE'].endswith('report_producer_password')
    old = [['adlog_user', *([False] * 5)]]
    added = ['sli_report_producer_login', *([False] * 5)]
    assert native_upgrade.worker_logins_added(old, [*old, added])
    assert not native_upgrade.worker_logins_added(old, [*old, [added[0], True, *added[2:]]])
    # Restoring the checkpoint's role inventory leaves the old inventory intact.
    assert native_upgrade.worker_logins_added(old, old)


def test_native_upgrade_migrator_provisions_lifecycle_secrets_without_old_coordinator_settings(monkeypatch):
    from contextlib import nullcontext
    from pathlib import Path
    from types import SimpleNamespace

    from deploy.linux import migrate, sli_secrets

    provisioned, statements = [], []
    monkeypatch.setenv('SLI_DEPLOYMENT_MODE', 'native')
    monkeypatch.setattr(migrate, 'WORKER_LOGINS', tuple(row for row in migrate.WORKER_LOGINS
                                                      if row[0].startswith('sli_storage_lifecycle')))
    monkeypatch.setattr(migrate, 'configure_job_logins', lambda connection: None)
    monkeypatch.setattr(sli_secrets, 'ensure', lambda directory, *, names: provisioned.append((directory, names)))
    for _, _, setting in migrate.WORKER_LOGINS:
        monkeypatch.delenv(setting, raising=False)
        monkeypatch.delenv(setting + '_FILE', raising=False)

    def secret(setting):
        assert os.environ[setting + '_FILE'].startswith(str(Path('/etc/sli/secrets')))
        return 'synthetic-only-password'

    monkeypatch.setattr(migrate, 'secret_value', secret)

    class Connection:
        def transaction(self):
            return nullcontext()

        def execute(self, query, params=None):
            statements.append(query.as_string() if hasattr(query, 'as_string') else query)
            return SimpleNamespace(fetchone=lambda: None)

    migrate.configure_worker_logins(Connection())
    assert provisioned == [(Path('/etc/sli/secrets'), ['storage_lifecycle_password', 'storage_lifecycle_delete_password', 'report_producer_password'])]
    assert statements.count("set local log_statement = 'none'") == 2
    assert statements.count("set local log_min_error_statement = 'panic'") == 2
    for login, role, _ in migrate.WORKER_LOGINS:
        assert any(f'grant "{role}" to "{login}" with inherit false' == sql for sql in statements)
        assert any(f'alter role "{login}" login noinherit nosuperuser nocreatedb nocreaterole' in sql for sql in statements)


def test_lifecycle_uses_isolated_copy_and_delete_credentials(monkeypatch):
    monkeypatch.setattr(runtime.clickhouse, 'configured_mode', lambda: 'native')
    config = dict(profiles=['light'], radius_pilot=False, bind='192.0.2.1',
                  health_url='https://192.0.2.1:8443/api/health/ready')
    env, secrets = runtime.environment('storage-lifecycle', config, dotnet=True)
    assert env['ADLOG_PG_DSN'].endswith('user=sli_storage_lifecycle_login')
    assert env['ADLOG_PG_PASSWORD_FILE'] == '%d/storage_lifecycle_password'
    assert env['ADLOG_STORAGE_LIFECYCLE_DELETE_DSN'].endswith('user=sli_storage_lifecycle_delete_login')
    assert env['ADLOG_STORAGE_LIFECYCLE_DELETE_PASSWORD_FILE'] == '%d/storage_lifecycle_delete_password'
    assert 'ADLOG_STORAGE_LIFECYCLE_DELETE_EXECUTION_ENABLED' not in env
    assert secrets == {'storage_lifecycle_password', 'storage_lifecycle_delete_password'}
    body = runtime.dotnet_units('synthetic', config)[runtime.dotnet_unit_name('storage-lifecycle')]
    assert 'LoadCredential=storage_lifecycle_password:/etc/sli/secrets/storage_lifecycle_password\n' in body
    assert 'ADLOG_PG_ADMIN_' not in body
    assert 'runtime_password' not in body
    assert 'storage_password' not in body
    assert 'LoadCredential=storage_lifecycle_delete_password:/etc/sli/secrets/storage_lifecycle_delete_password' in body
    assert 'ADLOG_STORAGE_NO_ARCHIVE_DELETE_CONFIRMATION' not in env


def test_retired_lifecycle_settings_do_not_enter_service_units():
    config = dict(profiles=['light'], radius_pilot=False, bind='192.0.2.1',
                  health_url='https://192.0.2.1:8443/api/health/ready',
                  storage_lifecycle_delete_enabled=True,
                  storage_lifecycle_delete_confirmation='invalid\nExecStart=/untrusted')
    env, secrets = runtime.environment('storage-lifecycle', config, dotnet=True)
    assert 'ADLOG_STORAGE_LIFECYCLE_DELETE_EXECUTION_ENABLED' not in env
    assert 'ADLOG_STORAGE_NO_ARCHIVE_DELETE_CONFIRMATION' not in env
    body = runtime.dotnet_units('synthetic', config)[runtime.dotnet_unit_name('storage-lifecycle')]
    assert '/untrusted' not in body
    assert 'storage_lifecycle_delete_password' in secrets


def test_dotnet_preserves_native_entrypoint_acquisition_guards(monkeypatch):
    monkeypatch.setattr(runtime.clickhouse, 'configured_mode', lambda: 'native')
    config = dict(profiles=['light'], radius_pilot=False, bind='192.0.2.1',
                  health_url='https://192.0.2.1:8443/api/health/ready')
    units = runtime.dotnet_units('synthetic', config)
    for service in runtime.selected(config):
        body = units[runtime.dotnet_unit_name(service)]
        assert 'Environment="ADLOG_ACQUISITION_DISABLED=1"\n' in body
        for name in ('ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER', 'ADLOG_ENABLE_INPROCESS_POST_COLLECTION',
                     'ADLOG_ENABLE_POSTGRES_COLLECTION', 'ADLOG_POSTGRES_RUNTIME_COLLECTION', 'ADLOG_NPS_EVENTLOG_ENABLED'):
            assert f'Environment="{name}=0"\n' in body
        assert 'ADLOG_PG_ADMIN_' not in body
        assert 'LoadCredential=postgres_password:' not in body
    setup = units[runtime.dotnet_unit_name('notification-setup')]
    post = units[runtime.dotnet_unit_name('post-collection')]
    assert 'Environment="Sli__EventCatalogPath=/opt/sli/current/config/event_catalog.json"\n' in post
    assert {line for line in post.splitlines() if line.startswith('LoadCredential=')} == {
        line for line in runtime.application_unit(config, 'post-collection', runtime.SERVICES['post-collection'], runtime.selected(config)).splitlines()
        if line.startswith('LoadCredential=')}
    assert 'RuntimeDirectoryMode=0700\n' in setup
    assert 'User=root\nGroup=root\n' in setup
    assert 'CapabilityBoundingSet=CAP_CHOWN\n' in setup


def test_api_receives_the_configured_postgres_data_directory():
    config = dict(profiles=['light'], radius_pilot=False, bind='192.0.2.1',
                  health_url='https://192.0.2.1:8443/api/health/ready')
    postgres = native_host.units()['sli-postgresql.service']
    directory = next(line for line in postgres.splitlines() if line.startswith('ExecStart=')).split()[2]
    api, _ = runtime.environment('api', config, dotnet=True)
    assert api['SLI_POSTGRES_DATA_DIRECTORY'] == directory


@pytest.mark.skipif(os.name == 'nt', reason='POSIX ownership checks; Linux CI')
def test_only_accepted_release_rendered_units_are_replaced(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, 'trusted', lambda path: path.read_bytes())
    state, recovery, units = tmp_path / 'state', tmp_path / 'recovery', tmp_path / 'units'
    for path in (state, recovery / 'old' / 'units', units):
        path.mkdir(parents=True)
    (state / 'installed.json').write_text(json.dumps({'schema_version': 1, 'release': '/opt/sli/releases/old'}))
    (recovery / 'old/units/sli-ready.service').write_text('old body\n')
    (recovery / 'old/units/sli-api.service').write_text('old api\n')
    (units / 'sli-ready.service').write_text('old body\n')
    (units / 'sli-api.service').write_text('edited by operator\n')
    (units / 'sli-health.service').write_text('new body\n')

    kwargs = dict(state=state, recovery=recovery)
    assert runtime.release_rendered_unit(units / 'sli-ready.service', 'new body\n', **kwargs)
    assert not (units / 'sli-ready.service').exists()
    assert not runtime.release_rendered_unit(units / 'sli-api.service', 'new api\n', **kwargs)
    assert (units / 'sli-api.service').read_text() == 'edited by operator\n'
    assert not runtime.release_rendered_unit(units / 'sli-health.service', 'new body\n', **kwargs)
    assert not runtime.release_rendered_unit(units / 'sli-missing.service', 'x\n', **kwargs)


def test_event_writers_receive_semantic_publication_settings(monkeypatch):
    monkeypatch.setattr(runtime.clickhouse, 'configured_mode', lambda: 'native')
    config = dict(profiles=['light'], radius_pilot=False, bind='192.0.2.1',
                  health_url='https://192.0.2.1:8443/api/health/ready')
    for units, unit_name in ((runtime.dotnet_units('synthetic', config), runtime.dotnet_unit_name),):
        for service in ('post-collection', 'semantic'):
            body = units[unit_name(service)]
            assert 'Environment="ADLOG_SEMANTIC_RUNTIME_MODE=findings-v1"\n' in body
            for name in ('PRODUCTION', 'NORMALIZATION', 'ASSEMBLY', 'CORRELATION',
                         'RISK_ENGINE', 'FINDING_CREATION'):
                assert f'Environment="ADLOG_SEMANTIC_{name}_ENABLED=1"\n' in body
        post = units[unit_name('post-collection')]
        assert 'user=sli_storage_login' in post
        assert 'ADLOG_SEMANTIC_WORKER_DSN' not in post


def test_import_queue_lock_directory_is_writable_by_every_unit_that_takes_it(monkeypatch):
    monkeypatch.setattr(runtime.clickhouse, 'configured_mode', lambda: 'native')
    config = dict(profiles=['light'], radius_pilot=False, bind='192.0.2.1',
                  health_url='https://192.0.2.1:8443/api/health/ready')
    units = runtime.dotnet_units('synthetic', config)
    lock = PurePosixPath(runtime.IMPORT_QUEUE_LOCK)
    importers = [name for name, body in units.items()
                 if f'Environment="ADLOG_POSTGRES_IMPORT_QUEUE_LOCK={lock}"\n' in body]
    assert runtime.dotnet_unit_name('post-collection') in importers
    for name in importers:
        paths = [line for line in units[name].splitlines() if line.startswith('ReadWritePaths=')][0].split()[1:]
        assert str(lock.parent) in paths, name
        assert 'ProtectSystem=strict\n' in units[name]
    mode, group = runtime.DATA_DIRECTORIES[lock.parent.name]
    assert group == 'sli-data' and mode == 0o2770
