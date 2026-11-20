import pytest

from deploy.linux import native_upgrade as upgrade

BASE = {'python': 'p', 'python_sha256': 'h', 'postgres_version': '18', 'clickhouse_version': '25',
        'migration_ledger': [], 'plugins': [], 'clickhouse_mode': 'docker', 'clickhouse_versions': {}}
OLD_ROLES = [['adlog_notification_worker', False, False, False, False, False, False]]
LOGIN = ['sli_notification_login', False, False, False, False, False, False]


def test_new_unprivileged_worker_login_is_compatible():
    upgrade.compatible({**BASE, 'roles': OLD_ROLES}, {**BASE, 'roles': OLD_ROLES + [LOGIN]})


def test_worker_login_addition_does_not_request_schema_migration(tmp_path):
    login = ['sli_report_producer_login', False, False, False, False, False, False]
    assert upgrade.migration_required({**BASE, 'roles': OLD_ROLES},
                                      {**BASE, 'roles': OLD_ROLES + [login]}, 'old', tmp_path) is False


@pytest.mark.parametrize('legacy_present', [False, True])
def test_legacy_coordinator_configures_new_worker_without_ledger_change(monkeypatch, tmp_path, legacy_present):
    """Exercise the candidate callback already invoked by the previous coordinator."""
    import sys
    from contextlib import nullcontext
    from types import SimpleNamespace

    from deploy.linux import backup, migrate, native_host as host, native_install as install
    from deploy.linux import native_runtime as runtime, sli_secrets

    events = []
    users = set()
    files = {}
    secrets = set()
    sql = []

    class Connection:
        def transaction(self):
            return nullcontext()

        def execute(self, query, params=None):
            sql.append((str(query), params))
            return SimpleNamespace(fetchone=lambda: (False,) if str(query).lstrip().startswith('select rolsuper') else None)

    def run(argv, **kw):
        events.append(argv)
        if argv[0] == 'useradd':
            users.add(argv[-1])
        return ''

    def systemctl(argv, **kwargs):
        events.append(argv)
        assert argv[:2] in (['systemctl', 'stop'], ['systemctl', 'show'])
        return SimpleNamespace(returncode=0 if legacy_present else 4, stdout=(
            'LoadState=' + ('loaded' if legacy_present else 'not-found') +
            '\nActiveState=inactive\nMainPID=0\nControlGroup=\n'))

    def write(path, body, mode):
        # No service may become visible before its identities are provisioned.
        assert 'sli-report' in users
        assert 'report_producer_password' in secrets
        assert any('insert into public.report_producer_principals' in query for query, _ in sql)
        files[path] = body

    machine = SimpleNamespace(receipt=lambda: None, directory=lambda *a, **kw: None, write=write)
    monkeypatch.setattr(host, 'administrative_lock', lambda: nullcontext())
    monkeypatch.setattr(host, 'Host', lambda: machine)
    monkeypatch.setattr(host, 'validate_identity', lambda: None)
    monkeypatch.setattr(host, 'account', lambda name: name in users)
    monkeypatch.setattr(host, 'group', lambda name: SimpleNamespace(gr_gid=-1, gr_mem=[]))
    monkeypatch.setattr(host, 'pwd', SimpleNamespace(getpwall=list))
    monkeypatch.setattr(host, 'run', run)
    monkeypatch.setattr(runtime.subprocess, 'run', systemctl)
    monkeypatch.setattr(runtime.clickhouse, 'configured_mode', lambda root=None: 'native')
    monkeypatch.setattr(runtime, 'release_rendered_unit', lambda *a, saved_directory='units': None)
    monkeypatch.setattr(runtime, 'configuration', lambda: {
        'schema_version': 1, 'profiles': ['light'], 'radius_pilot': False,
        'bind': '192.0.2.1', 'health_url': 'https://192.0.2.1:8443/api/health/ready'})
    monkeypatch.setattr(install, 'site_configuration', lambda: {})
    monkeypatch.setattr(install, 'trusted', lambda path: b'validated')
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(tmp_path / 'synthetic-passfile'))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **kw: nullcontext(Connection()))
    monkeypatch.setattr(migrate, 'secret_value', lambda setting: 'synthetic-password')
    monkeypatch.setattr(sli_secrets, 'ensure', lambda directory, *, names: secrets.update(names))

    def candidate(argv, **kwargs):
        assert argv[:4] == ['/pinned/python', '-I', '-B', '-c']
        monkeypatch.setattr(sys, 'argv', ['-c', *argv[5:]])
        monkeypatch.setattr(sys, 'path', list(sys.path))
        exec(argv[4], {})

    monkeypatch.setattr(install, 'command', candidate)
    # Ordinary package activation, with the previous manifest's ledger and a
    # newly declared login. The migration command must remain unnecessary.
    previous = {**BASE, 'python': '/pinned/python', 'roles': OLD_ROLES}
    manifest = {**previous, 'roles': OLD_ROLES + [
        ['sli_report_producer_login', False, False, False, False, False, False]]}
    recovery = tmp_path / 'recovery'
    recovery.mkdir()
    (recovery / 'recovery.json').write_text('{}')
    checkpoint = tmp_path / 'checkpoint'
    checkpoint.mkdir()
    (checkpoint / 'manifest.json').write_text('{}')

    class Journal:
        path = tmp_path / 'transaction'
        value = {'previous': 'old', 'target_version': '2.0-1~deb13',
                 'status': 'checkpoint_verified', 'step': 'after', 'checkpoint': 'checkpoint',
                 'recovery_sha256': upgrade.digest(recovery / 'recovery.json'),
                 'checkpoint_sha256': upgrade.digest(checkpoint / 'manifest.json')}

        def write(self):
            pass

        def transition(self, status):
            self.value.update(status=status, step='before')

        def complete(self, **values):
            self.value.update(step='after', **values)

    monkeypatch.setattr(install, 'inventory', lambda name: (tmp_path / 'old', previous, 'old-digest'))
    monkeypatch.setattr(upgrade, 'package_metadata', lambda root: {'version': '2.0-1~deb13'})
    monkeypatch.setattr(upgrade, 'verify_recovery', lambda name: (recovery, {}))
    monkeypatch.setattr(upgrade, 'checkpoint_root', lambda journal: tmp_path)
    monkeypatch.setattr(upgrade, 'checkpoint_receipt', lambda journal: None)
    monkeypatch.setattr(upgrade, 'fence', lambda: None)
    monkeypatch.setattr(upgrade, 'switch', lambda *a: None)
    monkeypatch.setattr(upgrade, 'testing_units', lambda *a: None)
    monkeypatch.setattr(upgrade, 'start_checked', lambda: None)
    monkeypatch.setattr(install, 'preserve_recovery', lambda *a: None)
    monkeypatch.setattr(upgrade, 'finish_committed', lambda *a: None)
    journal = Journal()
    upgrade.activate(journal, (tmp_path, manifest, 'new-digest'))
    assert journal.value['status'] == 'committed'
    assert journal.value['schema_changed'] is False
    assert 'sli-report' in users
    assert not any(c[:4] == ['usermod', '--append', '--groups', 'sli-data'] and c[-1] == 'sli-report' for c in events)
    assert 'report_producer_password' in secrets
    assert any('create role' in query and 'sli_report_producer_login' in query for query, _ in sql)
    assert any('grant ' in query and 'adlog_report_producer' in query and 'sli_report_producer_login' in query for query, _ in sql)
    assert any('insert into public.report_producer_principals' in query for query, _ in sql)
    assert '/usr/lib/systemd/system/sli-runtime.target' in files
    stopped = ['systemctl', 'stop', *map(runtime.unit_name, runtime.SERVICES)]
    disabled = ['systemctl', 'disable', *map(runtime.unit_name, runtime.SERVICES)]
    assert events.index(stopped) < events.index(['systemctl', 'daemon-reload'])
    assert (disabled in events) == legacy_present
    if legacy_present:
        assert events.index(stopped) < events.index(disabled) < events.index(['systemctl', 'daemon-reload'])
    assert not any(' launch ' in body for path, body in files.items()
                   if path.startswith('/usr/lib/systemd/system/'))


def test_worker_provisioning_error_is_fail_closed_and_redacted(monkeypatch, tmp_path):
    from contextlib import nullcontext

    from deploy.linux import backup, native_runtime as runtime

    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(tmp_path / 'synthetic-passfile'))

    def unavailable(*a, **kw):
        raise RuntimeError('synthetic-private-database-diagnostic')

    monkeypatch.setattr(backup, 'pg_connect', unavailable)
    with pytest.raises(runtime.RuntimeErrorCode, match='^native_worker_logins_failed$'):
        runtime.configure_worker_accounts()


def test_new_closed_lifecycle_roles_and_logins_are_compatible():
    names = ['sli_storage_lifecycle_login', 'sli_storage_lifecycle_delete_login',
             'adlog_storage_lifecycle_worker', 'adlog_storage_lifecycle_delete', 'adlog_storage_lifecycle_guard']
    roles = OLD_ROLES + [[name, False, False, False, False, False, False] for name in names]
    upgrade.compatible({**BASE, 'roles': OLD_ROLES}, {**BASE, 'roles': roles})


@pytest.mark.parametrize('roles', [
    [],  # a role disappeared
    OLD_ROLES + [['sli_notification_login', True, False, False, False, False, False]],  # privileged
    OLD_ROLES + [['some_other_role', False, False, False, False, False, False]],  # not a worker login
    [['adlog_notification_worker', True, False, False, False, False, False]],  # changed flags
])
def test_other_role_changes_still_block(roles):
    with pytest.raises(RuntimeError, match='native_upgrade_incompatible_inventory'):
        upgrade.compatible({**BASE, 'roles': OLD_ROLES}, {**BASE, 'roles': roles})
