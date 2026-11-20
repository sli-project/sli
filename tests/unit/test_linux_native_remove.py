import json

import pytest

from deploy.linux import native_remove as removal


@pytest.fixture
def site(tmp_path, monkeypatch):
    state = tmp_path / 'var/lib/sli/state'
    installed = state / 'installed.json'
    data = tmp_path / 'srv/data/pgdata'
    unrelated = data.parent / 'unrelated'
    units = tmp_path / 'etc/systemd/system'
    for directory in (state, data, units):
        directory.mkdir(parents=True)
    installed.write_text('{"release": "/opt/sli/releases/fixture"}', encoding='utf-8')
    (state / 'host-prepared.json').write_text(json.dumps({
        'version': 1, 'mount': '/srv/sli-db', 'storage_mode': 'directory', 'directory': '/srv/data',
    }), encoding='utf-8')
    (data / 'fixture').write_text('database contents', encoding='utf-8')
    unrelated.write_text('unrelated contents', encoding='utf-8')
    (units / 'sli-postgresql.service').write_text('[Unit]\nDescription=SLI PostgreSQL\n', encoding='utf-8')
    (units / 'other.service').write_text('[Unit]\nDescription=Unrelated\n', encoding='utf-8')
    (units / removal.BACKUP_MOUNT).write_text('[Unit]\nDescription=SLI backup volume\n', encoding='utf-8')
    monkeypatch.setattr(removal, 'STATE', state)
    monkeypatch.setattr(removal, 'CURRENT', tmp_path / 'opt/sli/current')
    monkeypatch.setattr(removal, 'SYSTEM_UNITS', units)
    monkeypatch.setattr(removal, 'VENDOR_UNITS', tmp_path / 'usr/lib/systemd/system')
    monkeypatch.setattr(removal, 'trusted', lambda _: None)  # The scratch directory needn't be owned by root.
    monkeypatch.setattr(removal, 'restore_cluster_guard', lambda: None)
    original = removal.purge_paths
    monkeypatch.setattr(removal, 'purge_paths', lambda: original(tmp_path))
    return installed, data, unrelated, units


def mock_host(monkeypatch, installed, *, legacy=True, live_writer=False, mounts=(), fail_package=None):
    calls = []
    packages = {
        'sli-host': '', 'sli-release-fixture': '', 'sli-runtime-fixture': '', 'sli': '',
        'sli-rollback-hold': 'yes' if legacy else '', 'sli-server-dotnet': '', 'postgresql-18': '',
    }

    def run(*argv, capture=False):
        calls.append(argv)
        if argv[:2] == ('systemctl', 'list-unit-files'):
            return 'sli.target enabled\nsli-postgresql.service enabled\npostgresql.service enabled\n'
        if argv[:2] == ('systemctl', 'list-units'):
            return ('sli-postgresql.service loaded active running fixture\n'
                    'sli-dotnet-api.service loaded active running fixture\n'
                    'sli-backup.timer loaded active waiting fixture\n'
                    'postgresql.service loaded active exited unrelated\n')
        if argv[:2] == ('systemctl', 'show'):
            if live_writer and argv[2] == 'sli-dotnet-api.service':
                return 'MainPID=42\nActiveState=active\nControlGroup=\n'
            return 'MainPID=0\nActiveState=inactive\nControlGroup=\n'
        if argv[0] == 'dpkg-query':
            return ''.join(f'{name} installed {protected}\n' for name, protected in packages.items())
        if argv[0] == 'dpkg':
            assert not installed.exists()
            assert not removal.CURRENT.is_symlink()
            if argv[-1] == fail_package:
                raise RuntimeError('fixture dpkg failure')
            del packages[argv[-1]]
        if argv[0] == 'findmnt':
            return json.dumps({'filesystems': [{'target': str(path)} for path in mounts]})
        return ''

    monkeypatch.setattr(removal, 'run', run)
    return calls, packages


@pytest.mark.parametrize('purge', [False, True])
def test_removal_stops_services_with_missing_current_and_preserves_data_by_default(site, monkeypatch, purge):
    installed, data, unrelated, units = site
    calls, packages = mock_host(monkeypatch, installed)

    removal.remove(purge_data=purge)

    timer = ('systemctl', 'stop', 'sli-backup.timer')
    writer = ('systemctl', 'stop', 'sli-dotnet-api.service')
    database = ('systemctl', 'stop', 'sli-postgresql.service')
    mount = ('systemctl', 'stop', removal.BACKUP_MOUNT)
    assert calls.index(timer) < calls.index(writer) < calls.index(database) < calls.index(mount)
    assert calls.index(mount) < calls.index(('dpkg', '--purge', 'sli'))
    assert [call for call in calls if '--force-remove-protected' in call] == [
        ('dpkg', '--force-remove-protected', '--purge', 'sli-rollback-hold'),
    ]
    assert packages == {'postgresql-18': ''}
    assert not (units / 'sli-postgresql.service').exists()
    assert (units / 'other.service').exists()
    assert unrelated.read_text(encoding='utf-8') == 'unrelated contents'
    assert (data / 'fixture').exists() is not purge
    assert installed.exists() is not purge
    if not purge:
        assert list((installed.parent / 'removed-units').glob('*/local/sli-postgresql.service'))


def test_failed_removal_and_retry_restore_receipt_and_do_not_force_new_packages(site, monkeypatch):
    installed, data, _, _ = site
    calls, _ = mock_host(monkeypatch, installed, legacy=False, fail_package='sli-host')
    before = installed.read_bytes()

    with pytest.raises(RuntimeError, match='fixture dpkg failure'):
        removal.remove(purge_data=True)

    assert installed.read_bytes() == before
    assert (data / 'fixture').exists()
    assert not any('--force-remove-protected' in call for call in calls)
    mock_host(monkeypatch, installed, legacy=False)
    removal.remove(purge_data=True)
    assert not installed.exists() and not data.exists()


@pytest.mark.parametrize('blocker', ['writer', 'mounted_data'])
def test_removal_refuses_to_remove_packages_or_data_when_not_safe(site, monkeypatch, blocker):
    installed, data, _, _ = site
    calls, _ = mock_host(monkeypatch, installed, live_writer=blocker == 'writer',
                         mounts=(data / 'nested',) if blocker == 'mounted_data' else ())

    with pytest.raises(RuntimeError, match='still running|Unexpected mount'):
        removal.remove(purge_data=True)

    assert installed.exists() and (data / 'fixture').exists()
    assert not any(call[0] == 'dpkg' for call in calls)


def test_stop_services_stops_databases_after_writers_and_keeps_data_and_packages(site, monkeypatch):
    installed, data, unrelated, units = site
    calls, packages = mock_host(monkeypatch, installed)

    removal.stop_services()

    timer = ('systemctl', 'stop', 'sli-backup.timer')
    writer = ('systemctl', 'stop', 'sli-dotnet-api.service')
    database = ('systemctl', 'stop', 'sli-postgresql.service')
    assert calls.index(timer) < calls.index(writer) < calls.index(database)
    assert not [call for call in calls if call[0] == 'dpkg']
    assert (data / 'fixture').read_text(encoding='utf-8') == 'database contents'
    assert unrelated.exists() and installed.exists()
    assert (units / 'sli-postgresql.service').exists()
