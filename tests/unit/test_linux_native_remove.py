import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import native_backup, native_host, native_preinstall, native_runtime
from deploy.linux import native_remove as removal


@pytest.fixture
def site(tmp_path, monkeypatch):
    state = tmp_path / 'var/lib/sli/state'
    installed = state / 'installed.json'
    data = tmp_path / 'srv/data/pgdata'
    unrelated = data.parent / 'unrelated'
    units = tmp_path / 'etc/systemd/system'
    vendor = tmp_path / 'usr/lib/systemd/system'
    generated = tmp_path / 'run/systemd/generator'
    for directory in (state, data, units, vendor, generated):
        directory.mkdir(parents=True)
    installed.write_text('{"release": "/opt/sli/releases/fixture"}', encoding='utf-8')
    (state / 'host-prepared.json').write_text(json.dumps({
        'version': 1, 'mount': '/srv/sli-db', 'storage_mode': 'directory', 'directory': '/srv/data',
    }), encoding='utf-8')
    (data / 'fixture').write_text('database contents', encoding='utf-8')
    unrelated.write_text('unrelated contents', encoding='utf-8')
    (units / 'sli-postgresql.service').write_text(native_host.units()['sli-postgresql.service'], encoding='utf-8')
    (vendor / 'sli.target').write_text(native_runtime.units({})['sli.target'], encoding='utf-8')
    (vendor / 'sli-backup.timer').write_text(native_backup.units()['sli-backup.timer'], encoding='utf-8')
    (vendor / 'sli-package-fixture.service').write_text('[Unit]\nDescription=Packaged test unit\n', encoding='utf-8')
    config = {'profiles': ['light'], 'radius_pilot': False, 'health_url': 'https://example.test/api/health',
              'bind': '192.0.2.1'}
    (generated / 'sli-dotnet-api.service').write_text(
        native_runtime.dotnet_unit('fixture', config, 'api'), encoding='utf-8')
    (units / 'other.service').write_text('[Unit]\nDescription=Unrelated\n', encoding='utf-8')
    (units / removal.BACKUP_MOUNT).write_text(
        '[Unit]\nDescription=SLI backup volume\n[Mount]\nWhat=/srv/backups\n'
        'Where=/var/backups/sli\nType=none\nOptions=bind\n', encoding='utf-8')
    tunnel = tmp_path / 'etc/sli-lab-tunnel/sli-lab-tunnel.service'
    tunnel.parent.mkdir()
    tunnel.write_text('[Unit]\nDescription=Lab tunnel\n', encoding='utf-8')
    (units / tunnel.name).write_bytes(tunnel.read_bytes())
    dropins = units / 'sli-postgresql.service.d'
    dropins.mkdir()
    (dropins / native_host.BACKUP_DROP_IN).write_text(native_host.BACKUP_DROP_IN_BODY, encoding='utf-8')
    (dropins / '90-admin.conf').write_text('[Service]\nNice=5\n', encoding='utf-8')
    monkeypatch.setattr(removal, 'STATE', state)
    monkeypatch.setattr(removal, 'CURRENT', tmp_path / 'opt/sli/current')
    monkeypatch.setattr(removal, 'SYSTEM_UNITS', units)
    monkeypatch.setattr(removal, 'VENDOR_UNITS', vendor)
    monkeypatch.setattr(removal, 'GENERATED_UNITS', generated)
    monkeypatch.setattr(removal, 'TRANSIENT_UNITS', tmp_path / 'run/systemd/transient')
    monkeypatch.setattr(removal, 'CLUSTER_GUARD', tmp_path / 'etc/postgresql-common/createcluster.conf')
    original_lstat = Path.lstat

    def metadata(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        return SimpleNamespace(st_uid=0, st_mode=info.st_mode & ~0o022)

    monkeypatch.setattr(Path, 'lstat', metadata)
    original = removal.purge_paths
    monkeypatch.setattr(removal, 'purge_paths', lambda **kwargs: original(tmp_path, **kwargs))
    return installed, data, unrelated, units


def mock_host(monkeypatch, installed, *, legacy=True, live_writer=False, mounts=(), fail_package=None,
              foreign_dotnet=False, backup_mount=None, extra_unit=None):
    calls = []
    mounts = list(mounts)
    if backup_mount is not None:
        mounts.append(backup_mount)
    packages = {
        'sli-host': '', 'sli-release-fixture': '', 'sli-runtime-fixture': '', 'sli': '',
        'sli-rollback-hold': 'yes' if legacy else '', 'sli-server-dotnet': '', 'postgresql-18': '',
    }
    installed_unit = removal.VENDOR_UNITS / 'sli-package-fixture.service'
    fragments = {
        'sli.target': removal.VENDOR_UNITS / 'sli.target',
        'sli-postgresql.service': removal.SYSTEM_UNITS / 'sli-postgresql.service',
        'sli-dotnet-api.service': removal.GENERATED_UNITS / 'sli-dotnet-api.service',
        'sli-backup.timer': removal.VENDOR_UNITS / 'sli-backup.timer',
        removal.BACKUP_MOUNT: removal.SYSTEM_UNITS / removal.BACKUP_MOUNT,
        installed_unit.name: installed_unit,
        'sli-lab-tunnel.service': removal.SYSTEM_UNITS.parent.parent / 'sli-lab-tunnel/sli-lab-tunnel.service',
        'postgresql.service': removal.VENDOR_UNITS / 'postgresql.service',
    }
    if foreign_dotnet:
        name = 'sli-dotnet-lab.service'
        fragments[name] = removal.SYSTEM_UNITS / name
        fragments[name].write_text('[Unit]\nDescription=Lab service\n', encoding='utf-8')
    if extra_unit is not None:
        fragments[extra_unit.name] = extra_unit

    def run(*argv, capture=False):
        calls.append(argv)
        if argv[:2] == ('systemctl', 'list-unit-files'):
            return ''.join(f'{name} enabled\n' for name in fragments)
        if argv[:2] == ('systemctl', 'list-units'):
            return ''.join(f'{name} loaded active running fixture\n' for name in fragments if name != 'sli.target')
        if argv[:3] == ('systemctl', 'show', '-p'):
            return str(fragments[argv[-1]])
        if argv == ('systemctl', 'stop', removal.BACKUP_MOUNT) and backup_mount is not None:
            mounts.remove(backup_mount)
        if argv[:2] == ('systemctl', 'show'):
            if live_writer and argv[2] == 'sli-dotnet-api.service':
                return 'MainPID=42\nActiveState=active\nControlGroup=\n'
            return 'MainPID=0\nActiveState=inactive\nControlGroup=\n'
        if argv[:2] == ('dpkg-query', '--listfiles'):
            assert 'postgresql-18' not in argv
            return f'{removal.DOTNET_GENERATOR}\n/opt/sli/dotnet/fixture/Sli.Server\n{installed_unit}\n'
        if argv[0] == 'dpkg-query':
            return ''.join(f'{name} installed {protected}\n' for name, protected in packages.items())
        if argv[0] == 'dpkg':
            assert not installed.exists()
            assert not removal.CURRENT.is_symlink()
            if argv[-1] == fail_package:
                raise RuntimeError('fixture dpkg failure')
            if argv[-1] == 'sli-release-fixture':
                installed_unit.unlink(missing_ok=True)
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
    writer = ('systemctl', 'stop', 'sli-dotnet-api.service', 'sli-package-fixture.service')
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
    assert (units / 'sli-lab-tunnel.service').is_file()
    assert (units.parent.parent / 'sli-lab-tunnel/sli-lab-tunnel.service').is_file()
    assert (units / 'sli-postgresql.service.d/90-admin.conf').is_file()
    assert not (units / 'sli-postgresql.service.d' / native_host.BACKUP_DROP_IN).exists()
    assert not any('sli-lab-tunnel.service' in call or 'postgresql.service' in call for call in calls)
    assert any(call[:2] == ('systemctl', 'disable') and 'sli-postgresql.service' in call for call in calls)
    assert not (removal.VENDOR_UNITS / 'sli-package-fixture.service').exists()
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
    if blocker == 'mounted_data':
        assert not any(call[:2] in {('systemctl', 'stop'), ('systemctl', 'disable')} for call in calls)


def test_stop_services_stops_databases_after_writers_and_keeps_data_and_packages(site, monkeypatch):
    installed, data, unrelated, units = site
    calls, packages = mock_host(monkeypatch, installed)

    removal.stop_services()

    timer = ('systemctl', 'stop', 'sli-backup.timer')
    writer = ('systemctl', 'stop', 'sli-dotnet-api.service', 'sli-package-fixture.service')
    database = ('systemctl', 'stop', 'sli-postgresql.service')
    assert calls.index(timer) < calls.index(writer) < calls.index(database)
    assert not [call for call in calls if call[0] == 'dpkg']
    assert (data / 'fixture').read_text(encoding='utf-8') == 'database contents'
    assert unrelated.exists() and installed.exists()
    assert (units / 'sli-postgresql.service').exists()


def postgres_metadata(monkeypatch, path, *, uid=123, mode=0o750):
    original = Path.lstat

    def metadata(item, *args, **kwargs):
        info = original(item, *args, **kwargs)
        if item == path:
            return SimpleNamespace(st_uid=uid, st_mode=mode)
        return info

    monkeypatch.setattr(Path, 'lstat', metadata)
    monkeypatch.setattr(removal, 'postgres_uid', lambda: 123)


@pytest.mark.parametrize('foreign_cluster', [False, True])
def test_purge_postgres_owned_configuration_and_prepare_again(site, tmp_path, monkeypatch, foreign_cluster):
    installed, _, _, _ = site
    mock_host(monkeypatch, installed)
    version = tmp_path / 'etc/postgresql/18'
    config = version / 'sli/postgresql.conf'
    config.parent.mkdir(parents=True)
    config.write_text('# SLI cluster\n', encoding='utf-8')
    postgres_metadata(monkeypatch, version, mode=stat.S_IFDIR | 0o750)
    foreign_config = version / 'main/postgresql.conf'
    if foreign_cluster:
        foreign_config.parent.mkdir()
        foreign_config.write_text('# Other cluster\n', encoding='utf-8')

    removal.remove(purge_data=True)

    assert not config.parent.exists()
    if foreign_cluster:
        assert foreign_config.read_text(encoding='utf-8') == '# Other cluster\n'
        with pytest.raises(RuntimeError, match='native_existing_database'):
            native_preinstall.prepare(tmp_path)
    else:
        assert not version.exists()
        monkeypatch.setattr(native_preinstall, 'ensure_directory',
                            lambda path, mode=0o755: path.mkdir(mode=mode, parents=True, exist_ok=True))
        native_preinstall.prepare(tmp_path)
        assert (installed.parent / 'vendor-prepared.json').is_file()


@pytest.mark.parametrize(('uid', 'mode'), [
    (123, stat.S_IFDIR | 0o770),
    (0, stat.S_IFDIR | 0o757),
    (123, stat.S_IFLNK | 0o700),
    (234, stat.S_IFDIR | 0o750),
])
def test_unsafe_postgres_path_fails_before_services_or_files_change(site, tmp_path, monkeypatch, uid, mode):
    installed, data, _, units = site
    calls, _ = mock_host(monkeypatch, installed)
    version = tmp_path / 'etc/postgresql/18'
    config = version / 'sli/postgresql.conf'
    config.parent.mkdir(parents=True)
    config.write_text('# SLI cluster\n', encoding='utf-8')
    postgres_metadata(monkeypatch, version, uid=uid, mode=mode)

    with pytest.raises(RuntimeError, match='Unsafe SLI path'):
        removal.remove(purge_data=True)

    assert not any(call[0] == 'dpkg' or call[:2] in {('systemctl', 'stop'), ('systemctl', 'disable')}
                   for call in calls)
    assert installed.exists() and data.exists() and config.exists()
    assert (units / 'sli-postgresql.service').exists()


def test_purge_fences_foreign_service_that_legacy_package_script_would_stop(site, monkeypatch):
    installed, data, _, units = site
    calls, _ = mock_host(monkeypatch, installed, foreign_dotnet=True)

    with pytest.raises(RuntimeError, match='sli-dotnet-lab.service'):
        removal.remove(purge_data=True)

    assert (units / 'sli-dotnet-lab.service').is_file()
    assert installed.exists() and data.exists()
    assert not any(call[0] == 'dpkg' or call[:2] in {('systemctl', 'stop'), ('systemctl', 'disable')}
                   for call in calls)


@pytest.mark.parametrize('nested_mount', [False, True])
def test_purge_checks_backup_mount_before_removing_local_data(site, tmp_path, monkeypatch, nested_mount):
    installed, _, _, units = site
    backup_mount = tmp_path / 'var/backups/sli'
    backup_mount.mkdir(parents=True)
    calls, _ = mock_host(monkeypatch, installed, backup_mount=backup_mount,
                         mounts=(backup_mount / 'other',) if nested_mount else ())

    if nested_mount:
        with pytest.raises(RuntimeError, match='Unexpected mount'):
            removal.remove(purge_data=True)
        assert not any(call[:2] == ('systemctl', 'stop') for call in calls)
        assert backup_mount.exists() and (units / removal.BACKUP_MOUNT).is_file()
    else:
        removal.remove(purge_data=True)
        assert ('systemctl', 'stop', removal.BACKUP_MOUNT) in calls
        assert not backup_mount.exists()


def test_purge_waits_for_active_sli_restore_drill(site, monkeypatch):
    installed, data, _, units = site
    drill = removal.TRANSIENT_UNITS / 'sli-drill-0123456789abcdef-pg.service'
    drill.parent.mkdir(parents=True)
    drill.write_text('[Service]\nExecStart=/usr/lib/postgresql/18/bin/postgres '
                     '-D /var/backups/sli/restore-check/0123456789abcdef/pg/data\n', encoding='utf-8')
    calls, _ = mock_host(monkeypatch, installed, extra_unit=drill)

    with pytest.raises(RuntimeError, match='Wait for sli-drill-0123456789abcdef-pg.service'):
        removal.remove(purge_data=True)

    assert not any(call[:2] == ('systemctl', 'stop') for call in calls)
    assert data.exists() and (units / 'sli-postgresql.service').is_file()
