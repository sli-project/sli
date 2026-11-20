"""Crash recovery policies rendered for systemd; no host services are started."""
import configparser
import json

import pytest

from deploy.linux import native_host as host
from deploy.linux import native_runtime as runtime


@pytest.fixture
def config(monkeypatch):
    monkeypatch.setattr(runtime.clickhouse, 'configured_mode', lambda: 'native')
    return {'profiles': ['light', 'heavy', 'long'], 'radius_pilot': False, 'bind': '192.0.2.1',
            'health_url': 'https://192.0.2.1:8443/api/health/ready'}


def test_database_and_every_dotnet_service_keep_retrying_after_crashes(config):
    units = {**host.units(), **runtime.dotnet_units('candidate', config)}
    for name, body in units.items():
        if name != 'sli-postgresql.service' and not name.startswith('sli-dotnet-'):
            continue
        policy = configparser.ConfigParser(strict=False, interpolation=None)
        policy.read_string(body)
        assert policy['Unit'].getint('StartLimitIntervalSec') == 0, name
        assert policy['Service']['Restart'] == 'on-failure', name
        assert policy['Service']['RestartSec'] == '5s', name


def test_database_crash_does_not_stop_readiness_and_its_application_dependents(config):
    policy = configparser.ConfigParser(strict=False, interpolation=None)
    policy.read_string(runtime.units(config)['sli-ready.service'])
    assert policy['Unit']['Wants'] == 'sli-postgresql.service'
    assert 'BindsTo' not in policy['Unit']
    assert 'Requires' not in policy['Unit']
    assert policy['Service']['RemainAfterExit'] == 'yes'


def test_update_replaces_sealed_postgresql_unit_but_preserves_later_edits(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, 'trusted', lambda path: path.read_bytes())
    state, recovery = tmp_path / 'state', tmp_path / 'recovery'
    saved = recovery / 'previous' / 'local-units'
    state.mkdir()
    saved.mkdir(parents=True)
    (state / 'installed.json').write_text(json.dumps({'schema_version': 1, 'release': '/opt/sli/releases/previous'}))
    old = host.units()['sli-postgresql.service'].replace('Restart=on-failure\nRestartSec=5s\n', '')
    path = tmp_path / 'sli-postgresql.service'
    path.write_text(old)
    (saved / path.name).write_text(old)
    new = host.units()[path.name]
    kwargs = {'state': state, 'recovery': recovery, 'saved_directory': 'local-units'}
    assert runtime.release_rendered_unit(path, new, **kwargs)
    path.write_text(new)
    assert not runtime.release_rendered_unit(path, new, **kwargs)
    path.write_text(old + '# operator change\n')
    assert not runtime.release_rendered_unit(path, new, **kwargs)



def test_enabling_the_platform_target_brings_up_database_and_dotnet_services_at_boot(config):
    units = {**host.units(), **runtime.units(config), **runtime.dotnet_units('candidate', config)}

    def directive(name, key):
        return {v for line in units[name].splitlines() if line.startswith(key + '=')
                for v in line.split('=', 1)[1].split()}

    assert directive('sli.target', 'WantedBy') == {'multi-user.target'}
    # `systemctl enable sli.target` also enables everything named in Also=.
    assert set(runtime.DATABASES) <= directive('sli.target', 'Also')
    assert all(directive(name, 'WantedBy') == {'multi-user.target'} for name in runtime.DATABASES)
    # The target pulls the dotnet target, which pulls every dotnet service.
    assert 'sli-dotnet.target' in directive('sli.target', 'Requires')
    dotnet = {runtime.dotnet_unit_name(s) for s in runtime.selected(config)}
    assert dotnet and dotnet <= directive('sli-dotnet.target', 'Wants')
    # Retired Python-era units are never pulled in.
    assert not {runtime.unit_name(s) for s in runtime.SERVICES} & (
        directive('sli.target', 'Also') | directive('sli-dotnet.target', 'Wants'))
