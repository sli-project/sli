"""Only confirmed unloaded units excuse an administrative stop failure."""
from types import SimpleNamespace

import pytest

from deploy.linux import native_upgrade as upgrade, native_install as install


@pytest.mark.parametrize('fields,code,expected', [
    ({'LoadState': 'not-found', 'ActiveState': 'inactive'}, 1, True),
    ({'LoadState': 'not-found', 'ActiveState': 'inactive', 'MainPID': '0', 'ControlGroup': ''}, 1, True),
    ({'LoadState': 'loaded', 'ActiveState': 'active', 'MainPID': '42'}, 0, False),
    ({}, 1, None),
    ({'LoadState': 'loaded'}, 1, None),
    ({'LoadState': 'not-found', 'ActiveState': 'active'}, 1, None),
    ({'LoadState': 'not-found', 'ActiveState': 'inactive', 'MainPID': '42'}, 1, None),
    ({'LoadState': 'not-found', 'ActiveState': 'inactive', 'ControlGroup': '/system.slice/sli-ready.service'}, 1, None),
])
def test_unit_absence_requires_known_inactive_state(monkeypatch, fields, code, expected):
    monkeypatch.setattr(upgrade.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(
        returncode=code, stdout='\n'.join(f'{key}={value}' for key, value in fields.items())))
    if expected is None:
        with pytest.raises(RuntimeError, match='^native_upgrade_unit_state_unconfirmed$'):
            upgrade.unit_state('sli-ready.service')
    else:
        assert (upgrade.unit_state('sli-ready.service')['LoadState'] == 'not-found') is expected


@pytest.mark.parametrize('unloaded', [False, True])
def test_stop_failure_is_excused_only_if_unit_was_unloaded_in_between(monkeypatch, unloaded):
    states = iter(('loaded', 'not-found' if unloaded else 'loaded'))
    monkeypatch.setattr(upgrade, 'unit_state', lambda _: {'LoadState': next(states)})
    def fail(*args, **kwargs):
        raise RuntimeError('native_install_command_failed')
    monkeypatch.setattr(install, 'command', fail)
    if unloaded:
        upgrade.stop_units(('sli-ready.service',))
    else:
        with pytest.raises(RuntimeError, match='^native_install_command_failed$'):
            upgrade.stop_units(('sli-ready.service',))


def test_successful_stop_requires_inactive_backup_job(monkeypatch):
    state = {'LoadState': 'loaded', 'ActiveState': 'deactivating', 'MainPID': '42'}
    monkeypatch.setattr(upgrade, 'unit_state', lambda _: state)
    monkeypatch.setattr(install, 'command', lambda *a, **k: None)
    with pytest.raises(RuntimeError, match='^native_writers_still_running$'):
        upgrade.stop_units(('sli-backup.service',))
