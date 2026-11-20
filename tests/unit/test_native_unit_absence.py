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
            upgrade.unit_absent('sli-ready.service')
    else:
        assert upgrade.unit_absent('sli-ready.service') is expected


@pytest.mark.parametrize('unloaded', [False, True])
def test_stop_failure_is_excused_only_if_unit_was_unloaded_in_between(monkeypatch, unloaded):
    states = iter((False, unloaded))
    monkeypatch.setattr(upgrade, 'unit_absent', lambda _: next(states))
    def fail(*args, **kwargs):
        raise RuntimeError('native_install_command_failed')
    monkeypatch.setattr(install, 'command', fail)
    if unloaded:
        upgrade.stop_units(('sli-ready.service',))
    else:
        with pytest.raises(RuntimeError, match='^native_install_command_failed$'):
            upgrade.stop_units(('sli-ready.service',))
