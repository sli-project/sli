import subprocess
from types import SimpleNamespace

import pytest

from deploy.linux import native_install as install


@pytest.mark.parametrize('program,shown,hidden', [
    ('/usr/bin/systemctl', ['Unit sli-x.service not loaded.'], []),
    ('/usr/bin/psql', ['native_existing_configuration_conflict: /usr/lib/systemd/system/sli-ready.service'],
     ['DETAIL:  Failing row contains (secret-value).']),
])
def test_failed_command_reports_codes_but_not_foreign_stderr(monkeypatch, capsys, program, shown, hidden):
    stderr = '\n'.join(['native_existing_configuration_conflict: /usr/lib/systemd/system/sli-ready.service',
                        'DETAIL:  Failing row contains (secret-value).', 'Unit sli-x.service not loaded.'])
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=1, stderr=stderr.encode()))
    with pytest.raises(RuntimeError, match='native_install_command_failed'):
        install.command([program, '--password=never-logged'])
    err = capsys.readouterr().err
    assert all(line in err for line in shown)
    assert not any(line in err for line in hidden)
    assert 'never-logged' not in err
