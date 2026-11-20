"""Manual restore uses observable progress and reaps stalled clients."""
import subprocess

import pytest

from deploy.linux import backup, operation_wait as operation, restore_existing as restore
from tests.unit.test_linux_operation_wait import Process


@pytest.mark.parametrize('progressing', [True, False])
def test_manual_restore_tracks_live_work_and_reaps_stall(tmp_path, monkeypatch, capsys, progressing):
    clock = [0.0]
    (tmp_path / 'toc.dat').write_bytes(b'toc')
    process = Process(clock, finishes=300 if progressing else 100000)
    captured = {}

    def popen(argv, **kwargs):
        captured.update(argv=argv, **kwargs)
        return process

    monkeypatch.setattr(operation.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(operation, 'native_rate', lambda _: 1)
    monkeypatch.setattr(operation, 'stall_seconds', lambda **_: 60)
    monkeypatch.setattr(operation, 'history_path', lambda: tmp_path / 'summary.json')
    monkeypatch.setattr(operation, 'postgres_probe', lambda *_: clock[0] if progressing else 0)
    monkeypatch.setattr(operation.os, 'killpg', lambda *args: process.kill(), raising=False)
    monkeypatch.setattr(backup.subprocess, 'Popen', popen)
    monkeypatch.setattr(backup.subprocess, 'run', lambda *args, **kwargs:
                        pytest.fail('restore bypassed progress-aware pg_tool'))
    monkeypatch.setenv('PGPASSWORD', 'synthetic-private')
    call = lambda: restore.run_restore(tmp_path, passfile=tmp_path / 'passfile', jobs=3, replace_existing=True)
    if progressing:
        call()
        assert clock[0] == 300
        assert 'operation_progress' in capsys.readouterr().err
    else:
        with pytest.raises(operation.OperationTimeout, match='^operation_stalled$'):
            call()
        assert clock[0] == 60
        assert process.killed
    assert process.reaped
    assert {'--jobs=3', '--clean', '--if-exists', '--format=directory'} <= set(captured['argv'])
    assert not {'--no-owner', '--no-acl'} & set(captured['argv'])
    assert captured['stdout'] == subprocess.DEVNULL
    assert 'PGPASSWORD' not in captured['env']
    assert 'statement_timeout=0' in captured['env']['PGOPTIONS']
    assert 'log_min_error_statement=panic' in captured['env']['PGOPTIONS']
