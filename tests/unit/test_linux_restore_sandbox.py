"""Private cluster lifecycle with fake binaries; no installed database is used."""
from __future__ import annotations

import os
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import restore_sandbox as sandbox


@pytest.mark.parametrize('configured', ['environment', 'argument', 'work_parent'])
def test_private_restore_records_history_on_backup_disk(tmp_path, monkeypatch, configured):
    import psycopg
    from deploy.linux import backup

    root = tmp_path / 'backups'
    root.mkdir()
    monkeypatch.delenv('SLI_DEPLOYMENT_MODE', raising=False)
    monkeypatch.setenv('SLI_BACKUP_ROOT', str(tmp_path / 'environment'))
    connection = SimpleNamespace(execute=lambda query: SimpleNamespace(
        fetchone=lambda: (None,) if 'to_regclass' in query else (7,)))
    monkeypatch.setattr(sandbox, 'postgres', lambda _: nullcontext({'host': 'synthetic'}))
    monkeypatch.setattr(psycopg, 'connect', lambda **kw: nullcontext(connection))
    monkeypatch.setattr(backup, 'row_counts', lambda _: {'synthetic': 2})
    process = SimpleNamespace(returncode=0, poll=lambda: 0, wait=lambda: 0)
    monkeypatch.setattr(sandbox.subprocess, 'Popen', lambda *a, **kw: process)
    # A configured work disk may differ from the backup disk.
    work = tmp_path / 'work' if configured == 'argument' else root / 'checks'
    args = {'backup_root': root} if configured == 'argument' else {}
    if configured == 'environment':
        monkeypatch.setenv('SLI_BACKUP_ROOT', str(root))
    elif configured == 'work_parent':
        monkeypatch.delenv('SLI_BACKUP_ROOT', raising=False)
    assert sandbox.restore(work, root / 'dump', {'synthetic': 2}, 7, **args) is None
    assert not work.exists()
    assert (root / '.status/summary.json').is_file()
    assert not (tmp_path / 'environment').exists()


@pytest.mark.parametrize('socket_bytes,allowed', [(107, True), (108, False)])
@pytest.mark.parametrize('multibyte', [False, True])
def test_socket_limit_measures_complete_encoded_socket_path(tmp_path, monkeypatch, socket_bytes, allowed, multibyte):
    prefix = 'я' if multibyte else ''
    work = tmp_path / (prefix + 'x')
    padding = socket_bytes - len(os.fsencode(work / '.s.PGSQL.5432'))
    work = tmp_path / (prefix + 'x' * (padding + 1))
    work.mkdir()
    monkeypatch.setattr(sandbox.tempfile, 'mkdtemp', lambda **kw: str(work))
    commands = []
    monkeypatch.setattr(sandbox, 'command', commands.append)
    if allowed:
        with sandbox.postgres(tmp_path) as connection:
            assert connection['host'] == str(work)
        assert len(commands) == 2
    else:
        with pytest.raises(ValueError, match='socket_path_too_long'), sandbox.postgres(tmp_path):
            pytest.fail('must reject before initdb')
        assert not commands
    assert not work.exists()


@pytest.mark.parametrize('start_fails', [False, True])
def test_started_or_partially_started_cluster_stops_before_removal(tmp_path_factory, monkeypatch, start_fails):
    from deploy.linux import operation_wait

    root = tmp_path_factory.mktemp('rc')
    commands = []
    removed = []
    monkeypatch.setattr(operation_wait, 'made_progress', lambda: removed.append(len(commands)))

    def command(args):
        commands.append(args)
        data = Path(args[args.index('-D') + 1])
        if args[-1] == 'start':
            data.mkdir(parents=True)
            (data / 'postmaster.pid').write_text('synthetic')
            for index in range(3):
                (data / str(index)).write_bytes(b'synthetic')
            if start_fails:
                raise RuntimeError('linux_backup_restore_sandbox_failed')
        if args[-1] == 'stop':
            assert (data / 'postmaster.pid').is_file()
            (data / 'postmaster.pid').unlink()

    monkeypatch.setattr(sandbox, 'command', command)
    if start_fails:
        with pytest.raises(RuntimeError, match='sandbox_failed'), sandbox.postgres(root):
            pytest.fail('must not restore after failed start')
    else:
        with sandbox.postgres(root):
            assert list(root.glob('pg-*/data/postmaster.pid'))
    assert commands[-1][-1] == 'stop'
    assert not list(root.iterdir())
    assert len(removed) >= 5 and all(count == len(commands) for count in removed)


@pytest.mark.parametrize('restore_failed', [False, True])
def test_failed_shutdown_preserves_cluster_and_original_error(tmp_path_factory, monkeypatch, restore_failed):
    root = tmp_path_factory.mktemp('rc')
    commands = []

    def command(args):
        commands.append(args)
        data = Path(args[args.index('-D') + 1])
        if args[-1] == 'start':
            (data / 'postmaster.pid').parent.mkdir(parents=True)
            (data / 'postmaster.pid').write_text('synthetic')
        if args[-1] == 'stop':
            raise RuntimeError('linux_backup_restore_sandbox_failed')

    monkeypatch.setattr(sandbox, 'command', command)
    original = RuntimeError('synthetic restore failure')
    with pytest.raises(RuntimeError) as caught, sandbox.postgres(root):
        if restore_failed:
            raise original
    if restore_failed:
        assert caught.value is original
        assert original.cleanup_diagnostic == {
            'error_code': 'linux_backup_restore_sandbox_failed', 'step': 'restore_check_cleanup',
        }
    else:
        assert str(caught.value) == 'linux_backup_restore_sandbox_failed'
    assert commands[-1][-1] == 'stop'
    assert len(list(root.glob('pg-*/data/postmaster.pid'))) == 1
