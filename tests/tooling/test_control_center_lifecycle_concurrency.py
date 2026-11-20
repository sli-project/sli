"""Synthetic local documents only: never launch a supervisor or web controller."""
from __future__ import annotations

import importlib.util
import json
import multiprocessing
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/maintenance/control_center_lifecycle.py'


def _module():
    spec = importlib.util.spec_from_file_location('isolated_lifecycle', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.managed_worker_names = lambda: ('alpha', 'beta')
    return module


def _operation(module, path, operation):
    if operation == 'observe':
        return module.record_worker_effective(
            'alpha', 'old', state='running', evidence='synthetic',
            resolve_to_running=True, state_path=path,
        )
    if operation == 'project':
        return module._project_worker_request('restart', state_path=path)
    action, worker = operation.split(':')
    return module.request_worker_action(
        action, worker, confirmation=module.confirmation_token('worker', action, worker),
        state_path=path,
    )


def _writer(path, operation, first, events, release):
    module = _module()
    load = module._load_state

    def controlled_load(state_path):
        result = load(state_path)
        events.put(('loaded', first))
        if first and not release.wait(10):
            raise RuntimeError('test_release_timeout')
        return result

    module._load_state = controlled_load
    # Instrument contention, not time/scheduling: an old implementation instead
    # reaches _load_state and completes before the first writer is released.
    if not first and hasattr(module, '_try_state_lock'):
        acquire = module._try_state_lock

        def observed_acquire(handle):
            try:
                acquire(handle)
            except BlockingIOError:
                events.put(('contended', False))
                raise

        module._try_state_lock = observed_acquire
    result = _operation(module, Path(path), operation)
    events.put(('done', first, result))


@pytest.mark.parametrize(('first_action', 'second_action'), [
    ('observe', 'stop:alpha'),
    ('stop:alpha', 'restart:beta'),
    ('project', 'stop:alpha'),
    ('observe', 'project'),
    ('stop:alpha', 'observe'),
])
def test_cross_process_updates_preserve_new_requests(tmp_path, first_action, second_action):
    module = _module()
    path = tmp_path / 'intents.json'
    document = module._state_template()
    module._request_intent(document, worker='alpha', desired_state='restart',
                           action='restart', request_id='old')
    document['workers']['unrelated'] = {'request_id': 'retain-me'}
    document['project'] = {'request_id': 'previous-project'}
    module._write_state(document, path)
    context = multiprocessing.get_context('spawn')
    events, release = context.Queue(), context.Event()
    processes = [context.Process(target=_writer, args=(str(path), op, first, events, release))
                 for op, first in ((first_action, True), (second_action, False))]
    results = {}
    try:
        processes[0].start()
        assert events.get(timeout=10) == ('loaded', True)
        processes[1].start()
        event = events.get(timeout=10)
        assert event in (('loaded', False), ('contended', False))
        if event == ('loaded', False):
            # Deliberately reproduce the old stale snapshot overwrite.
            completed = events.get(timeout=10)
            assert completed[:2] == ('done', False)
            results[False] = completed[2]
        release.set()
        for process in processes:
            process.join(10)
            assert process.exitcode == 0
        while len(results) < 2:
            event = events.get(timeout=10)
            if event[0] == 'done':
                results[event[1]] = event[2]
    finally:
        release.set()
        for process in processes:
            if process.pid is not None:
                process.join(2)
                if process.is_alive():
                    process.terminate()  # Only this isolated synthetic test child.
                    process.join(2)
        events.close()
    result = module._load_state(path)
    assert result['workers']['unrelated'] == {'request_id': 'retain-me'}
    if second_action == 'observe':
        assert results[False] is False
        assert result['workers']['alpha']['desired_state'] == 'stopped'
        assert result['workers']['alpha']['effective']['state'] == 'pending_supervisor'
    elif second_action == 'project':
        assert result['project']['request_id'] != 'previous-project'
        assert all(result['workers'][name]['project_request_id'] == result['project']['request_id']
                   for name in ('alpha', 'beta'))
    elif second_action == 'stop:alpha':
        assert result['workers']['alpha']['desired_state'] == 'stopped'
        assert result['workers']['alpha']['effective']['state'] == 'pending_supervisor'
        assert result['workers']['alpha']['request_id'] != 'old'
        if first_action == 'project':
            assert result['project']['request_id'] != 'previous-project'
            assert result['workers']['beta']['project_request_id'] == result['project']['request_id']
    else:
        assert result['workers']['alpha']['desired_state'] == 'stopped'
        assert result['workers']['beta']['desired_state'] == 'restart'
        assert result['project'] == {'request_id': 'previous-project'}


def test_stale_observation_rechecks_request_id(tmp_path):
    module = _module()
    path = tmp_path / 'intents.json'
    result = _operation(module, path, 'stop:alpha')
    before = path.read_bytes()
    assert result['status'] == 'requested'
    assert not _operation(module, path, 'observe')
    assert path.read_bytes() == before


def test_lock_timeout_blocks_without_modifying_state(tmp_path, monkeypatch):
    module = _module()
    path = tmp_path / 'intents.json'
    _operation(module, path, 'stop:alpha')
    before = path.read_bytes()
    monkeypatch.setattr(module, '_LOCK_TIMEOUT_SECONDS', 0)
    with module._state_lock(path):
        result = _operation(module, path, 'restart:beta')
        assert result['status'] == 'blocked'
        assert result['reason'] == 'control_state_lock_timeout'
        assert not _operation(module, path, 'observe')
        with pytest.raises(module.ControlStateError, match='control_state_lock_timeout'):
            _operation(module, path, 'project')
    assert path.read_bytes() == before
    assert _operation(module, path, 'restart:beta')['status'] == 'requested'


def test_lock_released_on_corrupt_document(tmp_path):
    module = _module()
    path = tmp_path / 'intents.json'
    path.write_text('{broken', encoding='utf-8')
    assert _operation(module, path, 'stop:alpha')['reason'] == 'control_state_unreadable'
    path.write_text(json.dumps(module._state_template()), encoding='utf-8')
    assert _operation(module, path, 'restart:beta')['status'] == 'requested'


def test_lock_failure_blocks_without_replacing_document(tmp_path, monkeypatch):
    import errno

    module = _module()
    path = tmp_path / 'intents.json'
    _operation(module, path, 'stop:alpha')
    before = path.read_bytes()

    def fail(_handle):
        raise OSError(errno.EIO, 'synthetic lock failure')

    monkeypatch.setattr(module, '_try_state_lock', fail)
    assert _operation(module, path, 'restart:beta')['reason'] == 'control_state_lock_failed'
    assert path.read_bytes() == before


def test_write_failure_releases_lock(tmp_path, monkeypatch):
    module = _module()
    path = tmp_path / 'intents.json'
    original = module._write_state

    def fail(*_args):
        raise module.ControlStateError('control_state_write_failed')

    monkeypatch.setattr(module, '_write_state', fail)
    assert _operation(module, path, 'stop:alpha')['reason'] == 'control_state_write_failed'
    monkeypatch.setattr(module, '_write_state', original)
    assert _operation(module, path, 'restart:beta')['status'] == 'requested'


def test_rejected_request_creates_no_lock_or_document(tmp_path):
    module = _module()
    path = tmp_path / 'not-created' / 'intents.json'
    assert module.request_worker_action('stop', 'alpha', confirmation=None,
                                        state_path=path)['status'] == 'blocked'
    assert not path.parent.exists()


def test_windows_lock_uses_first_byte_and_normalizes_contention(tmp_path, monkeypatch):
    import errno
    import sys
    from types import SimpleNamespace

    module = _module()
    calls = []
    fake = SimpleNamespace(LK_NBLCK=2, locking=lambda *args: calls.append(args))
    monkeypatch.setitem(sys.modules, 'msvcrt', fake)
    monkeypatch.setattr(module, 'os', SimpleNamespace(name='nt'))
    with (tmp_path / 'synthetic.lock').open('a+b') as handle:
        handle.seek(5)
        module._try_state_lock(handle)
        assert handle.tell() == 0
        assert calls == [(handle.fileno(), 2, 1)]

        def busy(*_args):
            raise OSError(errno.EACCES, 'synthetic contention')

        fake.locking = busy
        with pytest.raises(BlockingIOError):
            module._try_state_lock(handle)
