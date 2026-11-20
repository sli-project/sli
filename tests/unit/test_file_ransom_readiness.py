"""T026 policy wait is bounded and does not suppress other detectors."""
from datetime import timedelta
from unittest.mock import patch

import pytest

from tests.unit.test_default_detections import (
    NOW,
    FileDefaultConnection,
    configure_file_defaults,
    defaults,
    file_source,
)


@pytest.fixture(autouse=True)
def isolated_wait_state():
    defaults._RANSOM_WAITS.clear()
    yield
    defaults._RANSOM_WAITS.clear()


def test_waiting_policy_never_calls_reader_and_keeps_decoy(monkeypatch):
    configure_file_defaults(monkeypatch)
    source = file_source() | {'ransom_policy': {'state': 'waiting'}}
    conn = FileDefaultConnection()
    with conn.transaction():
        result = defaults.run_source(conn, source, now=NOW)
    assert result.jobs == 2 and result.failed == 1
    assert result.waiting == 1
    assert conn.writes == ['decoy', 'ransom-admission']


def test_same_revision_recovers_after_bounded_wait(monkeypatch):
    configure_file_defaults(monkeypatch)
    source = file_source() | {'ransom_policy': {'state': 'waiting'}}
    conn = FileDefaultConnection()
    with conn.transaction():
        defaults.run_source(conn, source, now=NOW)
    source['ransom_policy'] = {'state': 'ready'}
    with conn.transaction():
        waiting = defaults.run_source(conn, source, now=NOW + timedelta(seconds=1))
        recovered = defaults.run_source(conn, source, now=NOW + timedelta(seconds=61))
    assert waiting.waiting == 1
    assert recovered.jobs == 5 and recovered.failed == 0
    assert conn.writes.count('ransom-runtime') == 1


def test_disabled_rule_not_reported_as_waiting(monkeypatch):
    configure_file_defaults(monkeypatch, disabled=True)
    source = file_source() | {'ransom_policy': {'state': 'waiting'}}
    conn = FileDefaultConnection()
    with conn.transaction():
        result = defaults.run_source(conn, source, now=NOW)
    assert result.jobs == 2 and result.failed == 0


def test_wait_logs_once_and_has_no_source_identity(monkeypatch):
    configure_file_defaults(monkeypatch)
    source = file_source() | {'ransom_policy': {'state': 'waiting'}}
    source['config']['policy_revision'] = '999'
    conn = FileDefaultConnection()
    with patch.object(defaults, 'log_event') as log, conn.transaction():
        for seconds in (0, 1, 61, 121):
            defaults.run_source(conn, source, now=NOW + timedelta(seconds=seconds))
    assert log.call_count == 1
    assert '00000000-0000' not in str(log.call_args)


def test_legacy_reader_mismatch_is_backed_off_after_rollback(monkeypatch):
    from types import SimpleNamespace
    configure_file_defaults(monkeypatch)
    class Mismatch(Exception):
        sqlstate = 'P0001'
        diag = SimpleNamespace(message_primary='file_ransom_source_policy_mismatch')
    calls = []
    def mismatch(cur, **kwargs):
        calls.append(1)
        cur.writes.append('ransom-runtime')
        raise Mismatch()
    monkeypatch.setattr(defaults.file_ransom_runtime, 'run_once', mismatch)
    source = file_source()
    source['config']['policy_revision'] = '888'
    conn = FileDefaultConnection()
    with conn.transaction():
        first = defaults.run_source(conn, source, now=NOW)
        second = defaults.run_source(conn, source, now=NOW + timedelta(seconds=1))
    assert first.waiting == second.waiting == 1
    assert len(calls) == 1 and 'ransom-runtime' not in conn.writes


def test_changed_revision_does_not_inherit_other_policy_wait(monkeypatch):
    configure_file_defaults(monkeypatch)
    source = file_source() | {'ransom_policy': {'state': 'waiting'}}
    source['config']['policy_revision'] = '666'
    conn = FileDefaultConnection()
    with conn.transaction():
        defaults.run_source(conn, source, now=NOW)
        source['config']['policy_revision'] = '667'
        source['ransom_policy'] = {'state': 'ready'}
        result = defaults.run_source(conn, source, now=NOW + timedelta(seconds=1))
    assert result.jobs == 5 and result.waiting == 0


def test_wait_state_is_bounded(monkeypatch):
    configure_file_defaults(monkeypatch)
    monkeypatch.setattr(defaults, '_RANSOM_WAIT_LIMIT', 2)
    source = file_source() | {'ransom_policy': {'state': 'waiting'}}
    conn = FileDefaultConnection()
    with conn.transaction():
        for revision in ('901', '902', '903'):
            source['config']['policy_revision'] = revision
            defaults.run_source(conn, source, now=NOW)
    assert len(defaults._RANSOM_WAITS) == 2
    defaults._RANSOM_WAITS.clear()


def test_managed_wait_remains_failed_and_exposes_fixed_status(monkeypatch):
    configure_file_defaults(monkeypatch)
    source = file_source() | {'ransom_policy': {'state': 'waiting'}}
    monkeypatch.setattr('tests.unit.test_default_detections.file_source', lambda: source)
    # The fake discovery emits the imported helper's source.
    conn = FileDefaultConnection()
    result = defaults.run_default_detections(conn)
    assert result['jobs'] == 2 and result['failed'] == 1
    assert result['file_ransom_status']['code'] == 'source_policy_waiting'
    assert result['file_ransom_status']['sources'] == 1
    defaults._RANSOM_WAITS.clear()


@pytest.mark.parametrize('sqlstate,message', [('42501', 'file_ransom_source_policy_mismatch'),
                                             ('P0001', 'other_error'), ('40001', 'serialization')])
def test_other_database_errors_never_become_policy_wait(monkeypatch, sqlstate, message):
    from types import SimpleNamespace
    configure_file_defaults(monkeypatch)
    error = RuntimeError('private database error')
    error.sqlstate = sqlstate
    error.diag = SimpleNamespace(message_primary=message)
    def fail(cur, **kwargs):
        raise error
    monkeypatch.setattr(defaults.file_ransom_runtime, 'run_once', fail)
    conn = FileDefaultConnection()
    with conn.transaction():
        outcome = defaults.run_source(conn, file_source(), now=NOW)
    assert outcome.failed == 1 and outcome.waiting == 0
    assert not defaults._RANSOM_WAITS


def test_uncertain_transaction_is_not_converted_to_wait(monkeypatch):
    from types import SimpleNamespace
    configure_file_defaults(monkeypatch)
    error = RuntimeError('private database error')
    error.sqlstate = 'P0001'
    error.diag = SimpleNamespace(message_primary='file_ransom_source_policy_mismatch')
    def fail(cur, **kwargs):
        raise error
    monkeypatch.setattr(defaults.file_ransom_runtime, 'run_once', fail)
    conn = FileDefaultConnection(exit_failure=('rollback', 2))
    with pytest.raises(RuntimeError, match='rollback'):
        with conn.transaction():
            defaults.run_source(conn, file_source(), now=NOW)
    assert not defaults._RANSOM_WAITS


def test_backward_clock_does_not_make_ready_policy_wait_forever(monkeypatch):
    configure_file_defaults(monkeypatch)
    source = file_source() | {'ransom_policy': {'state': 'waiting'}}
    conn = FileDefaultConnection()
    with conn.transaction():
        defaults.run_source(conn, source, now=NOW)
        source['ransom_policy'] = {'state': 'ready'}
        result = defaults.run_source(conn, source, now=NOW - timedelta(hours=1))
    assert result.jobs == 5 and result.waiting == 0
    assert not defaults._RANSOM_WAITS


def test_wait_identity_includes_revision_threshold_window_and_entire_scope():
    from dataclasses import fields, replace

    from tests.unit.test_file_ransom import rule
    original = rule()
    changed = [replace(original, source_policy_revision='999'),
               replace(original, threshold=original.threshold + 1),
               replace(original, window_seconds=original.window_seconds + 1),
               replace(original, agent_id='00000000-0000-4000-8000-000000000099')]
    for field in fields(original.scope):
        if field.name == 'plugin_id':
            with pytest.raises(ValueError, match='file_ransom_rule_invalid'):
                replace(original, scope=replace(original.scope, plugin_id='sli.other'))
            continue
        value = ('00000000-0000-4000-8000-000000000099' if field.name == 'installation_id'
                 else getattr(original.scope, field.name) + '-changed')
        changed.append(replace(original, scope=replace(original.scope, **{field.name: value})))
    assert all(item.checkpoint_key != original.checkpoint_key for item in changed)
