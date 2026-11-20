"""Synthetic regressions: never open a database or publish real events."""
import json

import pytest

from scripts.maintenance import semantic_production_control as control
from tests.semantic.test_semantic_retained_facts_control import (
    _checkpoint, _configure_poll, _Connection, _Cursor,
)


@pytest.mark.parametrize('field', ['host', 'database', 'role', 'port', 'system_identifier', 'database_oid'])
@pytest.mark.parametrize('operation', ['facts_plan', 'facts_poll'])
def test_cross_target_rejected_before_selection_or_publication(monkeypatch, tmp_path, field, operation):
    path = tmp_path / 'checkpoint.json'
    checkpoint = _checkpoint(last_committed=10)
    checkpoint['database_identity'][field] = 'other'
    path.write_text(json.dumps(checkpoint))
    original = path.read_bytes()
    cursor = _Cursor([])
    _configure_poll(monkeypatch, path, cursor)
    monkeypatch.setattr(control, 'publish_semantic_candidates', lambda *a, **kw: pytest.fail('must not publish'))
    with pytest.raises(RuntimeError, match='database identity mismatch'):
        getattr(control, operation)()
    assert path.read_bytes() == original
    assert not any('where id >' in query for query, _ in cursor.calls)


@pytest.mark.parametrize('cursor_id', [0, 5, 10])
@pytest.mark.parametrize('operation', ['facts_plan', 'facts_poll'])
def test_legacy_checkpoint_never_automatically_adopted(monkeypatch, tmp_path, cursor_id, operation):
    path = tmp_path / 'checkpoint.json'
    checkpoint = _checkpoint(last_committed=cursor_id)
    del checkpoint['database_identity']
    path.write_text(json.dumps(checkpoint))
    original = path.read_bytes()
    cursor = _Cursor([])
    _configure_poll(monkeypatch, path, cursor)
    with pytest.raises(RuntimeError, match='operator-reviewed restart'):
        getattr(control, operation)()
    assert path.read_bytes() == original
    assert cursor.calls == []


def test_new_checkpoint_target_is_rechecked_in_publication_transaction(monkeypatch, tmp_path):
    path = tmp_path / 'checkpoint.json'
    cursor = _Cursor([])
    _configure_poll(monkeypatch, path, cursor)
    identity = {**_checkpoint()['database_identity'], 'system_identifier': 'other'}
    monkeypatch.setattr(control, '_facts_target_snapshot', lambda: (identity, 10))
    monkeypatch.setattr(control, 'publish_semantic_candidates', lambda *a, **kw: pytest.fail('must not publish'))
    with pytest.raises(RuntimeError, match='database identity mismatch'):
        control.facts_poll()
    assert json.loads(path.read_text())['last_committed_event_id'] == 0
    assert not any('where id >' in query for query, _ in cursor.calls)


def test_new_checkpoint_is_durable_before_publication(monkeypatch, tmp_path):
    path = tmp_path / 'checkpoint.json'
    cursor = _Cursor([1])
    _configure_poll(monkeypatch, path, cursor)
    identity = _checkpoint()['database_identity']
    monkeypatch.setattr(control, '_facts_target_snapshot', lambda: (identity, 10))
    def publish(*args, **kwargs):
        saved = json.loads(path.read_text())
        assert saved['database_identity'] == identity
        assert saved['last_committed_event_id'] == 0
        return {'queued': 1}
    monkeypatch.setattr(control, 'publish_semantic_candidates', publish)
    control.facts_poll()


def test_missing_strong_identity_fails_closed(monkeypatch):
    cursor = _Cursor([])
    monkeypatch.setattr(cursor, 'fetchone', lambda: {'host': '127.0.0.1', 'database': 'sli', 'role': 'owner'})
    with pytest.raises(RuntimeError, match='identity is unavailable'):
        control._facts_database_identity(cursor)


class QueueCursor:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def execute(self, query, params=None):
        self.calls.append((query, params))

    def fetchall(self):
        query, params = self.calls[-1]
        # Model version filtering only if the implementation actually requests it.
        if 'job.processor_version=%s' in query:
            assert params == (control.SEMANTIC_CONTRACT_VERSION, control.NORMALIZER_ID,
                              control.NORMALIZER_VERSION, [7], control.SEMANTIC_CONTRACT_VERSION,
                              control.PROCESSOR_ID, control.PROCESSOR_VERSION)
            assert "job.source_identity_json->>'id'=core.id::text" in query
            assert "job.source_identity_json->>'normalized_hash'=encode(core.normalized_hash,'hex')" in query
            assert 'normalized.source_event_sha256=core.normalized_hash' in query
            assert "normalized.processing_status='normalized'" in query
            return [row for row in self.rows if row.get('current', True)]
        return self.rows


def status(monkeypatch, rows):
    cur = QueueCursor(rows)
    monkeypatch.setattr(control, '_connect_admin', lambda: _Connection(cur))
    return control._facts_check_queue_status([7])


@pytest.mark.parametrize('old,current', [('completed', 'queued'), ('failed', 'completed')])
@pytest.mark.parametrize('reverse', [False, True])
def test_current_version_wins_regardless_of_old_row_order(monkeypatch, old, current, reverse):
    rows = [dict(source_event_id=7, status=old, current=False, identity_matches=True, normalized=True),
            dict(source_event_id=7, status=current, current=True, identity_matches=True, normalized=True)]
    result = status(monkeypatch, list(reversed(rows)) if reverse else rows)
    assert result[current] == 1
    assert result[old] == 0


@pytest.mark.parametrize('identity,normalized', [(False, True), (True, False), (None, True)])
def test_completed_requires_current_source_and_normalization(monkeypatch, identity, normalized):
    result = status(monkeypatch, [dict(source_event_id=7, status='completed', identity_matches=identity, normalized=normalized)])
    assert result['completed'] == 0
    assert result['incomplete'] == 1


def test_duplicate_current_jobs_fail_closed(monkeypatch):
    row = dict(source_event_id=7, status='completed', identity_matches=True, normalized=True)
    with pytest.raises(RuntimeError, match='ambiguous'):
        status(monkeypatch, [row, row])


def test_absent_jobs_remain_not_enqueued(monkeypatch):
    assert status(monkeypatch, [])['not_enqueued'] == 1


def test_identity_privilege_failure_has_actionable_nonsecret_error():
    from psycopg.errors import InsufficientPrivilege
    class DeniedCursor(_Cursor):
        def execute(self, query, params=None):
            super().execute(query, params)
            if 'pg_control_system()' in query:
                raise InsufficientPrivilege('fixture detail must not leak')
    with pytest.raises(RuntimeError, match='read-only EXECUTE on pg_control_system') as error:
        control._facts_database_identity(DeniedCursor([]))
    assert 'fixture detail' not in str(error.value)


@pytest.mark.parametrize('previous_state', ['intent', 'processed', 'no_admitted_events'])
def test_incomplete_readback_cannot_attest_terminal_success(monkeypatch, tmp_path, previous_state):
    from tests.semantic.test_semantic_retained_facts_control import _configure_facts_check_plan
    _configure_facts_check_plan(monkeypatch, [7])
    path = tmp_path / 'exact.json'
    monkeypatch.setattr(control, 'FACTS_CHECK_MANIFEST_PATH', path)
    plan = control.facts_check_plan([7])
    manifest = control._new_facts_check_manifest(
        event_ids=[7], rules_fingerprint='rules-v1', database_identity=plan['database_identity'],
        plan_digest=plan['plan_digest'])
    manifest['state'] = previous_state
    path.write_text(json.dumps(manifest))
    queue = dict.fromkeys(['completed', 'queued', 'failed', 'leased', 'quarantined', 'not_enqueued'], 0)
    queue['incomplete'] = 1
    monkeypatch.setattr(control, '_facts_check_queue_status', lambda ids: queue)
    publishes = []
    def execute(ids, *, publish):
        publishes.append(publish)
        return {'runtime': {'processing': {'failed': 0, 'completed': 0}}}
    monkeypatch.setattr(control, '_facts_check_execute', execute)
    result = control.facts_check([7], plan_digest=plan['plan_digest'], confirmation=plan['confirmation'])
    assert result['state'] == 'partial'
    assert publishes == [previous_state == 'intent']
    assert json.loads(path.read_text())['state'] == 'partial'
