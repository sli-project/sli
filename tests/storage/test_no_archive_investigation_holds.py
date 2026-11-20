"""Legacy retention must fence case writers before deleting hot evidence."""
from datetime import datetime, timezone

import pytest

from server.sli.storage.postgres_profile_retention import execute_no_archive_retention
from tests.storage.test_postgres_profile_retention import _DirectConnection, _DirectCursor


def run(connection, *, apply=True, preservation_check=lambda rows: None):
    return execute_no_archive_retention(
        connection, cutoff=datetime(2026, 8, 3, tzinfo=timezone.utc),
        apply=apply, admitted=True, preservation_check=preservation_check,
    )


def test_hold_is_in_both_classification_queries():
    conn = _DirectConnection()
    run(conn, apply=False)
    queries = [sql for sql in conn.cursor_instance.executed
               if 'direct_no_archive_prefilter_reconciliation' in sql
               or 'direct_no_archive_candidate_classification' in sql]
    assert len(queries) == 2
    assert all('from investigation_events' in sql for sql in queries)
    assert not any('lock table investigation_events' in sql for sql in conn.cursor_instance.executed)


def test_apply_locks_and_rechecks_before_preservation():
    conn = _DirectConnection()
    observed = []
    run(conn, preservation_check=lambda rows: observed.extend(conn.cursor_instance.executed))
    packed = next(i for i, sql in enumerate(observed) if 'lock table event_entity_link_blocks' in sql)
    cases = next(i for i, sql in enumerate(observed) if 'lock table investigation_events in share mode nowait' in sql)
    core = next(i for i, sql in enumerate(observed) if 'from events_v2_core where id=any' in sql)
    check = next(i for i, sql in enumerate(observed) if 'direct_no_archive_locked_investigation_holds' in sql)
    assert packed < cases < core < check


def test_changed_hold_aborts_before_preservation_or_delete():
    class Cursor(_DirectCursor):
        def fetchall(self):
            if 'direct_no_archive_locked_investigation_holds' in self.executed[-1]:
                return [{'event_db_id': 41}]
            return super().fetchall()
    conn = _DirectConnection()
    conn.cursor_instance = Cursor()
    reads = []
    with pytest.raises(RuntimeError, match='direct_no_archive_investigation_evidence_changed'):
        run(conn, preservation_check=reads.append)
    assert not reads
    assert conn.commits == 0
    assert not any('delete from events_v2_core' in sql for sql in conn.cursor_instance.executed)


def test_writer_contention_aborts_retention_before_delete():
    class Cursor(_DirectCursor):
        def execute(self, sql, params=()):
            super().execute(sql, params)
            if 'lock table investigation_events' in sql:
                raise RuntimeError('synthetic lock unavailable')
    conn = _DirectConnection()
    conn.cursor_instance = Cursor()
    with pytest.raises(RuntimeError, match='synthetic lock unavailable'):
        run(conn)
    assert conn.commits == 0
    assert not any('delete from events_v2_core' in sql for sql in conn.cursor_instance.executed)


@pytest.mark.parametrize('operation', ['create', 'add', 'copy'])
def test_writers_fence_before_evidence_validation(monkeypatch, operation):
    from server.sli.semantic import investigation_cases as cases
    from server.sli.semantic import investigation_finding_links as links

    statements = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, sql, params=()):
            statements.append(' '.join(sql.lower().split()))

        def fetchone(self):
            if statements[-1] == 'show transaction_isolation':
                return {'transaction_isolation': 'read committed'}
            return {'id': 7, 'event_db_id': 41}

    class Connection(Cursor):
        def cursor(self):
            return Cursor()

    def validate(*args, **kwargs):
        assert 'lock table investigation_events in row exclusive mode' in statements
        return [41] if operation == 'copy' else True

    monkeypatch.setattr(cases, 'connect', Connection)
    monkeypatch.setattr(cases, '_event_exists_for_route', validate)
    monkeypatch.setattr(cases, '_case_row', lambda *args: {'id': 7})
    monkeypatch.setattr(links, '_finding_event_ids', validate)
    if operation == 'create':
        cases.create_case(title='Synthetic', actor='test', event_db_id=41)
    elif operation == 'add':
        cases.add_event(investigation_id=7, event_db_id=41, actor='test')
    else:
        links._attach(Cursor(), case_id=7, finding_id=9, actor='test')


@pytest.mark.parametrize('isolation', ['repeatable read', 'serializable'])
def test_apply_rejects_stale_snapshot_isolation(isolation):
    class Cursor(_DirectCursor):
        def fetchone(self):
            if self.executed[-1] == 'show transaction_isolation':
                return {'transaction_isolation': isolation}
            return super().fetchone()
    conn = _DirectConnection()
    conn.cursor_instance = Cursor()
    result = run(conn)
    assert result['status'] == 'blocked'
    assert result['reason'] == 'direct_no_archive_requires_read_committed'
    assert conn.cursor_instance.executed == ['show transaction_isolation']
    assert conn.commits == 0


@pytest.mark.parametrize('isolation', ['repeatable read', 'serializable'])
@pytest.mark.parametrize('operation', ['create', 'add', 'copy'])
def test_writers_reject_stale_snapshots_before_lock_or_evidence_reads(monkeypatch, isolation, operation):
    from server.sli.semantic import investigation_cases as cases
    from server.sli.semantic import investigation_finding_links as links

    statements = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, sql, params=()):
            statements.append(sql)

        def fetchone(self):
            return {'transaction_isolation': isolation}

    class Connection(Cursor):
        def cursor(self):
            return Cursor()

    def no_evidence_reads(*args, **kwargs):
        pytest.fail('unsupported snapshot reached evidence validation or selection')

    monkeypatch.setattr(cases, 'connect', Connection)
    monkeypatch.setattr(cases, '_event_exists_for_route', no_evidence_reads)
    monkeypatch.setattr(cases, '_case_row', lambda *args: {'id': 7})
    monkeypatch.setattr(links, '_finding_event_ids', no_evidence_reads)
    with pytest.raises(cases.InvestigationCaseError) as error:
        if operation == 'create':
            cases.create_case(title='Synthetic', actor='test', event_db_id=41)
        elif operation == 'add':
            cases.add_event(investigation_id=7, event_db_id=41, actor='test')
        else:
            links._attach(Cursor(), case_id=7, finding_id=9, actor='test')
    assert error.value.code == 'evidence_write_requires_read_committed'
    assert statements == ['show transaction_isolation']
