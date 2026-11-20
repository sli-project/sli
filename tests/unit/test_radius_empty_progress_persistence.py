"""Cursor-only persistence uses the original activation, locking and CAS fences."""
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from uuid import uuid4

import pytest

from server.source_packs.radius.accounting_postgres import (
    RadiusPostgresContractError,
    commit_admitted_empty_radius_progress,
)
from sli_collect.radius_contract import initial_cursor


class CursorConnection:
    def __init__(self):
        self.before = initial_cursor(source_instance_id='fixture-radius', transport_binding='fixture-tail',
                                     file_generation='fixture-generation')
        self.after = replace(self.before, byte_offset=2)
        self.epoch = uuid4()
        self.revision = 3
        self.persisted = self.before
        self.calls = []
        self.mode = None
        self.rowcount = 1
        self.writes = 0
        self.depth = 0

    @contextmanager
    def transaction(self):
        snapshot = self.persisted, self.revision, self.writes
        self.depth += 1
        try:
            yield
        except Exception:
            self.persisted, self.revision, self.writes = snapshot
            raise
        finally:
            self.depth -= 1

    def cursor(self):
        return nullcontext(self)

    def execute(self, sql, params=()):
        assert self.depth > 0
        self.sql = sql
        self.calls.append((sql, params))
        if 'update acquisition_stream_cursors' in sql:
            assert params[7:] == (self.before.source_instance_id, self.before.stream_id,
                self.before.transport_binding, self.epoch, 3, self.before.file_generation,
                self.before.byte_offset, self.before.last_record_sha256)
            self.rowcount = 0 if self.mode == 'cas' else 1
            if self.rowcount:
                self.persisted = self.after
                self.revision += 1
                self.writes += 1

    def fetchone(self):
        if 'select current_role' in self.sql:
            return ('adlog_radius_accounting_worker',)
        if 'for update of c' in self.sql:
            epoch = uuid4() if self.mode == 'epoch' else self.epoch
            revision = self.revision + (1 if self.mode == 'revision' else 0)
            cursor = self.persisted
            if self.mode == 'offset':
                cursor = replace(cursor, byte_offset=1)
            if self.mode == 'hash':
                cursor = replace(cursor, last_record_sha256='a' * 64)
            enabled = 'disabled' if self.mode == 'disabled' else 'manual_enabled'
            return (epoch, cursor.file_generation, cursor.byte_offset, cursor.last_record_sha256,
                    revision, enabled, enabled)
        raise AssertionError('unexpected synthetic query')

    def commit_progress(self, **overrides):
        args = {'subscription_id': 'fixture-subscription', 'cursor_epoch': self.epoch, 'expected_revision': 3,
                    'current_cursor': self.before, 'next_cursor': self.after, 'skipped_bytes': 2, 'physical_lines': 1}
        commit_admitted_empty_radius_progress(self, **(args | overrides))


def test_cursor_only_commit_and_stale_retry_never_duplicate_progress():
    conn = CursorConnection()
    conn.commit_progress()
    assert conn.persisted == conn.after and conn.revision == 4 and conn.writes == 1
    with pytest.raises(RadiusPostgresContractError, match='stale_batch_cursor'):
        conn.commit_progress()
    assert conn.writes == 1
    assert not any('insert into' in sql or 'delete from' in sql for sql, _ in conn.calls)


@pytest.mark.parametrize('mode,error', [('epoch', 'stale_batch_cursor'), ('revision', 'stale_batch_cursor'),
    ('offset', 'stale_batch_cursor'), ('hash', 'stale_batch_cursor'),
    ('disabled', 'subscription_not_manually_enabled'), ('cas', 'cursor_compare_and_swap_failed')])
def test_concurrent_or_unowned_cursor_is_not_changed(mode, error):
    conn = CursorConnection()
    conn.mode = mode
    with pytest.raises(RadiusPostgresContractError, match=error):
        conn.commit_progress()
    assert conn.persisted == conn.before and conn.revision == 3 and conn.writes == 0


def test_outer_inbox_failure_rolls_back_cursor_progress():
    conn = CursorConnection()
    with pytest.raises(RuntimeError, match='inbox failure'), conn.transaction():
        conn.commit_progress()
        assert conn.writes == 1
        raise RuntimeError('inbox failure')
    assert conn.persisted == conn.before and conn.revision == 3 and conn.writes == 0


@pytest.mark.parametrize('override', [{'skipped_bytes': True}, {'physical_lines': True},
    {'skipped_bytes': -1}, {'skipped_bytes': 4 * 1024 * 1024 + 1}, {'physical_lines': 129},
    {'physical_lines': 0}, {'skipped_bytes': 0, 'physical_lines': 0}])
def test_cursor_only_api_rejects_malformed_progress_before_sql(override):
    conn = CursorConnection()
    with pytest.raises(RadiusPostgresContractError, match='empty_progress_invalid'):
        conn.commit_progress(**override)
    assert not conn.calls


def test_rotated_empty_cursor_retains_hash_without_evidence_or_cache_writes():
    conn = CursorConnection()
    conn.before = replace(conn.before, last_record_sha256='b' * 64)
    conn.persisted = conn.before
    conn.after = replace(conn.before, file_generation='next-generation')
    conn.commit_progress(skipped_bytes=0, physical_lines=0)
    assert conn.persisted == conn.after
    assert conn.persisted.last_record_sha256 == 'b' * 64
    assert conn.writes == 1
