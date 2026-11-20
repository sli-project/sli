"""Actual table-lock behavior, selected by the disposable PostgreSQL CI job."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import os
import time

import pytest

from server.sli.storage.postgres_profile_retention import execute_no_archive_retention
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


@pytest.fixture
def database():
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('requires disposable PostgreSQL fixture')
    psycopg = pytest.importorskip('psycopg')
    from psycopg.rows import dict_row

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    with connect() as conn:
        assert_disposable_database(conn)
        conn.execute("""
            create table storage_v2_channel(id bigint primary key, value text);
            create table storage_v2_provider(id bigint primary key, value text);
            create table events_v2_core(id bigint primary key, normalized_hash bytea,
                log_source_id bigint,event_id integer,channel_id bigint,provider_id bigint,
                time_created_utc timestamptz);
            create table event_facts_v2(event_id bigint references events_v2_core(id) on delete cascade);
            create table source_capture_continuity_declarations(log_source_id bigint,
                descriptor_source text,descriptor_stream text,provider_name text,channel_value text);
            create table semantic_processing_outbox(source_event_id bigint,status text);
            create table event_entity_link_blocks_v2(event_ids bigint[]);
            create table event_links(source_event_id bigint,target_event_id bigint);
            create table entity_state_current(source_event_db_id bigint);
            create table entity_states(evidence_event_id bigint);
            create table detections(primary_event_id bigint);
            create table finding_evidence(event_id bigint);
            create table investigation_events(investigation_id bigint,event_db_id bigint,relation_status text);
            insert into storage_v2_channel values(1,'Security');
            insert into storage_v2_provider values(1,'Microsoft-Windows-Security-Auditing');
            insert into events_v2_core values(41,decode(repeat('61',32),'hex'),1,4624,1,1,'2026-01-01');
            insert into event_facts_v2 values(41);
            insert into source_capture_continuity_declarations values(1,'sli.windows.ad-dc',
                'Security','Microsoft-Windows-Security-Auditing','Security');
            insert into semantic_processing_outbox values(41,'completed');
        """)
    yield connect


def retain(conn, *, apply=True, check=lambda rows: None):
    return execute_no_archive_retention(
        conn, cutoff=datetime(2026, 8, 3, tzinfo=timezone.utc), apply=apply,
        admitted=True, preservation_check=check,
    )


@pytest.mark.parametrize('status', ['confirmed', 'excluded'])
def test_committed_case_hold_preserves_event_and_facts(database, status):
    with database() as conn:
        conn.execute('insert into investigation_events values(7,41,%s)', (status,))
    with database() as conn:
        result = retain(conn)
        assert result['held_count'] == 1
        assert result['deleted_count'] == 0
        assert result['blocked_by_restrictive_reference_count'] == 1
        assert conn.execute('select count(*) as n from events_v2_core').fetchone()['n'] == 1
        assert conn.execute('select count(*) as n from event_facts_v2').fetchone()['n'] == 1


def test_active_writer_makes_retention_fail_nowait_without_deletion(database):
    from server.sli.semantic.investigation_cases import _lock_event_evidence_writes
    import psycopg

    with database() as writer, database() as retention:
        _lock_event_evidence_writes(writer.cursor())
        assert writer.execute('select id from events_v2_core where id=41').fetchone()
        with pytest.raises(psycopg.errors.LockNotAvailable):
            retain(retention)
        retention.rollback()
        assert retention.execute('select count(*) as n from events_v2_core').fetchone()['n'] == 1
        writer.execute("insert into investigation_events values(7,41,'confirmed')")
    with database() as conn:
        assert retain(conn)['deleted_count'] == 0


def test_writer_waits_before_validation_then_sees_deleted_event(database, monkeypatch):
    from server.sli.semantic import investigation_cases as cases

    monkeypatch.setattr(cases, 'connect', database)
    monkeypatch.setattr(cases, '_case_row', lambda *args: {'id': 7})
    monkeypatch.setattr(cases, '_event_route', lambda *args: 'v2')
    with database() as retention, database() as observer, ThreadPoolExecutor(max_workers=1) as pool:
        futures = []

        def check(_rows):
            futures.append(pool.submit(cases.add_event, investigation_id=7, event_db_id=41, actor='synthetic'))
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                blocked = observer.execute("""
                    select count(*) as n from pg_stat_activity
                    where datname=current_database() and wait_event_type='Lock'
                      and query='lock table investigation_events in row exclusive mode'
                """).fetchone()['n']
                # pg_stat_activity is cached within a transaction.
                observer.commit()
                if blocked:
                    break
                time.sleep(0.01)
            assert blocked == 1, 'writer did not block on the pre-validation fence'
            assert not futures[0].done()

        try:
            result = retain(retention, check=check)
            assert result['deleted_count'] == 1
        finally:
            # Release locks even when an assertion fails, before joining writer.
            retention.rollback()
        with pytest.raises(cases.InvestigationCaseError) as error:
            futures[0].result(timeout=5)
        assert error.value.code == 'event_not_found'
        assert observer.execute('select count(*) as n from investigation_events').fetchone()['n'] == 0


@pytest.mark.parametrize('isolation', ['REPEATABLE READ', 'SERIALIZABLE'])
def test_finding_copy_rejects_snapshot_established_before_retention(database, isolation):
    from server.sli.semantic.investigation_cases import InvestigationCaseError
    from server.sli.semantic.investigation_finding_links import _attach

    with database() as writer, database() as retention:
        # The isolation value is from the fixed parameter list, never input.
        writer.execute(f'SET TRANSACTION ISOLATION LEVEL {isolation}')
        assert writer.execute('select id from events_v2_core where id=41').fetchone()
        assert retain(retention)['deleted_count'] == 1
        # The old snapshot can still see the row; the helper must reject it.
        assert writer.execute('select id from events_v2_core where id=41').fetchone()
        with pytest.raises(InvestigationCaseError) as error:
            _attach(writer.cursor(), case_id=7, finding_id=9, actor='synthetic')
        assert error.value.code == 'evidence_write_requires_read_committed'
        writer.rollback()
    with database() as observer:
        assert observer.execute('select count(*) as n from investigation_events').fetchone()['n'] == 0
