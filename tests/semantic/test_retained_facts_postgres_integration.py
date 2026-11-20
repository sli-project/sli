"""Execute controller SQL only in CI-owned per-test disposable PostgreSQL clones.

The narrow tables retain query-relevant PostgreSQL column types; this is SQL
behavior/privilege coverage, not a replacement for migration/schema tests.
"""
from contextlib import nullcontext
import json
import os
import uuid

import pytest

from scripts.maintenance import semantic_production_control as control
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
SOURCE_HASH = b'c' * 32


@pytest.fixture
def postgres(monkeypatch, isolated_postgres_integration_database):
    dsn = str(os.environ.get('ADLOG_TEST_PG_DSN') or '').strip()
    if not dsn:
        pytest.skip('ADLOG_TEST_PG_DSN is required for disposable PostgreSQL tests')
    psycopg = pytest.importorskip('psycopg')
    from psycopg.rows import dict_row

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row, connect_timeout=5,
                               options='-c statement_timeout=10000 -c lock_timeout=2000')

    with connect() as conn:
        assert_disposable_database(conn)
        conn.execute('''
            create table public.events_v2_core(id integer primary key, normalized_hash bytea not null);
            create table public.semantic_processing_outbox(
                source_event_id integer not null, job_kind text not null,
                semantic_contract_version integer not null, processor_id text not null,
                processor_version text not null, source_identity_json jsonb not null, status text not null
            );
            create table public.normalized_events(
                source_event_id integer not null, semantic_contract_version integer not null,
                normalizer_id text not null, normalizer_version text not null,
                processing_status text not null, source_event_sha256 bytea not null
            )
        ''')
        conn.execute('insert into public.events_v2_core values (7,%s)', (SOURCE_HASH,))
    monkeypatch.setattr(control, '_connect_admin', connect)
    return connect


def _job(conn, status, **overrides):
    row = dict(source_event_id=7, job_kind='normalize_event',
               semantic_contract_version=control.SEMANTIC_CONTRACT_VERSION,
               processor_id=control.PROCESSOR_ID, processor_version=control.PROCESSOR_VERSION,
               source_identity_json=json.dumps({'id': 7, 'normalized_hash': SOURCE_HASH.hex()}),
               status=status)
    row.update(overrides)
    conn.execute('''insert into public.semantic_processing_outbox values
                 (%(source_event_id)s,%(job_kind)s,%(semantic_contract_version)s,
                  %(processor_id)s,%(processor_version)s,%(source_identity_json)s::jsonb,%(status)s)''', row)


def _normalized(conn, **overrides):
    row = dict(source_event_id=7, semantic_contract_version=control.SEMANTIC_CONTRACT_VERSION,
               normalizer_id=control.NORMALIZER_ID, normalizer_version=control.NORMALIZER_VERSION,
               processing_status='normalized', source_event_sha256=SOURCE_HASH)
    row.update(overrides)
    conn.execute('''insert into public.normalized_events values
                 (%(source_event_id)s,%(semantic_contract_version)s,%(normalizer_id)s,
                  %(normalizer_version)s,%(processing_status)s,%(source_event_sha256)s)''', row)


def test_actual_identity_query_and_frozen_watermark(postgres):
    identity, watermark = control._facts_target_snapshot()
    assert watermark == 7
    with postgres() as conn:
        assert_disposable_database(conn)
        expected = conn.execute('''select system_identifier::text as system_identifier,
            current_database() as database, session_user as role,
            inet_server_addr()::text as host, inet_server_port()::text as port,
            (select oid::text from pg_database where datname=current_database()) as database_oid
            from pg_control_system()''').fetchone()
        with conn.cursor() as cur:
            assert control._facts_database_identity(cur) == identity == dict(expected)
    assert all(identity.values())


def test_denied_identity_stops_poll_before_publication(postgres, monkeypatch, tmp_path):
    from psycopg import sql
    role = 'sli_test_identity_' + uuid.uuid4().hex
    path = tmp_path / 'checkpoint.json'
    monkeypatch.setattr(control, 'FACTS_CHECKPOINT_PATH', path)
    monkeypatch.setattr(control, '_load_environment', lambda: None)
    monkeypatch.setattr(control, '_validate_facts_admission', lambda: None)
    monkeypatch.setattr(control, '_facts_rules_fingerprint', lambda: 'test-rules')
    monkeypatch.setattr(control, 'session_advisory_lock', lambda *a, **kw: nullcontext(True))
    monkeypatch.setattr(control, '_facts_target_ids', lambda *a, **kw: pytest.fail('selected before identity'))
    monkeypatch.setattr(control, 'publish_semantic_candidates', lambda *a, **kw: pytest.fail('published before identity'))
    with postgres() as admin:
        assert_disposable_database(admin)
        admin.execute(sql.SQL('create role {} nologin nosuperuser nocreatedb nocreaterole noinherit').format(sql.Identifier(role)))
        admin.commit()
        try:
            # NOINHERIT does not exclude PUBLIC grants. Change only this guarded
            # per-test clone; its teardown drops the database and this ACL.
            admin.execute(sql.SQL('revoke execute on function pg_catalog.pg_control_system() from public, {}').format(sql.Identifier(role)))
            admin.commit()  # Make the denial visible to the controller connection.
            privilege = admin.execute("select has_function_privilege(%s,'pg_catalog.pg_control_system()','EXECUTE') as allowed", (role,)).fetchone()
            assert privilege['allowed'] is False, 'disposable role unexpectedly has identity privilege'

            def denied_connect():
                conn = postgres()
                try:
                    conn.execute(sql.SQL('set role {}').format(sql.Identifier(role)))
                    conn.commit()  # Controller can now start its read-only transaction.
                    return conn
                except BaseException:
                    conn.close()
                    raise

            monkeypatch.setattr(control, '_connect_admin', denied_connect)
            with pytest.raises(RuntimeError, match='read-only EXECUTE on pg_control_system'):
                control.facts_poll()
            assert not path.exists()
        finally:
            admin.rollback()
            admin.execute(sql.SQL('drop role {}').format(sql.Identifier(role)))
            admin.commit()


@pytest.mark.parametrize('old,current', [('completed', 'queued'), ('failed', 'completed')])
@pytest.mark.parametrize('field,stale', [
    ('semantic_contract_version', control.SEMANTIC_CONTRACT_VERSION + 1),
    ('processor_id', 'fixture-other-processor'), ('processor_version', 'fixture-other-version'),
])
def test_actual_current_queue_contract_ignores_stale_rows(postgres, old, current, field, stale):
    with postgres() as conn:
        _job(conn, old, **{field: stale})
        _job(conn, current)
        _normalized(conn)
    result = control._facts_check_queue_status([7])
    assert result[current] == 1
    assert result[old] == result['incomplete'] == result['not_enqueued'] == 0


@pytest.mark.parametrize('field,stale', [
    ('semantic_contract_version', control.SEMANTIC_CONTRACT_VERSION + 1),
    ('normalizer_id', 'fixture-other-normalizer'), ('normalizer_version', 'fixture-other-version'),
    ('processing_status', 'failed'), ('source_event_sha256', b'd' * 32), ('source_event_id', 8),
])
def test_actual_normalization_requires_every_current_predicate(postgres, field, stale):
    with postgres() as conn:
        _job(conn, 'completed')
        _normalized(conn, **{field: stale})
    result = control._facts_check_queue_status([7])
    assert result['incomplete'] == 1
    assert result['completed'] == 0
    with postgres() as conn:
        _normalized(conn)
    assert control._facts_check_queue_status([7])['completed'] == 1


@pytest.mark.parametrize('identity', [
    {'id': 8, 'normalized_hash': SOURCE_HASH.hex()},
    {'id': 7, 'normalized_hash': (b'd' * 32).hex()}, {},
])
def test_actual_source_identity_mismatch_is_incomplete(postgres, identity):
    with postgres() as conn:
        _job(conn, 'completed', source_identity_json=json.dumps(identity))
        _normalized(conn)
    result = control._facts_check_queue_status([7])
    assert result['incomplete'] == 1
    assert result['completed'] == result['not_enqueued'] == 0


def test_actual_duplicate_current_coverage_is_rejected(postgres):
    # Deliberately omit outbox uniqueness in this narrow SQL fixture to exercise
    # the defensive guard independently of current schema constraints.
    with postgres() as conn:
        _job(conn, 'queued')
        _job(conn, 'completed')
        _normalized(conn)
    with pytest.raises(RuntimeError, match='ambiguous'):
        control._facts_check_queue_status([7])


def test_actual_absent_current_jobs_preserve_no_admitted_contract(postgres):
    with postgres() as conn:
        _job(conn, 'completed', processor_version='fixture-old')
        _normalized(conn)
    result = control._facts_check_queue_status([7])
    assert result['not_enqueued'] == 1
    assert sum(value for key, value in result.items() if key != 'not_enqueued') == 0
