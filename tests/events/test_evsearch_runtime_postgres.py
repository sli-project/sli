"""Native PostgreSQL SQL/aggregate execution through the HTTP runtime callsite."""
from contextlib import contextmanager
import os

import pytest

from tests.events.test_evsearch_runtime_routes import rig  # noqa: F401
from tests.postgres_integration_guard import assert_disposable_database
from server.sli.core.database import query_rows_bounded as actual_query


@pytest.mark.postgres_integration
def test_dispatcher_uses_real_pg_capture_and_aggregate_with_published_contract(rig, monkeypatch):
    dsn = os.environ.get('ADLOG_TEST_PG_DSN', '').strip()
    if not dsn:
        pytest.skip('Disposable PostgreSQL CI is required; no live database fallback')
    psycopg = pytest.importorskip('psycopg')
    from psycopg.rows import dict_row
    from server.sli.core import database, postgres_runtime_pipeline
    from server.sli.events import evsearch_postgres, evsearch_runtime

    # The ordinary unit fixture replaced query transport. Restore the actual
    # bounded adapter, including placeholder conversion and PG timeout calls.
    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        assert_disposable_database(connection)
        # Isolated source tables shadow public storage only on this connection.
        # Registry and field policies are the REAL migrated published contracts.
        connection.execute('create temporary table storage_v2_channel(id bigint, value text)')
        connection.execute('create temporary table events_v2_core(id bigint, time_created_utc timestamptz, event_id integer, channel_id bigint, normalized_hash bytea)')
        connection.execute("insert into storage_v2_channel values(1,'Security')")
        connection.execute("insert into events_v2_core values(1,'2026-10-18T12:00:00Z',4740,1,%s),(2,'2026-10-18T12:00:00Z',4740,1,%s)", (bytes.fromhex('AA' * 32), bytes.fromhex('AA' * 32)))
        @contextmanager
        def connect():
            yield connection
        monkeypatch.setattr(postgres_runtime_pipeline, 'connect', connect)
        monkeypatch.setenv('ADLOG_DB_BACKEND', 'postgres')
        monkeypatch.setattr(evsearch_runtime, 'query_rows_bounded', actual_query)
        monkeypatch.setattr(evsearch_postgres, 'query_rows_bounded', actual_query)
        monkeypatch.setattr(database, 'query_rows_bounded', actual_query)
        status, result = rig.call('query')
        assert status == 200, result
        seen = []
        while True:
            for group in result['items']:
                status, members = rig.call('members', {'execution_id': result['execution_id'], 'group_key': group['group_key']})
                assert status == 200, members
                seen.extend(row['event_db_id'] for row in members['items'])
            if not result['next_cursor']:
                break
            status, result = rig.call('page', {'execution_id': result['execution_id'], 'cursor': result['next_cursor']})
            assert status == 200, result
        assert sorted(seen) == [1, 2, 3]  # two actual PG rows + synthetic CH transport
        connection.rollback()


@pytest.mark.postgres_integration
def test_existing_runtime_role_reads_registry_and_event_projection_without_grants():
    """Permission/type smoke using the existing role, not superuser grants.

    The dispatcher fixture above intentionally supplies synthetic effective
    grants. This separate check proves DB reader privileges and psycopg JSONB
    decoding only; it does not claim a full persisted-user authorization test.
    """
    dsn = os.environ.get('ADLOG_TEST_PG_DSN', '').strip()
    if not dsn:
        pytest.skip('Disposable PostgreSQL CI is required; no live database fallback')
    psycopg = pytest.importorskip('psycopg')
    from psycopg.rows import dict_row
    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        assert_disposable_database(connection)
        connection.execute('set local role adlog_user')
        role = connection.execute('select current_user as name, rolsuper from pg_roles where rolname=current_user').fetchone()
        assert role == {'name': 'adlog_user', 'rolsuper': False}
        publication = connection.execute(
            "select r.definition_json,d.dataset_key,d.fields_json,r.version,pg_typeof(d.fields_json)::text as field_type "
            "from public.report_registry_v4 r join public.report_datasets_v4 d on d.id=r.dataset_id "
            "where r.report_key='events.explorer' and r.version=1 "
            "and r.status='published' and d.status='published' limit 1"
        ).fetchone()
        assert publication is not None
        assert publication['field_type'] == 'jsonb'
        assert isinstance(publication['fields_json'], list)
        assert all(isinstance(field, dict) for field in publication['fields_json'])
        assert isinstance(publication['definition_json'], dict)
        # The shipped reader projects individual events from both retained layers.
        # LIMIT 0 checks column privileges without relying on any stored event.
        for table in ("event_hot", "event_cold_facts"):
            projection = connection.execute(
                f"select event_id as id,time_created_utc,event_kind as event_id,"
                f"method->>'$channel' as channel,source_sha256 from public.{table} limit 0"
            )
            assert [column.name for column in projection.description] == [
                "id", "time_created_utc", "event_id", "channel", "source_sha256",
            ]
            assert projection.fetchall() == []
        grouped = connection.execute(
            "select group_key,count(*) as n from jsonb_to_recordset(%s::jsonb) as captured(group_key text,stamp timestamptz) group by group_key",
            ('[{"group_key":"synthetic","stamp":"2026-10-18T12:00:00Z"}]',),
        ).fetchone()
        assert grouped == {'group_key': 'synthetic', 'n': 1}
        connection.rollback()
