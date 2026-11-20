"""Migration 284 and real SQL replay in disposable PostgreSQL only."""
import os
from pathlib import Path

import pytest

from tests.unit.test_event_source_identity import reservation, source

SQL = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/284_event_source_identity.sql").read_text(encoding="utf-8")


def test_additive_migration_preserves_hashes_and_has_exact_predecessor():
    assert "version=283 and name='file_audit_snapshot_hash'" in SQL
    assert "version>=284" in SQL
    assert "update events_v2_core" not in SQL and "update storage_v2_event_identity_allocations" not in SQL
    assert "grant update(representation,representation_sha256)" in SQL
    assert "i.imported_at is not null" in SQL
    assert "grant execute on function public.recheck_agent_quarantine_v284(uuid,text) to adlog_user" in SQL


def test_semantic_reader_exposes_only_exact_imported_source_and_preferred_representation():
    reader = SQL.split("create or replace function public.read_agent_semantic_source_v190", 1)[1].split("$$;", 1)[0]
    assert "security definer" in reader and "set search_path=pg_catalog,public" in reader
    assert "'preferred',to_jsonb(preferred)" in reader
    assert "preferred.event_id=core.id" in reader
    assert "core.id=p_event_id and p_event_id>0" in reader
    assert "inbox.imported_at is not null" in reader
    assert "receipt.receipt->>'status'='committed'" in reader
    assert "inbox.envelope=receipt.envelope" in reader
    assert "count(*)=1" in reader
    assert "core.event_id in (4608,4624,4625" in reader
    assert "interval '1 microsecond'" in reader
    assert "grant select on public.event_source_representations_v2 to adlog_semantic_worker" not in SQL


def connection():
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable migrated PostgreSQL required")
    from tools.e2e.scenario import admin_connection

    return admin_connection(dsn)


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(283, "file_audit_snapshot_hash")
def test_migration_grants_narrow_updates_and_cannot_release_unimported_quarantine():
    with connection() as conn:
        conn.execute(SQL)
        assert conn.execute("select name from schema_migrations where version=284").fetchone()["name"] == "event_source_identity"
        assert not conn.execute("select has_table_privilege('adlog_user','sli_agent_packet_quarantine','DELETE') as ok").fetchone()["ok"]
        assert not conn.execute("""select has_column_privilege('adlog_storage_worker',
            'event_source_representations_v2','normalized_hash','UPDATE') as ok""").fetchone()["ok"]
        assert conn.execute("""select has_column_privilege('adlog_storage_worker',
            'event_source_representations_v2','representation','UPDATE') as ok""").fetchone()["ok"]
        assert not conn.execute("""select has_table_privilege('adlog_semantic_worker',
            'event_source_representations_v2','SELECT') as ok""").fetchone()["ok"]
        assert conn.execute("""select has_function_privilege('adlog_semantic_worker',
            'read_agent_semantic_source_v190(bigint)','EXECUTE') as ok""").fetchone()["ok"]
        assert not conn.execute("""select exists(select 1 from pg_proc p,
            lateral aclexplode(p.proacl) acl where p.oid='read_agent_semantic_source_v190(bigint)'::regprocedure
            and acl.grantee=0 and acl.privilege_type='EXECUTE') as ok""").fetchone()["ok"]
        assert conn.execute("select recheck_agent_quarantine_v284('00000000-0000-4000-8000-000000000063',null) as ok").fetchone()["ok"] is False
        assert not conn.execute("""select exists(select 1 from pg_proc p,
            lateral aclexplode(p.proacl) acl where p.oid='event_source_packet_v284(bigint)'::regprocedure
            and acl.grantee=0 and acl.privilege_type='EXECUTE') as ok""").fetchone()["ok"]


@pytest.mark.postgres_integration
def test_postgres_replay_transport_xml_upgrade_conflict_and_readonly_sequence():
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable migrated PostgreSQL required")
    import psycopg
    from psycopg.rows import dict_row

    from server.sli.storage.storage_v2_repository import (
        PostgresStorageV2Repository,
        SourceEventIdentityConflict,
    )

    with connection() as conn:
        if conn.execute("select to_regclass('public.event_source_representations_v2') as name").fetchone()["name"] is None:
            conn.commit()
            conn.execute(SQL)
        conn.execute("create schema t063_test")
        conn.execute("""create table t063_test.storage_v2_event_identity_allocations(
            id bigint generated always as identity primary key, server_id bigint,channel_id integer,
            event_record_id bigint,time_created_utc timestamptz,normalized_hash bytea,
            unique(server_id,channel_id,event_record_id,time_created_utc));
            create table t063_test.events_v2_core(id bigint,server_id bigint,channel_id integer,
                event_record_id bigint,time_created_utc timestamptz,normalized_hash bytea);
            create table t063_test.event_source_representations_v2(
                like public.event_source_representations_v2 including all);""")

    def connect():
        return psycopg.connect(dsn, options="-c search_path=t063_test,public", row_factory=dict_row)

    repo = PostgresStorageV2Repository(connect)
    old = source()
    reserved = repo.reserve_event_identities([reservation(old)])[0]
    full = {**source(27), "connect_address": "fixture-dc.example.test"}
    assert repo.reserve_event_identities([reservation(full)])[0]["id"] == reserved["id"]
    assert len(repo.reserve_event_identities([reservation(old)])[0]["source_row"]["properties"]) == 27
    with connect() as conn:
        before = conn.execute("select * from storage_v2_event_identity_allocations_id_seq").fetchone()
        fingerprint = conn.execute("select normalized_hash from storage_v2_event_identity_allocations").fetchone()
    repo.reserve_event_identities([reservation(old)], read_only=True)
    with connect() as conn:
        assert conn.execute("select * from storage_v2_event_identity_allocations_id_seq").fetchone() == before
    with pytest.raises(SourceEventIdentityConflict):
        repo.reserve_event_identities([reservation(source(changed=True))])
    with connect() as conn:
        assert conn.execute("select normalized_hash from storage_v2_event_identity_allocations").fetchone() == fingerprint
