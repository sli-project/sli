"""Actual forward269 transaction/upgrade guard; no installed or performance claim."""
from pathlib import Path

import pytest

from tests.migrations.test_file_acl_semantic_migration265 import native_pg as native_pg
from tests.migrations.test_file_audit_acl_bridge_migration264 import acl_pg as acl_pg
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / 'config/postgres_migrations/269_file_audit_canonical_aggregation.sql'


def ready(admin):
    assert_disposable_database(admin)
    admin.execute("insert into schema_migrations values(266,'file_audit_source_lookup_index'),(267,'file_audit_discovery_join'),(268,'agent_packet_path_lookup_index')")


def body(admin):
    return admin.execute("select prosrc from pg_proc where oid='public.file_audit_snapshot_canonical_v264(jsonb,integer)'::regprocedure").fetchone()[0]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize('invalid', ['missing268', 'wrong268', 'occupied269', 'future270', 'reapply'])
def test_actual269_rejects_bad_predecessor_or_reapplication(native_pg, invalid):
    import psycopg
    with psycopg.connect(native_pg, autocommit=True) as admin:
        ready(admin)
        if invalid == 'missing268':
            admin.execute('delete from schema_migrations where version=268')
        elif invalid == 'wrong268':
            admin.execute("update schema_migrations set name='wrong' where version=268")
        elif invalid == 'occupied269':
            admin.execute("insert into schema_migrations values(269,'other')")
        elif invalid == 'future270':
            admin.execute("insert into schema_migrations values(270,'future')")
        else:
            admin.execute(MIGRATION.read_text('utf-8-sig'))
        before = body(admin)
        with pytest.raises(psycopg.errors.RaiseException, match='migration 269 prerequisites failed'):
            admin.execute(MIGRATION.read_text('utf-8-sig'))
        admin.execute('rollback')
        assert body(admin) == before


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_actual269_unauthorized_login_cannot_apply(native_pg, postgres_semantic_worker_dsn):
    import psycopg
    with psycopg.connect(native_pg, autocommit=True) as admin:
        ready(admin)
        before = body(admin)
    with psycopg.connect(postgres_semantic_worker_dsn, autocommit=True) as worker:
        worker.execute('set role adlog_semantic_worker')
        with pytest.raises((psycopg.errors.InsufficientPrivilege, psycopg.errors.RaiseException)):
            worker.execute(MIGRATION.read_text('utf-8-sig'))
        worker.execute('rollback')
    with psycopg.connect(native_pg) as admin:
        assert body(admin) == before
        assert not admin.execute('select 1 from schema_migrations where version=269').fetchone()
