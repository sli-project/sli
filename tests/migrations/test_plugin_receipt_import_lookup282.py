"""Index-only migration boundaries on a disposable fully migrated clone."""
import os
from pathlib import Path

import pytest

from tests.postgres_integration_guard import assert_disposable_database

pytestmark = pytest.mark.postgres_integration
MIGRATION = Path(__file__).resolve().parents[2] / 'config/postgres_migrations/282_plugin_receipt_import_lookup.sql'
INDEXES = ('sli_agent_receipts_module_received', 'sli_agent_inbox_imported_prefix')


@pytest.fixture
def before_migration():
    psycopg = pytest.importorskip('psycopg')
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('Disposable migrated PostgreSQL required')
    with psycopg.connect(dsn, autocommit=True) as conn:
        assert_disposable_database(conn)
        # Reconstruct only this index-only migration's predecessor on the
        # isolated per-test clone. No roles, grants, real data or shared DB.
        assert conn.execute('select max(version) from public.schema_migrations').fetchone()[0] >= 282
        assert conn.execute('select name from public.schema_migrations where version=282').fetchone()[0] == 'plugin_receipt_import_lookup'
        for name in INDEXES:
            conn.execute('drop index public.' + name)
        # Later objects remain: this is NOT a clean schema281. Reconstruct only
        # ledger/index preconditions for index-only282. T065's283 modifies a
        # different native table/function, not these two indexes or their ACLs.
        conn.execute('delete from public.schema_migrations where version>=282')
        yield conn


def authority(conn):
    return (
        conn.execute("""select oid,relowner,relacl::text,relrowsecurity,relforcerowsecurity
            from pg_class where oid in ('public.sli_agent_receipts'::regclass,
                'public.sli_agent_packet_inbox'::regclass) order by oid""").fetchall(),
        conn.execute('select roleid,member,grantor,admin_option from pg_auth_members order by roleid,member,grantor').fetchall(),
    )


def test_index_only_migration_preserves_authority_and_rejects_reapply(before_migration):
    import psycopg
    conn = before_migration
    before = authority(conn)
    source = MIGRATION.read_text('utf-8')
    conn.execute(source)
    assert authority(conn) == before
    for name in INDEXES:
        assert conn.execute('select to_regclass(%s)', ('public.' + name,)).fetchone()[0]
    with pytest.raises(psycopg.errors.RaiseException, match='migration 282 prerequisites failed'):
        conn.execute(source)
    conn.execute('rollback')
    assert authority(conn) == before
    assert conn.execute('select count(*) from public.schema_migrations where version=282').fetchone()[0] == 1


@pytest.mark.parametrize('case', ['missing', 'wrong_name', 'occupied', 'future'])
def test_exact_predecessor_and_unoccupied_version(before_migration, case):
    import psycopg
    conn = before_migration
    if case == 'missing':
        conn.execute('delete from public.schema_migrations where version=281')
    elif case == 'wrong_name':
        conn.execute("update public.schema_migrations set name='wrong' where version=281")
    else:
        conn.execute("insert into public.schema_migrations(version,name) values(%s,'occupied')",
                     (282 if case == 'occupied' else 283,))
    with pytest.raises(psycopg.errors.RaiseException, match='migration 282 prerequisites failed'):
        conn.execute(MIGRATION.read_text('utf-8'))
    conn.execute('rollback')
    assert all(conn.execute('select to_regclass(%s)', ('public.' + name,)).fetchone()[0] is None for name in INDEXES)


def test_fault_rolls_back_both_indexes_and_ledger(before_migration):
    import psycopg
    conn = before_migration
    before = authority(conn)
    source = MIGRATION.read_text('utf-8').replace('commit;', 'select 1/0;\ncommit;', 1)
    with pytest.raises(psycopg.errors.DivisionByZero):
        conn.execute(source)
    conn.execute('rollback')
    assert all(conn.execute('select to_regclass(%s)', ('public.' + name,)).fetchone()[0] is None for name in INDEXES)
    assert conn.execute('select count(*) from public.schema_migrations where version=282').fetchone()[0] == 0
    assert authority(conn) == before

