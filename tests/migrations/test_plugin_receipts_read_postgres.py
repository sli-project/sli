"""Exact receipt query under the existing API role on the migrated CI clone."""
import os

import pytest

from server.sli.sources.plugin_receipts import PLUGIN_MODULES, _RECEIPTS_SQL
from server.sli.core.database import _pg_sql
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = pytest.mark.postgres_integration


def test_migrated_receipt_query_uses_existing_runtime_role_without_grants():
    psycopg = pytest.importorskip('psycopg')
    from psycopg.rows import dict_row
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('Disposable migrated PostgreSQL required')
    # The suite's autouse fixture supplies a migrated per-test disposable clone.
    # No surrogate tables, grants, data changes or elevated query execution.
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        conn.execute('begin read only')
        conn.execute('set local role adlog_user')
        conn.execute('set local search_path=pg_catalog,public')
        conn.execute("set local statement_timeout='3s'")
        assert conn.execute('select current_user as role').fetchone()['role'] == 'adlog_user'
        modules = sorted({module for values in PLUGIN_MODULES.values() for module in values})
        rows = conn.execute(_pg_sql(_RECEIPTS_SQL), (modules, modules)).fetchall()
        assert {row['module_id'] for row in rows} <= set(modules)
        assert len(rows) <= len(modules)
        constraints = conn.execute("""select pg_get_constraintdef(oid) as definition
            from pg_constraint where conrelid='public.sli_agent_snapshot_cycles'::regclass
            and contype='c'""").fetchall()
        definitions = ' '.join(row['definition'] for row in constraints)
        assert all(value in definitions for value in (
            'published_at IS NOT NULL', 'transport_state', 'complete', 'publication_state', 'published'))
        # Catalog access and the actual SQL use the existing adlog_user role;
        # no fixture GRANT or elevated receipt SELECT hides a missing permission.
        indexes = conn.execute("""select c.relname,i.indisvalid,i.indisready,
            i.indnkeyatts,i.indnatts,am.amname,c.relowner=t.relowner as same_owner,
            pg_get_indexdef(c.oid) as definition,pg_get_expr(i.indpred,i.indrelid) as predicate
            from pg_index i join pg_class c on c.oid=i.indexrelid
            join pg_class t on t.oid=i.indrelid join pg_am am on am.oid=c.relam
            where c.oid in ('public.sli_agent_receipts_module_received'::regclass,
                           'public.sli_agent_inbox_imported_prefix'::regclass)""").fetchall()
        assert len(indexes) == 2
        by_name = {row['relname']: row for row in indexes}
        for row in indexes:
            assert row['indisvalid'] and row['indisready'] and row['same_owner']
            assert row['amname'] == 'btree' and row['indnkeyatts'] == 2
        receipt = by_name['sli_agent_receipts_module_received']
        assert receipt['indnatts'] == 3 and receipt['predicate'] is None
        assert '(module_id, received_at DESC) INCLUDE (packet_id)' in receipt['definition']
        inbox = by_name['sli_agent_inbox_imported_prefix']
        assert inbox['indnatts'] == 2
        assert '(imported_at DESC, packet_id)' in inbox['definition']
        assert inbox['predicate'] == '(imported_at IS NOT NULL)'

