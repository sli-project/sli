"""Native-CI disposable migration, actual-login and report lifecycle contracts.

Uses the repository's fully migrated postgres_integration clone. Predecessor
guard cases use an empty disposable database. No externally preinstalled
producer functions or manually supplied worker credentials are required.
Only synthetic CI logins/data are created by these tests when CI runs them.
Both transports are always replaced by spies. Do not run on an operator DB.
"""
import json
import os
import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.migrations import t070_fixture
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / 'config/postgres_migrations/285_report_producer.sql'
DDL = MIGRATION.read_text('utf-8')
LABEL_DDL = (ROOT / 'config/postgres_migrations/286_sigma_rule_labels.sql').read_text('utf-8')
LABEL_ROLLBACK = (ROOT / 'config/postgres_migrations/286_sigma_rule_labels.rollback.sql').read_text('utf-8')
pytestmark = pytest.mark.postgres_integration


def rollback_successors(admin, *, after):
    """Unwind inventory successors through storage-lifecycle wait 333 in an owned clone."""
    from scripts.maintenance.existing_postgres_bootstrap import (
        forward_migration_inventory,
    )

    assert_disposable_database(admin)
    # Match the guarded 288 fixture's connection.execute interface. Real callers
    # use both psycopg's default tuple rows and dict rows.
    rows = admin.execute(
        f'select version,name from public.schema_migrations where version>{int(after)} order by version'
    ).fetchall()
    successors = [(row['version'], row['name']) if isinstance(row, dict) else (row[0], row[1]) for row in rows]
    known = [(item.version, item.name) for item in
             forward_migration_inventory(ROOT / 'config/postgres_migrations') if item.version > after]
    if successors != known[:len(successors)]:
        raise ValueError('producer_fixture_successor_invalid')
    # Validate the entire chain and its files before the first rollback. Unknown
    # markers or missing scripts must not cause a partially committed teardown.
    for version, name in successors:
        if not (ROOT / f'config/postgres_migrations/{version}_{name}.sql').is_file():
            raise ValueError('producer_fixture_reviewed_successor_missing')
        if version != 288 and not (ROOT / f'config/postgres_migrations/{version}_{name}.rollback.sql').is_file():
            raise ValueError('producer_fixture_reviewed_successor_missing')
    for version, name in reversed(successors):
        if (version, name) == (288, 'file_audit_service_filter'):
            # 288 has no production rollback: use main's guarded test-only
            # restoration, after removing all later migrations it rejects.
            t070_fixture.preflight(admin)
            t070_fixture.remove(admin)
        else:
            t070_fixture.execute_script(admin, (ROOT / f'config/postgres_migrations/{version}_{name}.rollback.sql').read_text('utf-8'))
    return successors


def restore_successors(admin, successors):
    """Reapply the exact chain returned by rollback_successors in forward order."""
    for version, name in successors:
        t070_fixture.execute_script(admin, (ROOT / f'config/postgres_migrations/{version}_{name}.sql').read_text('utf-8'))


def predecessor(admin):
    """Reset only this candidate's objects in the per-test full-schema clone."""
    assert_disposable_database(admin)
    upstream = admin.execute("select * from public.schema_migrations where version=284").fetchone()
    assert upstream and upstream["name"] == "event_source_identity"
    successors = rollback_successors(admin, after=285)
    functions = re.findall(r'create function public\.([a-z_]+)\(', DDL)
    signatures = admin.execute("""select p.oid::regprocedure::text as signature
        from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid=p.pronamespace
        where n.nspname='public' and p.proname=any(%s)""", (functions,)).fetchall()
    from psycopg import sql
    for row in signatures:
        # Signature comes exclusively from catalog rows for the fixed DDL names.
        admin.execute(sql.SQL('drop function if exists {} cascade').format(sql.SQL(row['signature'])))
    for table in ('report_delivery_fairness', 'report_producer_publications', 'report_producer_claims',
                  'report_producer_leader', 'report_producer_principals'):
        admin.execute(sql.SQL('drop table if exists public.{} cascade').format(sql.Identifier(table)))
    admin.execute("delete from public.schema_migrations where version=285 and name='report_producer'")
    assert admin.execute("select * from public.schema_migrations where version=284").fetchone() == upstream
    if admin.execute("select 1 from pg_catalog.pg_roles where rolname='adlog_report_producer_owner'").fetchone():
        # Remove the exact P1 grant too: reapplication must establish it itself.
        admin.execute('revoke update(id) on public.notification_outbox from adlog_report_producer_owner')
    return successors


def reapply(admin):
    """Restore the original successor chain after reconstructing migration 285."""
    successors = predecessor(admin)
    admin.execute(DDL)
    restore_successors(admin, successors)


@pytest.mark.parametrize('change', ['missing', 'wrong_name', 'already_applied', 'future'])
@pytest.mark.postgres_empty
def test_migration_predecessor_guard_leaves_no_partial_objects(change):
    import psycopg

    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('disposable PostgreSQL required')
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert_disposable_database(admin)
        admin.execute('create table schema_migrations(version integer primary key,name text not null)')
        if change != 'missing':
            admin.execute('insert into schema_migrations values(284,%s)',
                          ('synthetic-wrong' if change == 'wrong_name' else 'event_source_identity',))
        if change in ('already_applied', 'future'):
            admin.execute('insert into public.schema_migrations(version,name) values(%s,%s)',
                          (285 if change == 'already_applied' else 286, 'synthetic-future'))
        before = admin.execute('select * from schema_migrations order by version').fetchall()
        with pytest.raises(psycopg.errors.RaiseException, match='migration 285 prerequisites failed'):
            admin.execute(DDL)
        admin.rollback()
        assert admin.execute("select to_regclass('public.report_producer_claims')").fetchone()[0] is None
        assert admin.execute('select * from schema_migrations order by version').fetchall() == before
