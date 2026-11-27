"""T065: private write-time canonical hash, real provenance/RLS, no stand claim."""
import json
import os
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest

from tests.migrations.test_file_acl_semantic_migration265 import native_pg as native_pg
from tests.migrations.test_file_audit_acl_bridge_migration264 import (
    AGENT, COMMAND, inventory, acl_pg as acl_pg,
)
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / 'config/postgres_migrations/283_file_audit_snapshot_hash.sql'
TABLE = 'sli_plugin_file_audit.access_snapshots'
TRIGGER = 'file_audit_snapshot_hash_v283'
HASH_FUNCTION = 'public.file_audit_snapshot_hash_v283()'
PROVENANCE = 'public.file_audit_snapshot_provenance_v264(uuid,uuid)'
pytestmark = pytest.mark.postgres_integration


def prepare(admin):
    assert_disposable_database(admin)
    # Reduced profile has real264/265/269 functions, but not unrelated270..282.
    admin.execute("insert into schema_migrations values(282,'plugin_receipt_import_lookup')")


def apply(admin):
    admin.execute(MIGRATION.read_text('utf-8'))


def provenance(admin, item):
    return admin.execute('select public.file_audit_snapshot_provenance_v264(%s,%s)',
                         (AGENT, item['snapshot_id'])).fetchone()[0]


def cached(admin, item):
    return admin.execute(f'select canonical_body_sha256 from {TABLE} where snapshot_id=%s',
                         (item['snapshot_id'],)).fetchone()[0]


def authority(admin):
    return (
        admin.execute("""select oid,relowner,relacl::text,relrowsecurity,relforcerowsecurity
            from pg_class where oid='sli_plugin_file_audit.access_snapshots'::regclass""").fetchone(),
        admin.execute('select roleid,member,grantor,admin_option from pg_auth_members order by 1,2,3').fetchall(),
        admin.execute("""select oid,proowner,proacl::text,provolatile,prosecdef,proconfig
            from pg_proc where oid=%s::regprocedure""", (PROVENANCE,)).fetchone(),
    )


def test_full_schema_actual_store_audit_result_and_replay():
    """Exercise the installed185 writer and its actual column ACL, not a stub."""
    import psycopg
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('disposable migrated PostgreSQL required')
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert_disposable_database(admin)
        admin.execute("insert into public.sli_agents(id,host_id,key_fingerprint) values(%s,%s,repeat('a',64))",
                      (AGENT, str(uuid4())))
        admin.execute('''insert into sli_plugin_file_audit.audit_commands
            (command_id,agent_id,source_instance_id,policy_revision,action,collection_scope_ids,
             requested_at,actor_kind,actor_id,command_sha256)
            values(%s,%s,'synthetic-source',1,'check',array['synthetic-root'],now(),'session',1,repeat('b',64))''',
                      (COMMAND, AGENT))
        fresh = inventory()
        fresh['snapshot_id'] = str(uuid4())
        payload = dict(command_id=COMMAND, policy_revision='1', action='check', snapshots=[fresh], scopes=[])
        admin.execute('set role adlog_user')
        admin.execute('select sli_plugin_file_audit.store_audit_result(%s,%s::jsonb)', (AGENT, json.dumps(payload)))
        admin.execute('reset role')
        assert cached(admin, fresh) == fresh['snapshot_sha256']
        # Existing idempotent replay cannot replace original evidence or cache.
        payload['snapshots'][0]['share']['dacl'] = 'D:'
        admin.execute('set role adlog_user')
        admin.execute('select sli_plugin_file_audit.store_audit_result(%s,%s::jsonb)', (AGENT, json.dumps(payload)))
        admin.execute('reset role')
        assert cached(admin, fresh) == fresh['snapshot_sha256']
