"""T065: private write-time canonical hash, real provenance/RLS, no stand claim."""
import json
import os
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest

from sli_agent.envelope import canonical, digest
from tests.migrations.test_acl_backlog_native_profile import (
    profile_pg as profile_pg, retained, stats,
)
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


def measured_provenance(admin_dsn, item, stage, expected):
    import psycopg
    from psycopg.rows import dict_row
    # Transaction-local counters must bracket the call in the same transaction.
    # Use the owner connection: the worker must not gain this private API.
    with psycopg.connect(admin_dsn, row_factory=dict_row) as admin:
        assert admin.execute('show track_functions').fetchone()['track_functions'] == 'all'
        start = stats(admin)
        actual = admin.execute('select public.file_audit_snapshot_provenance_v264(%s,%s) as value',
                               (AGENT, item['snapshot_id'])).fetchone()['value']
        end = stats(admin)
        calls = {name: end[name]['calls'] - start[name]['calls'] for name in start}
        assert actual == expected, (stage, actual, expected)
        assert calls['file_audit_snapshot_provenance_v264'] > 0, (stage, calls)
        for name in ('file_audit_snapshot_canonical_v264', 'file_audit_snapshot_quote_v264'):
            assert (calls[name] > 0 if stage == 'before' else calls[name] == 0), (stage, name, calls)
        return calls


@pytest.mark.postgres_empty
@pytest.mark.parametrize('near', [False, True], ids=['small', 'near49k'])
def test_native_provenance_and_qw_rls_no_read_canonical_calls(profile_pg, near):
    import psycopg
    from psycopg.rows import dict_row
    admin_dsn, worker_dsn = profile_pg
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        item, resource, result_id, result_hash = retained(admin, near)
        prepare(admin)
        expected = provenance(admin, item)
        assert expected is not None
        before_authority = authority(admin)
        with psycopg.connect(worker_dsn) as login:
            principal = login.execute('select session_user').fetchone()[0]
        admin.execute("""update finding_evidence_source_bindings set
            principal_oid=(select oid from pg_roles where rolname=%s),principal_name=%s""",
            (principal, principal))
    with psycopg.connect(worker_dsn, row_factory=dict_row) as worker:
        worker.execute('set role adlog_semantic_worker')
        worker.execute("set local statement_timeout='30s'")
        for statement in (
            'select * from sli_plugin_file_audit.access_snapshots',
            "select public.file_audit_snapshot_canonical_v264('{}')",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege), worker.transaction(force_rollback=True):
                worker.execute(statement)
        portion = worker.execute('select public.prepare_file_acl_portion_v265(%s::jsonb,%s::jsonb) as value',
            (json.dumps(resource), json.dumps([dict(result_id=result_id, result_sha256=result_hash)]))).fetchone()['value']
        worker.execute("insert into semantic_qw_signals values(%s,'enabled',%s::jsonb,now())",
                       (portion['signal_id'], json.dumps(portion['document'])))
        worker.commit()
        records = []
        for stage in ('before', 'after'):
            if stage == 'after':
                with psycopg.connect(admin_dsn, autocommit=True) as admin:
                    apply(admin)
                    assert authority(admin) == before_authority
                    assert provenance(admin, item) == expected
                    assert cached(admin, item) == item['snapshot_sha256']
                with pytest.raises(psycopg.errors.InsufficientPrivilege), worker.transaction(force_rollback=True):
                    worker.execute('select public.file_audit_snapshot_hash_v283()')
            provenance_calls = measured_provenance(admin_dsn, item, stage, expected)
            worker.execute("set local statement_timeout='30s'")
            start = stats(worker)
            # Actual row-level policy, not a source/regex assertion or mock.
            plan = worker.execute('explain(analyze,buffers,format json) select signal_id from semantic_qw_signals').fetchone()['QUERY PLAN']
            rows = worker.execute('select signal_id from semantic_qw_signals').fetchall()
            end = stats(worker)
            assert rows == [{'signal_id': portion['signal_id']}]
            calls = {name: end[name]['calls'] - start[name]['calls'] for name in start}
            assert calls['file_audit_snapshot_provenance_v264'] > 0, (stage, calls)
            assert calls['file_acl_native_verdict_v265'] > 0, (stage, calls)
            # Migration265 still canonicalizes producer identity. Only snapshot
            # provenance above must reach zero; do not remove that live guard.
            for name in ('file_audit_snapshot_canonical_v264', 'file_audit_snapshot_quote_v264'):
                assert calls[name] > 0, (stage, name, calls)
                if stage == 'after':
                    assert calls[name] < records[0]['calls'][name], (stage, name, calls, records[0])
            records.append(dict(stage=stage, canonical_bytes=len(canonical(item)), calls=calls,
                                provenance_calls=provenance_calls,
                                execution_ms=plan[0]['Execution Time'], plan=plan))
            worker.commit()
        print('T065_SYNTHETIC ' + json.dumps(records, sort_keys=True))
        with psycopg.connect(admin_dsn, autocommit=True) as admin:
            admin.execute(f"update {TABLE} set snapshot=jsonb_set(snapshot,'{{share,dacl}}','\"D:\"')")
            assert cached(admin, item) != item['snapshot_sha256']
            assert provenance(admin, item) is None
        assert worker.execute('select signal_id from semantic_qw_signals').fetchall() == []


@pytest.mark.postgres_empty
@pytest.mark.parametrize('case', ['forged_cache', 'body_changed', 'expected_hash_changed', 'oversize', 'fraction', 'unicode'])
def test_cache_overwrite_and_canonical_semantics(profile_pg, case):
    import psycopg
    with psycopg.connect(profile_pg[0], autocommit=True) as admin:
        item, *_ = retained(admin, False)
        prepare(admin)
        apply(admin)
        changed = deepcopy(item)
        if case == 'forged_cache':
            admin.execute(f"update {TABLE} set canonical_body_sha256=repeat('f',64)")
            assert cached(admin, item) == item['snapshot_sha256']
            assert provenance(admin, item) is not None
            return
        if case == 'expected_hash_changed':
            admin.execute(f"update {TABLE} set snapshot_sha256=repeat('f',64)")
            assert cached(admin, item) == item['snapshot_sha256']
            assert provenance(admin, item) is None
            return
        if case == 'oversize':
            # Body alone is small; excluded identity field MUST still be bounded.
            changed['snapshot_id'] = 'x' * 49152
        elif case == 'fraction':
            changed['page_number'] = 0.5
        elif case == 'unicode':
            changed['objects'][0]['object_id'] = '尾😀\u007f'
        else:
            changed['share']['dacl'] = 'D:'
        admin.execute(f'update {TABLE} set snapshot=%s::jsonb,canonical_body_sha256=%s',
                      (json.dumps(changed), item['snapshot_sha256']))
        if case in ('oversize', 'fraction'):
            assert cached(admin, item) is None
        else:
            expected = digest({k: v for k, v in changed.items() if k not in ('snapshot_id', 'snapshot_sha256')})
            assert cached(admin, item) == expected != item['snapshot_sha256']
        assert provenance(admin, item) is None


@pytest.mark.postgres_empty
@pytest.mark.parametrize('mutation', ['config', 'receipt', 'domain', 'source', 'scope'])
def test_current_authority_not_cached(profile_pg, mutation):
    import psycopg
    with psycopg.connect(profile_pg[0], autocommit=True) as admin:
        item, *_ = retained(admin, False)
        prepare(admin)
        apply(admin)
        assert provenance(admin, item) is not None
        statement = {
            'config': "update sli_agents set assigned_modules='[]'",
            'receipt': 'delete from sli_plugin_file_audit.audit_receipts',
            'domain': 'update servers set is_active=false',
            'source': f"update {TABLE} set source_instance_id='other'",
            'scope': f"update {TABLE} set collection_scope_id='other'",
        }[mutation]
        admin.execute(statement)
        assert cached(admin, item) == item['snapshot_sha256']
        assert provenance(admin, item) is None


@pytest.mark.postgres_empty
@pytest.mark.parametrize('failure', ['missing', 'wrong', 'occupied', 'future', 'rollback'])
def test_migration_guards_and_atomicity(profile_pg, failure):
    import psycopg
    with psycopg.connect(profile_pg[0], autocommit=True) as admin:
        item, *_ = retained(admin, False)
        prepare(admin)
        before = authority(admin)
        original = admin.execute('select pg_get_functiondef(%s::regprocedure)', (PROVENANCE,)).fetchone()[0]
        if failure == 'missing':
            admin.execute('delete from schema_migrations where version=282')
        elif failure == 'wrong':
            admin.execute("update schema_migrations set name='wrong' where version=282")
        elif failure in ('occupied', 'future'):
            admin.execute("insert into schema_migrations values(%s,'occupied')", (283 if failure == 'occupied' else 284,))
        source = MIGRATION.read_text('utf-8')
        error = psycopg.errors.RaiseException
        if failure == 'rollback':
            source = source.replace('commit;', 'select 1/0;\ncommit;')
            error = psycopg.errors.DivisionByZero
        with pytest.raises(error):
            admin.execute(source)
        admin.execute('rollback')
        assert authority(admin) == before
        assert admin.execute('select pg_get_functiondef(%s::regprocedure)', (PROVENANCE,)).fetchone()[0] == original
        assert admin.execute('select to_regprocedure(%s)', (HASH_FUNCTION,)).fetchone()[0] is None
        assert provenance(admin, item) is not None


def test_full_schema_roles_trigger_and_direct_insert():
    """Real migrated schema/role memberships; no fixture GRANT masks privileges."""
    import psycopg
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('disposable migrated PostgreSQL required')
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert_disposable_database(admin)
        function = admin.execute("""select r.rolname,p.prosecdef,p.proconfig from pg_proc p
            join pg_roles r on r.oid=p.proowner where p.oid=%s::regprocedure""", (HASH_FUNCTION,)).fetchone()
        assert function == ('adlog_storage_owner', True, ['search_path=pg_catalog, pg_temp'])
        for role in ('adlog_user', 'adlog_semantic_worker', 'adlog_file_audit_runtime'):
            assert not admin.execute('select has_function_privilege(%s,%s,\'EXECUTE\')', (role, HASH_FUNCTION)).fetchone()[0]
        for role in ('adlog_user', 'adlog_semantic_worker'):
            assert not admin.execute('select has_table_privilege(%s,%s,\'SELECT\')', (role, TABLE)).fetchone()[0]
        assert not admin.execute("select has_table_privilege('adlog_file_audit_runtime',%s,'UPDATE')", (TABLE,)).fetchone()[0]
        admin.execute('set role adlog_file_audit_runtime')
        value = {'payload': 'synthetic😀', 'snapshot_id': str(uuid4()), 'snapshot_sha256': 'e' * 64}
        expected = digest({'payload': value['payload']})
        admin.execute(f'''insert into {TABLE}(snapshot_id,agent_id,source_instance_id,collection_scope_id,
            observed_at,contract_version,completeness,snapshot_sha256,snapshot,unread_objects,canonical_body_sha256)
            values(%s,%s,'synthetic','synthetic',now(),1,'partial',%s,%s::jsonb,0,%s)''',
            (value['snapshot_id'], AGENT, value['snapshot_sha256'], json.dumps(value), 'f' * 64))
        assert cached(admin, value) == expected
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            admin.execute(f"update {TABLE} set canonical_body_sha256=repeat('f',64)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            admin.execute(f'alter table {TABLE} disable trigger {TRIGGER}')
        admin.execute('reset role')
        with pytest.raises(psycopg.errors.RaiseException, match='migration 283 prerequisites failed'):
            apply(admin)
        admin.execute('rollback')


@pytest.mark.postgres_empty
@pytest.mark.parametrize('invalid', [False, True])
def test_backfill_preserves_valid_and_invalid_provenance(profile_pg, invalid):
    import psycopg
    with psycopg.connect(profile_pg[0], autocommit=True) as admin:
        item, *_ = retained(admin, False)
        prepare(admin)
        if invalid:
            admin.execute(f"update {TABLE} set snapshot=jsonb_set(snapshot,'{{page_number}}','0.5')")
        before = provenance(admin, item)
        apply(admin)
        assert provenance(admin, item) == before
        assert (cached(admin, item) is None) == invalid


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
