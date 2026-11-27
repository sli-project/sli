"""Additive file lookup path on real PG; unrelated predecessor tables are reduced.

Uses real 183/186 observations, 157 receipts/inbox and the unchanged 263
function. This is not the complete installed 265/native conveyor gate.
"""
import json
from pathlib import Path
from uuid import uuid4

import pytest

from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg

from tests.migrations.test_default_native_detections_migration262 import (
    defaults_pg as defaults_pg,  # noqa: PLC0414
)
from tests.migrations.test_file_acl_semantic_migration265 import (
    native_pg as native_pg,  # noqa: PLC0414
)
from tests.migrations.test_file_audit_acl_bridge_migration264 import (
    acl_pg as acl_pg,  # noqa: PLC0414
)
from tests.migrations.test_qw_semantic_input_migration228 import (
    pg as pg,  # noqa: PLC0414
)

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / 'config/postgres_migrations/266_file_audit_source_lookup_index.sql'
INDEX = 'file_audit_source_lookup_index'
AGENT = '00000000-0000-4000-8000-000000000003'
OTHER_AGENT = '00000000-0000-4000-8000-000000000004'
MODULE = 'sli.file-audit'
LOOKUP = '''select source_instance_id,generation from sli_plugin_file_audit.observations
    where agent_id=%s and collection_scope_id=%s and policy_revision=%s'''


def migration_source(version, name):
    return (ROOT / f'config/postgres_migrations/{version}_{name}.sql').read_text('utf-8')


def observation_ddl(conn):
    source = migration_source(183, 'file_audit_contracts')
    conn.execute(source[source.index('create table sli_plugin_file_audit.observations'):
                        source.index('create table sli_plugin_file_audit.actions')])
    source = migration_source(186, 'file_audit_collection')
    conn.execute(source[source.index('alter table sli_plugin_file_audit.observations drop constraint'):
                        source.index('alter table sli_plugin_file_audit.actions add column')])


@pytest.fixture
def lookup_pg(defaults_pg):
    """Exact relevant tables/function; ledger 264/265 is a reduced fixture marker."""
    import psycopg

    with psycopg.connect(defaults_pg, autocommit=True) as conn:
        if not conn.execute("select 1 from pg_roles where rolname='adlog_file_audit_owner'").fetchone():
            conn.execute('create role adlog_file_audit_owner nologin noinherit')
        conn.execute('grant adlog_file_audit_owner to adlog_storage_owner')
        conn.execute('drop table sli_plugin_file_audit.observations')
        conn.execute('alter schema sli_plugin_file_audit owner to adlog_file_audit_owner')
        conn.execute('set role adlog_file_audit_owner')
        observation_ddl(conn)
        conn.execute('reset role')
        conn.execute('grant usage on schema sli_plugin_file_audit to adlog_storage_owner')
        conn.execute('grant select on sli_plugin_file_audit.observations to adlog_storage_owner')
        conn.execute('drop table public.sli_agent_packet_inbox,public.sli_agent_receipts')
        conn.execute('set role adlog_storage_owner')
        source = migration_source(157, 'agent_packets')
        conn.execute(source[source.index('create table sli_agent_receipts'):
                            source.index('revoke all on sli_agent_module_bindings')])
        conn.execute('reset role')
        conn.execute(migration_source(263, 'native_source_lookup_index'))
        conn.execute("insert into schema_migrations values(264,'file_audit_acl_bridge'),(265,'file_acl_semantic_bridge')")
    return defaults_pg


def apply_if_present(conn):
    # Leaves a real database without the path for the pre-implementation RED.
    if MIGRATION.exists():
        conn.execute(MIGRATION.read_text('utf-8'))


def function_state(conn):
    return conn.execute('''select oid,proowner,proacl,proconfig,prosecdef,pg_get_functiondef(oid)
        from pg_proc where oid='public.default_detection_sources()'::regprocedure''').fetchone()


def authority_state(conn):
    return conn.execute('''select c.oid,c.relowner,c.relacl,c.relrowsecurity,c.relforcerowsecurity
        from pg_class c join pg_namespace n on n.oid=c.relnamespace
        where (n.nspname='sli_plugin_file_audit' and c.relname='observations')
           or (n.nspname='public' and c.relname in
              ('sli_agent_receipts','sli_agent_packet_inbox','finding_evidence_source_bindings'))
        order by c.oid''').fetchall()


def index_state(conn):
    return conn.execute('''select am.amname,i.indisunique,i.indisvalid,i.indisready,
        i.indnkeyatts,i.indnatts,pg_get_expr(i.indpred,i.indrelid),
        pg_get_expr(i.indexprs,i.indrelid),c.relowner=t.relowner,
        pg_get_indexdef(c.oid),pg_get_userbyid(c.relowner)
        from pg_index i join pg_class c on c.oid=i.indexrelid
        join pg_class t on t.oid=i.indrelid join pg_am am on am.oid=c.relam
        where c.oid=to_regclass('sli_plugin_file_audit.file_audit_source_lookup_index')''').fetchone()


def plan_nodes(plan):
    nodes = [plan[0]['Plan']]
    while nodes:
        node = nodes.pop()
        yield node
        nodes.extend(node.get('Plans', []))


def plan_evidence(plan):
    keys = ('Node Type', 'Index Name', 'Index Cond', 'Plan Rows', 'Startup Cost', 'Total Cost')
    return [{key: node[key] for key in keys if key in node} for node in plan_nodes(plan)]


def observe(conn, n, *, root='selected-root', revision=2, source='selected-source',
            generation='generation-2', agent=AGENT):
    conn.execute('''insert into sli_plugin_file_audit.observations
        (evidence_key,agent_id,source_instance_id,collection_scope_id,channel,provider,generation,
         record_id,event_id,event_version,observed_at,policy_revision,core_evidence_ref,payload_sha256)
        values(%s,%s,%s,%s,'Security','Microsoft-Windows-Security-Auditing',%s,%s,4663,0,
            '2026-01-01T00:00:00Z',%s,'synthetic-core',repeat('b',64))''',
        (f'{n:064x}', agent, source, root, generation, n, revision))


def receipt(conn, n, *, source='selected-source', generation='generation-2',
            imported=True, mismatched=False):
    packet = str(uuid4())
    envelope = {'source_instance_id': source, 'generation': generation}
    conn.execute('''insert into public.sli_agent_receipts
        (agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
        values(%s,%s,%s,%s,repeat('a',64),%s::jsonb,'{"status":"committed"}')''',
        (AGENT, MODULE, n, packet, json.dumps(envelope)))
    conn.execute('''insert into public.sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
        values(%s,%s::jsonb,'{"contract":"sli.collection-packet.v1"}','[]',%s)''',
        (packet, json.dumps(envelope | ({'mismatched': True} if mismatched else {})),
         '2026-01-01T00:00:00Z' if imported else None))


def full_file_select():
    source = migration_source(263, 'native_source_lookup_index')
    # Owner projection of the unchanged SELECT, using the actual worker's
    # captured identity. This is not the nested PL/pgSQL execution plan.
    return source[source.index('select distinct login,session_user,installation,'):
                  source.index('    on conflict do nothing;', source.index('select distinct login,'))].replace(
        'login', '%s::oid').replace('session_user', '%s::name').replace('installation,', '%s::uuid,')

@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_combined_lookup_catalog_and_natural_plan(lookup_pg):
    import psycopg

    with psycopg.connect(lookup_pg, autocommit=True) as conn:
        before_function, before_authority = function_state(conn), authority_state(conn)
        conn.execute('''insert into public.sli_agents values(%s,'active','[]'),(%s,'active','[]')''',
                     (AGENT, OTHER_AGENT))
        # 2048 rows, one selected triple. Same-agent history defeats its old PK prefix.
        for n in range(1, 2049):
            observe(conn, n, root='selected-root' if n == 2048 else f'irrelevant-{n % 127}',
                    revision=2 if n == 2048 else 1, source=f'synthetic-{n % 31}')
        conn.execute('analyze sli_plugin_file_audit.observations')
        before = conn.execute('explain(format json) ' + LOOKUP, (AGENT, 'selected-root', 2)).fetchone()[0]
        assert index_state(conn) is None
        assert all(node.get('Index Name') != INDEX for node in plan_nodes(before))
        apply_if_present(conn)
        state = index_state(conn)
        assert state is not None, 'missing combined agent/root/revision lookup index'
        assert state[:9] == ('btree', False, True, True, 3, 3, None, None, True)
        assert state[9].endswith('USING btree (agent_id, collection_scope_id, policy_revision)')
        assert state[10] == 'adlog_file_audit_owner'
        assert function_state(conn) == before_function
        assert authority_state(conn) == before_authority
        after = conn.execute('explain(format json) ' + LOOKUP, (AGENT, 'selected-root', 2)).fetchone()[0]
        chosen = [node for node in plan_nodes(after) if node.get('Index Name') == INDEX]
        assert len(chosen) == 1
        assert all(key in chosen[0]['Index Cond'] for key in ('agent_id', 'collection_scope_id', 'policy_revision'))
        assert conn.execute(LOOKUP, (AGENT, 'absent-root', 2)).fetchall() == []
        print('lookup_plan_evidence=' + json.dumps({'before': plan_evidence(before), 'after': plan_evidence(after)}, sort_keys=True))


def enumerate_sources(conn):
    return sorted((row[0] for row in conn.execute('select source from public.default_detection_sources()')),
                  key=lambda row: json.dumps(row, sort_keys=True))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize('disabled', [False, True])
def test_physical_worker_login_exact_sources_unchanged(lookup_pg, request, disabled):
    import psycopg

    # Reuses the existing physical non-superuser LOGIN fixture; no impersonation.
    worker_dsn = request.getfixturevalue('postgres_semantic_worker_dsn')
    with psycopg.connect(lookup_pg, autocommit=True) as admin:
        roots = ['selected-root', 'pending-root', 'mismatch-root', 'old-revision-root', 'absent-root']
        config = {'policy_revision': '2', 'roots': [{'collection_scope_id': root} for root in roots]}
        admin.execute("insert into public.sli_agents values(%s,'active',%s::jsonb)",
                      (AGENT, json.dumps([{'module_id': MODULE, 'enabled': not disabled, 'config': config}])))
        observe(admin, 1)
        observe(admin, 2, root='pending-root', source='pending-source')
        observe(admin, 3, root='mismatch-root', source='mismatch-source')
        observe(admin, 4, root='old-revision-root', revision=1)
        observe(admin, 5, root='removed-root', source='retained-source', generation='generation-1')
        receipt(admin, 1)
        receipt(admin, 2, source='pending-source', imported=False)
        receipt(admin, 3, source='mismatch-source', mismatched=True)
        # An eligible file witness older than the most recent 128 receipts remains reachable.
        for n in range(4, 134):
            receipt(admin, n, source='unrelated-source', generation='generation-3')
        before_function, before_authority = function_state(admin), authority_state(admin)
        with psycopg.connect(worker_dsn, autocommit=True) as worker:
            principal = worker.execute('''select session_user,current_user,oid,rolsuper,rolbypassrls
                from pg_roles where rolname=session_user''').fetchone()
            assert principal[0] == principal[1] and principal[3:] == (False, False)
            assert not worker.execute("select pg_has_role(session_user,'adlog_storage_owner','MEMBER')").fetchone()[0]
            worker.execute('set role adlog_semantic_worker')
            assert worker.execute('select session_user,current_user').fetchone() == (principal[0], 'adlog_semantic_worker')
            # Retained old generation is deliberately returned for a still-configured file root.
            installation = admin.execute('select installation_id from semantic_default_installation').fetchone()[0]
            for root in ('selected-root', 'removed-root'):
                admin.execute('''insert into public.finding_evidence_source_bindings
                    (principal_oid,principal_name,installation_id,plugin_id,source_instance_id,
                     source_generation,collection_scope_id,storage_kind,agent_id)
                    values(%s,%s,%s,%s,'retained-source','generation-1',%s,'file_audit_observation',%s)''',
                    (principal[2], principal[0], installation, MODULE, root, AGENT))
            # Roll back each enumeration's binding effects; same caller and pre-state before/after.
            with worker.transaction(force_rollback=True):
                before = enumerate_sources(worker)
                for _ in range(6):
                    assert enumerate_sources(worker) == before
            projection = (principal[2], principal[0], installation, principal[2], principal[0])
            admin.execute('set role adlog_storage_owner')
            before_plan = admin.execute('explain(format json) ' + full_file_select(), projection).fetchone()[0]
            admin.execute('reset role')
            apply_if_present(admin)
            assert index_state(admin) is not None, 'missing combined agent/root/revision lookup index'
            admin.execute('set role adlog_storage_owner')
            after_plan = admin.execute('explain(format json) ' + full_file_select(), projection).fetchone()[0]
            admin.execute('reset role')
            with worker.transaction(force_rollback=True):
                after = enumerate_sources(worker)
                for _ in range(6):
                    assert enumerate_sources(worker) == after
            assert after == before
            expected = [] if disabled else [('retained-source', 'generation-1', 'selected-root'),
                                             ('selected-source', 'generation-2', 'selected-root')]
            assert sorted((row['scope']['source_instance_id'], row['scope']['source_generation'],
                           row['scope']['collection_scope_id']) for row in after) == expected
            assert all(row['agent_id'] == AGENT and row['config'] == config for row in after)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute('select * from sli_plugin_file_audit.observations')
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute('select * from public.finding_evidence_source_bindings')
        assert function_state(admin) == before_function
        assert authority_state(admin) == before_authority
        assert admin.execute('select count(*) from finding_evidence_source_bindings').fetchone() == (2,)
        print('file_select_plan_evidence=' + json.dumps({'before': plan_evidence(before_plan), 'after': plan_evidence(after_plan)}, sort_keys=True))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize('guard', ['wrong_predecessor', 'occupied_version', 'not_owner_member'])
def test_guards_leave_catalog_function_and_ledger_unchanged(lookup_pg, guard):
    import psycopg
    from psycopg import sql

    assert MIGRATION.exists()
    with psycopg.connect(lookup_pg, autocommit=True) as conn:
        if guard == 'wrong_predecessor':
            conn.execute("update schema_migrations set name='wrong' where version=265")
        elif guard == 'occupied_version':
            conn.execute("insert into schema_migrations values(267,'occupied')")
        before = function_state(conn), authority_state(conn)
        ledger = conn.execute('select * from schema_migrations order by version').fetchall()
        login = 'sli_test_no_owner_' + uuid4().hex
        if guard == 'not_owner_member':
            conn.execute(sql.SQL('create role {} login').format(sql.Identifier(login)))
            conn.execute(sql.SQL('grant select on public.schema_migrations to {}').format(sql.Identifier(login)))
            conn.execute(sql.SQL('set session authorization {}').format(sql.Identifier(login)))
        try:
            with pytest.raises(psycopg.errors.RaiseException, match='migration 266 prerequisites failed'):
                conn.execute(MIGRATION.read_text('utf-8'))
            conn.execute('rollback')
        finally:
            conn.execute('reset session authorization; reset role')
            if guard == 'not_owner_member':
                conn.execute(sql.SQL('drop owned by {}').format(sql.Identifier(login)))
                conn.execute(sql.SQL('drop role {}').format(sql.Identifier(login)))
        assert (function_state(conn), authority_state(conn)) == before
        assert conn.execute('select * from schema_migrations order by version').fetchall() == ledger
        assert index_state(conn) is None


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_migration_ledger_and_repeat_are_atomic(lookup_pg):
    import psycopg

    assert MIGRATION.exists()
    with psycopg.connect(lookup_pg, autocommit=True) as conn:
        conn.execute(MIGRATION.read_text('utf-8'))
        assert conn.execute('select name from schema_migrations where version=266').fetchone() == ('file_audit_source_lookup_index',)
        before = index_state(conn), function_state(conn), authority_state(conn)
        with pytest.raises(psycopg.errors.RaiseException, match='migration 266 prerequisites failed'):
            conn.execute(MIGRATION.read_text('utf-8'))
        conn.execute('rollback')
        assert (index_state(conn), function_state(conn), authority_state(conn)) == before


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_exact_index_after_actual_265_migration(native_pg):
    """265 itself executes here; unrelated predecessor tables remain reduced."""
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as conn:
        assert conn.execute('select name from schema_migrations where version=265').fetchone() == ('file_acl_semantic_bridge',)
        conn.execute('set role adlog_file_audit_owner')
        observation_ddl(conn)
        conn.execute('reset role')
        before = conn.execute("select oid,proowner,proacl,proconfig,pg_get_functiondef(oid) from pg_proc where proname='file_acl_dacl_mask_v265' order by oid").fetchall()
        conn.execute(MIGRATION.read_text('utf-8'))
        assert index_state(conn)[:9] == ('btree', False, True, True, 3, 3, None, None, True)
        assert index_state(conn)[10] == 'adlog_file_audit_owner'
        assert conn.execute("select oid,proowner,proacl,proconfig,pg_get_functiondef(oid) from pg_proc where proname='file_acl_dacl_mask_v265' order by oid").fetchall() == before
