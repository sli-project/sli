"""Exact264 verifier with real157 packet constraints on guarded PG.
Only relevant core/raw columns are reduced;265--267 ledger rows are markers.
No native verifier is replaced or stubbed by this index test.
"""
import json
from pathlib import Path

import pytest

from tests.migrations.test_file_audit_acl_bridge_migration264 import (
    AGENT, INSTALLATION, acl_pg as acl_pg,
)
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / 'config/postgres_migrations/268_agent_packet_path_lookup_index.sql'
INDEX = 'sli_agent_inbox_packet_path_index'
PLUGIN = 'sli.windows.ad-dc'
SOURCE = 'synthetic-core-source'
GENERATION = 'synthetic-core-generation'
PACKET = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
SHA = 'a' * 64
FUNCTION = 'public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)'


@pytest.fixture
def core_pg(acl_pg):
    import psycopg
    with psycopg.connect(acl_pg, autocommit=True) as conn:
        assert_disposable_database(conn)
        conn.execute('set role adlog_storage_owner')
        conn.execute('''create table public.raw_log_files(id bigint primary key,file_path text);
          create table public.events_v2_core(id bigint primary key,raw_log_file_id bigint references raw_log_files(id),
            log_source_id bigint not null,normalized_hash bytea not null check(octet_length(normalized_hash)=32));''')
        source = (ROOT / 'config/postgres_migrations/157_agent_packets.sql').read_text('utf-8')
        conn.execute(source[source.index('create table sli_agent_receipts'):source.index('revoke all on sli_agent_module_bindings')])
        conn.execute("insert into sli_agents values(%s,%s,'active','[]')", (AGENT, SOURCE))
        # Restore219's actual EXECUTE boundary omitted by acl_pg's earlier
        # placeholder declaration; the current264 body is unchanged.
        conn.execute('''revoke all on public.sli_agent_receipts,public.sli_agent_packet_inbox from public,adlog_user,adlog_semantic_worker;
          revoke all on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) from public;
          grant execute on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) to adlog_semantic_worker;
          insert into schema_migrations values(265,'file_acl_semantic_bridge'),
            (266,'file_audit_source_lookup_index'),(267,'file_audit_discovery_join');''')
        conn.execute('reset role')
        bind(conn, conn.execute('select session_user').fetchone()[0])
    return acl_pg


def bind(conn, login):
    conn.execute('''insert into finding_evidence_source_bindings
      (principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,
       collection_scope_id,storage_kind,log_source_id,agent_key,agent_id)
      select oid,rolname,%s,%s,%s,%s,'','core_event',7,null,%s from pg_roles where rolname=%s''',
      (INSTALLATION, PLUGIN, SOURCE, GENERATION, AGENT, login))


def seed(conn, number=1):
    packet = PACKET if number == 1 else f'aaaaaaaa-bbbb-4ccc-8ddd-{number:012x}'
    envelope = dict(agent_id=AGENT, module_id=PLUGIN, source_instance_id=SOURCE, generation=GENERATION)
    conn.execute('''insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
      values(%s,%s,%s,%s,repeat('a',64),%s::jsonb,'{"status":"committed"}')''',
      (AGENT, PLUGIN, number, packet, json.dumps(envelope)))
    conn.execute('''insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
      values(%s,%s::jsonb,'{"contract":"sli.collection-packet.v1"}','[]',now())''', (packet, json.dumps(envelope)))
    conn.execute('insert into raw_log_files values(%s,%s)', (number, 'agent-packet:' + packet))
    conn.execute("insert into events_v2_core values(%s,%s,7,decode(%s,'hex'))", (number, number, SHA))


def resolver(conn, *, native='1', sha=SHA, source=SOURCE, generation=GENERATION, plugin=PLUGIN, collection=''):
    return conn.execute('select public.resolve_finding_evidence_ref(%s,%s,%s,%s,%s,%s,%s,%s)',
        (INSTALLATION, plugin, source, generation, collection, 'core_event', native, sha)).fetchone()[0]


def apply_if_present(conn):
    if MIGRATION.exists():
        conn.execute(MIGRATION.read_text('utf-8'))


def authority(conn):
    return (
        conn.execute('''select oid,proowner,proacl::text,proconfig,prosecdef,pg_get_functiondef(oid)
          from pg_proc where oid=%s::regprocedure''', (FUNCTION,)).fetchone(),
        conn.execute('''select oid,relowner,relacl::text,relrowsecurity,relforcerowsecurity from pg_class
          where oid in ('public.events_v2_core'::regclass,'public.raw_log_files'::regclass,
            'public.sli_agent_receipts'::regclass,'public.sli_agent_packet_inbox'::regclass,
            'public.finding_evidence_source_bindings'::regclass) order by oid''').fetchall(),
        conn.execute('select roleid,member,grantor,admin_option from pg_auth_members order by roleid,member,grantor').fetchall(),
    )


def nodes(plan):
    pending = [plan[0]['Plan']]
    while pending:
        item = pending.pop()
        yield item
        pending.extend(item.get('Plans', []))


def prepare(conn):
    source = (ROOT / 'config/postgres_migrations/264_file_audit_acl_bridge.sql').read_text('utf-8')
    start = source.index('return exists(select 1 from public.events_v2_core e', source.index("elsif p_kind='core_event' then"))
    query = source[start:source.index(');', start) + 2].replace('return exists', 'select exists', 1)
    for old, new in {'p_native::bigint': '$1', 'b.log_source_id': '$2', 'p_sha256': '$3',
                     'p_plugin': '$4', 'b.agent_id::text': '$5::text', 'p_source': '$6', 'p_generation': '$7'}.items():
        query = query.replace(old, new)
    conn.execute('prepare fixture_core_lookup(bigint,bigint,text,text,uuid,text,text) as ' + query)


def plan(conn, mode='force_generic_plan'):
    from psycopg import sql
    with conn.transaction():
        assert mode in {'force_generic_plan', 'force_custom_plan'}
        conn.execute('set local plan_cache_mode=' + mode)
        return conn.execute(sql.SQL('explain(format json,analyze false) execute fixture_core_lookup({})').format(
            sql.SQL(',').join(map(sql.Literal, (1, 7, SHA, PLUGIN, AGENT, SOURCE, GENERATION))))).fetchone()[0]


def pad(conn):
    # Planner population only; no synthetic row count/estimate is an installed speed claim.
    conn.execute('''insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
      select %s,%s,n,md5('synthetic-packet-'||n)::uuid,repeat('b',64),
        jsonb_build_object('agent_id',%s::text,'module_id',%s::text,'source_instance_id','irrelevant-source','generation','irrelevant-generation'),
        '{"status":"committed"}'::jsonb from generate_series(2,4097) n''', (AGENT, PLUGIN, AGENT, PLUGIN))
    conn.execute('''insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
      select packet_id,envelope,'{"contract":"sli.collection-packet.v1"}'::jsonb,'[]'::jsonb,now()
      from sli_agent_receipts where sequence>1''')
    for table in ('events_v2_core', 'raw_log_files', 'sli_agent_receipts', 'sli_agent_packet_inbox'):
        conn.execute('analyze public.' + table)


pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def test_expression_path_catalog_and_natural_generic_plan(core_pg):
    import psycopg
    with psycopg.connect(core_pg, autocommit=True) as conn:
        seed(conn)
        assert resolver(conn) is True
        pad(conn)
        before_authority = authority(conn)
        prepare(conn)
        before = plan(conn)
        assert all(n.get('Index Name') != INDEX for n in nodes(before))
        apply_if_present(conn)
        after = plan(conn)
        chosen = [n for n in nodes(after) if n.get('Index Name') == INDEX]
        assert chosen, 'missing native inbox packet-path access path under the normal generic planner'
        custom = plan(conn, 'force_custom_plan')
        assert any(n.get('Index Name') == INDEX for n in nodes(custom))
        assert all(n.get('Relation Name') != 'sli_agent_receipts' or n.get('Node Type') != 'Seq Scan' for n in nodes(custom))
        assert all(n.get('Relation Name') != 'sli_agent_receipts' or n.get('Node Type') != 'Seq Scan' for n in nodes(after))
        assert any(n.get('Index Name') == 'sli_agent_receipts_packet_id_key' for n in nodes(after))
        assert authority(conn) == before_authority
        assert resolver(conn) is True
        state = conn.execute('''select am.amname,i.indisunique,i.indisvalid,i.indisready,i.indnkeyatts,i.indnatts,
          pg_get_expr(i.indpred,i.indrelid),pg_get_expr(i.indexprs,i.indrelid),c.relowner=t.relowner,
          pg_get_userbyid(c.relowner) from pg_index i join pg_class c on c.oid=i.indexrelid
          join pg_class t on t.oid=i.indrelid join pg_am am on am.oid=c.relam where c.oid=to_regclass(%s)''',
          ('public.' + INDEX,)).fetchone()
        assert state[:7] == ('btree', False, True, True, 1, 1, None)
        assert state[7] == "('agent-packet:'::text || (packet_id)::text)"
        assert state[8:] == (True, 'adlog_storage_owner')
        for function in ('pg_catalog.textcat(text,text)', 'pg_catalog.uuid_out(uuid)'):
            assert conn.execute('select provolatile from pg_proc where oid=%s::regprocedure', (function,)).fetchone()[0] == 'i'
        keys = ('Node Type', 'Relation Name', 'Index Name', 'Plan Rows', 'Total Cost')
        print('synthetic_plan_only=' + json.dumps({k: [{key: n[key] for key in keys if key in n} for n in nodes(p)]
              for k, p in [('before', before), ('after', after), ('custom', custom)]}, sort_keys=True))


@pytest.mark.parametrize('case', ['hash', 'log_source', 'unimported', 'envelope', 'module', 'agent', 'source', 'generation', 'missing_receipt', 'revoked_binding'])
def test_actual264_native_negative_equivalence(core_pg, case):
    import psycopg
    with psycopg.connect(core_pg, autocommit=True) as conn:
        seed(conn)
        assert resolver(conn) is True
        changes = {
            'hash': "update events_v2_core set normalized_hash=decode(repeat('b',64),'hex')",
            'log_source': 'update events_v2_core set log_source_id=8',
            'unimported': 'update sli_agent_packet_inbox set imported_at=null',
            'envelope': "update sli_agent_packet_inbox set envelope=envelope||'{\"mismatch\":true}'::jsonb",
            'module': "update sli_agent_receipts set module_id='sli.vpn-nps'",
            'agent': "update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{agent_id}','\"foreign-agent\"')",
            'source': "update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{source_instance_id}','\"foreign-source\"')",
            'generation': "update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{generation}','\"foreign-generation\"')",
            'missing_receipt': 'delete from sli_agent_packet_inbox;delete from sli_agent_receipts',
            'revoked_binding': 'delete from finding_evidence_source_bindings',
        }
        conn.execute(changes[case])
        if case in {'agent', 'source', 'generation'}:
            conn.execute('update sli_agent_receipts set envelope=(select envelope from sli_agent_packet_inbox)')
        assert resolver(conn) is False
        before = authority(conn)
        apply_if_present(conn)
        assert resolver(conn) is False
        assert authority(conn) == before


@pytest.mark.parametrize('path', [None, 'ordinary-file', 'agent-packet:', 'agent-packet:not-a-uuid',
    'agent-packet:' + PACKET.upper(), 'agent-packet:{' + PACKET + '}',
    'agent-packet:' + PACKET.replace('-', ''), 'agent-packet:' + PACKET + 'suffix'])
def test_malformed_paths_keep_exact_text_semantics(core_pg, path):
    import psycopg
    with psycopg.connect(core_pg, autocommit=True) as conn:
        seed(conn)
        conn.execute('update raw_log_files set file_path=%s', (path,))
        expected = resolver(conn)
        assert expected is False
        apply_if_present(conn)
        assert resolver(conn) is expected


def test_physical_worker_permissions_scope_and_post_index_write(core_pg, request):
    import psycopg
    worker_dsn = request.getfixturevalue('postgres_semantic_worker_dsn')
    with psycopg.connect(core_pg, autocommit=True) as admin, psycopg.connect(worker_dsn, autocommit=True) as worker:
        seed(admin)
        principal = worker.execute('select session_user').fetchone()[0]
        bind(admin, principal)
        worker.execute('set role adlog_semantic_worker')
        assert worker.execute("select pg_has_role(session_user,'adlog_storage_owner','MEMBER')").fetchone()[0] is False
        assert resolver(worker) is True
        before = authority(admin)
        apply_if_present(admin)
        assert resolver(worker) is True
        assert resolver(worker, source='foreign-source') is False
        assert resolver(worker, collection='foreign-root') is False
        for table in ('sli_agent_receipts', 'sli_agent_packet_inbox', 'events_v2_core', 'raw_log_files'):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute('select * from ' + table)
        seed(admin, 2)
        assert resolver(worker, native='2') is True
        worker.execute("select set_config('sli.fixture_principal','forged',false)")
        admin.execute('delete from finding_evidence_source_bindings where principal_name=%s', (principal,))
        assert resolver(worker) is False
        assert authority(admin) == before


@pytest.mark.parametrize('case', ['missing', 'wrong_name', 'occupied', 'future'])
def test_predecessor_and_unoccupied_version_guards(core_pg, case):
    import psycopg
    with psycopg.connect(core_pg, autocommit=True) as conn:
        if case == 'missing':
            conn.execute('delete from schema_migrations where version=267')
        if case == 'wrong_name':
            conn.execute("update schema_migrations set name='wrong' where version=267")
        if case in {'occupied', 'future'}:
            conn.execute("insert into schema_migrations values(%s,'occupied')", (268 if case == 'occupied' else 269,))
        with pytest.raises(psycopg.errors.RaiseException, match='migration 268 prerequisites failed'):
            conn.execute(MIGRATION.read_text('utf-8'))
        conn.execute('rollback')
        assert conn.execute('select to_regclass(%s)', ('public.' + INDEX,)).fetchone()[0] is None


def test_reapply_and_fault_rollback_are_atomic(core_pg):
    import psycopg
    source = MIGRATION.read_text('utf-8')
    with psycopg.connect(core_pg, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.DivisionByZero):
            conn.execute(source.replace('commit;', 'select 1/0;\ncommit;', 1))
        conn.execute('rollback')
        assert conn.execute('select to_regclass(%s)', ('public.' + INDEX,)).fetchone()[0] is None
        assert conn.execute('select count(*) from schema_migrations where version=268').fetchone()[0] == 0
        conn.execute(source)
        assert conn.execute("select name from schema_migrations where version=268").fetchone()[0] == 'agent_packet_path_lookup_index'
        with pytest.raises(psycopg.errors.RaiseException, match='migration 268 prerequisites failed'):
            conn.execute(source)
        conn.execute('rollback')


def test_physical_nonowner_cannot_apply_migration(core_pg, request):
    import psycopg
    worker_dsn = request.getfixturevalue('postgres_semantic_worker_dsn')
    with psycopg.connect(worker_dsn, autocommit=True) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match='schema_migrations'):
            worker.execute(MIGRATION.read_text('utf-8'))
        worker.execute('rollback')
        assert worker.execute('select to_regclass(%s)', ('public.' + INDEX,)).fetchone()[0] is None


def test_committed_status_and_exact_principal_oid_binding(core_pg, request):
    import psycopg
    worker_dsn = request.getfixturevalue('postgres_semantic_worker_dsn')
    with psycopg.connect(core_pg, autocommit=True) as admin, psycopg.connect(worker_dsn, autocommit=True) as worker:
        seed(admin)
        principal, oid = worker.execute('select session_user,oid from pg_roles where rolname=session_user').fetchone()
        bind(admin, principal)
        worker.execute('set role adlog_semantic_worker')
        assert resolver(worker) is True
        with pytest.raises(psycopg.errors.CheckViolation):
            admin.execute("update sli_agent_receipts set receipt='{\"status\":\"pending\"}'")
        assert resolver(worker) is True
        admin.execute("update finding_evidence_source_bindings set principal_oid=(select oid from pg_roles where rolname='adlog_user') where principal_name=%s", (principal,))
        assert resolver(worker) is False
        before = authority(admin)
        apply_if_present(admin)
        assert resolver(worker) is False
        admin.execute('update finding_evidence_source_bindings set principal_oid=%s where principal_name=%s', (oid, principal))
        assert resolver(worker) is True
        with pytest.raises(psycopg.errors.CheckViolation):
            admin.execute("update sli_agent_receipts set receipt='{\"status\":\"pending\"}'")
        assert authority(admin) == before
