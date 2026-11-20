#!/usr/bin/env python3
"""Bounded actual244 reader/current264 verifier profile, disposable PG only.
Narrow source extractions, not a full bootstrap. No admission/runtime redesign.
"""
import hashlib
import json
import os
import statistics
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from server.sli.semantic.account_decoy_runtime import read_events
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = 'sli.windows.ad-dc'
SOURCE = 'synthetic-ad-source'
GENERATION = 'synthetic-ad-generation'
INSTALLATION = '00000000-0000-4000-8000-000000000099'
AGENT = '00000000-0000-4000-8000-000000000001'
CHECKPOINT = 'c' * 64
SHA = 'a' * 64
FUNCTIONS = (
    'public.finding_evidence_scope_allowed(uuid,text,text,text,text,text)',
    'public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)',
    'public.read_account_decoy_events(uuid,text,text,text,text,uuid)',
)
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def source(name):
    return (ROOT / 'config/postgres_migrations' / name).read_text('utf-8-sig')


def fragment(text, start, end):
    return text[text.index(start):text.index(end, text.index(start))]


def function(text, marker):
    return fragment(text, marker, '$$;') + '$$;'


@pytest.fixture
def ad_pg(isolated_postgres_integration_database):
    import psycopg
    from psycopg import sql
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('disposable PostgreSQL not configured')
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert_disposable_database(admin)
        for role in ('adlog_storage_owner', 'adlog_semantic_worker', 'adlog_user'):
            if not admin.execute('select 1 from pg_roles where rolname=%s', (role,)).fetchone():
                admin.execute(sql.SQL('create role {} nologin').format(sql.Identifier(role)))
        admin.execute('grant usage,create on schema public to adlog_storage_owner')
        admin.execute(sql.SQL("alter database {} set track_functions='all'").format(sql.Identifier(admin.info.dbname)))
        admin.execute('set role adlog_storage_owner')
        # Reduced unrelated parents/core columns; all columns read by244/264 exist.
        admin.execute('''create table schema_migrations(version integer primary key,name text);
          create table domains(id bigint primary key,fqdn text,netbios_name text);
          create table observed_entities(id bigint primary key);
          create table semantic_risk_policies(policy_id text,policy_version integer,primary key(policy_id,policy_version));
          create table sli_agents(id uuid primary key);
          create table raw_log_files(id bigint primary key,file_path text);
          create table events_v2_core(id bigint primary key,raw_log_file_id bigint references raw_log_files(id),
            log_source_id bigint not null,normalized_hash bytea not null check(octet_length(normalized_hash)=32),
            event_id integer not null,domain_id bigint references domains(id),time_created_utc timestamptz not null);''')
        governance = source('153_semantic_governance.sql')
        admin.execute(fragment(governance, 'create table semantic_policy_admission', '-- Empty overrides'))
        admin.execute(function(governance, 'create function semantic_policy_mode_v160'))
        admin.execute('''revoke all on semantic_policy_admission from public,adlog_user,adlog_semantic_worker;
          grant select on semantic_policy_admission to adlog_semantic_worker;
          revoke all on function semantic_policy_mode_v160(text,integer,text) from public;
          grant execute on function semantic_policy_mode_v160(text,integer,text) to adlog_semantic_worker''')
        native = source('157_agent_packets.sql')
        admin.execute(fragment(native, 'create table sli_agent_receipts', 'revoke all on sli_agent_module_bindings'))
        # Actual157 grants do not grant native reads to semantic worker.
        admin.execute('revoke all on sli_agent_receipts,sli_agent_packet_inbox from public,adlog_semantic_worker')
        refs = source('219_finding_evidence_refs.sql')
        admin.execute(fragment(refs, 'create table public.finding_evidence_source_bindings', 'create function public.finding_evidence_scope_allowed'))
        admin.execute(function(refs, 'create function public.finding_evidence_scope_allowed'))
        admin.execute('revoke all on function public.finding_evidence_scope_allowed(uuid,text,text,text,text,text) from public')
        admin.execute('grant execute on function public.finding_evidence_scope_allowed(uuid,text,text,text,text,text) to adlog_semantic_worker')
        context = source('017_ad_context_foundation.sql')
        admin.execute(fragment(context, 'create table if not exists ad_context_runs', 'create table if not exists ad_context_sections'))
        admin.execute(fragment(context, 'create table if not exists ad_context_entity_versions', 'create table if not exists ad_context_relation_versions'))
        normal = source('022_semantic_processing_foundation.sql')
        admin.execute(fragment(normal, 'create table if not exists normalized_events', '-- A canonical action'))
        identity = source('138_normalized_event_versioned_identity.sql')
        admin.execute(fragment(identity, 'alter table public.normalized_events', 'do $$'))
        # Actual150 dynamic widening entry, reproduced only for this retained column.
        assert "('normalized_events', 'source_event_id', 'bigint')" in source('150_storage_v2_event_bigint.sql')
        admin.execute('alter table normalized_events alter column source_event_id type bigint')
        contract = source('025_semantic_persistence_contract.sql')
        admin.execute(fragment(contract, 'alter table normalized_events', 'update normalized_events'))
        admin.execute(fragment(contract, 'alter table normalized_events\n    alter column', 'do $$'))
        admin.execute('create index idx_normalized_events_source on normalized_events(source_event_id,normalized_at desc)')
        admin.execute('create index idx_normalized_events_semantic_time on normalized_events(semantic_type,occurred_at_utc desc,normalized_event_id)')
        registry = source('243_decoy_registry.sql')
        admin.execute(fragment(registry, 'create table public.decoy_label_versions', 'create function public.guard_decoy_label_interval'))
        # Distinct directory owner: require the exact244 column-level rights.
        admin.execute('reset role')
        for table in ('domains', 'ad_context_runs', 'ad_context_entity_versions'):
            admin.execute('alter table '+table+' owner to adlog_user')
        reader = source('244_account_decoy.sql')
        admin.execute(fragment(reader, 'grant select(id,fqdn,netbios_name)', 'set local role adlog_storage_owner;'))
        admin.execute('set role adlog_storage_owner')
        admin.execute(fragment(reader, 'create table public.semantic_account_decoy_checks', '-- All returned events'))
        admin.execute(fragment(reader, 'create function public.read_account_decoy_events', '-- Keep the shared atomic outbox'))
        current = source('264_file_audit_acl_bridge.sql')
        admin.execute(fragment(current, 'create or replace function public.resolve_finding_evidence_ref', 'insert into public.schema_migrations'))
        # Actual268 entire migration against explicit unrelated predecessor marker.
        admin.execute("insert into schema_migrations values(267,'file_audit_discovery_join')")
        admin.execute('reset role')
        admin.execute(source('268_agent_packet_path_lookup_index.sql'))
        admin.execute('set role adlog_storage_owner')
        # Actual263 index statement; discovery body is not invoked by this profile.
        admin.execute(fragment(source('263_native_source_lookup_index.sql'), 'create index events_v2_core_raw_packet_lookup', 'create or replace function'))
        admin.execute('reset role')
    return dsn


def catalog(conn):
    expected_sources = (
        function(source('219_finding_evidence_refs.sql'), 'create function public.finding_evidence_scope_allowed'),
        function(source('264_file_audit_acl_bridge.sql'), 'create or replace function public.resolve_finding_evidence_ref'),
        function(source('244_account_decoy.sql'), 'create function public.read_account_decoy_events'),
    )
    result = []
    for signature, definition in zip(FUNCTIONS, expected_sources, strict=True):
        row = conn.execute('''select pg_get_userbyid(proowner),proacl::text,prosecdef,provolatile,
          proconfig,pronargdefaults,prosrc from pg_proc where oid=%s::regprocedure''', (signature,)).fetchone()
        assert row[6] == definition.split('$$', 2)[1]
        assert row[0] == 'adlog_storage_owner' and row[2:4] == (True, 's')
        assert row[4] == ['search_path=pg_catalog, pg_temp'] and row[5] == 0
        result.append({'signature': signature, 'owner': row[0], 'acl': row[1], 'security_definer': row[2],
                           'volatility': row[3], 'config': row[4], 'defaults': row[5],
                           'prosrc_sha256': hashlib.sha256(row[6].encode()).hexdigest()})
    indexes = conn.execute('''select c.relname,i.indisvalid,i.indisready,pg_get_indexdef(c.oid)
      from pg_index i join pg_class c on c.oid=i.indexrelid
      where i.indrelid in ('normalized_events'::regclass,'events_v2_core'::regclass,
        'sli_agent_packet_inbox'::regclass,'sli_agent_receipts'::regclass,
        'finding_evidence_source_bindings'::regclass,'decoy_label_versions'::regclass)
      order by c.relname''').fetchall()
    assert any(r[0] == 'sli_agent_inbox_packet_path_index' and r[1:3] == (True, True) for r in indexes)
    tables = conn.execute('''select relname,pg_get_userbyid(relowner),relacl::text,relrowsecurity,relforcerowsecurity
      from pg_class where oid in ('events_v2_core'::regclass,'raw_log_files'::regclass,
        'sli_agent_receipts'::regclass,'sli_agent_packet_inbox'::regclass,
        'semantic_account_decoy_checks'::regclass,'finding_evidence_source_bindings'::regclass,
        'domains'::regclass,'ad_context_runs'::regclass,'ad_context_entity_versions'::regclass) order by relname''').fetchall()
    return {'functions': result, 'indexes': indexes, 'tables': tables}


def seed(conn, count):
    from psycopg.types.json import Jsonb
    conn.execute("insert into domains values(1,'synthetic.invalid','SYNTHETIC')")
    conn.execute('insert into observed_entities values(1)')
    conn.execute('insert into sli_agents values(%s)', (AGENT,))
    conn.execute('''insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,
      observed_at_utc,bundle_sha256,status) values(%s,'synthetic','1',1,'full','2026-01-01',decode(%s,'hex'),'completed')''', (AGENT, SHA))
    conn.execute('''insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,
      last_observed_at_utc,content_sha256,attributes_json,source_run_id)
      values(1,'directory_accounts','2025-01-01','2026-01-01',decode(%s,'hex'),
      '{"identity":{"kind":"ad_user","object_sid":"S-1-5-21-1","object_guid":"synthetic-guid"}}',%s)''', (SHA, AGENT))
    conn.execute('''insert into decoy_label_versions values(%s,1,'account',
      '{"domain_id":1,"entity_id":1,"sid":"S-1-5-21-1","guid":"synthetic-guid"}',
      'synthetic-owner','profile',true,'2025-01-01',null,'session',1,'{"state":"ready"}',
      'sli.ad',null,null,1,'ad-domain:1')''', (INSTALLATION,))
    for n in range(1, count + 1):
        local = count == 8 or n <= 128
        packet = UUID(int=n)
        envelope = Jsonb({'agent_id': AGENT,'module_id': PLUGIN,'source_instance_id': SOURCE if local else 'foreign-source','generation': GENERATION})
        conn.execute('''insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
          values(%s,%s,%s,%s,%s,%s,'{"status":"committed"}')''', (AGENT,PLUGIN,n,packet,SHA,envelope))
        conn.execute('''insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
          values(%s,%s,'{"contract":"sli.collection-packet.v1"}','[]',now())''', (packet,envelope))
        conn.execute('insert into raw_log_files values(%s,%s)', (n,'agent-packet:'+str(packet)))
        conn.execute("insert into events_v2_core values(%s,%s,7,decode(%s,'hex'),4625,1,'2026-01-01')", (n,n,SHA))
        conn.execute('''insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,
          normalizer_id,normalizer_version,processing_status,normalized_at,source_event_sha256,semantic_sha256,
          semantic_type,occurred_at_utc,source_ingested_at,roles_json)
          values(%s,%s,1,'windows.named-eventdata','1','normalized','2026-01-02'::timestamptz+%s*interval '1 millisecond',
          decode(%s,'hex'),decode(%s,'hex'),'authentication.failed','2026-01-01','2026-01-01','{"actor":"sid:S-1-5-21-1"}')''',
          (UUID(int=n),n,n,SHA,SHA))
    for table in ('normalized_events','events_v2_core','raw_log_files','sli_agent_receipts','sli_agent_packet_inbox','decoy_label_versions','ad_context_entity_versions'):
        conn.execute('analyze '+table)


def stats(observer, worker):
    worker.execute('select pg_stat_force_next_flush()')
    observer.execute('select pg_stat_clear_snapshot()')
    return {r[0]:{'calls': r[1],'total_ms': r[2],'self_ms': r[3]} for r in observer.execute(
        "select funcname,calls,total_time,self_time from pg_stat_user_functions where funcname in ('read_account_decoy_events','resolve_finding_evidence_ref','finding_evidence_scope_allowed')").fetchall()}


def measure(observer, worker, rule, expected, *, exact=False, repeats=1):
    before = stats(observer,worker)
    times = []
    for _ in range(repeats):
        started=time.perf_counter()
        with worker.cursor() as cur:
            rows=read_events(cur,rule,normalized_event_id=str(UUID(int=1)) if exact else None)
        times.append((time.perf_counter()-started)*1000)
        assert len(rows) == expected
    after=stats(observer,worker)
    delta={k:{key:v[key]-before.get(k,{}).get(key,0) for key in v} for k,v in after.items()}
    return {'ms': times,'stats': delta,'returned': expected}



def inner_plan(conn, *, native):
    """Admin diagnostic only: exact264 core EXISTS, no reader/worker bypass."""
    from psycopg import sql
    current = source('264_file_audit_acl_bridge.sql')
    start = current.index('return exists(select 1 from public.events_v2_core e', current.index("elsif p_kind='core_event' then"))
    query = current[start:current.index(');', start)+2].replace('return exists', 'select exists', 1)
    values = {'p_native::bigint': native, 'b.log_source_id': 7, 'p_sha256': SHA,
              'p_plugin': PLUGIN, 'b.agent_id::text': AGENT, 'p_source': SOURCE, 'p_generation': GENERATION}
    for key, value in values.items():
        query = query.replace(key, sql.Literal(value).as_string(conn))
    plan = conn.execute('explain(analyze,buffers,format json,timing off) '+query).fetchone()[0][0]
    queue = [plan['Plan']]
    nodes = []
    keys = ('Node Type', 'Relation Name', 'Index Name', 'Actual Rows', 'Actual Loops',
            'Rows Removed by Filter', 'Shared Hit Blocks', 'Shared Read Blocks')
    while queue:
        node = queue.pop()
        nodes.append({key:node[key] for key in keys if key in node})
        queue.extend(node.get('Plans', []))
    return {'authority': 'admin diagnostic, literal binding constants; not worker acceptance',
                'execution_ms': plan['Execution Time'], 'nodes': nodes}

def test_actual_public_reader_bounded_profile(ad_pg, request):
    import psycopg
    from psycopg.rows import dict_row
    worker_dsn=request.getfixturevalue('postgres_semantic_worker_dsn')
    result={'scope': 'synthetic disposable public reader baseline only', 'run_once_and_qw_admission': False, 'cases': {}}
    with psycopg.connect(ad_pg,autocommit=True) as admin, psycopg.connect(worker_dsn,autocommit=True,row_factory=dict_row) as worker:
        worker.execute('set role adlog_semantic_worker')  # Existing NOINHERIT physical LOGIN fixture.
        worker.execute("set statement_timeout='60s'")
        identity=worker.execute('''select session_user<>current_user as selected_semantic_role,
          current_user='adlog_semantic_worker' as semantic,not rolsuper and not rolbypassrls as bounded,
          not pg_has_role(session_user,'adlog_storage_owner','MEMBER') as nonowner
          from pg_roles where rolname=session_user''').fetchone()
        assert all(identity.values())
        result['principal_checks']=identity
        admin.execute('''insert into finding_evidence_source_bindings
          select oid,rolname,%s,%s,%s,%s,'','core_event',7,null,%s from pg_roles where rolname=%s''',
          (INSTALLATION,PLUGIN,SOURCE,GENERATION,AGENT,worker.info.user))
        result['catalog_before']=catalog(admin)
        for table in ('domains', 'ad_context_runs', 'ad_context_entity_versions'):
            assert admin.execute("select pg_get_userbyid(relowner)='adlog_user' from pg_class where oid=%s::regclass", (table,)).fetchone()[0]
            assert not admin.execute("select has_table_privilege('adlog_storage_owner',%s,'SELECT')", (table,)).fetchone()[0]
        assert worker.execute("select public.semantic_policy_mode_v160('synthetic-missing',1,'enabled') as mode").fetchone()['mode']=='enabled'
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.execute("insert into semantic_policy_admission values('synthetic-denied',1,true,'fixture',now())")
        for table in ('events_v2_core','raw_log_files','sli_agent_receipts','sli_agent_packet_inbox','finding_evidence_source_bindings'):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute('select * from '+table)
        rule=SimpleNamespace(scope=SimpleNamespace(installation_id=INSTALLATION,plugin_id=PLUGIN,
            source_instance_id=SOURCE,source_generation=GENERATION),checkpoint_key=CHECKPOINT)
        # Fixture reset only by admin; bindings/catalog remain unchanged.
        for count in (8,1024):
            seed(admin,count)
            expected=min(count,128)
            measure(admin,worker,rule,expected)
            control = measure(admin,worker,rule,1,exact=True)
            assert control['stats']['read_account_decoy_events']['calls'] == 1
            assert control['stats']['resolve_finding_evidence_ref']['calls'] == 1
            foreign=SimpleNamespace(scope=SimpleNamespace(**(vars(rule.scope)|{'source_instance_id':'unbound'})),checkpoint_key=CHECKPOINT)
            with pytest.raises(psycopg.errors.InsufficientPrivilege), worker.cursor() as cur:
                read_events(cur,foreign)
            admin.execute("update sli_agent_receipts set envelope=envelope||'{\"synthetic_mismatch\":true}'::jsonb where packet_id=%s", (UUID(int=1),))
            assert measure(admin,worker,rule,0,exact=True)['returned'] == 0
            admin.execute('update sli_agent_receipts set envelope=(select envelope from sli_agent_packet_inbox where packet_id=%s) where packet_id=%s', (UUID(int=1), UUID(int=1)))
            assert measure(admin,worker,rule,1,exact=True)['returned'] == 1
            admin.execute('update sli_agent_packet_inbox set imported_at=null where packet_id=%s',(UUID(int=1),))
            assert measure(admin,worker,rule,0,exact=True)['returned'] == 0
            admin.execute('update sli_agent_packet_inbox set imported_at=now() where packet_id=%s',(UUID(int=1),))
            assert measure(admin,worker,rule,1,exact=True)['returned'] == 1
            admin.execute("update events_v2_core set normalized_hash=decode(repeat('b',64),'hex') where id=1")
            assert measure(admin,worker,rule,0,exact=True)['returned'] == 0
            admin.execute("update events_v2_core set normalized_hash=decode(%s,'hex') where id=1",(SHA,))
            assert measure(admin,worker,rule,1,exact=True)['returned'] == 1
            case={'scan': [],'empty': []}
            scope_json=json.dumps(vars(rule.scope))
            for batch in range(5):
                # Alternate filled/empty states on identical fixed population.
                order=('scan','empty') if batch%2==0 else ('empty','scan')
                for state in order:
                    admin.execute('delete from semantic_account_decoy_checks')
                    if state=='empty':
                        admin.execute('''insert into semantic_account_decoy_checks
                          select %s,normalized_event_id,%s::jsonb,'no_match',now() from normalized_events
                          where source_event_id<=%s''',(CHECKPOINT,scope_json,expected))
                    case[state].append(measure(admin,worker,rule,expected if state=='scan' else 0,repeats=2))
            for state in ('scan','empty'):
                values=[v for batch in case[state] for v in batch['ms']]
                case[state+'_summary']={'median_ms': statistics.median(values),'min_ms': min(values),'max_ms': max(values)}
            if count == 1024:
                case['inner_plan_local'] = inner_plan(admin, native=1)
                case['inner_plan_foreign'] = inner_plan(admin, native=1024)
            result['cases'][str(count)]=case
            admin.execute('truncate semantic_account_decoy_checks,normalized_events,events_v2_core,raw_log_files,sli_agent_packet_inbox,sli_agent_receipts,ad_context_entity_versions,ad_context_runs,observed_entities,decoy_label_versions,domains,sli_agents cascade')
        assert catalog(admin)==result['catalog_before']
    print('AD_PROFILE_RESULT='+json.dumps(result,sort_keys=True,default=str))