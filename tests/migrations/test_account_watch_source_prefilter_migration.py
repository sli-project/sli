"""Actual253/current264 WATCH proof and whole271 on disposable PG.

Reuse guarded native fixture, not W02's fake resolver. Reduced core/directory
parents; actual249 registry/trigger,253 reader/checks,264 proof and270 upgrade.
Unrelated269 ledger marker explicitly stands in for ACL-only aggregation.
"""
import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from server.sli.semantic.account_watch_runtime import read_events
from tests.migrations import test_account_decoy_native_profile as base
from tests.migrations import test_account_decoy_prefilter_candidate as native
from tests.migrations.test_account_decoy_native_profile import ad_pg as ad_pg
from tests.migrations.test_account_decoy_prefilter_candidate import env as native_env

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT/'config/postgres_migrations/271_account_watch_source_prefilter.sql'
NAME = 'account_watch_source_prefilter'
READER = 'public.read_account_watch_events(uuid,text,text,text,text,uuid)'
RESOLVER = native.RESOLVER
FUNCTIONS = (*base.FUNCTIONS, READER)
GUID = '00000000-0000-4000-8000-000000000001'
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def baseline_sql():
    return base.function(base.source('253_account_watch.sql'),
                         'create function public.read_account_watch_events').replace(
                             'create function', 'create or replace function', 1)


def candidate_sql():
    return MIGRATION.read_text('utf-8-sig').split('$reader$')[1]


def proc(admin, signature):
    return admin.execute('select to_jsonb(p) from pg_proc p where oid=%s::regprocedure',
                         (signature,)).fetchone()[0]


def table_authority(row):
    # VACUUM/ANALYZE maintain these statistics and transaction horizons independently
    # of the migration. Keep every other catalog field (including unknown future
    # fields), so ACL, owner, RLS and DDL drift still fails the authority guard.
    # https://www.postgresql.org/docs/18/catalog-pg-class.html
    bookkeeping = {'relpages', 'reltuples', 'relallvisible', 'relallfrozen',
                   'relfrozenxid', 'relminmxid'}
    return {key: value for key, value in row.items() if key not in bookkeeping}


def authority(admin):
    return dict(functions={sig: proc(admin, sig) for sig in FUNCTIONS if sig != READER},
        tables=[(table_authority(row),) for (row,) in admin.execute('''select to_jsonb(c) from pg_class c where c.oid in
          ('watch_entry_versions'::regclass,'semantic_account_watch_checks'::regclass,
           'finding_evidence_source_bindings'::regclass,'events_v2_core'::regclass,
           'raw_log_files'::regclass,'sli_agent_packet_inbox'::regclass,'sli_agent_receipts'::regclass)
          order by c.oid''').fetchall()],
        column_acl=admin.execute('''select attrelid,attnum,attacl::text from pg_attribute
          where attrelid in ('watch_entry_versions'::regclass,
            'semantic_account_watch_checks'::regclass) order by attrelid,attnum''').fetchall(),
        policies=admin.execute('select to_jsonb(p) from pg_policy p order by oid').fetchall(),
        bindings=admin.execute('select * from finding_evidence_source_bindings').fetchall())


def state(admin):
    return dict(function=proc(admin, READER), authority=authority(admin),
        ledger=admin.execute('select version,name from schema_migrations order by version').fetchall())


@pytest.fixture
def env(native_env):
    env = native_env
    # Reuse synthetic packet population before widening the reduced core shape.
    base.seed(env.admin, 1024)
    env.admin.execute('set role adlog_storage_owner')
    try:
        foundation = base.source('009_storage_v2_foundation.sql')
        env.admin.execute(base.fragment(foundation, 'create table if not exists storage_v2_provider',
                                       'create table if not exists storage_v2_computer'))
        env.admin.execute('''alter table events_v2_core add column channel_id integer,
          add column provider_id integer, add column level integer default 0;
          insert into storage_v2_channel(id,value) values(1,'Security');
          insert into storage_v2_provider(id,value) values(1,'Microsoft-Windows-Security-Auditing');
          update events_v2_core set channel_id=1,provider_id=1;''')
        registry = base.source('249_watch_registry.sql')
        env.admin.execute(base.fragment(registry, 'create table public.watch_entry_versions', 'reset role;'))
        watch = base.source('253_account_watch.sql')
        env.admin.execute(base.fragment(watch, 'create table public.semantic_account_watch_checks',
                                       '-- Published priority only.'))
    finally:
        env.admin.execute('reset role')
    env.admin.execute('''update ad_context_entity_versions set attributes_json=
      jsonb_set(attributes_json,'{identity,object_guid}',to_jsonb(%s::text))''', (GUID,))
    env.admin.execute('''insert into watch_entry_versions(id,revision,identity,entity_id,
      collection_scope_id,owner,reason,active,active_from,expires_at,valid_from,actor_type,actor_id)
      values(%s,1,%s::jsonb,1,'ad-domain:1','synthetic-owner','fixture',true,
        '2025-01-01','2026-02-01','2025-01-01','session',1)''',
      (UUID(int=9000), json.dumps(dict(domain_id=1,entity_id=1,sid='S-1-5-21-1',guid=GUID))))
    env.admin.execute('''update normalized_events set roles_json=
      '{"actor":"sid:S-1-5-21-1","affected_entity":"guid:00000000-0000-4000-8000-000000000001",
        "session_principal":"sid:S-1-5-21-1"}'::jsonb''')
    # Real270 predecessor over the explicit unrelated269 ACL ledger marker.
    env.admin.execute("insert into schema_migrations values(269,'file_audit_canonical_aggregation')")
    env.admin.execute(base.source('270_account_decoy_source_prefilter.sql'))
    assert hashlib.sha256(proc(env.admin, READER)['prosrc'].encode()).hexdigest() == '908729a5c5eee1cae7efa4a193cf0f272fa89e882282030f98992b91e70900a9'
    env.watch_catalog = proc(env.admin, READER)
    env.watch_authority = authority(env.admin)
    try:
        yield env
    finally:
        env.admin.execute('rollback')
        native.install(env.admin, baseline_sql())
        assert proc(env.admin, READER) == env.watch_catalog
        assert authority(env.admin) == env.watch_authority
        native.install(env.admin, native.baseline_sql())


def stats(env):
    env.worker.execute('select pg_stat_force_next_flush()')
    env.admin.execute('select pg_stat_clear_snapshot()')
    return {sig: env.admin.execute('''select coalesce(s.calls,0) from pg_proc p
      left join pg_stat_user_functions s on s.funcid=p.oid where p.oid=%s::regprocedure''',
      (sig,)).fetchone()[0] for sig in (READER, RESOLVER)}


def read(env, normalized=None, rule=None):
    before = stats(env)
    with env.worker.cursor() as cur:
        rows = read_events(cur, rule or env.rule,
                           normalized_event_id=str(normalized) if normalized else None)
    after = stats(env)
    assert after[READER]-before[READER] == 1
    return rows, dict(rows=len(rows), resolver_calls=after[RESOLVER]-before[RESOLVER],
        output_sha256=hashlib.sha256(json.dumps(rows,sort_keys=True,default=str).encode()).hexdigest())


@contextmanager
def reader(env, variant):
    protected = authority(env.admin)
    definition = baseline_sql() if variant == 'baseline' else candidate_sql()
    native.install(env.admin, definition)
    current = proc(env.admin, READER)
    assert {k:v for k,v in current.items() if k != 'prosrc'} == {
        k:v for k,v in env.watch_catalog.items() if k != 'prosrc'}
    assert current['prosrc'] == definition.split('$$', 2)[1]
    assert authority(env.admin) == protected
    try:
        yield
    finally:
        native.install(env.admin, baseline_sql())


def paired(env, normalized=None):
    rows, records = {}, {}
    for variant in ('baseline','candidate'):
        with reader(env, variant):
            rows[variant], records[variant] = read(env, normalized)
    assert rows['baseline'] == rows['candidate']
    return rows['baseline'], records


def checkpoint(env, ids):
    # Actual253 RLS/INSERT privilege, through the bound physical worker.
    for normalized in ids:
        env.worker.execute('''insert into semantic_account_watch_checks
          values(%s,%s,%s::jsonb,'no_match',now()) on conflict do nothing''',
          (base.CHECKPOINT,normalized,json.dumps(vars(env.rule.scope))))


def test_source_prefilter_native_calls_output_and_whole271_catalog(env):
    before = state(env.admin)
    rows, baseline = read(env)
    exact, baseline_exact = read(env, UUID(int=1))
    checkpoint(env, [UUID(int=n) for n in range(1,129)])
    empty, baseline_empty = read(env)
    assert len(rows) == 128 and len(exact) == 1 and empty == []
    assert baseline['resolver_calls'] == 1024 and baseline_empty['resolver_calls'] == 1024
    env.admin.execute(MIGRATION.read_text('utf-8-sig'))
    env.admin.execute('delete from semantic_account_watch_checks')
    result, candidate = read(env)
    assert result == rows
    print('WATCH271_COUNTER_RESULT='+json.dumps(dict(scan_baseline=baseline,
        scan_candidate=candidate,empty_baseline=baseline_empty),sort_keys=True))
    assert candidate['resolver_calls'] == 128
    upgraded = state(env.admin)
    assert upgraded['ledger'] == before['ledger']+[(271,NAME)]
    assert upgraded['authority'] == before['authority']
    assert {k:v for k,v in upgraded['function'].items() if k != 'prosrc'} == {
        k:v for k,v in before['function'].items() if k != 'prosrc'}
    assert upgraded['function']['prosrc'] == candidate_sql().split('$$', 2)[1]
    candidate_exact, exact_stats = read(env, UUID(int=1))
    assert candidate_exact == exact and baseline_exact['resolver_calls'] == exact_stats['resolver_calls'] == 1
    checkpoint(env, [UUID(int=n) for n in range(1,129)])
    candidate_empty, empty_stats = read(env)
    assert candidate_empty == [] and empty_stats['resolver_calls'] == 0
    native.boundary(env.worker)
    import psycopg
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        env.worker.execute('select * from watch_entry_versions')
    print('WATCH271_APPLY_RESULT='+json.dumps(dict(scan_baseline=baseline,scan_candidate=candidate,
        exact_baseline=baseline_exact,exact_candidate=exact_stats,empty_baseline=baseline_empty,
        empty_candidate=empty_stats,body_sha256=hashlib.sha256(upgraded['function']['prosrc'].encode()).hexdigest(),
        complete_reader_catalog_except_body_preserved=True,protected_authority_unchanged=True,
        physical_login=env.identity,reader_oid=upgraded['function']['oid'],
        reader_acl=upgraded['function']['proacl'],reader_owner=upgraded['function']['proowner'],
        resolver_body_sha256=hashlib.sha256(proc(env.admin,RESOLVER)['prosrc'].encode()).hexdigest()),sort_keys=True,default=str))


@pytest.mark.parametrize('drift',['missing270','wrong270','duplicate271','higher272',
                                'body','acl','owner','search_path','security','volatility'])
def test_whole271_rejects_precursor_and_reader_drift_atomically(env, drift):
    import psycopg
    if drift == 'missing270':
        env.admin.execute('delete from schema_migrations where version=270')
    elif drift == 'wrong270':
        env.admin.execute("update schema_migrations set name='wrong' where version=270")
    elif drift in ('duplicate271','higher272'):
        env.admin.execute('insert into schema_migrations values(%s,%s)',
                          (271 if drift == 'duplicate271' else 272,'synthetic-existing'))
    elif drift == 'body':
        native.install(env.admin,baseline_sql().replace('begin\n','begin\n -- synthetic drift\n',1))
    elif drift == 'acl':
        env.admin.execute('grant execute on function '+READER+' to adlog_user')
    elif drift == 'owner':
        env.admin.execute('alter function '+READER+' owner to adlog_user')
    elif drift == 'search_path':
        env.admin.execute('alter function '+READER+' set search_path=public')
    elif drift == 'security':
        env.admin.execute('alter function '+READER+' security invoker')
    elif drift == 'volatility':
        env.admin.execute('alter function '+READER+' volatile')
    before = state(env.admin)
    try:
        with pytest.raises(psycopg.errors.RaiseException,match='migration 271 prerequisites failed'):
            env.admin.execute(MIGRATION.read_text('utf-8-sig'))
        env.admin.execute('rollback')
        assert state(env.admin) == before
        print('WATCH271_GUARD_RESULT='+json.dumps(dict(case=drift,atomic_rejection=True)))
    finally:
        env.admin.execute('rollback')
        if drift == 'owner':
            env.admin.execute('alter function '+READER+' owner to adlog_storage_owner')
        if drift == 'acl':
            env.admin.execute('revoke execute on function '+READER+' from adlog_user')
        native.install(env.admin,baseline_sql())


def test_whole271_denies_semantic_migrator_and_rolls_back_after_ddl_and_ledger(env):
    import psycopg
    before = state(env.admin)
    migration = MIGRATION.read_text('utf-8-sig')
    with pytest.raises(psycopg.errors.RaiseException,match='migration 271 prerequisites failed'):
        env.worker.execute(migration)
    env.worker.execute('rollback')
    assert state(env.admin) == before
    anchor = '\ncommit;\n'
    assert migration.count(anchor) == 1 and migration.endswith(anchor)
    body_hash = hashlib.sha256(candidate_sql().split('$$', 2)[1].encode()).hexdigest()
    fault = '''
do $postddl_fault$ begin
    if not exists(select 1 from pg_catalog.pg_proc p
        where p.oid=to_regprocedure('public.read_account_watch_events(uuid,text,text,text,text,uuid)')
          and encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='%s')
       or not exists(select 1 from public.schema_migrations
          where version=271 and name='account_watch_source_prefilter') then
        raise exception 'migration271_postddl_state_missing';
    end if;
    raise exception 'migration271_postddl_rollback_probe';
end $postddl_fault$;
''' % body_hash
    with pytest.raises(psycopg.errors.RaiseException) as error:
        env.admin.execute(migration.replace(anchor,fault+anchor,1))
    assert error.value.diag.message_primary == 'migration271_postddl_rollback_probe'
    env.admin.execute('rollback')
    assert state(env.admin) == before
    print('WATCH271_POSTDDL_RESULT='+json.dumps(dict(candidate_body_and_ledger_observed=True,
        error=error.value.diag.message_primary,full_reader_resolver_authority_ledger_restored=True)))


def test_native_proof_and_physical_binding_freshness(env):
    import psycopg
    initial, _ = paired(env,UUID(int=1))
    assert len(initial) == 1
    records = {}
    changes = (
        ('receipt',"update sli_agent_receipts set envelope=envelope||'{\"synthetic_mismatch\":true}'::jsonb where packet_id=%s",
         'update sli_agent_receipts set envelope=(select envelope from sli_agent_packet_inbox where packet_id=%s) where packet_id=%s'),
        ('import','update sli_agent_packet_inbox set imported_at=null where packet_id=%s',
         'update sli_agent_packet_inbox set imported_at=now() where packet_id=%s'),
        ('hash',"update events_v2_core set normalized_hash=decode(repeat('b',64),'hex') where id=1",
         "update events_v2_core set normalized_hash=decode(repeat('a',64),'hex') where id=1"),
    )
    for name,mutation,restore in changes:
        env.admin.execute(mutation,(UUID(int=1),) if '%s' in mutation else None)
        try:
            denied,records[name] = paired(env,UUID(int=1))
            assert denied == []
        finally:
            params = (UUID(int=1),)*(2 if name == 'receipt' else 1) if '%s' in restore else None
            env.admin.execute(restore,params)
        assert paired(env,UUID(int=1))[0] == initial
    for key,wrong in (('agent_id',str(UUID(int=999))),('source_instance_id','foreign-source'),
                      ('generation','foreign-generation')):
        original = env.admin.execute('select envelope from sli_agent_packet_inbox where packet_id=%s',
                                     (UUID(int=1),)).fetchone()[0]
        for table in ('sli_agent_packet_inbox','sli_agent_receipts'):
            env.admin.execute('update '+table+' set envelope=%s::jsonb where packet_id=%s',
                              (json.dumps(original | {key:wrong}),UUID(int=1)))
        try:
            denied,records[key] = paired(env,UUID(int=1))
            assert denied == []
        finally:
            for table in ('sli_agent_packet_inbox','sli_agent_receipts'):
                env.admin.execute('update '+table+' set envelope=%s::jsonb where packet_id=%s',
                                  (json.dumps(original),UUID(int=1)))
        assert paired(env,UUID(int=1))[0] == initial
    for column,value in (('principal_name','synthetic-missing-login'),('principal_oid',0),('log_source_id',8)):
        original = env.admin.execute('select '+column+' from finding_evidence_source_bindings').fetchone()[0]
        env.admin.execute('update finding_evidence_source_bindings set '+column+'=%s',(value,))
        try:
            for variant in ('baseline','candidate'):
                with reader(env,variant):
                    if column == 'log_source_id':
                        assert read(env,UUID(int=1))[0] == []
                    else:
                        with pytest.raises(psycopg.errors.InsufficientPrivilege):
                            read(env,UUID(int=1))
        finally:
            env.admin.execute('update finding_evidence_source_bindings set '+column+'=%s',(original,))
        assert paired(env,UUID(int=1))[0] == initial
    for field in ('source_instance_id','source_generation'):
        rule = SimpleNamespace(scope=SimpleNamespace(**(vars(env.rule.scope)|{field:'unbound'})),
                               checkpoint_key=base.CHECKPOINT)
        for variant in ('baseline','candidate'):
            with reader(env,variant),pytest.raises(psycopg.errors.InsufficientPrivilege):
                read(env,rule=rule)
    print('WATCH271_FRESHNESS_RESULT='+json.dumps(dict(cases=records,
        physical_oid_name_unbound_denials=True,all_exact_outputs_restored=True),sort_keys=True))


def test_late_valid_latest_uuid_checkpoint_and_exact_id(env):
    env.admin.execute("update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{source_instance_id}',to_jsonb('foreign-source'::text))")
    env.admin.execute("update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{source_instance_id}',to_jsonb(%s::text)) where packet_id in (%s,%s)",
                      (base.SOURCE,UUID(int=1023),UUID(int=1024)))
    env.admin.execute('update sli_agent_receipts r set envelope=i.envelope from sli_agent_packet_inbox i where i.packet_id=r.packet_id')
    env.admin.execute("update normalized_events set normalized_at='2026-01-03' where source_event_id in (1023,1024)")
    env.admin.execute('''insert into normalized_events(normalized_event_id,source_event_id,semantic_contract_version,
      normalizer_id,normalizer_version,processing_status,normalized_at,source_event_sha256,semantic_sha256,
      semantic_type,occurred_at_utc,source_ingested_at,roles_json)
      select %s,source_event_id,semantic_contract_version,normalizer_id,'2',processing_status,normalized_at,
      source_event_sha256,semantic_sha256,semantic_type,occurred_at_utc,source_ingested_at,roles_json
      from normalized_events where normalized_event_id=%s''',(UUID(int=2048),UUID(int=1024)))
    rows,records = paired(env)
    assert [r['normalized_event_id'] for r in rows] == [UUID(int=1023),UUID(int=2048)]
    checkpoint(env,[UUID(int=1024)])
    assert paired(env)[0] == rows
    checkpoint(env,[UUID(int=2048)])
    assert [r['normalized_event_id'] for r in paired(env)[0]] == [UUID(int=1023)]
    for normalized in (UUID(int=1024),UUID(int=2048)):
        assert len(paired(env,normalized)[0]) == 1
    checkpoint(env,[UUID(int=1023)])
    assert paired(env)[0] == []
    print('WATCH271_LATE_ORDER_RESULT='+json.dumps(records,sort_keys=True))


def test_watch_intervals_roles_no_match_event_item_and_dictionary_join_parity(env):
    # Preserve broad domain eligibility even when roles do not match a WATCH identity.
    env.admin.execute("update normalized_events set roles_json='{}' where normalized_event_id=%s",(UUID(int=2),))
    rows,_ = paired(env,UUID(int=1))
    assert {i['role'] for i in rows[0]['identities']} == {'actor','affected_entity','session_principal'}
    assert rows[0]['event_item']['channel'] == 'Security'
    assert rows[0]['event_item']['provider_name'] == 'Microsoft-Windows-Security-Auditing'
    no_match,_ = paired(env,UUID(int=2))
    assert len(no_match) == 1 and no_match[0]['identities'] == []
    checkpoint(env,[UUID(int=2)])
    assert paired(env,UUID(int=2))[0] == no_match
    # Close revision1 through the actual249 immutable interval trigger, add revision2.
    env.admin.execute("update watch_entry_versions set valid_to='2026-01-01'")
    env.admin.execute('''insert into watch_entry_versions
      select id,2,identity,entity_id,plugin_id,collection_scope_id,owner,reason,active,
        active_from,expires_at,'2026-01-01',null,actor_type,actor_id
      from watch_entry_versions where revision=1''')
    for timestamp,expected in (('2024-12-31 23:59:59+00',None),('2025-01-01',1),
                               ('2025-12-31 23:59:59+00',1),('2026-01-01',2),('2026-02-01',None)):
        env.admin.execute('update events_v2_core set time_created_utc=%s where id=1',(timestamp,))
        env.admin.execute('update normalized_events set occurred_at_utc=%s where normalized_event_id=%s',
                          (timestamp,UUID(int=1)))
        selected,_ = paired(env,UUID(int=1))
        if expected is None:
            assert selected == []
        else:
            assert [entry['revision'] for entry in selected[0]['entries']] == [expected]
    # A valid history revision can still be before its independent active_from.
    env.admin.execute("update watch_entry_versions set valid_to='2026-01-02' where revision=2")
    env.admin.execute('''insert into watch_entry_versions
      select id,3,identity,entity_id,plugin_id,collection_scope_id,owner,reason,active,
        '2026-01-03',expires_at,'2026-01-02',null,actor_type,actor_id
      from watch_entry_versions where revision=2''')
    for timestamp,expected in (('2026-01-02',False),('2026-01-03',True)):
        env.admin.execute('update events_v2_core set time_created_utc=%s where id=1',(timestamp,))
        env.admin.execute('update normalized_events set occurred_at_utc=%s where normalized_event_id=%s',
                          (timestamp,UUID(int=1)))
        selected,_ = paired(env,UUID(int=1))
        assert bool(selected) is expected
    for column in ('provider_id','channel_id'):
        env.admin.execute('update events_v2_core set '+column+'=null where id=1')
        try:
            assert paired(env,UUID(int=1))[0] == []
        finally:
            env.admin.execute('update events_v2_core set '+column+'=1 where id=1')
    assert paired(env,UUID(int=1))[0][0]['entries'][0]['revision'] == 3
    print('WATCH271_SEMANTICS_RESULT='+json.dumps(dict(all_eleven_columns_paired=True,
        half_open_active_expiry_history_intervals=True,session_principal_sid_guid=True,
        unmatched_roles_retained=True,event_item_and_inner_dictionary_joins_preserved=True)))


def test_table_authority_ignores_vacuum_bookkeeping():
    before = dict(oid='48148', relowner='16401', relacl=['owner=arwdDxtm/owner'],
                  relpages=14, reltuples=1024, relallvisible=0, relallfrozen=0,
                  relfrozenxid='96471', relminmxid='17')
    after = before | dict(relpages=30, reltuples=1023, relallvisible=28,
                          relallfrozen=13, relfrozenxid='101638', relminmxid='18')
    original = before.copy()
    assert table_authority(before) == table_authority(after)
    assert before == original


@pytest.mark.parametrize('field', [
    'oid', 'relname', 'relnamespace', 'relowner', 'relacl', 'relrowsecurity',
    'relforcerowsecurity', 'relkind', 'relam', 'relfilenode', 'reltablespace',
    'relnatts', 'relchecks', 'relhasindex', 'relhasrules', 'relhastriggers',
    'relhassubclass', 'relpersistence', 'relreplident', 'relispartition',
    'reloptions', 'relpartbound', 'future_catalog_field',
])
def test_table_authority_retains_other_catalog_fields(field):
    assert table_authority({field: 'before'}) != table_authority({field: 'after'})
