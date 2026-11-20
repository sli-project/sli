"""Prospective assignment retention on disposable PG; no complete bootstrap claim.

Actual156/163/169 and232 execute.183 policy-table and219 binding/scope DDL
are copied unchanged; unrelated empty plugin relation shapes are fixture-only.
No native proof is replaced. Factory/ensure/QW publication is outside this seam.
"""
from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from server.sli.agents import policies
from server.sli.semantic import file_ransom_runtime
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_file_ransom import rule

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT/'config/postgres_migrations'
PATH = MIGRATIONS/'272_file_audit_assignment_policy.sql'
AGENT = '00000000-0000-4000-8000-000000000071'
HOST = '00000000-0000-4000-8000-000000000072'
APP = 'sli_test_file_policy_app272'
WORKER = 'sli_test_file_policy_worker272'
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def source(name):
    return (MIGRATIONS/name).read_text('utf-8-sig')


def table(text, name):
    return text[text.index('create table '+name):].split('\n);', 1)[0]+'\n);'


@contextmanager
def connect(dsn, user=None):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row
    with psycopg.connect(make_conninfo(dsn, **({'user': user} if user else {})), row_factory=dict_row) as conn:
        yield conn


@pytest.fixture
def base():
    from psycopg import sql
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('disposable PostgreSQL not configured')
    with connect(dsn) as admin:
        assert_disposable_database(admin)
        for name in ('adlog_storage_owner', 'adlog_user', 'adlog_semantic_worker',
                     'adlog_storage_worker', 'adlog_file_audit_owner', APP, WORKER):
            if not admin.execute('select 1 from pg_roles where rolname=%s', (name,)).fetchone():
                admin.execute(sql.SQL('create role {} {}').format(sql.Identifier(name),
                              sql.SQL('login' if name in (APP, WORKER) else 'nologin')))
        admin.execute(sql.SQL('grant adlog_user to {}; grant adlog_semantic_worker to {}').format(
            sql.Identifier(APP), sql.Identifier(WORKER)))
        admin.execute('grant adlog_file_audit_owner to adlog_storage_owner; '
                      'grant usage,create on schema public to adlog_storage_owner; '
                      'grant usage on schema public to adlog_user,adlog_semantic_worker; '
                      'set role adlog_storage_owner; create table schema_migrations(version integer primary key,name text); '
                      'create sequence schema_migrations_id_seq; '
                      "insert into schema_migrations values(155,'core_identity_scope'); reset role")
        admin.execute(source('156_agent_registry.sql'))
        admin.execute("insert into schema_migrations values(162,'finding_risk_acceptance')")
        admin.execute(source('163_agent_policy_revisions.sql'))
        admin.execute("insert into schema_migrations values(168,'plugin_core_drain_handoff')")
        admin.execute(source('169_agent_collection_control.sql'))
        # Current runtime helpers also require the registry columns from296.
        admin.execute("""alter table sli_agents
            add column source_host_id uuid,
            add column source_agent_id uuid references sli_agents(id),
            add column runtime_resume jsonb not null default '{}'::jsonb check(jsonb_typeof(runtime_resume)='object')""")
        admin.execute('grant update(assigned_modules) on sli_agents to adlog_user; '
                      'create schema sli_plugin_file_audit authorization adlog_file_audit_owner; '
                      'grant usage on schema sli_plugin_file_audit to adlog_user,adlog_storage_owner; '
                      'grant select(id,host_id,policy_revision,status) on sli_agents to adlog_file_audit_owner; '
                      'set role adlog_file_audit_owner')
        admin.execute(table(source('183_file_audit_contracts.sql'), 'sli_plugin_file_audit.policy_revisions'))
        admin.execute('''
            create table sli_plugin_file_audit.observations(evidence_key text primary key,agent_id uuid,
                source_instance_id text,collection_scope_id text,generation text,policy_revision bigint,
                payload_sha256 text,normalized jsonb);
            create table sli_plugin_file_audit.actions(action_id text primary key,agent_id uuid,
                source_instance_id text,collection_scope_id text,outcome text,operation text,correlation_state text);
            create table sli_plugin_file_audit.rule_results(result_id text primary key,agent_id uuid,
                source_instance_id text,collection_scope_id text,rule_code text,conclusion_state text,
                observed_at timestamptz,result jsonb);
            create table sli_plugin_file_audit.rule_actions(result_id text,action_id text);
            create table sli_plugin_file_audit.action_evidence(action_id text,evidence_key text);
            reset role; set role adlog_storage_owner;
            create table sli_agent_receipts(packet_id uuid primary key,agent_id uuid,module_id text,envelope jsonb,receipt jsonb);
            create table sli_agent_packet_inbox(packet_id uuid primary key,envelope jsonb,imported_at timestamptz);
        ''')
        native = source('219_finding_evidence_refs.sql')
        admin.execute(table(native, 'public.finding_evidence_source_bindings'))
        admin.execute("revoke all on finding_evidence_source_bindings from public,adlog_user,adlog_semantic_worker")
        scope = native[native.index('create function public.finding_evidence_scope_allowed('):native.index('-- Companion')]
        admin.execute(scope)
        admin.execute("insert into schema_migrations values(230,'nps_threshold'),(231,'agent_gpo_plans'); reset role")
        admin.execute(source('232_file_ransom.sql'))
        # Explicit reduced predecessor metadata, not execution of233Р Р†Р вЂљРІР‚Сљ271.
        admin.execute("insert into schema_migrations values(271,'account_watch_source_prefilter')")
        admin.execute('insert into sli_agents(id,host_id,key_fingerprint) values(%s,%s,%s)', (AGENT, HOST, 'a'*64))
        selected = rule(threshold=25, window_seconds=60, evaluation_mode='enabled')
        selected = replace(selected, agent_id=AGENT, source_policy_revision='2',
                           scope=replace(selected.scope, source_instance_id=HOST))
        admin.execute('''insert into finding_evidence_source_bindings(
            principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,
            collection_scope_id,storage_kind,agent_id)
            values(%s::regrole::oid,%s,%s,'sli.file-audit',%s,%s,%s,'file_audit_observation',%s)''',
            (WORKER, WORKER, selected.scope.installation_id, HOST,
             selected.scope.source_generation, selected.scope.collection_scope_id, AGENT))
    return dsn, selected


def assignment(enabled=True, expected=1):
    return dict(agent_id=AGENT, module_id='sli.file-audit', enabled=enabled, expected_revision=expected,
                config=dict(source_name='fixture-server', mass_operation_files=25, mass_operation_seconds=60,
                    roots=[dict(collection_scope_id='scope:one', share_name='fixture-share', path='C:\\fixture',
                        important=True, sacl=dict(trustee_sids=['S-1-1-0'], inherit_files=True, inherit_directories=True))]))


def test_ordinary_assignment_reaches_unchanged_reader(installed):
    dsn, selected = installed
    # Same genuine write/read boundary as RED, now with272 and normal hook installed.
    with connect(dsn, APP) as app:
        policies.assign_module(app.cursor(), assignment(), actor='session:1')
    with connect(dsn) as admin:
        row = admin.execute('select revision,source_instance_id,policy from sli_plugin_file_audit.policy_revisions').fetchone()
        assert row['revision'] == 2 and row['source_instance_id'] == HOST
        assert row['policy']['mass_operation_files'] == 25 and row['policy']['mass_operation_seconds'] == 60
        assert [r['revision'] for r in admin.execute('select revision from sli_agent_policy_history order by revision')] == [1, 2]
        assert admin.execute("select count(*) as n from sli_agent_audit where action='module_assign'").fetchone()['n'] == 1
    with connect(dsn, WORKER) as worker:
        assert worker.execute('select session_user=%s as physical_login', (WORKER,)).fetchone()['physical_login']
        assert file_ransom_runtime.read_results(worker.cursor(), selected) == []


@pytest.fixture
def installed(base):
    with connect(base[0]) as admin:
        before = admin.execute("select pg_get_functiondef('public.read_file_ransom_results(jsonb,uuid,text,text,integer,integer)'::regprocedure) as body").fetchone()
        admin.execute(PATH.read_text('utf-8-sig'))
        assert admin.execute("select pg_get_functiondef('public.read_file_ransom_results(jsonb,uuid,text,text,integer,integer)'::regprocedure) as body").fetchone() == before
    return base


def snapshot(dsn):
    with connect(dsn) as admin:
        return {name: admin.execute('select to_jsonb(t) as row from '+name+' t order by 1').fetchall()
                for name in ('sli_agents', 'sli_agent_policy_history', 'sli_agent_audit',
                             'sli_plugin_file_audit.policy_revisions')}


@pytest.mark.parametrize('actor', ['session:1', 'api_key:7'])
def test_exact_retention_replay_keeps_authorship_and_disabled_assignment(installed, actor):
    dsn, _ = installed
    with connect(dsn, APP) as app:
        result = policies.assign_module(app.cursor(), assignment(enabled=False), actor=actor)
        assert result['assigned_modules'][0]['enabled'] is False
    with connect(dsn) as admin:
        retained = admin.execute('select * from sli_plugin_file_audit.policy_revisions').fetchone()
        assert retained['policy'] == result['assigned_modules'][0]['config']
        assert retained['revision'] == result['policy_revision'] == 2
        assert retained['source_instance_id'] == HOST
        assert retained['actor_kind'] == actor.split(':')[0] and retained['actor_id'] == int(actor.split(':')[1])
        assert admin.execute("select policy_sha256=encode(sha256(convert_to(policy::text,'UTF8')),'hex') as ok from sli_plugin_file_audit.policy_revisions").fetchone()['ok']
        assert not admin.execute("select 1 from pg_class where oid=to_regclass('sli_plugin_file_audit.audit_commands')").fetchone()
    before = snapshot(dsn)
    with connect(dsn, APP) as app:
        app.execute('select sli_plugin_file_audit.retain_assignment_policy(%s,%s,%s)', (AGENT, 'api_key', 99))
    assert snapshot(dsn) == before


@pytest.mark.parametrize('kind', ['audit', 'cas', 'retention_conflict', 'missing_hook'])
def test_assignment_failure_rolls_back_all_state(installed, kind, monkeypatch):
    import psycopg
    from server.sli.agents.ca import AgentError
    dsn, _ = installed
    if kind == 'audit':
        with connect(dsn) as admin:
            admin.execute("create function public.fixture_fail_audit272() returns trigger language plpgsql security definer set search_path=pg_catalog,pg_temp as $$ begin if not exists(select 1 from sli_plugin_file_audit.policy_revisions where revision=2) then raise exception 'fixture_retention_not_before_audit'; end if; raise exception 'fixture_audit_failed'; end $$; create trigger fixture_fail_audit272 before insert on sli_agent_audit for each row execute function public.fixture_fail_audit272()")
    if kind == 'retention_conflict':
        with connect(dsn) as admin:
            admin.execute("insert into sli_plugin_file_audit.policy_revisions values(%s,%s,2,now(),'session',1,'{}',repeat('a',64))", (AGENT, HOST))
    if kind == 'missing_hook':
        original = policies.plugin_hook
        monkeypatch.setattr(policies, 'plugin_hook', lambda plugin, name: None if name == 'retain_assignment_policy' else original(plugin, name))
    before = snapshot(dsn)
    with pytest.raises((psycopg.Error, AgentError)) as raised:
        with connect(dsn, APP) as app:
            policies.assign_module(app.cursor(), assignment(expected=0 if kind == 'cas' else 1), actor='session:1')
    if kind in ('audit', 'retention_conflict'):
        assert isinstance(raised.value, psycopg.Error)
        assert raised.value.sqlstate == ('P0001' if kind == 'audit' else '55000')
        assert ('fixture_audit_failed' if kind == 'audit' else 'file_audit_assignment_policy_conflict') in str(raised.value)
    else:
        assert isinstance(raised.value, AgentError)
        assert str(raised.value) == ('agent_policy_revision_conflict' if kind == 'cas' else 'file_audit_plugin_unavailable')
    assert snapshot(dsn) == before


@pytest.mark.parametrize('change,sqlstate', [
    ('source', '42501'), ('revision', 'P0001'), ('threshold', 'P0001'), ('window', 'P0001'), ('login', '42501')])
def test_unchanged_reader_still_denies_mismatched_authority(installed, change, sqlstate):
    import psycopg
    dsn, selected = installed
    with connect(dsn, APP) as app:
        policies.assign_module(app.cursor(), assignment(), actor='session:1')
    if change == 'source':
        selected = replace(selected, scope=replace(selected.scope, source_instance_id='other-synthetic-source'))
    elif change == 'revision':
        selected = replace(selected, source_policy_revision='3')
    elif change == 'threshold':
        selected = replace(selected, threshold=26)
    elif change == 'window':
        selected = replace(selected, window_seconds=61)
    with pytest.raises(psycopg.Error) as raised:
        with connect(dsn, APP if change == 'login' else WORKER) as worker:
            file_ransom_runtime.read_results(worker.cursor(), selected)
    assert raised.value.sqlstate == sqlstate


def test_private_catalog_and_no_extra_app_or_worker_table_rights(installed):
    import psycopg
    dsn, _ = installed
    with connect(dsn) as admin:
        catalog = admin.execute("""select owner.rolname,p.prosecdef,p.provolatile,p.proconfig,
            pg_get_function_identity_arguments(p.oid) as args,
            has_function_privilege('adlog_user',p.oid,'EXECUTE') as app,
            has_function_privilege('adlog_semantic_worker',p.oid,'EXECUTE') as worker
            from pg_proc p join pg_roles owner on owner.oid=p.proowner
            where p.oid='sli_plugin_file_audit.retain_assignment_policy(uuid,text,bigint)'::regprocedure""").fetchone()
        assert catalog == dict(rolname='adlog_file_audit_owner', prosecdef=True, provolatile='v',
            proconfig=['search_path=pg_catalog, pg_temp'], args='p_agent uuid, p_actor_kind text, p_actor_id bigint', app=True, worker=False)
        for role in ('adlog_user', 'adlog_semantic_worker'):
            assert not admin.execute("select has_table_privilege(%s,'sli_plugin_file_audit.policy_revisions','SELECT,INSERT,UPDATE,DELETE') as ok", (role,)).fetchone()['ok']
        assert admin.execute("select has_column_privilege('adlog_file_audit_owner','sli_agents','assigned_modules','SELECT') as ok").fetchone()['ok']
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with connect(dsn, WORKER) as worker:
            worker.execute('select sli_plugin_file_audit.retain_assignment_policy(%s,%s,%s)', (AGENT, 'session', 1))


@pytest.mark.parametrize('actor', ['request:1', 'session:0', 'session:01', 'api_key:-1', 'session:9223372036854775808'])
def test_bad_trusted_actor_rolls_back_assignment(installed, actor):
    from server.sli.agents.ca import AgentError
    dsn, _ = installed
    before = snapshot(dsn)
    with pytest.raises(AgentError):
        with connect(dsn, APP) as app:
            policies.assign_module(app.cursor(), assignment(), actor=actor)
    assert snapshot(dsn) == before


@pytest.mark.parametrize('drift', ['missing271', 'wrong271', 'occupied272', 'unauthorized', 'late_failure'])
def test_migration_guard_and_late_failure_leave_no_partial_grant_or_function(base, drift):
    import psycopg
    dsn, _ = base
    text = PATH.read_text('utf-8-sig')
    with connect(dsn) as admin:
        if drift == 'missing271':
            admin.execute('delete from schema_migrations where version=271')
        elif drift == 'wrong271':
            admin.execute("update schema_migrations set name='wrong' where version=271")
        elif drift == 'occupied272':
            admin.execute("insert into schema_migrations values(272,'occupied')")
    if drift == 'late_failure':
        marker = "insert into public.schema_migrations(version,name) values(272,'file_audit_assignment_policy');"
        assert marker in text
        text = text.replace(marker, 'select 1/0;\n'+marker)
    with pytest.raises(psycopg.Error):
        with connect(dsn, APP if drift == 'unauthorized' else None) as runner:
            runner.execute(text)
    with connect(dsn) as admin:
        assert admin.execute("select to_regprocedure('sli_plugin_file_audit.retain_assignment_policy(uuid,text,bigint)') as name").fetchone()['name'] is None
        assert not admin.execute("select has_column_privilege('adlog_file_audit_owner','sli_agents','assigned_modules','SELECT') as ok").fetchone()['ok']


def test_migration_does_not_backfill_existing_assignment(base):
    dsn, _ = base
    from sli_agent.file_audit_policy import policy
    with connect(dsn) as admin:
        # Legacy setup only;272 must not infer/backfill this existing valid assignment.
        config = policy(dict(assignment()['config'], policy_revision='2'))
        admin.execute('update sli_agents set policy_revision=2,assigned_modules=%s::jsonb where id=%s',
            (json.dumps([dict(module_id='sli.file-audit', enabled=True, config=config)]), AGENT))
        admin.execute(PATH.read_text('utf-8-sig'))
        assert not admin.execute('select 1 from sli_plugin_file_audit.policy_revisions').fetchone()
        assert admin.execute("select name from schema_migrations where version=272").fetchone()['name'] == 'file_audit_assignment_policy'


def test_other_module_assignment_has_no_file_policy_side_effect(installed):
    dsn, _ = installed
    with connect(dsn, APP) as app:
        policies.assign_module(app.cursor(), dict(agent_id=AGENT, module_id='sli.workstations', enabled=False,
            expected_revision=1, config={}), actor='session:1')
    with connect(dsn) as admin:
        assert not admin.execute('select 1 from sli_plugin_file_audit.policy_revisions').fetchone()


@pytest.mark.parametrize('change', ['revision', 'extra', 'numeric_string', 'duplicate_root', 'null_enabled'])
def test_definer_rejects_noncanonical_current_assignment_without_retaining(installed, change):
    import psycopg
    from sli_agent.file_audit_policy import policy
    dsn, _ = installed
    config = policy(dict(assignment()['config'], policy_revision='2'))
    enabled = True
    if change == 'revision':
        config['policy_revision'] = '1'
    elif change == 'extra':
        config['unexpected'] = True
    elif change == 'numeric_string':
        config['mass_operation_files'] = '25'
    elif change == 'duplicate_root':
        config['roots'] *= 2
    else:
        enabled = None
    with connect(dsn) as admin:
        admin.execute('update sli_agents set policy_revision=2,assigned_modules=%s::jsonb where id=%s',
            (json.dumps([dict(module_id='sli.file-audit', enabled=enabled, config=config)]), AGENT))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with connect(dsn, APP) as app:
            app.execute('select sli_plugin_file_audit.retain_assignment_policy(%s,%s,%s)', (AGENT, 'session', 1))
    with connect(dsn) as admin:
        assert not admin.execute('select 1 from sli_plugin_file_audit.policy_revisions').fetchone()


def test_maximum_scope_length_is_preserved(installed):
    dsn, _ = installed
    body = assignment()
    body['config']['roots'][0]['collection_scope_id'] = 'x'*256
    with connect(dsn, APP) as app:
        policies.assign_module(app.cursor(), body, actor='session:1')
    with connect(dsn) as admin:
        assert len(admin.execute("select policy#>>'{roots,0,collection_scope_id}' as scope from sli_plugin_file_audit.policy_revisions").fetchone()['scope']) == 256


def test_default_execute_grants_cannot_leak_retainer(base):
    import psycopg
    dsn, _ = base
    with connect(dsn) as admin:
        admin.execute('alter default privileges for role adlog_file_audit_owner in schema sli_plugin_file_audit grant execute on functions to adlog_semantic_worker')
    # Named worker is explicitly revoked, including owner-defined defaults.
    with connect(dsn) as admin:
        admin.execute(PATH.read_text('utf-8-sig'))
        assert not admin.execute("select has_function_privilege('adlog_semantic_worker','sli_plugin_file_audit.retain_assignment_policy(uuid,text,bigint)','EXECUTE') as ok").fetchone()['ok']
        assert not admin.execute("select exists(select 1 from pg_proc p cross join lateral aclexplode(p.proacl) a where p.oid='sli_plugin_file_audit.retain_assignment_policy(uuid,text,bigint)'::regprocedure and a.grantee=0) as public_execute").fetchone()['public_execute']
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with connect(dsn, WORKER) as worker:
            worker.execute('select sli_plugin_file_audit.retain_assignment_policy(%s,%s,%s)', (AGENT, 'session', 1))


def test_two_normal_revisions_preserve_old_retained_policy_and_reader(installed):
    dsn, old = installed
    with connect(dsn, APP) as app:
        policies.assign_module(app.cursor(), assignment(), actor='session:1')
    before = snapshot(dsn)['sli_plugin_file_audit.policy_revisions']
    body = assignment(expected=2)
    body['config']['mass_operation_files'] = 26
    with connect(dsn, APP) as app:
        policies.assign_module(app.cursor(), body, actor='api_key:7')
    after = snapshot(dsn)['sli_plugin_file_audit.policy_revisions']
    assert len(after) == 2 and all(row in after for row in before)
    with connect(dsn) as admin:
        assert [(r['revision'], r['n']) for r in admin.execute("select revision,(policy->>'mass_operation_files')::integer as n from sli_plugin_file_audit.policy_revisions order by revision")] == [(2, 25), (3, 26)]
        assert [r['revision'] for r in admin.execute('select revision from sli_agent_policy_history order by revision')] == [1, 2, 3]
    with connect(dsn, WORKER) as worker:
        assert file_ransom_runtime.read_results(worker.cursor(), old) == []
        assert file_ransom_runtime.read_results(worker.cursor(), replace(old, source_policy_revision='3', threshold=26)) == []


@pytest.mark.parametrize('kind,actor_id', [('request', 1), ('session', 0), (None, 1)])
def test_sql_actor_guard_is_not_just_python_validation(installed, kind, actor_id):
    import psycopg
    dsn, _ = installed
    with connect(dsn, APP) as app:
        policies.assign_module(app.cursor(), assignment(), actor='session:1')
    before = snapshot(dsn)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with connect(dsn, APP) as app:
            app.execute('select sli_plugin_file_audit.retain_assignment_policy(%s,%s,%s)', (AGENT, kind, actor_id))
    assert snapshot(dsn) == before
