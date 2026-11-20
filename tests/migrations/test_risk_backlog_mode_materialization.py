"""Query-local mode work bound; actual native RLS, exclusive worker semantics.

Unrelated graph targets are reduced. Not full-schema/installed acceptance.
"""
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from uuid import UUID

import pytest
from server.sli.semantic import semantic_risk_runtime_repository as repository
from server.sli.semantic.qw_input import QWSignal
from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
from server.sli.sigma.detection_input import DetectionMatch
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope
from tests.migrations.test_file_audit_acl_bridge_migration264 import acl_pg as acl_pg
from tests.migrations.test_agent_packet_path_lookup_index268 import (
    GENERATION, INSTALLATION, PLUGIN, SHA, SOURCE, bind, core_pg as core_pg, seed,
)
from tests.postgres_integration_guard import assert_disposable_database

ROOT=Path(__file__).resolve().parents[2]
STAMP=datetime(2026,1,1,tzinfo=timezone.utc)
KINDS=('canonical_action','control_health','correlation_candidate','detection_match','qw_signal')


def source(name):
    return (ROOT/'config/postgres_migrations'/name).read_text('utf-8-sig')


def section(text,start,end):
    return text[text.index(start):text.index(end,text.index(start))]


@dataclass(repr=False)
class Database:
    admin: str
    worker: str

    def connect(self, *, privileged=False):
        import psycopg
        from psycopg.rows import dict_row
        conn=psycopg.connect(self.admin if privileged else self.worker,row_factory=dict_row)
        if not privileged:
            conn.execute('set role adlog_semantic_worker')
            check=assert_semantic_worker_least_privilege(conn.cursor())
            assert check['exclusive_worker_membership'] and not check['elevated_privileges']
        return conn


@pytest.fixture
def backlog_pg(core_pg,postgres_semantic_worker_dsn):
    import psycopg
    with psycopg.connect(core_pg,autocommit=True) as conn:
        assert_disposable_database(conn)
        conn.execute('set role adlog_storage_owner')
        sql029=source('029_semantic_risk_runtime.sql')
        conn.execute(section(sql029,'create table if not exists semantic_risk_policies','create table if not exists semantic_control_health_observations'))
        conn.execute(section(sql029,'create table if not exists semantic_control_health_observations','create table if not exists semantic_risk_evaluation_jobs'))
        conn.execute(section(source('022_semantic_processing_foundation.sql'),'create table if not exists canonical_actions','-- Evidence is ordered'))
        conn.execute('create table semantic_correlation_candidates(candidate_id uuid primary key,relation_kind text,candidate_status text,first_matched_at timestamptz); create table semantic_security_scenarios(scenario_id uuid primary key)')
        conn.execute(section(sql029,'create table if not exists semantic_risk_evaluation_jobs','create table if not exists semantic_risk_evaluation_results'))
        conn.execute(section(source('053_semantic_canonical_action_risk.sql'),'alter table semantic_risk_policies','insert into schema_migrations'))
        gov=source('153_semantic_governance.sql')
        conn.execute(section(gov,'create table semantic_policy_admission','-- Empty overrides'))
        conn.execute(section(gov,'create function semantic_policy_mode_v160','-- The classifier'))
        conn.execute(section(source('219_finding_evidence_refs.sql'),'create function public.finding_evidence_scope_allowed','-- Companion'))
        for name in ('220_detection_match_risk.sql','228_qw_semantic_input.sql'):
            text=source(name)
            table='semantic_detection_matches' if name.startswith('220') else 'semantic_qw_signals'
            conn.execute(section(text,'create table public.'+table,'alter table public.semantic_risk_policies'))
            for table in ('semantic_risk_policies','semantic_risk_policy_subscriptions','semantic_risk_evaluation_jobs'):
                clause=text[text.index('alter table public.'+table+'\n'):].split(';',1)[0]+';'
                conn.execute(clause)
        conn.execute(section(source('246_semantic_throughput.sql'),'create index idx_canonical_actions_risk_fifo','-- Hourly completion'))
        conn.execute('revoke all on function semantic_policy_mode_v160(text,integer,text) from public')
        conn.execute('grant execute on function semantic_policy_mode_v160(text,integer,text) to adlog_semantic_worker')
        # Actual050 relevant table privileges;153 adds admission SELECT.
        conn.execute('''grant select,insert,update on canonical_actions,semantic_correlation_candidates,
            semantic_risk_policies,semantic_risk_evaluation_jobs to adlog_semantic_worker;
            grant select on semantic_risk_policy_subscriptions,semantic_policy_admission to adlog_semantic_worker;
            grant select,insert on semantic_control_health_observations to adlog_semantic_worker;''')
        conn.execute('reset role')
        seed(conn)
        with psycopg.connect(postgres_semantic_worker_dsn) as worker:
            login=worker.execute('select session_user').fetchone()[0]
        bind(conn,login)
    return Database(core_pg,postgres_semantic_worker_dsn)


class Capture:
    def execute(self,sql,params=()):
        self.sql,self.params=sql,params
    def fetchall(self):
        return []


def query(limit=16):
    cur=Capture();repository.enqueue_risk_backlog(cur,limit=limit)
    return cur.sql,cur.params


def selected(conn,*,old=False,limit=16):
    sql,params=query(limit)
    return [tuple(row.values()) for row in conn.execute(BEFORE_QUERY if old else sql,params)]


def policy(conn,kind,*,name=None,mode='enabled',execution=None,revision=1,sub_hash=None):
    name=name or 'policy-'+kind
    selector={'canonical_action':'fixture.action','control_health':'fixture.control',
              'correlation_candidate':'fixture.relation','detection_match':'00000000-0000-0000-0000-000000000014','qw_signal':'qw.fixture'}[kind]
    definition={'source_selector':{'execution':execution}} if execution is not None else {}
    digest=sha256(json.dumps(definition,sort_keys=True).encode()).digest()
    conn.execute('insert into semantic_risk_policies(policy_id,policy_version,source_kind,definition_json,definition_sha256) values(%s,%s,%s,%s::jsonb,%s)',(name,revision,kind,json.dumps(definition),digest))
    conn.execute('insert into semantic_risk_policy_subscriptions(policy_id,policy_version,source_kind,selector_value,definition_sha256) values(%s,%s,%s,%s,%s)',(name,revision,kind,selector,sub_hash or digest))
    conn.execute('update semantic_risk_policies set lifecycle_status=%s where policy_id=%s',(mode,name))
    if mode=='enabled':
        conn.execute("insert into semantic_policy_admission(policy_id,policy_version,enabled,updated_by) values(%s,%s,true,'fixture')",(name,revision))
    return name


def action(conn,number,*,status='observed'):
    identity=str(UUID(int=number))
    conn.execute('''insert into canonical_actions(canonical_action_id,action_kind,action_status,semantic_contract_version,
        assembler_id,assembler_version,occurred_at_utc,contribution_key,action_sha256)
        values(%s,'fixture.action',%s,1,'fixture','1',%s,decode(%s,'hex'),decode(%s,'hex'))''',
        (identity,status,STAMP,f'{number:064x}',f'{number:064x}'))
    return identity


def inputs(db,mode='enabled'):
    scope=EvidenceScope(installation_id=INSTALLATION,plugin_id=PLUGIN,source_instance_id=SOURCE,source_generation=GENERATION,collection_scope_id='')
    ref=EvidenceRef(scope=scope,storage_kind='core_event',native_id='1',sha256=SHA)
    signal=QWSignal(kind='threshold',rule_id='qw.fixture',rule_version=1,rule_sha256='1'*64,policy_revision=1,
        evaluation_mode=mode,entity_key='2'*64,episode_key='3'*64,occurred_at_utc=STAMP,received_at_utc=STAMP,evidence_refs=(ref,))
    detection=DetectionMatch(rule_id='00000000-0000-0000-0000-000000000014',rule_sha256='1'*64,manifest_sha256='2'*64,
        compiler_version='fixture',mapping_version='fixture',overlay_sha256='3'*64,evidence=ref,entity_key='4'*64,occurred_at_utc=STAMP,evaluation_mode=mode)
    with db.connect(privileged=True) as conn:
        ids={'canonical_action':action(conn,1),'correlation_candidate':str(UUID(int=2)),'control_health':str(UUID(int=3)),
             'detection_match':detection.match_id,'qw_signal':signal.signal_id}
        conn.execute("insert into semantic_correlation_candidates values(%s,'fixture.relation','matched',%s)",(ids['correlation_candidate'],STAMP))
        conn.execute("insert into semantic_control_health_observations(observation_id,observation_key,control_id,partition_key,coverage_status,reason,observed_at_utc,source_reference) values(%s,decode(repeat('a',64),'hex'),'fixture.control','fixture','complete','fixture',%s,'fixture')",(ids['control_health'],STAMP))
        for kind in KINDS:policy(conn,kind,mode=mode,execution=detection.execution if kind=='detection_match' else signal.execution if kind=='qw_signal' else None)
    with db.connect() as conn:
        conn.execute('insert into semantic_detection_matches(match_id,rule_id,evaluation_mode,occurred_at_utc,evidence_key,document_json) values(%s,%s,%s,%s,%s,%s::jsonb)',(detection.match_id,detection.rule_id,mode,STAMP,detection.evidence_key,json.dumps(detection.document)))
        conn.execute('insert into semantic_qw_signals(signal_id,evaluation_mode,document_json,created_at) values(%s,%s,%s::jsonb,%s)',(signal.signal_id,mode,json.dumps(signal.document),STAMP))
    return ids,signal,detection


def nodes(plan):
    pending=[plan[0]['Plan']]
    while pending:
        node=pending.pop();yield node;pending.extend(node.get('Plans',[]))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_mode_call_work_is_per_valid_policy_not_already_jobbed_history(backlog_pg):
    n=12000
    with backlog_pg.connect(privileged=True) as conn:
        policy(conn,'canonical_action')
        conn.execute("insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256) select 'unrelated-'||g,1,'canonical_action','shadow','{}',decode(repeat('b',64),'hex') from generate_series(1,100) g")
        conn.execute('''insert into canonical_actions(canonical_action_id,action_kind,action_status,semantic_contract_version,assembler_id,assembler_version,occurred_at_utc,contribution_key,action_sha256)
            select md5(g::text)::uuid,'fixture.action','observed',1,'fixture','1',%s,decode(md5(g::text)||md5(g::text),'hex'),decode(repeat('a',64),'hex') from generate_series(1,%s) g''',(STAMP,n))
        conn.execute('''insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,canonical_action_id,source_reference,evaluation_mode,idempotency_key)
            select canonical_action_id,'policy-canonical_action',1,'canonical_action',canonical_action_id,canonical_action_id::text,'enabled',decode(md5(canonical_action_id::text)||md5(canonical_action_id::text),'hex') from canonical_actions''')
        conn.execute('analyze canonical_actions');conn.execute('analyze semantic_risk_evaluation_jobs')
        conn.execute("set local track_functions='all'")
        oid=conn.execute("select 'semantic_policy_mode_v160(text,integer,text)'::regprocedure::oid as oid").fetchone()['oid']
        def calls():
            row=conn.execute('select calls from pg_stat_xact_user_functions where funcid=%s',(oid,)).fetchone()
            return row['calls'] if row else 0
        before=calls();assert selected(conn)==[];delta=calls()-before
        sql,params=query();plan=conn.execute('explain(analyze,format json) '+sql,params).fetchone()['QUERY PLAN']
        print(json.dumps({'profile_scope':'privileged disposable; semantic/RLS tested separately','mode_calls':delta,'history_rows':n,'plan':[{k:v for k,v in node.items() if k in ('Node Type','Index Name','Actual Rows','Actual Loops','Total Cost')} for node in nodes(plan)]},sort_keys=True))
        assert 0<delta<=1, 'discovery mode calls grow with historical source probes'
        late=action(conn,n+1)
        conn.execute('update canonical_actions set occurred_at_utc=%s where canonical_action_id=%s',(STAMP+timedelta(seconds=1),late))
        assert selected(conn)==selected(conn,old=True)==[('canonical_action',late)]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize('mode',['test','shadow','enabled'])
def test_all_five_sources_fifo_multiple_policies_admission_and_idempotency(backlog_pg,mode):
    ids,signal,detection=inputs(backlog_pg,mode)
    with backlog_pg.connect(privileged=True) as conn:
        policy(conn,'canonical_action',name='second-action',mode=mode)
        policy(conn,'qw_signal',name='second-qw',mode=mode,execution=signal.execution)
    with backlog_pg.connect() as conn:
        want=[(kind,ids[kind]) for kind in KINDS]
        for limit in (1,2,5,16,1000):
            assert selected(conn,limit=limit)==want[:limit]
            assert selected(conn,old=True,limit=limit)==want[:limit]
        jobs=repository.enqueue_risk_backlog(conn.cursor(),limit=16)
        assert len(jobs)==7
        assert {row['source_kind'] for row in conn.execute('select source_kind from semantic_risk_evaluation_jobs')}==set(KINDS)
        assert repository.enqueue_risk_backlog(conn.cursor())==()
    with backlog_pg.connect(privileged=True) as conn:
        conn.execute('delete from semantic_risk_evaluation_jobs')
        conn.execute("insert into semantic_policy_admission(policy_id,policy_version,enabled,updated_by) select policy_id,policy_version,false,'fixture' from semantic_risk_policies on conflict(policy_id,policy_version) do update set enabled=false")
    with backlog_pg.connect() as conn:assert selected(conn)==selected(conn,old=True)==[]
    with backlog_pg.connect(privileged=True) as conn:conn.execute('delete from semantic_policy_admission')
    with backlog_pg.connect() as conn:
        assert selected(conn)==selected(conn,old=True)==([] if mode=='enabled' else want)


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_hash_revision_execution_mismatches_and_legacy_status_do_not_expand(backlog_pg):
    ids,signal,detection=inputs(backlog_pg)
    with backlog_pg.connect(privileged=True) as conn:
        conn.execute("update semantic_risk_policies set lifecycle_status='draft'")
        conn.execute("update semantic_risk_policy_subscriptions set definition_sha256=decode(repeat('f',64),'hex')")
        conn.execute("update semantic_risk_policies set lifecycle_status='enabled'")
    with backlog_pg.connect() as conn:assert selected(conn)==selected(conn,old=True)==[]
    with backlog_pg.connect(privileged=True) as conn:
        conn.execute("update semantic_risk_policies set lifecycle_status='draft'")
        conn.execute('update semantic_risk_policy_subscriptions s set definition_sha256=p.definition_sha256 from semantic_risk_policies p where p.policy_id=s.policy_id')
        conn.execute("update semantic_risk_policies set definition_json=jsonb_set(definition_json,'{source_selector,execution,rule_sha256}',to_jsonb(repeat('f',64)),false) where source_kind in ('detection_match','qw_signal')")
        conn.execute("update semantic_risk_policies set lifecycle_status='enabled'")
        conn.execute("update canonical_actions set action_status='quarantined'")
        conn.execute("update semantic_correlation_candidates set candidate_status='unmatched'")
    with backlog_pg.connect() as conn:
        assert selected(conn)==selected(conn,old=True)==[('control_health',ids['control_health'])]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_existing_jobs_in_every_status_remain_excluded(backlog_pg):
    inputs(backlog_pg)
    with backlog_pg.connect() as conn:
        assert len(repository.enqueue_risk_backlog(conn.cursor()))==5
    for status in ('queued','leased','failed','completed','quarantined'):
        with backlog_pg.connect(privileged=True) as conn:
            conn.execute("""update semantic_risk_evaluation_jobs set evaluation_status=%s,
                lease_token=case when %s='leased' then '00000000-0000-0000-0000-000000000099'::uuid end,
                lease_until=case when %s='leased' then now()+interval '5 minutes' end,
                last_error_code=case when %s in ('failed','quarantined') then 'FixtureError' end,
                completed_at=case when %s='completed' then now() end""",(status,)*5)
        with backlog_pg.connect() as conn:
            assert selected(conn)==selected(conn,old=True)==[]
            assert repository.enqueue_risk_backlog(conn.cursor())==()


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_promotion_queues_new_mode_without_relabeling_detection_or_qw(backlog_pg):
    ids,_,_=inputs(backlog_pg,'shadow')
    with backlog_pg.connect() as conn:
        assert len(repository.enqueue_risk_backlog(conn.cursor()))==5
    with backlog_pg.connect(privileged=True) as conn:
        conn.execute("insert into semantic_policy_admission(policy_id,policy_version,enabled,updated_by) select policy_id,policy_version,true,'fixture' from semantic_risk_policies")
    with backlog_pg.connect() as conn:
        expected=[(kind,ids[kind]) for kind in KINDS[:3]]
        assert selected(conn)==selected(conn,old=True)==expected
        assert len(repository.enqueue_risk_backlog(conn.cursor()))==3
        assert selected(conn)==[]
        modes={r['evaluation_mode']:r['n'] for r in conn.execute('select evaluation_mode,count(*) n from semantic_risk_evaluation_jobs group by evaluation_mode')}
        assert modes=={'shadow':5,'enabled':3}


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_qw_policy_revision_does_not_match_a_different_source_revision(backlog_pg):
    ids,signal,_=inputs(backlog_pg)
    with backlog_pg.connect(privileged=True) as conn:
        conn.execute("update semantic_risk_policies set lifecycle_status='disabled'")
        policy(conn,'qw_signal',name='new-qw-version',revision=2,execution=signal.execution)
    with backlog_pg.connect() as conn:
        assert selected(conn)==selected(conn,old=True)==[]
        assert repository.enqueue_risk_backlog(conn.cursor())==()

BEFORE_QUERY = "\n        select source_kind,source_id from (\n            select distinct 'canonical_action' as source_kind,\n                   canonical_action_id::text as source_id,\n                   occurred_at_utc as source_time\n            from semantic_risk_policy_subscriptions subscription\n            join semantic_risk_policies policy\n              on policy.policy_id=subscription.policy_id\n             and policy.policy_version=subscription.policy_version\n             and policy.definition_sha256=subscription.definition_sha256\n            cross join lateral (\n                select action.canonical_action_id,action.occurred_at_utc\n                from canonical_actions action\n                where subscription.selector_value=action.action_kind\n                  and action_status not in ('contradicted','superseded','quarantined')\n                  and not exists (\n                      select 1 from semantic_risk_evaluation_jobs job\n                      where job.policy_id=policy.policy_id\n                        and job.policy_version=policy.policy_version\n                        and job.source_kind='canonical_action'\n                        and job.source_reference=action.canonical_action_id::text\n                        and job.evaluation_mode=semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)\n                  )\n                order by action.occurred_at_utc,action.canonical_action_id\n                limit %s\n            ) action\n            where subscription.source_kind='canonical_action'\n              and semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)=any(%s)\n              and (semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)<>'enabled'\n                   or exists(select 1 from semantic_policy_admission admission\n                       where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version\n                         and admission.enabled is true))\n            union all\n            select 'correlation_candidate' as source_kind,candidate_id::text as source_id,\n                   first_matched_at as source_time\n            from semantic_correlation_candidates candidate\n            where candidate_status='matched' and exists (\n                select 1 from semantic_risk_policy_subscriptions subscription\n                join semantic_risk_policies policy\n                  on policy.policy_id=subscription.policy_id\n                 and policy.policy_version=subscription.policy_version\n                 and policy.definition_sha256=subscription.definition_sha256\n                where subscription.source_kind='correlation_candidate'\n                  and subscription.selector_value=candidate.relation_kind\n                  and semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)=any(%s)\n                  and (semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)<>'enabled'\n                       or exists(select 1 from semantic_policy_admission admission\n                           where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version\n                             and admission.enabled is true))\n                  and not exists (\n                      select 1 from semantic_risk_evaluation_jobs job\n                      where job.policy_id=policy.policy_id\n                        and job.policy_version=policy.policy_version\n                        and job.source_kind='correlation_candidate'\n                        and job.source_reference=candidate.candidate_id::text\n                        and job.evaluation_mode=semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)\n                  )\n            )\n            union all\n            select 'control_health',observation_id::text,observed_at_utc\n            from semantic_control_health_observations health\n            where exists (\n                select 1 from semantic_risk_policy_subscriptions subscription\n                join semantic_risk_policies policy\n                  on policy.policy_id=subscription.policy_id\n                 and policy.policy_version=subscription.policy_version\n                 and policy.definition_sha256=subscription.definition_sha256\n                where subscription.source_kind='control_health'\n                  and subscription.selector_value=health.control_id\n                  and semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)=any(%s)\n                  and (semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)<>'enabled'\n                       or exists(select 1 from semantic_policy_admission admission\n                           where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version\n                             and admission.enabled is true))\n                  and not exists (\n                      select 1 from semantic_risk_evaluation_jobs job\n                      where job.policy_id=policy.policy_id\n                        and job.policy_version=policy.policy_version\n                        and job.source_kind='control_health'\n                        and job.source_reference=health.observation_id::text\n                        and job.evaluation_mode=semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)\n                  )\n            )\n            union all\n            select 'detection_match',detection.match_id,detection.occurred_at_utc\n            from semantic_detection_matches detection\n            where exists (\n                select 1 from semantic_risk_policy_subscriptions subscription\n                join semantic_risk_policies policy\n                  on policy.policy_id=subscription.policy_id\n                 and policy.policy_version=subscription.policy_version\n                 and policy.definition_sha256=subscription.definition_sha256\n                where subscription.source_kind='detection_match'\n                  and subscription.selector_value=detection.rule_id\n                  and semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)=detection.evaluation_mode\n                  and policy.definition_json#>'{source_selector,execution}'=jsonb_build_object(\n                      'version','sli.sigma.execution.v1','rule_id',detection.rule_id,\n                      'rule_sha256',detection.document_json->'rule_sha256',\n                      'manifest_sha256',detection.document_json->'manifest_sha256',\n                      'compiler_version',detection.document_json->'compiler_version',\n                      'mapping_version',detection.document_json->'mapping_version',\n                      'overlay_sha256',detection.document_json->'overlay_sha256',\n                      'scope',detection.document_json#>'{evidence,scope}')\n                  and (detection.evaluation_mode<>'enabled' or exists(\n                      select 1 from semantic_policy_admission admission\n                      where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version\n                        and admission.enabled is true))\n                  and not exists (\n                      select 1 from semantic_risk_evaluation_jobs job\n                      where job.policy_id=policy.policy_id and job.policy_version=policy.policy_version\n                        and job.source_kind='detection_match' and job.source_reference=detection.match_id\n                        and job.evaluation_mode=detection.evaluation_mode\n                  )\n            )\n            union all\n            select 'qw_signal',signal.signal_id,signal.created_at\n            from semantic_qw_signals signal\n            where exists (\n                select 1 from semantic_risk_policy_subscriptions subscription\n                join semantic_risk_policies policy\n                  on policy.policy_id=subscription.policy_id\n                 and policy.policy_version=subscription.policy_version\n                 and policy.definition_sha256=subscription.definition_sha256\n                where subscription.source_kind='qw_signal'\n                  and subscription.selector_value=signal.document_json->>'rule_id'\n                  and to_jsonb(policy.policy_version)=signal.document_json->'policy_revision'\n                  and semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)=signal.evaluation_mode\n                  and policy.definition_json#>'{source_selector,execution}'=case when signal.document_json->>'kind'='acl'\n                    then jsonb_build_object('version','sli.qw.file-acl-execution.v1','kind','acl',\n                      'rule_id',signal.document_json->'rule_id','rule_version',signal.document_json->'rule_version',\n                      'rule_sha256',signal.document_json->'rule_sha256','resource',signal.document_json#>'{acl_context,resource}')\n                    else jsonb_build_object(\n                      'version','sli.qw.execution.v1','kind',signal.document_json->'kind',\n                      'rule_id',signal.document_json->'rule_id','rule_version',signal.document_json->'rule_version',\n                      'rule_sha256',signal.document_json->'rule_sha256',\n                      'scope',signal.document_json#>'{evidence_refs,0,scope}') end\n                  and (signal.evaluation_mode<>'enabled' or exists(\n                      select 1 from semantic_policy_admission admission\n                      where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version\n                        and admission.enabled is true))\n                  and not exists (\n                      select 1 from semantic_risk_evaluation_jobs job\n                      where job.policy_id=policy.policy_id and job.policy_version=policy.policy_version\n                        and job.source_kind='qw_signal' and job.source_reference=signal.signal_id\n                        and job.evaluation_mode=signal.evaluation_mode\n                  )\n            )\n        ) source\n        order by source_time,source_kind,source_id limit %s\n        "
