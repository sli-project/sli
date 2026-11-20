"""One actual managed producer -> leased consumer -> publication, disposable only.

Real264/273/275 authority and runtime callbacks are retained. The reduced265
fixture is expanded with actual historical publication/queue DDL fragments;
unrelated normalized/entity FK targets remain empty primary-key fixtures.
No State/ledger/retained-proof seed, manual enqueue, default switch or delivery.
"""
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import pytest

from server.sli.semantic import password_attack_policy as factory
from server.sli.semantic import password_attack_producer as producer
from server.sli.semantic import password_attack_runtime as password_runtime
from server.sli.semantic import qw_input, semantic_risk_runtime_repository as runtime
from server.sli.semantic.password_attack_v2 import Rule
from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
from tests.migrations.test_password_attacks_v2_migration import _seed
from tests.migrations.test_password_coverage_domain_migration import HOST
from tests.migrations.test_password_policy_management_migration import (
    AGENT, SCOPE,
    managed_pg as managed_pg, managed_base_pg as managed_base_pg,
    coverage_pg as coverage_pg, password_base_pg as password_base_pg,
    coordinator_pg as coordinator_pg, reservation_pg as reservation_pg,
    password_pg as password_pg, native_pg as native_pg, acl_pg as acl_pg,
    original_base as original_base,
)

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / 'config/postgres_migrations'


def _source(name):
    return (MIGRATIONS / name).read_text('utf-8-sig')


def _region(source, start, stop):
    assert source.count(start) == 1
    assert stop in source.split(start, 1)[1]
    return start + source.split(start, 1)[1].split(stop, 1)[0]


def _table(source, name):
    start = 'create table ' + name + ' ('
    assert source.count(start) == 1
    return start + source.split(start, 1)[1].split('\n);', 1)[0] + '\n);'


def _authority(conn):
    return conn.execute("""select oid,proowner,proacl,prosecdef,provolatile,proconfig,prosrc
        from pg_proc where oid='public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)'::regprocedure""").fetchone()



def _publication_authority(conn):
    return conn.execute("""select oid,proowner,proacl,prosecdef,provolatile,proconfig,prosrc
        from pg_proc where oid='public.enqueue_qw_finding_notifications(uuid)'::regprocedure""").fetchone()


@pytest.fixture
def conveyor_pg(managed_pg):
    """Actual DDL fragments, not whole-bootstrap/issuer acceptance.

    The inherited unrelated269/270/271/272/274 ledger markers and old-scope
    storage policy remain fixture metadata. Only native packet/receipt data and
    one notification subscription are seeded here; managed policy/CP/State/QW/
    jobs/episode reservations/findings/outbox must be created by public runtime.
    """
    import psycopg
    from psycopg.rows import dict_row

    with psycopg.connect(managed_pg[0], autocommit=True, row_factory=dict_row) as conn:
        before = _authority(conn)
        before_publication = _publication_authority(conn)
        conn.execute('set role adlog_storage_owner')
        schema = (ROOT / 'config/postgres_schema.sql').read_text('utf-8')
        # Existing reduced findings has id only. Restore the actual base fields
        # and sequence, retaining its PK/FK dependants and no existing data.
        findings = _table(schema, 'if not exists findings')
        for line in findings.splitlines()[2:-1]:
            column = line.strip().rstrip(',')
            conn.execute('alter table findings add column ' + column)
        conn.execute('create sequence findings_id_seq owned by findings.id')
        conn.execute("alter table findings alter id set default nextval('findings_id_seq')")
        conn.execute('create table normalized_events(normalized_event_id uuid primary key,source_event_id bigint)')
        conn.execute('create table observed_entities(id bigint primary key)')
        # Actual012 cutover binds legacy evidence IDs to the current core.
        conn.execute(_table(schema, 'if not exists finding_evidence').replace(
            'references events(id)', 'references events_v2_core(id)'))
        for name in ('finding_entities', 'finding_status_history'):
            conn.execute(_table(schema, 'if not exists ' + name))
        conn.execute('reset role')
        for name in ('findings', 'finding_evidence', 'finding_entities', 'finding_status_history'):
            conn.execute('alter table ' + name + ' owner to adlog_user')
        publication = _source('055_semantic_finding_publication.sql')
        conn.execute(_region(publication, 'grant select,insert,update on table findings', 'do $$'))
        conn.execute('set role adlog_storage_owner')

        scenario = _source('028_semantic_risk_scenarios.sql')
        conn.execute(_region(scenario, 'create table if not exists semantic_scenario_evidence',
                            'create index if not exists idx_semantic_scenario_identity_window'))
        detect = _source('220_detection_match_risk.sql')
        # Actual220 field/grant omitted by the unrelated empty detection FK fixture.
        evidence_column, = [line.strip().rstrip(',') for line in detect.splitlines()
                            if line.strip().startswith('evidence_key text ')]
        conn.execute('alter table semantic_detection_matches add column ' + evidence_column)
        grant = 'grant select,insert on public.semantic_detection_matches to adlog_semantic_worker;'
        assert detect.count(grant) == 1
        conn.execute(grant)
        conn.execute(_region(detect, 'alter table public.semantic_risk_contributions',
                            'insert into public.schema_migrations'))
        notifications = _source('229_qw_finding_notifications.sql')
        conn.execute(_region(notifications, 'alter table public.semantic_risk_contributions',
                            'alter table public.notification_outbox'))

        queue = _source('029_semantic_risk_runtime.sql')
        # Extend, never replace, jobs: retain real273 QW/deferred guards.
        jobs = _table(queue, 'if not exists semantic_risk_evaluation_jobs')
        missing = ('attempt_count', 'max_attempts', 'available_at', 'lease_token', 'lease_until',
                   'heartbeat_at', 'last_error_code', 'last_error_detail', 'created_at',
                   'updated_at', 'completed_at')
        for name in missing:
            declaration, = [line.strip().rstrip(',') for line in jobs.splitlines()
                            if line.strip().startswith(name + ' ')]
            conn.execute('alter table semantic_risk_evaluation_jobs add column ' + declaration)
        for name in ('semantic_risk_evaluation_lease', 'semantic_risk_evaluation_terminal'):
            clause = jobs.split('constraint ' + name + ' check (', 1)[1].split('\n    ),', 1)[0]
            conn.execute('alter table semantic_risk_evaluation_jobs add constraint ' + name + ' check (' + clause + '\n)')
        conn.execute(_region(queue, 'create table if not exists semantic_risk_evaluation_results',
                            'create index if not exists idx_semantic_risk_subscription_source'))
        completeness = _source('052_semantic_conclusion_completeness.sql')
        conn.execute(_region(completeness, 'alter table semantic_risk_evaluation_results\n    add column',
                            'insert into schema_migrations'))
        conn.execute("insert into schema_migrations values(52,'semantic_conclusion_completeness')")

        # Restore exact219 refs/linker plus264 kind constraint. Do not replace
        # real264 resolver, native203 reader, source bindings, or273/275 bodies.
        assert conn.execute('select count(*) as n from finding_evidence_refs').fetchone()['n'] == 0
        conn.execute('drop table finding_evidence_refs')
        refs = _source('219_finding_evidence_refs.sql')
        conn.execute(_region(refs, 'create table public.finding_evidence_refs',
                            'create function public.resolve_finding_evidence_ref'))
        conn.execute(_region(_source('264_file_audit_acl_bridge.sql'),
                            'alter table public.finding_evidence_refs drop constraint',
                            'revoke all on function public.file_audit_snapshot_quote_v264'))
        conn.execute(_region(refs, 'create function public.link_finding_evidence_ref',
                            'insert into public.schema_migrations'))

        publication = _source('055_semantic_finding_publication.sql')
        conn.execute(_region(publication, 'create table if not exists semantic_finding_publications',
                            'insert into schema_migrations'))
        channels = _source('224_notification_channels.sql')
        conn.execute(_region(channels, 'create table public.notification_channels', 'reset role;'))
        outbox = _source('225_notification_outbox.sql')
        conn.execute(_region(outbox, 'create table public.notification_subscriptions', 'reset role;'))
        conn.execute(_region(notifications, 'alter table public.notification_outbox', '-- Fixed SQL'))
        # Whole265 already installed the current notification admission body.
        # Restore its real historical table dependencies; never regress to229.
        conn.execute(_region(_source('230_nps_threshold.sql'),
                            'alter table public.notification_outbox\n    add column',
                            'create or replace function public.enqueue_qw_finding_notifications'))
        conn.execute(_region(_source('247_decoy_delivery_context.sql'),
                            'alter table public.notification_outbox\n    add column', '-- Reference-only bridge.'))
        conn.execute(_region(_source('253_account_watch.sql'),
                            'alter table public.notification_outbox drop constraint',
                            'create or replace function public.enqueue_qw_finding_notifications'))
        conn.execute(_region(notifications, 'create function public.notification_finding_object', 'reset role;'))
        conn.execute('reset role')
        # Historical055 exact legacy-owner grants;050 exact scenario/queue
        # grants. No principal-specific, source, role or product grants added.
        # Actual054 allows the ordinary consumer completeness ledger guard.
        grant = 'grant select on table schema_migrations to adlog_semantic_worker;'
        assert _source('054_semantic_worker_runtime_schema_guard.sql').count(grant) == 1
        conn.execute(grant)
        conn.execute('grant select,insert on finding_evidence to adlog_storage_owner')
        conn.execute('grant usage,select on sequence finding_evidence_id_seq to adlog_storage_owner')
        conn.execute('grant select,insert,update on normalized_events,semantic_security_scenarios to adlog_semantic_worker')
        conn.execute('grant select,insert on semantic_scenario_steps,semantic_scenario_evidence,semantic_risk_contributions,semantic_scenario_coverage_history,semantic_risk_evaluation_results to adlog_semantic_worker')
        assert _authority(conn) == before
        assert _publication_authority(conn) == before_publication
        conn.execute('set role adlog_user')
        conn.execute("insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled) values(%s,1,2,'smtp',true)", (uuid4(),))
        conn.execute('reset role')
    return managed_pg


def _native_managed(conn):
    # Thin adaptation of the exact native fixture encoder. No native/proof
    # callback is substituted: inbox+receipt carry the managed issued authority.
    at = conn.execute("select clock_timestamp()-interval '400 seconds' as at").fetchone()['at']
    _seed(conn, 10, at=at)
    envelope = json.dumps({'agent_id': AGENT, 'source_instance_id': HOST, 'generation': HOST})
    for table in ('sli_agent_packet_inbox', 'sli_agent_receipts'):
        conn.execute('update ' + table + ' set envelope=%s::jsonb', (envelope,))
    return at


def _identity(conn):
    return conn.execute("select current_user as role,session_user as principal,pg_backend_pid() as pid,"
        "(select oid from pg_roles where rolname=session_user) as principal_oid").fetchone()


def test_actual_managed_conveyor_one_committed_root_to_published_context(conveyor_pg):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    rule = Rule(SCOPE, 'brute')
    policy = factory.risk_policy(rule)
    with psycopg.connect(conveyor_pg[0], autocommit=True, row_factory=dict_row) as observer:
        at = _native_managed(observer)
        for table in ('semantic_password_checkpoints', 'semantic_password_episode_budgets',
                      'semantic_qw_signals', 'semantic_risk_evaluation_jobs', 'findings',
                      'semantic_finding_publications', 'notification_outbox'):
            assert observer.execute('select count(*) as n from ' + table).fetchone()['n'] == 0
        assert observer.execute('select count(*) as n from semantic_risk_policies where policy_id=%s',
                                (policy.policy_id,)).fetchone()['n'] == 0
        authority = _authority(observer)
        publication_authority = _publication_authority(observer)

    # Physical LOGIN, same normal role and owned connection through all stages.
    with psycopg.connect(make_conninfo(conveyor_pg[0], user=conveyor_pg[1]),
                         autocommit=True, row_factory=dict_row) as worker:
        worker.execute('set role adlog_semantic_worker')
        assert assert_semantic_worker_least_privilege(worker.cursor())['exclusive_worker_membership']
        identity = _identity(worker)
        assert identity['principal'] == conveyor_pg[1] and identity['role'] == 'adlog_semantic_worker'
        outcome = producer.run_password_producer(worker, rule=rule, managed_policy=policy)
        assert not outcome.failed and outcome.status == 'committed', outcome
        assert outcome.jobs == outcome.revision == 1
        assert outcome.work['native_items'] == outcome.work['reservation_occurrences'] == 10
        assert _identity(worker) == identity and worker.info.transaction_status == 0
        with worker.transaction():
            claimed, = runtime.claim_risk_evaluation_jobs(worker.cursor())
        assert _identity(worker) == identity and worker.info.transaction_status == 0
        with worker.transaction():
            work = runtime.load_risk_evaluation_work_item(worker.cursor(),
                job_id=claimed['job_id'], lease_token=claimed['lease_token'])
            result = runtime.execute_risk_evaluation(worker.cursor(), work=work,
                evaluation_ms=0, create_finding=True)
        assert result.finding_created and result.finding_id is not None
        assert _identity(worker) == identity and worker.info.transaction_status == 0
        with worker.transaction():
            signal = password_runtime.scenario_password_signal(worker.cursor(), result.scenario_id)
            episode = password_runtime.load_episode(worker.cursor(), signal)
            emission, = episode.emissions
            assert emission.sequence == 1 and emission.previous_id is None and len(emission.root_proof) == 10
            assert len(emission.occurrences) == 10
            assert {w.ref.native_id for w in emission.occurrences} == {str(i) for i in range(1, 11)}
            assert all(w.at == at and w.ref.scope == SCOPE for w in emission.occurrences)
            assert episode.rule == rule and episode.signals == (signal,)
            assert signal.password_context['root_id'] == emission.emission_id
            assert signal.password_context['occurrence_total'] == 10
            assert qw_input.load_qw_signal(worker.cursor(), signal_id=signal.signal_id) == signal
        for table in ('notification_outbox', 'notification_subscriptions', 'semantic_password_checkpoints'):
            assert not worker.execute('select has_table_privilege(current_user,%s,\'SELECT\') as v', (table,)).fetchone()['v']
        assert _identity(worker) == identity

    with psycopg.connect(conveyor_pg[0], autocommit=True, row_factory=dict_row) as observer:
        assert _authority(observer) == authority
        assert _publication_authority(observer) == publication_authority
        stored, = observer.execute('select signal_id,document_json from semantic_qw_signals').fetchall()
        assert stored['signal_id'] == signal.signal_id
        assert stored['document_json']['password_context'] == signal.password_context
        assert signal.execution == rule.execution
        ledger, = observer.execute('select * from semantic_password_episode_budgets').fetchall()
        assert ledger['last_sequence'] == ledger['first_ledger_revision'] == ledger['admitted_revision'] == 1
        assert ledger['reserved_ref_occurrences'] == 10
        job, = observer.execute('select * from semantic_risk_evaluation_jobs').fetchall()
        assert str(job['job_id']) == str(claimed['job_id'])
        assert job['policy_id'] == policy.policy_id and job['policy_version'] == 1
        assert job['source_kind'] == 'qw_signal' and job['evaluation_status'] == 'completed'
        assert job['evaluation_mode'] == 'enabled' and job['qw_signal_id'] == signal.signal_id
        scenario, = observer.execute('select * from semantic_security_scenarios').fetchall()
        assert str(scenario['scenario_id']) == str(result.scenario_id)
        assert scenario['scenario_kind'] == rule.execution['rule_id'] and scenario['evidence_state'] == 'ready'
        step, = observer.execute('select * from semantic_scenario_steps').fetchall()
        assert str(step['scenario_id']) == str(result.scenario_id) and step['qw_signal_id'] == signal.signal_id
        evaluation, = observer.execute('select * from semantic_risk_evaluation_results').fetchall()
        assert str(evaluation['job_id']) == str(job['job_id'])
        assert str(evaluation['scenario_id']) == str(result.scenario_id)
        assert evaluation['evaluation_mode'] == 'enabled' and evaluation['conclusion_state'] == 'observed'
        assert 'supports_negative_conclusion' in evaluation['completeness_snapshot_json']
        publication, = observer.execute('select * from semantic_finding_publications').fetchall()
        assert str(publication['first_job_id']) == str(job['job_id'])
        assert str(publication['scenario_id']) == str(result.scenario_id)
        assert publication['finding_id'] == result.finding_id and publication['published_evidence_count'] == 10
        finding, = observer.execute('select * from findings').fetchall()
        assert finding['id'] == result.finding_id and finding['evidence_count'] == 10
        assert finding['fingerprint'] == publication['finding_fingerprint']
        refs = observer.execute('select * from finding_evidence_refs order by native_id::bigint').fetchall()
        assert len(refs) == 10
        for ref, witness in zip(refs, sorted(emission.occurrences, key=lambda w: int(w.ref.native_id))):
            assert ref['finding_id'] == result.finding_id and ref['storage_kind'] == 'core_event'
            assert ref['native_id'] == witness.ref.native_id and ref['sha256'] == witness.ref.sha256
            assert {key: str(ref[key]) for key in asdict(SCOPE)} == asdict(SCOPE)
        outbox, = observer.execute('select * from notification_outbox').fetchall()
        assert outbox['object_kind'] == 'semantic_finding' and outbox['state'] == 'pending' and outbox['attempts'] == 0
        assert str(outbox['object_id']) == str(outbox['publication_scenario_id']) == str(result.scenario_id)
        assert outbox['recipient_user_id'] == 2 and outbox['channel'] == 'smtp'
        assert observer.execute('select count(*) as n from finding_evidence').fetchone()['n'] == 10
        assert observer.execute('select count(*) as n from notification_attempts').fetchone()['n'] == 0
        observer.execute('set role adlog_user')
        assert observer.execute('select notification_finding_object(%s) as id', (result.scenario_id,)).fetchone()['id'] == result.finding_id
        print('MANAGED_CONVEYOR_PROOF=' + json.dumps({
            'producer_jobs_committed': outcome.jobs, 'producer_revision': outcome.revision,
            'one_physical_worker_oid_pid_role': True, 'native_items': outcome.work['native_items'],
            'root_sequence': emission.sequence, 'episode_occurrences': len(emission.occurrences),
            'typed_refs': len(refs), 'finding_evidence_count': finding['evidence_count'],
            'outbox_rows': 1, 'outbox_attempts': 0, 'postpublication_context_read': True,
            'actual264_prosrc_sha256': sha256(authority['prosrc'].encode()).hexdigest(),
            'actual264_oid_owner_acl_unchanged': True,
            'actual265_enqueue_prosrc_sha256': sha256(publication_authority['prosrc'].encode()).hexdigest(),
            'actual265_enqueue_oid_owner_acl_unchanged': True,
            'completeness_callback': 'actual', 'default_switch': False,
        }, sort_keys=True))
