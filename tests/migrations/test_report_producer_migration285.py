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


@pytest.fixture
def producer_pg(monkeypatch, isolated_postgres_integration_database, request):
    dsn = (os.environ.get('ADLOG_TEST_PG_DSN') or '').strip()
    if not dsn:
        pytest.skip('native disposable PostgreSQL template not configured')
    psycopg = pytest.importorskip('psycopg')
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from psycopg.rows import dict_row
    parts = conninfo_to_dict(dsn)
    assert parts.get('dbname', '').startswith('sli_test_')
    assert parts.get('host') in {'127.0.0.1', 'localhost', '::1'}
    assert not parts.get('hostaddr') or parts['hostaddr'] in {'127.0.0.1', '::1'}
    def connect(role='admin', **kwargs):
        return psycopg.connect(dsns[role], row_factory=dict_row, connect_timeout=2,
            application_name='sli-report-native-ci', options='-c statement_timeout=10000 -c lock_timeout=500', **kwargs)
    dsns = {'admin': dsn}
    channel = getattr(request, 'param', 'smtp')
    assert channel in {'smtp', 'telegram'}
    logins = []
    def cleanup():
        if not logins:
            return
        with connect(autocommit=True) as admin:
            for name in logins:
                admin.execute('select pg_terminate_backend(pid) from pg_stat_activity '
                    'where usename=%s and pid<>pg_backend_pid()', (name,))
                if admin.execute("select to_regclass('public.report_producer_principals') as relation").fetchone()['relation']:
                    admin.execute('delete from public.report_producer_principals where principal_name=%s', (name,))
                admin.execute(sql.SQL('drop role {}').format(sql.Identifier(name)))
    # Registered before setup so failures after LOGIN creation also clean up.
    request.addfinalizer(cleanup)
    with connect(autocommit=True) as admin:
        assert_disposable_database(admin)
        assert admin.execute('select name from schema_migrations where version=285').fetchone()['name'] == 'report_producer'
        for kind, group in (('producer', 'adlog_report_producer'), ('delivery', 'adlog_notification_worker')):
            name, password = 'sli_test_report_' + uuid4().hex, secrets.token_urlsafe(32)
            admin.execute(sql.SQL('create role {} login inherit nosuperuser nocreatedb nocreaterole '
                'nobypassrls noreplication password {}').format(sql.Identifier(name), sql.Literal(password)))
            logins.append(name)
            admin.execute(sql.SQL('grant {} to {}').format(sql.Identifier(group), sql.Identifier(name)))
            dsns[kind] = make_conninfo(dsn, user=name, password=password)
        admin.execute('insert into public.report_producer_principals '
            'select oid,rolname from pg_catalog.pg_roles where rolname=%s', (logins[0],))
        ids = []
        for _ in range(2):
            user = admin.execute("insert into public.auth_users(username,password_hash,role) "
                "values(%s,'synthetic-ci-only','viewer') returning id", ('report-' + uuid4().hex,)).fetchone()['id']
            ids.append(user)
            caps = ['reports.export', 'file-audit.view', 'file-audit.export', 'field.identity_basic',
                    'field.technical', 'field.security', 'field.privilege']
            admin.execute("""insert into public.access_capability_assignments
                (subject_type,subject_id,capability_id,effect,scope_json,business_reason,source_type)
                select 'user',%s,id,'allow','{"kind":"all"}'::jsonb,'synthetic report CI','direct'
                from public.access_capabilities where capability_key=any(%s)""", (user, caps))
            admin.execute("""insert into public.access_report_assignments
                (subject_type,subject_id,report_key,effect,scope_json,field_categories,allowed_actions,business_reason)
                values('user',%s,'file-audit.mass-operations','allow','{"kind":"all"}'::jsonb,
                    array['identity_basic','technical','security','privilege'],array['view','export'],'synthetic report CI')""", (user,))
        owner, recipient = ids
        subscription, schedule, agent = uuid4(), uuid4(), uuid4()
        now = admin.execute('select clock_timestamp() as now').fetchone()['now']
        local_time = (now - timedelta(minutes=10)).strftime('%H:%M')
        admin.execute("update public.notification_channels set enabled=true,next_delivery_at='epoch' where kind=%s", (channel,))
        admin.execute("insert into public.notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled) "
                      "values(%s,%s,%s,%s,true)", (subscription, owner, recipient, channel))
        admin.execute("""insert into public.report_schedules
            (id,owner_user_id,report_key,filters,timezone,local_time,weekday,period_days,language,enabled,created_at)
            values(%s,%s,'file-audit.mass-operations','{}','UTC',%s,null,1,'en',true,%s)""",
            (schedule, owner, local_time, now - timedelta(days=2)))
        admin.execute('insert into public.report_schedule_subscriptions values(%s,%s)', (schedule, subscription))
        root = {'collection_scope_id': 'synthetic-root', 'path': 'C:\\Synthetic', 'share_name': None,
                    'source_kind': 'server', 'important': False}
        admin.execute("""insert into sli_plugin_file_audit.policy_revisions
            (agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
            values(%s,'synthetic-source',1,%s,'session',%s,%s::jsonb,%s)""",
            (agent, now, owner, json.dumps({'roots': [root]}), '0' * 64))
        for index, operation in enumerate(('read', 'write', 'delete'), 1):
            rule = 'file-audit.mass-' + operation
            finding = admin.execute("insert into public.findings(fingerprint,rule_code,title,severity) "
                "values(%s,%s,'Synthetic report result','medium') returning id", (uuid4().hex, rule)).fetchone()['id']
            result_id = f'{index:064x}'
            row = {'rule_code': rule, 'agent_id': str(agent), 'source_instance_id': 'synthetic-source',
                'collection_scope_id': 'synthetic-root', 'observed_at': (now - timedelta(hours=1)).isoformat(),
                'details': {'distinct_files': 3, 'window_seconds': 60}, 'conclusion_state': 'observed'}
            admin.execute("""insert into sli_plugin_file_audit.rule_results
                (result_id,finding_id,agent_id,source_instance_id,collection_scope_id,rule_code,
                    rule_version,conclusion_state,observed_at,result,result_sha256)
                values(%s,%s,%s,'synthetic-source','synthetic-root',%s,1,'observed',%s,%s::jsonb,%s)""",
                (result_id, finding, agent, rule, now - timedelta(hours=1), json.dumps(row), '0' * 64))
    from server.sli.access import access_control_v4
    from server.sli.core import notification_outbox as outbox
    from server.sli.core import notification_smtp as smtp
    from server.sli.core import notification_telegram as telegram
    from server.sli.plugins.file_audit import reports as file_reports
    monkeypatch.setattr(access_control_v4, '_connect', lambda: connect('delivery'))
    monkeypatch.setattr(outbox, 'connect', lambda: connect('delivery'))
    # The report oracle runs against the same synthetic retained rows, with
    # the actual saved owner's Python authorization, never the service role.
    monkeypatch.setattr(file_reports, 'connect', connect)
    sent = []
    monkeypatch.setattr(smtp, 'send', lambda job, channel: sent.append(job) or 'accepted')
    monkeypatch.setattr(telegram, 'send', lambda job, channel: sent.append(job) or telegram.Outcome('accepted'))
    yield SimpleNamespace(connect=connect, dsns=dsns, owner=owner, recipient=recipient,
        schedule=schedule, subscription=subscription, sent=sent, psycopg=psycopg, channel=channel)


@contextmanager
def staged(pg, *, sql_candidates=False):
    from server.sli.core import report_schedule_producer as producer
    from server.sli.core.report_schedule_projection import project
    from server.sli.reporting.v2.registry import get_report
    with pg.connect('producer') as conn:
        identity = conn.execute('select session_user,current_user').fetchone()
        assert identity['session_user'] == identity['current_user']
        conn.commit()
        backend, deadline = producer.SqlBackend(conn), time.monotonic() + 20
        token = backend.lead(None, deadline)
        assert token is not None
        claims = backend.claim(token, 2, deadline)
        assert len(claims) == 1 and str(claims[0]['schedule']['id']) == str(pg.schedule)
        claim = claims[0]
        snapshot = backend.facts(claim, deadline)
        if sql_candidates:
            raw = conn.execute('select public.report_schedule_candidates(%s,%s) as value',
                               (claim['job_id'], claim['lease'])).fetchone()['value']
            candidate = producer.normalize_candidate(raw, claim['schedule']['report_key'])
        else:
            candidate = backend.candidates(claim, deadline)
        selection = project(get_report(claim['schedule']['report_key']), snapshot, candidate)['selection']
        yield backend, claim, snapshot, selection, deadline


def publish(pg):
    with staged(pg) as (backend, claim, _snapshot, selection, deadline):
        first = backend.publish(claim, selection, deadline)
        assert first['published'] and first['jobs'] == 1
        assert not backend.publish(claim, selection, deadline)['published']
        return first


def claim_delivery(pg):
    from server.sli.core import notification_outbox as outbox
    job = outbox.claim_job(telegram=True, notification_only=True, include_reports=True)
    assert job is not None
    return job


def test_real_migration_definer_lock_positive_and_direct_access_negative(producer_pg):
    pg = producer_pg
    publish(pg)
    job = claim_delivery(pg)
    with pg.connect('delivery') as delivery:
        identity = delivery.execute('select session_user,current_user').fetchone()
        assert identity['session_user'] == identity['current_user']
        row = delivery.execute('select public.report_schedule_delivery(%s,%s) as prepared',
            (job['id'], job['lease_token'])).fetchone()['prepared']
        assert row['run']['item_count'] == 3 and row['run']['quality'] == 'partial'
    with pg.connect() as admin:
        grants = admin.execute("""select
            has_column_privilege('adlog_report_producer_owner','public.notification_outbox','id','UPDATE') as column_update,
            has_table_privilege('adlog_report_producer_owner','public.notification_outbox','UPDATE') as table_update""").fetchone()
        assert grants == {'column_update': True, 'table_update': False}
    for role, sql in (('producer', 'select * from public.findings_active limit 1'),
                      ('producer', 'select * from public.event_hot limit 1'),
                      ('producer', 'select * from public.finding_event_copies337 limit 1'),
                      ('producer', 'select * from public.report_schedules limit 1'),
                      ('producer', 'select * from public.notification_claim_fair()'),
                      ('producer', 'select * from public.report_delivery_fairness'),
                      ('delivery', 'select * from public.report_delivery_fairness'),
                      ('delivery', 'select * from public.report_schedules limit 1'),
                      ('delivery', 'update public.notification_outbox set id=id where false'),
                      ('producer', 'update public.notification_outbox set id=id where false')):
        with pg.connect(role) as conn, pytest.raises(pg.psycopg.errors.InsufficientPrivilege):
            conn.execute(sql)


@pytest.mark.parametrize('producer_pg', ['smtp', 'telegram'], indirect=True)
def test_due_actual_aggregate_matches_report_then_outbox_and_transport_spy(producer_pg):
    pg = producer_pg
    from server.sli.access.access_control_v4 import effective_access
    from server.sli.core import notification_outbox as outbox
    from server.sli.plugins.file_audit import reports as file_reports
    from server.sli.reporting.v2.access import ReportAccess
    from server.sli.reporting.v2.definition import QueryContext
    from server.sli.reporting.v2.registry import get_report
    with staged(pg) as (backend, claim, _snapshot, selection, deadline):
        candidate = backend.candidates(claim, deadline)
        assert all(set(root) == {'agent_id', 'source_instance_id', 'collection_scope_id', 'source_kind'}
                   for root in candidate['roots'])
        access = effective_access(None, preview_user_id=pg.owner)
        definition = get_report('file-audit.mass-operations')
        context = QueryContext(access=access, params={'period': {'from_utc': claim['period_from'], 'to_utc': claim['slot']}},
            limit=definition.default_limit, scope=ReportAccess(definition, access).scope)
        oracle = file_reports.query('mass-operations', context)
        first = backend.publish(claim, selection, deadline)
        assert first['published']
        assert not backend.publish(claim, selection, deadline)['published']
    assert outbox.process_one(smtp=True, telegram=True, notification_only=True, include_reports=True)
    assert len(pg.sent) == 1
    assert pg.sent[0]['channel'] == pg.channel
    run = pg.sent[0]['report_run']
    assert run['item_count'] == oracle['filtered_count'] == 3
    assert run['quality'] == 'partial' and run['truncated'] == oracle['has_more']
    with pg.connect() as conn:
        assert conn.execute('select count(*) as n from public.report_schedule_runs').fetchone()['n'] == 1
        assert conn.execute('select state from public.notification_outbox').fetchone()['state'] == 'accepted'


@pytest.mark.parametrize('change', ['disabled', 'revision', 'recipient_export'])
def test_change_after_staging_fences_atomic_publication(producer_pg, change):
    pg = producer_pg
    with staged(pg) as (backend, claim, _snapshot, selection, deadline):
        with pg.connect() as admin:
            if change == 'disabled':
                admin.execute('update public.report_schedules set enabled=false where id=%s', (pg.schedule,))
            elif change == 'revision':
                admin.execute('update public.report_schedules set revision=revision+1 where id=%s', (pg.schedule,))
            else:
                admin.execute("""delete from public.access_capability_assignments a using public.access_capabilities c
                    where a.capability_id=c.id and a.subject_type='user' and a.subject_id=%s
                      and c.capability_key='reports.export'""", (pg.recipient,))
        with pytest.raises(RuntimeError):
            backend.publish(claim, selection, deadline)
    with pg.connect() as conn:
        assert conn.execute('select count(*) as n from public.report_schedule_runs').fetchone()['n'] == 0
        assert conn.execute('select count(*) as n from public.notification_outbox').fetchone()['n'] == 0


@pytest.mark.parametrize('retry', [False, True])
def test_revoked_export_after_publication_blocks_actual_worker(producer_pg, monkeypatch, retry):
    pg = producer_pg
    from server.sli.core import notification_outbox as outbox
    from server.sli.core import notification_smtp as smtp
    publish(pg)
    if retry:
        monkeypatch.setattr(smtp, 'send', lambda *_: 'smtp_unavailable')
        assert outbox.process_one(smtp=True, telegram=True, notification_only=True, include_reports=True)
        with pg.connect() as admin:
            assert admin.execute('select state from public.notification_outbox').fetchone()['state'] == 'retry'
            admin.execute('update public.notification_outbox set available_at=clock_timestamp()')
        monkeypatch.setattr(smtp, 'send', lambda job, channel: pg.sent.append(job) or 'accepted')
    with pg.connect() as admin:
        admin.execute("""delete from public.access_capability_assignments a using public.access_capabilities c
            where a.capability_id=c.id and a.subject_type='user' and a.subject_id=%s
              and c.capability_key='reports.export'""", (pg.recipient,))
    assert outbox.process_one(smtp=True, telegram=True, notification_only=True, include_reports=True)
    assert pg.sent == []
    with pg.connect() as conn:
        assert conn.execute('select state from public.notification_outbox').fetchone()['state'] == 'blocked'


@pytest.mark.parametrize('change', ['lease', 'recipient', 'binding_revision', 'disabled_schedule', 'schedule_revision'])
def test_delivery_rejects_wrong_linkage(producer_pg, change):
    pg = producer_pg
    publish(pg)
    job = claim_delivery(pg)
    with pg.connect() as admin:
        if change == 'recipient':
            admin.execute('update public.notification_outbox set recipient_user_id=%s where id=%s', (pg.owner, job['id']))
        elif change == 'binding_revision':
            admin.execute('update public.notification_subscriptions set revision=revision+1 where id=%s', (pg.subscription,))
        elif change == 'disabled_schedule':
            admin.execute('update public.report_schedules set enabled=false where id=%s', (pg.schedule,))
        elif change == 'schedule_revision':
            admin.execute('update public.report_schedules set revision=revision+1 where id=%s', (pg.schedule,))
    with pg.connect('delivery') as conn:
        lease = uuid4() if change == 'lease' else job['lease_token']
        assert conn.execute('select public.report_schedule_delivery(%s,%s) as prepared',
            (job['id'], lease)).fetchone()['prepared'] is None


def test_delivery_holds_schedule_fence_through_transaction(producer_pg):
    pg = producer_pg
    publish(pg)
    job = claim_delivery(pg)
    with pg.connect('delivery') as delivery:
        assert delivery.execute('select public.report_schedule_delivery(%s,%s) as prepared',
            (job['id'], job['lease_token'])).fetchone()['prepared'] is not None
        with pg.connect() as admin, pytest.raises(pg.psycopg.errors.LockNotAvailable):
            admin.execute("set local lock_timeout='50ms'")
            admin.execute('update public.report_schedules set enabled=false where id=%s', (pg.schedule,))


def test_leader_contention_and_concurrent_claim_are_fenced(producer_pg):
    pg = producer_pg
    from server.sli.core.report_schedule_producer import SqlBackend
    deadline = time.monotonic() + 20
    with pg.connect('producer') as conn:
        token = SqlBackend(conn).lead(None, deadline)
    with pg.connect('producer') as conn:
        assert SqlBackend(conn).lead(None, deadline) is None
    def claim(_):
        with pg.connect('producer') as conn:
            return SqlBackend(conn).claim(token, 2, deadline)
    with ThreadPoolExecutor(max_workers=2) as pool:
        portions = list(pool.map(claim, range(2)))
    assert sum(map(len, portions)) == 1



def test_reapply_is_rejected_without_mutating_ledger_or_report_data(producer_pg):
    pg = producer_pg
    with pg.connect(autocommit=True) as admin:
        ledger = admin.execute("select * from public.schema_migrations order by version").fetchall()
        schedules = admin.execute("select * from public.report_schedules order by id").fetchall()
        with pytest.raises(pg.psycopg.errors.RaiseException, match='migration 285 prerequisites failed'):
            admin.execute(DDL)
        admin.rollback()
        assert admin.execute("select * from public.schema_migrations order by version").fetchall() == ledger
        assert admin.execute("select * from public.report_schedules order by id").fetchall() == schedules


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


@pytest.mark.parametrize('backlog', ['new_alerts', 'aged_reports'])
def test_persistent_fair_share_progress_under_continuing_backlog(producer_pg, backlog):
    pg = producer_pg
    publish(pg)
    def alert():
        with pg.connect() as admin:
            admin.execute("""insert into public.notification_outbox
                (id,subscription_id,subscription_revision,object_kind,object_id,recipient_user_id,channel)
                values(%s,%s,1,'test_problem',%s,%s,'smtp')""",
                (uuid4(), pg.subscription, uuid4(), pg.recipient))
    def replenish(job):
        with pg.connect() as admin:
            # Controlled arrival/load fixture: both eligible classes stay
            # nonempty, without invoking a provider or timing a worker cadence.
            admin.execute("update public.notification_outbox set state='pending',result_code=null,"
                "lease_token=null,lease_until=null,available_at=clock_timestamp() where id=%s", (job['id'],))
    with pg.connect() as admin:
        if backlog == 'aged_reports':
            admin.execute("update public.notification_outbox set created_at=clock_timestamp()-interval '1 day' "
                          "where object_kind='report_schedule'")
    alert()
    classes = []
    for _ in range(20):
        if backlog == 'new_alerts':
            alert()  # New alerts keep arriving before every actual SQL claim.
        job = claim_delivery(pg)
        classes.append('R' if job['object_kind'] == 'report_schedule' else 'A')
        replenish(job)
    assert classes == list('AAAR' * 5)
    # Recreate the worker/connection: fairness state belongs to the DB.
    assert claim_delivery(pg)['object_kind'] == 'test_problem'
