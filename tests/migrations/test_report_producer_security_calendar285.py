"""Retained security aggregates, producer ACL and SQL calendar contracts.

Uses the real migrated schema, publication/evidence FKs, saved-owner ACL and
fixed producer RPC. No predicate/report function is replaced, no raw row is
returned to the producer, and no role impersonation substitutes session_user.
Fixtures use finding-owned event copies after retirement of the former store.
"""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from uuid import uuid4

import pytest

from tests.postgres_integration_guard import assert_disposable_database
from tests.migrations.test_report_producer_migration285 import producer_pg as producer_pg, staged

pytestmark = pytest.mark.postgres_integration


def security_population(pg, identity, filters):
    """Seed real synthetic retained rows without disabling any schema guard."""
    from server.sli.core.report_schedule_calendar import latest_slot, period_start
    with pg.connect() as admin:
        schedule = admin.execute('select * from public.report_schedules where id=%s', (pg.schedule,)).fetchone()
        now = admin.execute('select clock_timestamp() as now').fetchone()['now']
        slot = latest_slot(schedule, now)
        start = period_start(schedule, slot)
        at = slot - timedelta(hours=1)
        admin.execute("update public.report_schedules set report_key='security.problems',filters=%s::jsonb "
                      "where id=%s", (json.dumps(filters), pg.schedule))
        for user in (pg.owner, pg.recipient):
            admin.execute("""insert into public.access_report_assignments
                (subject_type,subject_id,report_key,effect,scope_json,field_categories,allowed_actions,business_reason)
                values('user',%s,'security.queue','allow','{"kind":"all"}',
                    array['security','identity_basic'],array['view','export'],'synthetic security report CI')""", (user,))
        if not identity:
            # Actual global field deny overrides role/direct identity grants;
            # this still leaves the report's required security field readable.
            admin.execute("""insert into public.access_capability_assignments
                (subject_type,subject_id,capability_id,effect,scope_json,business_reason,source_type)
                select 'user',%s,id,'deny','{"kind":"all"}','synthetic identity policy','direct'
                from public.access_capabilities where capability_key='field.identity_basic'""", (pg.owner,))
        forest = admin.execute('insert into public.forests(name) values(%s) returning id', ('report-' + uuid4().hex,)).fetchone()['id']
        domain = admin.execute("insert into public.domains(forest_id,fqdn) values(%s,'report.example.test') returning id", (forest,)).fetchone()['id']
        server = admin.execute("insert into public.servers(domain_id,hostname) values(%s,'synthetic-dc') returning id", (domain,)).fetchone()['id']
        source = admin.execute("insert into public.log_sources(name) values(%s) returning id", ('report-' + uuid4().hex,)).fetchone()['id']
        for table, value in (('storage_v2_channel', 'Security'), ('storage_v2_provider', 'Microsoft-Windows-Security-Auditing')):
            # Both identifiers are fixed literals, not caller-picked SQL.
            admin.execute(f'insert into public.{table}(value) values(%s) on conflict(value) do nothing', (value,))
        channel = admin.execute("select id from public.storage_v2_channel where value='Security'").fetchone()['id']
        provider = admin.execute("select id from public.storage_v2_provider where value='Microsoft-Windows-Security-Auditing'").fetchone()['id']
        policy = 'report-ci-' + uuid4().hex
        admin.execute("""insert into public.semantic_risk_policies
            (policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
            values(%s,1,'control_health','draft','{}',%s)""", (policy, bytes(32)))
        subject, member, group = (f'S-1-5-21-100000001-200000002-300000003-{rid}' for rid in (4444, 1101, 512))
        def finding(label, severity='high', status='new', observed=at, publish=True, repeat=0):
            rule = 'semantic.fixture.' + ('membership' if label.startswith('cohort-') else label)
            digest = sha256(uuid4().bytes).digest()
            fingerprint = 'semantic:' + digest.hex()
            identifier = admin.execute("""insert into public.findings
                (fingerprint,rule_code,title,severity,status,first_seen_utc,last_seen_utc,target,evidence_count,repeat_count)
                values(%s,%s,'Synthetic security report',%s,%s,%s,%s,%s,1,%s) returning id""",
                (fingerprint, rule, severity, status, observed.isoformat(), observed.isoformat(), member, repeat)).fetchone()['id']
            event = admin.execute("select nextval('public.storage_v2_event_id_seq') as id").fetchone()['id']
            # Aggregate fixtures retain the same finding-owned event record that
            # the short-event publication path copies before hot retention.
            admin.execute("""insert into public.finding_event_copies337
                (finding_id,event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields,
                 source_sha256,evidence_role,event_record_id)
                values(%s,%s,%s,4728,%s,'synthetic-dc',%s::jsonb,'{}',%s::jsonb,%s,'semantic_scenario',%s)""",
                (identifier, event, observed, domain, json.dumps({'$server_id': server, '$channel': 'Security',
                 '$provider': 'Microsoft-Windows-Security-Auditing', '$principals': {
                     'SubjectUserSid': subject, 'TargetUserSid': group}}),
                 json.dumps({'MemberSid': member}), digest, event))
            if publish:
                observation, job, scenario = uuid4(), uuid4(), uuid4()
                admin.execute("""insert into public.semantic_control_health_observations
                    (observation_id,observation_key,control_id,partition_key,coverage_status,reason,observed_at_utc,source_reference)
                    values(%s,%s,'synthetic.report','report-ci','complete','synthetic fixture',%s,%s)""",
                    (observation, digest, observed, str(observation)))
                admin.execute("""insert into public.semantic_risk_evaluation_jobs
                    (job_id,policy_id,policy_version,source_kind,control_health_id,source_reference,
                        evaluation_mode,idempotency_key,evaluation_status,completed_at)
                    values(%s,%s,1,'control_health',%s,%s,'enabled',%s,'completed',%s)""",
                    (job, policy, observation, str(observation), digest, now))
                admin.execute("""insert into public.semantic_security_scenarios
                    (scenario_id,scenario_kind,result_class,identity_key,scenario_key,partition_key,strict_keys_json,
                        merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
                    values(%s,'synthetic.report','security_exposure',%s,%s,'report-ci','{}',60,
                        'Synthetic report','Synthetic report fixture',%s,%s,'medium')""",
                    (scenario, digest, digest, observed, observed))
                admin.execute("""insert into public.semantic_risk_evaluation_results
                    (job_id,scenario_id,evaluation_mode,risk_class,raw_score,display_score,hard_critical,
                        confidence,confidence_score,coverage_status,evaluation_ms)
                    values(%s,%s,'enabled','medium',1,1,false,'high',100,'complete',0)""", (job, scenario))
                admin.execute("""insert into public.semantic_finding_publications
                    (scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
                    values(%s,%s,%s,%s,1)""", (scenario, identifier, job, fingerprint))
            return identifier, rule
        for number in range(51):
            finding('cohort-' + str(number), severity='critical')
        finding('closed', status='closed')
        finding('progress', status='active')
        suppressed, rule = finding('suppressed')
        admin.execute("""insert into public.semantic_suppressions
            (semantic_type,domain_id,scope_kind,scope_value,reason,expires_at,created_by)
            values(%s,%s,'subject_sid',%s,'synthetic suppression',%s,'fixture-ci')""", (rule, domain, subject, now + timedelta(days=1)))
        assert admin.execute('select public.semantic_finding_suppressed_v160(%s,%s) as hidden',
                             (suppressed, rule)).fetchone()['hidden']
        for label, expiry, repeat in (('accepted', now + timedelta(days=1), 0), ('expired', now - timedelta(hours=1), 1)):
            identifier, rule = finding(label, status='closed', repeat=repeat)
            admin.execute("""insert into public.semantic_suppressions
                (semantic_type,domain_id,scope_kind,scope_value,reason,expires_at,created_at,created_by,
                    kind,finding_id,responsible_user_id,state)
                values(%s,null,'finding',%s,'synthetic acceptance',%s,%s,'fixture-ci',
                    'risk_acceptance',%s,%s,'active')""",
                (rule, str(identifier), expiry, now - timedelta(days=2), identifier, pg.owner))
        finding('start', severity='low', observed=start)
        finding('end', observed=slot)
        finding('before', observed=start - timedelta(seconds=1))
        unpublished, _ = finding('unpublished', publish=False)
        assert not admin.execute('select public.is_semantic_finding_published_v1(%s) as published',
                                 (unpublished,)).fetchone()['published']


def assert_security_aggregate_and_digest_policy(pg, identity, filters, individual, cohorts, *, export_allowed):
    """Check retained-finding counts and the authenticated producer's export ACL."""
    from server.sli.access.access_control_v4 import effective_access
    from server.sli.core.report_schedule_projection import project
    from server.sli.reporting.v2.access import ReportAccess
    from server.sli.reporting.v2.registry import get_report
    with staged(pg, sql_candidates=True) as (backend, claim, snapshot, selection, deadline):
        from server.sli.core.report_schedule_producer import normalize_candidate
        raw = backend.conn.execute('select public.report_schedule_candidates(%s,%s) as value',
                                   (claim['job_id'], claim['lease'])).fetchone()['value']
        candidate = normalize_candidate(raw, claim['schedule']['report_key'])
        assert candidate['counts']['individual']['total'] == individual
        assert candidate['counts']['cohorts']['total'] == cohorts
        assert candidate['counts']['individual']['has_more'] == (individual > 50)
        assert candidate['counts']['cohorts']['has_more'] == (cohorts > 50)
        definition = get_report('security.problems')
        access = effective_access(None, preview_user_id=pg.owner)
        authority = ReportAccess(definition, access)
        assert authority.fields_allowed(frozenset({'identity_basic'})) is identity
        assert definition.export_csv is None
        for user in (pg.owner, pg.recipient):
            ui = effective_access(None, preview_user_id=user)
            worker = snapshot['actors'][user]
            ui_report = next(row for row in ui['reports'] if row['report_key'] == 'security.queue')
            worker_report = next(row for row in worker['reports'] if row['report_key'] == 'security.queue')
            for key in ('report_key', 'version', 'dataset_key', 'dataset_version', 'allowed',
                        'allowed_actions', 'field_categories', 'grants'):
                assert ui_report[key] == worker_report[key], (user, key)
            assert 'reports.export' in ui['capabilities'] and 'reports.export' in worker['capabilities']
            assert ('export' in ui_report['allowed_actions']) is export_allowed
            for actor in (ui, worker):
                if export_allowed:
                    assert ReportAccess(definition, actor, 'export').scope.mode == 'all'
                else:
                    with pytest.raises(PermissionError):
                        ReportAccess(definition, actor, 'export')
        projected = project(definition, snapshot, candidate)
        assert selection['variant'] == ('cohorts' if identity else 'individual')
        expected_count = cohorts if identity else individual
        assert candidate['counts'][selection['variant']]['total'] == expected_count
        assert projected['item_count'] == (expected_count if export_allowed else None)
        assert projected['selection']['include_count'] is export_allowed
        assert selection['include_count'] is export_allowed
        assert projected['truncated'] is (expected_count > 50)
        # This fixture has retained findings, but no collection heartbeat.
        assert projected['quality'] == 'partial'


@pytest.mark.parametrize('identity', [False, True], ids=['security-fields-only', 'identity-basic-fields'])
@pytest.mark.parametrize('filters,individual,cohorts', [
    ({}, 54, 4), ({'severity': 'critical'}, 51, 1), ({'population': 'all'}, 55, 5),
    ({'population': 'attention'}, 53, 3), ({'status': 'closed'}, 1, 1),
    ({'severity': 'high', 'population': 'all'}, 3, 3),
])
def test_security_aggregate_and_owner_variant_match_retained_findings(producer_pg, identity, filters, individual, cohorts):
    security_population(producer_pg, identity, filters)
    assert_security_aggregate_and_digest_policy(producer_pg, identity, filters, individual, cohorts,
                                                 export_allowed=False)


def seed_disposable_synthetic_security_export_policy(pg):
    """Alter only this test clone's dataset/definition; production policy remains unchanged."""
    with pg.connect() as admin:
        assert_disposable_database(admin)
        row = admin.execute("""select r.id as report_id,d.id as dataset_id,d.actions_json,
            r.definition_json->'actions' as report_actions from public.report_registry_v4 r
            join public.report_datasets_v4 d on d.id=r.dataset_id
            where r.report_key='security.queue' and r.status='published'
            order by r.version desc limit 1""").fetchone()
        assert 'export' not in row['actions_json'] and 'export' not in row['report_actions']
        admin.execute("""update public.report_datasets_v4
            set actions_json=actions_json||'["export"]'::jsonb,
                name='Synthetic CI security export dataset' where id=%s""", (row['dataset_id'],))
        assert admin.execute("""update public.report_registry_v4
            set definition_json=jsonb_set(definition_json,'{actions}',
                (definition_json->'actions')||'["export"]'::jsonb),
                name='Synthetic CI security export definition' where id=%s""", (row['report_id'],)).rowcount == 1


@pytest.mark.parametrize('identity', [False, True], ids=['security-fields-only', 'identity-basic-fields'])
def test_disposable_synthetic_export_policy_enables_security_digest_parity(producer_pg, identity):
    security_population(producer_pg, identity, {})
    seed_disposable_synthetic_security_export_policy(producer_pg)
    assert_security_aggregate_and_digest_policy(producer_pg, identity, {}, 54, 4, export_allowed=True)


@pytest.mark.parametrize('zone,wall,weekday,days,now,expected', [
    ('America/New_York', '02:30', None, 1, '2026-03-08T07:15:00+00:00', '2026-03-08T07:00:00+00:00'),
    ('America/New_York', '01:30', None, 1, '2026-11-01T06:45:00+00:00', '2026-11-01T05:30:00+00:00'),
    ('America/New_York', '01:30', None, 1, '2026-11-01T06:00:00+00:00', '2026-11-01T05:30:00+00:00'),
    ('America/New_York', '02:30', 6, 7, '2026-03-08T08:00:00+00:00', '2026-03-08T07:00:00+00:00'),
    ('America/New_York', '02:30', 0, 7, '2026-03-15T15:00:00+00:00', '2026-03-09T06:30:00+00:00'),
    ('America/New_York', '01:30', 0, 7, '2026-11-02T12:00:00+00:00', '2026-11-02T06:30:00+00:00'),
    ('UTC', '09:00', 0, 7, '2026-10-25T12:00:00+00:00', '2026-10-19T09:00:00+00:00'),
])
def test_sql_calendar_latest_and_period_match_python_gap_fold_and_weekly(producer_pg, zone, wall, weekday, days, now, expected):
    from server.sli.core.report_schedule_calendar import latest_slot, period_start
    row = dict(timezone=zone, local_time=wall, weekday=weekday, period_days=days,
               created_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    instant, expected = datetime.fromisoformat(now), datetime.fromisoformat(expected)
    with producer_pg.connect() as admin:
        serialized = {**row, 'created_at': row['created_at'].isoformat()}
        actual = admin.execute('select public.report_calendar_latest(%s::jsonb,%s) as slot',
                               (json.dumps(serialized), instant)).fetchone()['slot']
        assert actual == latest_slot(row, instant) == expected
        beginning = admin.execute("select public.report_calendar_instant("
            "pg_catalog.timezone(%s,%s::timestamptz)-(%s * interval '1 day'),%s) as start",
            (zone, actual, days, zone)).fetchone()['start']
        assert beginning == period_start(row, expected)
        if weekday == 0 and instant.month in {3, 11}:
            assert (actual - beginning).total_seconds() / 3600 == (167 if instant.month == 3 else 169)
        # Creation after the latest witness does not replay an older slot.
        serialized['created_at'] = (expected + timedelta(seconds=1)).isoformat()
        assert admin.execute('select public.report_calendar_latest(%s::jsonb,%s) as slot',
            (json.dumps(serialized), instant)).fetchone()['slot'] is None
