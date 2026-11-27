"""Native SQL authority: ordered ACE masks, unsupported whole DACL, private ACL."""
import json
from copy import deepcopy
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import NAMESPACE_URL, uuid4, uuid5

import pytest

from tests.migrations.test_file_audit_acl_bridge_migration264 import (
    AGENT, INSTALLATION, SCOPE, SOURCE, acl_pg, broad_write_fixture, seed,
)  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / 'config/postgres_migrations/265_file_acl_semantic_bridge.sql'


@pytest.fixture
def native_pg(acl_pg):
    import psycopg

    with psycopg.connect(acl_pg, autocommit=True) as conn:
        # Actual predecessor table/RLS definitions, with only unrelated later
        # sections omitted. This is a development fixture, NOT full-schema gate.
        sql187 = (ROOT / 'config/postgres_migrations/187_file_audit_rules.sql').read_text('utf-8')
        table_ddl = sql187[sql187.index('create table sli_plugin_file_audit.rule_results'):sql187.index('revoke all on sli_plugin_file_audit.rule_results')]
        conn.execute('grant references(id) on public.findings to adlog_file_audit_owner')
        conn.execute('set role adlog_file_audit_owner')
        conn.execute('create table sli_plugin_file_audit.actions(action_id text primary key)')
        conn.execute(table_ddl)
        conn.execute('reset role')
        conn.execute('set role adlog_storage_owner')
        conn.execute('create table public.semantic_default_installation(singleton boolean primary key,installation_id uuid)')
        conn.execute('insert into public.semantic_default_installation values(true,%s)', (INSTALLATION,))
        conn.execute('''create table public.semantic_risk_policies(policy_id text,policy_version integer,source_kind text,
          lifecycle_status text default 'draft',definition_json jsonb,definition_sha256 bytea,updated_at timestamptz default now(),
          primary key(policy_id,policy_version));
          create table public.semantic_risk_policy_subscriptions(policy_id text,policy_version integer,source_kind text,
            selector_value text,definition_sha256 bytea,primary key(policy_id,policy_version));
          create table public.semantic_policy_admission(policy_id text,policy_version integer,enabled boolean,
            updated_by text,primary key(policy_id,policy_version));
          create table public.semantic_control_audit(id bigserial primary key,action text,target text,actor text,
            occurred_at timestamptz default now(),details jsonb);
          create table public.semantic_risk_evaluation_jobs(policy_id text,policy_version integer,source_kind text,
            qw_signal_id text,evaluation_mode text);''')
        # Actual pre-baseline029 body/trigger: unqualified policy lookup relies
        # on the calling default-policy function's public resolution contract.
        sql029 = (ROOT / 'config/postgres_migrations/029_semantic_risk_runtime.sql').read_text('utf-8')
        conn.execute(sql029[sql029.index('create or replace function enforce_semantic_risk_subscription_draft_only()'):
                            sql029.index('create table if not exists semantic_control_health_observations')])
        governance = (ROOT / 'config/postgres_migrations/153_semantic_governance.sql').read_text('utf-8')
        for function in ('semantic_control_audit_v160', 'semantic_policy_mode_v160'):
            body = governance.split('create function ' + function + '(', 1)[1].split('$$;', 1)[0]
            conn.execute('create function public.' + function + '(' + body + '$$;')
        conn.execute('''create trigger semantic_policy_admission_audit after insert or update on semantic_policy_admission
          for each row execute function public.semantic_control_audit_v160()''')
        sql219 = (ROOT / 'config/postgres_migrations/219_finding_evidence_refs.sql').read_text('utf-8')
        conn.execute(sql219[sql219.index('create function public.finding_evidence_scope_allowed'):sql219.index('-- Companion')])
        sql228 = (ROOT / 'config/postgres_migrations/228_qw_semantic_input.sql').read_text('utf-8')
        conn.execute(sql228[sql228.index('create table public.semantic_qw_signals'):sql228.index('alter table public.semantic_risk_policies')])
        # Real028 table constraints, followed by the real220/229 step changes.
        # Only unrelated FK targets are reduced to their primary keys.
        conn.execute('''create table public.canonical_actions(canonical_action_id uuid primary key);
          create table public.semantic_correlation_candidates(candidate_id uuid primary key);
          create table public.semantic_detection_matches(match_id text primary key)''')
        sql028 = (ROOT / 'config/postgres_migrations/028_semantic_risk_scenarios.sql').read_text('utf-8')
        conn.execute(sql028[sql028.index('create table if not exists semantic_security_scenarios'):
                            sql028.index('create table if not exists semantic_scenario_evidence')])
        sql220 = (ROOT / 'config/postgres_migrations/220_detection_match_risk.sql').read_text('utf-8')
        conn.execute(sql220[sql220.index('alter table public.semantic_scenario_steps'):
                            sql220.index('alter table public.semantic_risk_contributions')])
        sql229 = (ROOT / 'config/postgres_migrations/229_qw_finding_notifications.sql').read_text('utf-8')
        conn.execute(sql229[sql229.index('alter table public.semantic_security_scenarios'):
                            sql229.index('alter table public.semantic_risk_contributions')])
        conn.execute('''create index idx_semantic_scenario_step_scenario
          on public.semantic_scenario_steps(scenario_id,occurred_at_utc,step_id);
          grant select,insert,update on public.semantic_security_scenarios to adlog_storage_worker;
          grant select,insert on public.semantic_scenario_steps to adlog_storage_worker''')
        conn.execute('''create function public.fixture_qw_gate(document jsonb) returns boolean language sql
          begin atomic select public.qw_signal_evidence_allowed(document,true); end''')
        sql262 = (ROOT / 'config/postgres_migrations/262_default_native_detections.sql').read_text('utf-8')
        conn.execute(sql262[sql262.index('create function public.ensure_default_qw_policy'):sql262.index('create function public.read_default_password_events')])
        conn.execute('reset role')
        if MIGRATION.exists():
            conn.execute(MIGRATION.read_text('utf-8-sig'))
    return acl_pg


CASES = [
    ('D:', 0), ('D:P(A;;FW;;;WD)', 0x120116),
    ('D:(D;;FW;;;WD)(A;;FW;;;WD)', 0),
    ('D:(A;;FW;;;WD)(D;;FW;;;WD)', 0x120116),
    ('D:(A;IO;FA;;;WD)', 0), ('D:(A;ID;FW;;;WD)', 0x120116),
    ('D:(A;OICINPID;0x40000000;;;WD)', 0x120116),
    ('D:PAIAR(A;;FRFW;;;S-1-1-0)', 0x12019f),
    ('D:(A;;0xFFFFFFFF;;;WD)', 0x0fffffff),
    ('D:(A;;FA;;;AU)', 0), ('D:(A;;GW;;;WD)', 0x120116),
    ('D:(A;;0x0;;;WD)', 0), ('D:(A;;;;;WD)', 0),
    ('D:(A;;RCWDWO;;;WD)', 0xe0000),
]
UNSUPPORTED = [None, '', 'S:', 'D:(A;;FW;;;WD)trailing',
               'D:(A;;FW;;;WD)(OA;;FA;;;WD)', 'D:(A;ZZ;FA;;;WD)',
               'D:(A;I;FA;;;WD)', 'D:(A;;FA;guid;;WD)',
               'D:(A;;FA;;;WD;extra)', 'D:(A;;0x100000000;;;WD)',
               'D:(A;;CC;;;WD)', 'D:(A;;FW;;;bad)', 'D:NO_ACCESS_CONTROL',
               'D:(A;;FW;;;WD)(XA;;FR;;;SY)', 'D:(A;;0x_1;;;WD)']


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_worker_cannot_call_native_parser_or_read_retained_sources(native_pg):
    import psycopg

    with psycopg.connect(native_pg) as conn:
        for role in ('adlog_semantic_worker', 'adlog_user'):
            assert conn.execute("select to_regprocedure('public.file_acl_dacl_mask_v265(text,text[])')").fetchone()[0]
            assert not conn.execute('select has_function_privilege(%s,%s,\'EXECUTE\')',
                                    (role, 'public.file_acl_dacl_mask_v265(text,text[])')).fetchone()[0]
            assert not conn.execute('select has_table_privilege(%s,%s,\'SELECT\')',
                                    (role, 'sli_plugin_file_audit.access_snapshots')).fetchone()[0]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_native_parser_does_not_treat_other_sid_unsupported_ace_as_partial_allow(native_pg):
    import psycopg

    with psycopg.connect(native_pg) as conn:
        assert conn.execute("select to_regprocedure('public.file_acl_dacl_mask_v265(text,text[])')").fetchone()[0]
        descriptor = 'D:(A;;FW;;;WD)(XA;;FA;;;SY)'
        assert conn.execute('select public.file_acl_dacl_mask_v265(%s,%s)',
                            (descriptor, ['S-1-1-0'])).fetchone()[0] == {'supported': False, 'mask': None}


def retained_result(conn, *, rich=False):
    item = seed(conn)
    row = broad_write_fixture(item, AGENT, SOURCE)
    if rich:
        row['details']['principal'] = {'kind': 'group', 'domain_users': True}
    conn.execute('insert into public.findings values(1)')
    conn.execute('''insert into sli_plugin_file_audit.rule_results values(
        %s,1,%s,%s,%s,%s,1,'observed',%s,%s::jsonb,repeat('0',64))''',
        (row['result_id'], AGENT, SOURCE, row['collection_scope_id'], row['rule_code'], row['observed_at'], json.dumps(row)))
    conn.execute('''update sli_plugin_file_audit.rule_results set
        result_sha256=encode(sha256(convert_to(result::text,'UTF8')),'hex')''')
    conn.execute('insert into sli_plugin_file_audit.rule_snapshots values(%s,%s)', (row['result_id'], item['snapshot_id']))
    stored_hash = conn.execute('select result_sha256 from sli_plugin_file_audit.rule_results').fetchone()[0]
    resource = {'installation_id': INSTALLATION, 'plugin_id': 'sli.file-audit', 'agent_id': AGENT,
                'source_instance_id': SOURCE, 'collection_scope_id': item['collection_scope_id']}
    return resource, row, stored_hash


def authority_counts(conn):
    return tuple(conn.execute('select count(*) from public.' + table).fetchone()[0] for table in (
        'semantic_file_acl_episodes', 'semantic_file_acl_portions', 'semantic_file_acl_members',
        'finding_evidence_source_bindings', 'semantic_qw_signals'))


def configured_discovery_roots(admin, names):
    """Only synthetic current configuration, never native authority fixtures."""
    modules = admin.execute('select assigned_modules from public.sli_agents where id=%s', (AGENT,)).fetchone()[0]
    original = modules[0]['config']['roots'][0]
    modules[0]['config']['roots'] = [original | {'collection_scope_id': name} for name in names]
    admin.execute('update public.sli_agents set assigned_modules=%s::jsonb where id=%s', (json.dumps(modules), AGENT))
    return modules


def discovered_page(worker, limit=1):
    return worker.execute('select public.read_default_file_acl_resources(null,%s)', (limit,)).fetchone()[0]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_acl_discovery_real_sql_crosses_128_without_observation_sources_and_wraps(native_pg):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as admin, psycopg.connect(native_pg, autocommit=True) as worker:
        seed(admin)
        roots = [f'root-{index:03d}' for index in range(129)]
        configured_discovery_roots(admin, roots)
        assert admin.execute("select to_regclass('sli_plugin_file_audit.observations')").fetchone()[0] is None
        worker.execute('set session authorization adlog_semantic_worker')
        first = discovered_page(worker, 128)
        assert first['has_more'] and len(first['items']) == 128
        second = discovered_page(worker, 128)
        assert not second['has_more'] and len(second['items']) == 1
        assert [r['collection_scope_id'] for r in first['items'] + second['items']] == roots
        assert discovered_page(worker)['items'][0]['collection_scope_id'] == roots[0]
        with pytest.raises(psycopg.errors.InsufficientPrivilege), worker.transaction(force_rollback=True):
            discovered_page(worker, 129)


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_acl_discovery_late_root_behind_committed_cursor_returns_after_eof(native_pg):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as admin, psycopg.connect(native_pg, autocommit=True) as worker:
        seed(admin)
        configured_discovery_roots(admin, ['root-b', 'root-c'])
        worker.execute('set session authorization adlog_semantic_worker')
        first = discovered_page(worker)
        assert first['has_more'] and first['items'][0]['collection_scope_id'] == 'root-b'
        configured_discovery_roots(admin, ['root-a', 'root-b', 'root-c'])
        second = discovered_page(worker)
        assert not second['has_more'] and second['items'][0]['collection_scope_id'] == 'root-c'
        third = discovered_page(worker)
        assert third['has_more'] and third['items'][0]['collection_scope_id'] == 'root-a'


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_acl_discovery_cursor_commits_independently_of_current_native_denial(native_pg):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as admin, psycopg.connect(native_pg, autocommit=True) as worker:
        resource, _, _ = retained_result(admin)
        enabled = configured_discovery_roots(admin, [SCOPE, 'zz-later-root'])
        worker.execute('set session authorization adlog_semantic_worker')
        first = discovered_page(worker)
        assert first['items'] == [resource] and first['has_more']
        cursor = admin.execute("select after_key from public.semantic_file_acl_scan_state where resource_key='_resources'").fetchone()[0]
        before = authority_counts(admin)
        disabled = deepcopy(enabled)
        disabled[0]['enabled'] = False
        admin.execute('update public.sli_agents set assigned_modules=%s::jsonb where id=%s', (json.dumps(disabled), AGENT))
        # Discovery is not authority: a post-discovery configuration change is
        # rejected by the existing native gate inside the resource transaction.
        with pytest.raises(psycopg.errors.InsufficientPrivilege), worker.transaction():
            worker.execute('select public.read_file_acl_results(%s::jsonb,null,32)', (json.dumps(resource),))
        assert authority_counts(admin) == before
        assert admin.execute("select after_key from public.semantic_file_acl_scan_state where resource_key='_resources'").fetchone()[0] == cursor
        admin.execute('update public.sli_agents set assigned_modules=%s::jsonb where id=%s', (json.dumps(enabled), AGENT))
        second = discovered_page(worker)
        assert not second['has_more'] and second['items'][0]['collection_scope_id'] == 'zz-later-root'
        assert discovered_page(worker)['items'] == [resource]
        # Real role privileges remain narrow; application/storage worker cannot
        # discover ACL resources even if they know the function signature.
        for role in ('adlog_user', 'adlog_storage_worker'):
            assert not admin.execute("select has_function_privilege(%s,'public.read_default_file_acl_resources(jsonb,integer)','EXECUTE')", (role,)).fetchone()[0]


def insert_extra_step(conn, scenario_id, *, signal_id=None, occurred='2026-01-03T00:00:00+00:00'):
    conn.execute('''insert into public.semantic_scenario_steps(
      step_id,scenario_id,step_key,source_kind,control_reference,qw_signal_id,occurred_at_utc,
      title,explanation,confidence,confidence_score,confidence_factors_json)
      values(%s,%s,%s,%s,%s,%s,%s,'Synthetic','Synthetic','medium',50,'{}')''',
      (uuid4(), scenario_id, uuid4().bytes + uuid4().bytes,
       'qw_signal' if signal_id else 'control_health', None if signal_id else 'synthetic-control', signal_id, occurred))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize('kind', ['legacy', 'R01', 'qw.nps-denials', 'qw.password-spray', 'qw.account-decoy'])
def test_ordinary_scenarios_keep_actual_24h_ordering_and_merge_bounds(native_pg, kind):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as conn:
        scenario_id = uuid4()
        conn.execute('''insert into public.semantic_security_scenarios(
          scenario_id,scenario_kind,result_class,identity_key,scenario_key,partition_key,strict_keys_json,
          merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
          values(%s,%s,'security_incident',%s,%s,'synthetic','{}',300,'Synthetic','Synthetic',
          '2026-01-03T00:00Z','2026-01-04T00:00Z','medium')''', (scenario_id, kind, b'x' * 32, b'y' * 32))
        for mutation in ("last_seen_utc=last_seen_utc+interval '1 microsecond'",
                         "last_seen_utc=first_seen_utc-interval '1 microsecond'",
                         'merge_window_seconds=0', 'merge_window_seconds=86401'):
            with pytest.raises(psycopg.errors.CheckViolation), conn.transaction(force_rollback=True):
                conn.execute('update public.semantic_security_scenarios set ' + mutation + ' where scenario_id=%s', (scenario_id,))
        with pytest.raises(psycopg.errors.CheckViolation) as denied, conn.transaction(force_rollback=True):
            conn.execute('''insert into public.semantic_security_scenarios
              select (jsonb_populate_record(null::public.semantic_security_scenarios,to_jsonb(s)||
                jsonb_build_object('scenario_id',%s::text,'scenario_key','\\x'||repeat('ab',32),
                  'last_seen_utc','2026-01-04T00:00:00.000001Z'))).* from public.semantic_security_scenarios s
              where scenario_id=%s''', (str(uuid4()), scenario_id))
        assert denied.value.diag.constraint_name == 'semantic_scenario_time_window'


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_worker_resource_shape_types_lengths_and_uuid_spelling_fail_closed(native_pg):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as admin:
        resource, row, stored_hash = retained_result(admin)
        before = authority_counts(admin)
        members = json.dumps([{'result_id': row['result_id'], 'result_sha256': stored_hash}])
        malformed = [None, [], 'resource', resource | {'extra': 'unsupported'},
                     {k: v for k, v in resource.items() if k != 'plugin_id'}]
        malformed += [resource | {field: value} for field in resource for value in (None, True, 7, [], {}, '', 'x' * 257)]
        malformed += [resource | {field: resource[field].replace('-', '')} for field in ('installation_id', 'agent_id')]
        with psycopg.connect(native_pg, autocommit=True) as worker:
            worker.execute('set session authorization adlog_semantic_worker')
            for invalid in malformed:
                with worker.transaction(force_rollback=True), pytest.raises(psycopg.errors.InsufficientPrivilege):
                    worker.execute('select public.prepare_file_acl_portion_v265(%s::jsonb,%s::jsonb)',
                                   (json.dumps(invalid), members))
            assert authority_counts(admin) == before


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_owner_native_verdict_recomputes_retained_grant_and_rejects_rehashed_caller_mask(native_pg):
    import psycopg

    with psycopg.connect(native_pg) as conn:
        resource, row, stored_hash = retained_result(conn)
        assert conn.execute("select to_regprocedure('public.file_acl_native_verdict_v265(jsonb,text,text)')").fetchone()[0], \
            'native result authority missing'
        verdict = conn.execute('select public.file_acl_native_verdict_v265(%s::jsonb,%s,%s)',
                               (json.dumps(resource), row['result_id'], stored_hash)).fetchone()[0]
        assert verdict['status'] == 'verified'
        assert verdict['severity'] == 'medium'
        altered = deepcopy(row)
        altered['details']['effective_smb_mask'] = 2032127
        altered['details']['membership_complete'] = True
        conn.execute('''update sli_plugin_file_audit.rule_results set result=%s::jsonb,
            result_sha256=encode(sha256(convert_to((%s::jsonb)::text,'UTF8')),'hex')''',
            (json.dumps(altered), json.dumps(altered)))
        changed_hash = conn.execute('select result_sha256 from sli_plugin_file_audit.rule_results').fetchone()[0]
        denied = conn.execute('select public.file_acl_native_verdict_v265(%s::jsonb,%s,%s)',
                              (json.dumps(resource), row['result_id'], changed_hash)).fetchone()[0]
        assert denied['status'] == 'blocked_result_detail_subset'


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_ref_only_predecessor_cannot_admit_forged_legacy_kind_around_snapshot(native_pg):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as admin:
        resource, row, stored_hash = retained_result(admin)
        admin.execute('''insert into finding_evidence_source_bindings select
            (select oid from pg_roles where rolname='adlog_semantic_worker'),'adlog_semantic_worker',
            installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind,
            log_source_id,agent_key,agent_id from finding_evidence_source_bindings limit 1''')
        # Shared development worker is NOLOGIN. Exercise its actual session
        # authority without altering cluster-global roles; authenticated LOGIN
        # MEMBER coverage remains a separate isolated full-schema release gate.
        with psycopg.connect(native_pg) as worker:
            worker.execute('set session authorization adlog_semantic_worker')
            ref = {'scope': {k: v for k, v in resource.items() if k != 'agent_id'},
                   'storage_kind': 'file_audit_snapshot', 'native_id': row['snapshot_ids'][0],
                   'sha256': row['details']['snapshot_sha256']}
            ref['scope']['source_generation'] = 'audit-command:synthetic-command'
            forged = {'kind': 'threshold', 'rule_id': 'qw.nps-denials',
                      'effective_severity': 'high', 'evaluation_mode': 'enabled', 'evidence_refs': [ref]}
            assert worker.execute('select public.fixture_qw_gate(%s::jsonb)', (json.dumps(forged),)).fetchone()[0] is False
            with worker.transaction(force_rollback=True), pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute('insert into semantic_qw_signals(signal_id,evaluation_mode,document_json) values(%s,%s,%s::jsonb)',
                               ('f' * 64, 'enabled', json.dumps(forged)))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_bounded_reader_uses_native_verdict_and_hides_foreign_resource(native_pg):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as admin:
        resource, row, stored_hash = retained_result(admin)
        with psycopg.connect(native_pg, autocommit=True) as worker:
            worker.execute('set session authorization adlog_semantic_worker')
            page = worker.execute('select public.read_file_acl_results(%s::jsonb,null,32)',
                                  (json.dumps(resource),)).fetchone()[0]
            assert len(page['items']) == 1 and page['items'][0]['status'] == 'verified'
            assert page['has_more'] is False
            assert page['items'][0]['result']['result_id'] == row['result_id']
            with worker.transaction(force_rollback=True), pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute('select public.read_file_acl_results(%s::jsonb,null,32)',
                               (json.dumps(resource | {'source_instance_id': 'other-source'}),))
            worker.execute('select public.prepare_file_acl_portion_v265(%s::jsonb,%s::jsonb)',
                (json.dumps(resource), json.dumps([{'result_id': row['result_id'], 'result_sha256': stored_hash}])))
            page = worker.execute('select public.read_file_acl_results(%s::jsonb,null,32)',
                                  (json.dumps(resource),)).fetchone()[0]
            assert page['items'] == []  # prepared member recovery uses exact immutable portion
            pending = worker.execute('select public.read_pending_file_acl_portions_v265(%s::jsonb)',
                                     (json.dumps(resource),)).fetchone()[0]
            assert len(pending) == 1
