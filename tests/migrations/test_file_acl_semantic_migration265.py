"""Native SQL authority: ordered ACE masks, unsupported whole DACL, private ACL."""
import json
from copy import deepcopy
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import NAMESPACE_URL, uuid4, uuid5

import pytest

from server.sli.plugins.file_audit.acl import access_mask, parse_dacl
from tests.migrations.test_file_audit_acl_bridge_migration264 import (
    AGENT, INSTALLATION, SCOPE, SOURCE, acl_pg, seed,
)  # noqa: F401
from server.sli.plugins.file_audit.rules import permission_findings

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
def test_native_sql_ordered_masks_and_whole_descriptor_equivalence(native_pg):
    import psycopg

    with psycopg.connect(native_pg) as conn:
        assert conn.execute("select to_regprocedure('public.file_acl_dacl_mask_v265(text,text[])')").fetchone()[0], \
            'native ACL authority missing; refs alone cannot authorize ACL severity'
        for descriptor, expected in CASES:
            parsed, known = parse_dacl(descriptor)
            assert known and access_mask(parsed, {'S-1-1-0'}) == expected
            actual = conn.execute('select public.file_acl_dacl_mask_v265(%s,%s)',
                                  (descriptor, ['S-1-1-0'])).fetchone()[0]
            assert actual == {'supported': True, 'mask': expected}, descriptor
        for descriptor in UNSUPPORTED:
            actual = conn.execute('select public.file_acl_dacl_mask_v265(%s,%s)',
                                  (descriptor, ['S-1-1-0'])).fetchone()[0]
            assert actual == {'supported': False, 'mask': None}, descriptor


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
    config = conn.execute('select policy from sli_plugin_file_audit.policy_revisions').fetchone()[0]
    config.update(service_account_exclusions=[])
    snapshot = item | {'agent_id': AGENT, 'source_instance_id': SOURCE}
    row = permission_findings(snapshot, config=config)[0]
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


def native_history(admin, worker):
    """Three genuine native issuances, with late Jan2 following Jan3/Jan4.

    The reduced retained tables have no management API; all native264/265
    provenance, parser, issuer, row CHECK and worker RLS remain real.
    """
    from sli_agent.envelope import digest
    from tests.migrations.test_file_audit_acl_bridge_migration264 import COMMAND, inventory

    resource, _, _ = retained_result(admin)
    config = admin.execute('select policy from sli_plugin_file_audit.policy_revisions').fetchone()[0]
    config['service_account_exclusions'] = []
    portions = []
    for day in (3, 4, 2):
        item = inventory()
        item.update(observed_at_utc=f'2026-01-0{day}T00:00:00+00:00', scan_id=str(uuid4()))
        item['snapshot_sha256'] = digest({k: v for k, v in item.items() if k not in ('snapshot_id', 'snapshot_sha256')})
        item['snapshot_id'] = str(uuid5(NAMESPACE_URL, COMMAND + item['snapshot_sha256']))
        admin.execute('insert into sli_plugin_file_audit.access_snapshots values(%s,%s,%s,%s,%s,%s::jsonb,%s,%s,0,1)',
                      (item['snapshot_id'], AGENT, SOURCE, SCOPE, item['snapshot_sha256'], json.dumps(item),
                       item['observed_at_utc'], item['completeness']))
        admin.execute("insert into sli_plugin_file_audit.audit_receipts values(%s,%s,%s,1,%s,'verified',%s)",
                      (COMMAND, AGENT, SOURCE, SCOPE, item['observed_at_utc']))
        row = permission_findings(item | {'agent_id': AGENT, 'source_instance_id': SOURCE}, config=config)[0]
        admin.execute('''insert into sli_plugin_file_audit.rule_results values(
          %s,1,%s,%s,%s,%s,1,'observed',%s,%s::jsonb,repeat('0',64))''',
          (row['result_id'], AGENT, SOURCE, SCOPE, row['rule_code'], row['observed_at'], json.dumps(row)))
        admin.execute('''update sli_plugin_file_audit.rule_results set
          result_sha256=encode(sha256(convert_to(result::text,'UTF8')),'hex') where result_id=%s''', (row['result_id'],))
        admin.execute('insert into sli_plugin_file_audit.rule_snapshots values(%s,%s)', (row['result_id'], item['snapshot_id']))
        stored_hash = admin.execute('select result_sha256 from sli_plugin_file_audit.rule_results where result_id=%s',
                                    (row['result_id'],)).fetchone()[0]
        portion = worker.execute('select public.prepare_file_acl_portion_v265(%s::jsonb,%s::jsonb)',
                    (json.dumps(resource), json.dumps([{'result_id': row['result_id'], 'result_sha256': stored_hash}]))).fetchone()[0]
        worker.execute("insert into public.semantic_qw_signals values(%s,'enabled',%s::jsonb,now())",
                       (portion['signal_id'], json.dumps(portion['document'])))
        portions.append(portion)
    return resource, portions


def history_proposal(portion, *, result_class='security_incident', window=300):
    from server.sli.semantic.file_acl_input import signal_from_portion
    from server.sli.semantic.semantic_risk import (
        ConfidenceFactors, MachineRisk, RiskContribution, ScenarioProposal,
        ScenarioResultClass, ScenarioSourceKind, ScenarioStep,
    )

    signal = signal_from_portion(portion)
    source = ScenarioSourceKind.QW_SIGNAL
    return ScenarioProposal(scenario_kind=signal.rule_id, result_class=ScenarioResultClass(result_class),
        partition_key=signal.partition_key,
        strict_keys={'kind': signal.kind, 'entity': signal.entity_key, 'episode': signal.episode_key},
        merge_window=timedelta(seconds=window), title='Synthetic ACL', explanation='Synthetic retained history',
        step=ScenarioStep(step_key=signal.signal_id, source_kind=source, source_id=signal.signal_id,
            occurred_at_utc=signal.occurred_at_utc, title='Synthetic ACL', explanation='Synthetic retained history',
            normalized_event_ids=(), confidence_factors=ConfidenceFactors(), evidence_refs=signal.evidence_refs),
        contribution=RiskContribution(contribution_key=signal.signal_id, source_kind=source, source_id=signal.signal_id,
            policy_id='synthetic-policy', policy_version=1, policy_sha256=b'\x01' * 32, risk_class=MachineRisk.MEDIUM,
            raw_score=Decimal(25), display_points=25, hard_critical=False, rationale='Synthetic', evidence_key=signal.evidence_key))


def insert_history_scenario(conn, portion, **kwargs):
    proposal = history_proposal(portion, **kwargs)
    identity = proposal.identity_sha256
    scenario_id = uuid5(NAMESPACE_URL, 'adlog:semantic-scenario:' + identity.hex())
    conn.execute('''insert into public.semantic_security_scenarios(
      scenario_id,scenario_kind,result_class,identity_key,scenario_key,partition_key,strict_keys_json,
      merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,risk_class)
      values(%s,%s,%s,%s,%s,%s,%s::jsonb,%s,'Synthetic','Synthetic',%s,%s,'medium')''',
      (scenario_id, proposal.scenario_kind, proposal.result_class.value, identity, identity, proposal.partition_key,
       json.dumps(dict(proposal.strict_keys)), int(proposal.merge_window.total_seconds()),
       proposal.step.occurred_at_utc, proposal.step.occurred_at_utc))
    return scenario_id


def append_history_step(conn, scenario_id, portion, *, occurred=None, refresh=True):
    # Actual repository persist_step body, then its established all-step min/max.
    from server.sli.semantic.semantic_risk_repository import _persist_step

    _persist_step(conn.cursor(), scenario_id=str(scenario_id), proposal=history_proposal(portion))
    if occurred is not None:
        conn.execute('update public.semantic_scenario_steps set occurred_at_utc=%s where qw_signal_id=%s',
                     (occurred, portion['signal_id']))
    if refresh:
        conn.execute('''update public.semantic_security_scenarios s set
          first_seen_utc=a.first_at,last_seen_utc=a.last_at,step_count=a.total
          from (select min(occurred_at_utc) first_at,max(occurred_at_utc) last_at,count(*) total
            from public.semantic_scenario_steps where scenario_id=%s) a where s.scenario_id=%s''', (scenario_id, scenario_id))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_native_history_late_jan2_keeps_exact_full_span_and_python_identity(native_pg):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as admin, psycopg.connect(native_pg, autocommit=True) as worker:
        worker.execute('set session authorization adlog_semantic_worker')
        _, portions = native_history(admin, worker)
        # Actual repository body reads dict rows; use its normal row factory.
        from psycopg.rows import dict_row
        admin.row_factory = dict_row
        for result_class, window in (('security_incident', 300), ('security_exposure', 86400), ('control_gap', 1)):
            with admin.transaction():
                scenario_id = insert_history_scenario(admin, portions[0], result_class=result_class, window=window)
                for portion in portions:
                    append_history_step(admin, scenario_id, portion)
                row = admin.execute('select * from public.semantic_security_scenarios where scenario_id=%s', (scenario_id,)).fetchone()
                proposal = history_proposal(portions[0], result_class=result_class, window=window)
                assert row['identity_key'] == row['scenario_key'] == proposal.identity_sha256
                assert row['scenario_id'] == uuid5(NAMESPACE_URL, 'adlog:semantic-scenario:' + proposal.identity_sha256.hex())
                if (result_class, window) == ('security_incident', 300):
                    assert str(row['scenario_id']) == 'b09b85bb-0633-57b0-8f21-b7b1f90203e0'
                assert row['first_seen_utc'].isoformat() == '2026-01-02T00:00:00+00:00'
                assert row['last_seen_utc'].isoformat() == '2026-01-04T00:00:00+00:00'
                assert row['step_count'] == 3
                # Replay does not create another step.
                append_history_step(admin, scenario_id, portions[-1])
            # Remove only this test scenario as owner; no runtime mutation grants.
            with admin.transaction():
                admin.execute('delete from public.semantic_scenario_steps where scenario_id=%s', (scenario_id,))
                admin.execute('delete from public.semantic_security_scenarios where scenario_id=%s', (scenario_id,))


def widened_history(admin, worker):
    from psycopg.rows import dict_row

    resource, portions = native_history(admin, worker)
    admin.row_factory = dict_row
    with admin.transaction():
        scenario_id = insert_history_scenario(admin, portions[0])
        for portion in portions:
            append_history_step(admin, scenario_id, portion)
    return resource, portions, scenario_id


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
def test_wide_acl_requires_complete_seal_identity_and_forbids_first_insert(native_pg):
    import psycopg
    from psycopg.rows import dict_row

    with psycopg.connect(native_pg, autocommit=True) as admin, psycopg.connect(native_pg, autocommit=True) as worker:
        worker.execute('set session authorization adlog_semantic_worker')
        _, portions = native_history(admin, worker)
        admin.row_factory = dict_row
        with admin.transaction():
            scenario_id = insert_history_scenario(admin, portions[0])
            for portion in portions[:2]:
                append_history_step(admin, scenario_id, portion)
        for mutation in (
            "scenario_kind='qw.nps-denials'", "partition_key=repeat('0',64)",
            "strict_keys_json=strict_keys_json||'{\"trusted\":true}'::jsonb",
            "strict_keys_json=jsonb_set(strict_keys_json,'{episode}',to_jsonb(repeat('f',64)))",
            "identity_key=decode(repeat('f',64),'hex')", "scenario_key=decode(repeat('f',64),'hex')",
            "scenario_id='00000000-0000-4000-8000-000000000009'", "result_class='control_gap'", 'merge_window_seconds=301',
        ):
            with pytest.raises(psycopg.errors.CheckViolation) as denied, admin.transaction(force_rollback=True):
                # Has real Jan2 step, but every full identity field must agree.
                append_history_step(admin, scenario_id, portions[-1], refresh=False)
                admin.execute("update public.semantic_security_scenarios set first_seen_utc='2026-01-02T00:00Z'," + mutation +
                              ' where scenario_id=%s', (scenario_id,))
            assert denied.value.diag.constraint_name == 'semantic_scenario_time_window'
        with pytest.raises(psycopg.errors.CheckViolation), admin.transaction(force_rollback=True):
            # Exact identity but no persisted Jan2 proof cannot widen min/max.
            admin.execute("update public.semantic_security_scenarios set first_seen_utc='2026-01-02T00:00Z' where scenario_id=%s", (scenario_id,))
        with pytest.raises(psycopg.errors.CheckViolation), admin.transaction(force_rollback=True):
            admin.execute('''insert into public.semantic_security_scenarios
              select (jsonb_populate_record(null::public.semantic_security_scenarios,to_jsonb(s)||
                jsonb_build_object('scenario_id',%s::text,'scenario_key','\\x'||repeat('ab',32),
                  'first_seen_utc','2026-01-02T00:00Z'))).* from public.semantic_security_scenarios s where scenario_id=%s''',
              (str(uuid4()), scenario_id))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_deferred_all_step_guard_rejects_unsealed_foreign_time_delete_and_move(native_pg):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as admin, psycopg.connect(native_pg, autocommit=True) as issuer:
        issuer.execute('set session authorization adlog_semantic_worker')
        _, portions, scenario_id = widened_history(admin, issuer)
        # A legacy signal is not proof, even if its caller labels it ACL-like.
        foreign_id = 'f' * 64
        admin.execute('''insert into public.semantic_qw_signals(signal_id,evaluation_mode,document_json)
          values(%s,'enabled','{"kind":"threshold","rule_id":"qw.nps-denials","evaluation_mode":"enabled",
            "evidence_refs":[{"storage_kind":"core_event"}]}')''', (foreign_id,))
        with psycopg.connect(native_pg, autocommit=True) as writer:
            writer.execute('set session authorization adlog_storage_worker')
            for signal_id, occurred in ((None, '2026-01-03T00:00Z'), (foreign_id, '2026-01-03T00:00Z'),
                                       (portions[0]['signal_id'], '2026-01-03T00:00:00.000001Z')):
                with pytest.raises(psycopg.errors.CheckViolation) as denied:
                    with writer.transaction():
                        insert_extra_step(writer, scenario_id, signal_id=signal_id, occurred=occurred)
                        # Intentionally no scenario refresh. It is deferred.
                        assert writer.execute('select count(*) from public.semantic_scenario_steps where scenario_id=%s', (scenario_id,)).fetchone()[0] == 4
                assert denied.value.diag.constraint_name == 'semantic_scenario_time_window'
            # Exact sealed duplicate is valid at transaction end; no subset cap.
            with writer.transaction():
                insert_extra_step(writer, scenario_id, signal_id=portions[0]['signal_id'])
            assert writer.execute('select count(*) from public.semantic_scenario_steps where scenario_id=%s', (scenario_id,)).fetchone()[0] == 4
            for permission in ('UPDATE', 'DELETE', 'TRUNCATE'):
                assert writer.execute("select has_table_privilege(session_user,'public.semantic_scenario_steps',%s)", (permission,)).fetchone()[0] is False
        # Existing owner mutation paths are covered too; no mutation grant added.
        for mutation in (
            "update public.semantic_scenario_steps set occurred_at_utc=occurred_at_utc+interval '1 microsecond' where qw_signal_id=%s",
            'delete from public.semantic_scenario_steps where qw_signal_id=%s',
        ):
            with pytest.raises(psycopg.errors.CheckViolation):
                with admin.transaction():
                    admin.execute(mutation, (portions[-1]['signal_id'],))
        other_id = insert_history_scenario(admin, portions[-1], result_class='control_gap')
        with pytest.raises(psycopg.errors.CheckViolation):
            with admin.transaction():
                admin.execute('update public.semantic_scenario_steps set scenario_id=%s where qw_signal_id=%s',
                              (other_id, portions[-1]['signal_id']))
        assert admin.execute('select count(*) total from public.semantic_scenario_steps where scenario_id=%s', (scenario_id,)).fetchone()['total'] == 4


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_wide_history_lifecycle_survives_current_authority_loss_but_not_relabel_or_truncation(native_pg):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as admin, psycopg.connect(native_pg, autocommit=True) as issuer:
        issuer.execute('set session authorization adlog_semantic_worker')
        _, portions, scenario_id = widened_history(admin, issuer)
        original = admin.execute('select * from public.semantic_security_scenarios where scenario_id=%s', (scenario_id,)).fetchone()
        for mutation in ('delete from sli_plugin_file_audit.rule_snapshots; delete from sli_plugin_file_audit.access_snapshots',
                         "update public.sli_agents set status='inactive'",
                         "update public.sli_agents set assigned_modules='[]'",
                         'update public.servers set domain_id=null',
                         'update public.finding_evidence_source_bindings set principal_oid=0'):
            with admin.transaction(force_rollback=True):
                admin.execute(mutation)
                # Owner-only retained proof has no current native lookup.
                assert admin.execute('select public.file_acl_scenario_history_span_allowed_v265(s) allowed from public.semantic_security_scenarios s where scenario_id=%s', (scenario_id,)).fetchone()['allowed']
                admin.execute("update public.semantic_security_scenarios set scenario_status='resolved',title='Owner closed' where scenario_id=%s", (scenario_id,))
                assert issuer.execute('select public.qw_signal_evidence_allowed(%s::jsonb,true)', (json.dumps(portions[0]['document']),)).fetchone()[0] is True
                # Changes above are uncommitted to the other session. Execute
                # native check in this same transaction under its actual login.
                admin.execute('set local session authorization adlog_semantic_worker')
                assert admin.execute('select public.qw_signal_evidence_allowed(%s::jsonb,true) allowed', (json.dumps(portions[0]['document']),)).fetchone()['allowed'] is False
                admin.execute('reset session authorization')
        for mutation in ("scenario_kind='qw.nps-denials'", "partition_key=repeat('e',64)",
                         "strict_keys_json='{}'", "result_class='control_gap'", 'merge_window_seconds=301',
                         "first_seen_utc='2026-01-03T00:00Z'", "last_seen_utc='2026-01-03T00:00Z'",
                         "identity_key=decode(repeat('f',64),'hex')"):
            with pytest.raises(psycopg.errors.CheckViolation), admin.transaction(force_rollback=True):
                admin.execute('update public.semantic_security_scenarios set ' + mutation + ' where scenario_id=%s', (scenario_id,))
        admin.execute("update public.semantic_security_scenarios set scenario_status='resolved' where scenario_id=%s", (scenario_id,))
        append_history_step(admin, scenario_id, portions[-1])
        row = admin.execute('select * from public.semantic_security_scenarios where scenario_id=%s', (scenario_id,)).fetchone()
        assert row['scenario_status'] == 'resolved'
        for field in ('scenario_id', 'identity_key', 'scenario_key', 'first_seen_utc', 'last_seen_utc'):
            assert row[field] == original[field]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_private_history_guards_and_repeatable_read_serialization_fence(native_pg):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as admin, psycopg.connect(native_pg, autocommit=True) as issuer:
        issuer.execute('set session authorization adlog_semantic_worker')
        _, portions, scenario_id = widened_history(admin, issuer)
        for function in ('file_acl_scenario_history_span_allowed_v265(public.semantic_security_scenarios)',
                         'file_acl_scenario_time_guard_v265()', 'file_acl_step_history_guard_v265()'):
            row = admin.execute('select proowner::regrole::text owner,prosecdef,proconfig,pg_get_functiondef(oid) body from pg_proc where oid=%s::regprocedure', (function,)).fetchone()
            assert row['owner'] == 'adlog_storage_owner' and row['prosecdef']
            assert row['proconfig'] == ['search_path=pg_catalog, pg_temp']
            assert all(name not in row['body'] for name in ('file_acl_resource_allowed_v265(', 'file_acl_native_verdict_v265(',
                'qw_signal_evidence_allowed(', 'resolve_finding_evidence_ref(', 'pg_roles', 'session_user', 'semantic_policy_admission'))
            for role in ('adlog_user', 'adlog_storage_worker', 'adlog_semantic_worker'):
                assert admin.execute("select has_function_privilege(%s,%s,'EXECUTE') allowed", (role, function)).fetchone()['allowed'] is False
        trigger = admin.execute("select tgdeferrable,tginitdeferred from pg_trigger where tgrelid='public.semantic_scenario_steps'::regclass and tgname='file_acl_step_history_guard_v265'").fetchone()
        assert trigger == {'tgdeferrable': True, 'tginitdeferred': True}
        before = admin.execute('select * from public.semantic_security_scenarios where scenario_id=%s', (scenario_id,)).fetchone()
        with psycopg.connect(native_pg, autocommit=True) as winner, psycopg.connect(native_pg, autocommit=True) as loser:
            for writer in (winner, loser):
                writer.execute('set session authorization adlog_storage_worker')
                writer.execute('begin isolation level repeatable read')
                writer.execute("set local statement_timeout='3s'")
                writer.execute("set local lock_timeout='1s'")
                assert writer.execute('select count(*) from public.semantic_scenario_steps where scenario_id=%s', (scenario_id,)).fetchone()[0] == 3
            insert_extra_step(winner, scenario_id, signal_id=portions[0]['signal_id'])
            insert_extra_step(loser, scenario_id)  # stale transaction + mixed legacy step
            winner.execute('commit')
            with pytest.raises(psycopg.errors.SerializationFailure):
                loser.execute('commit')
            loser.execute('rollback')
        after = admin.execute('select * from public.semantic_security_scenarios where scenario_id=%s', (scenario_id,)).fetchone()
        assert after == before, 'serialization fence must not touch timestamps/counters/lifecycle'
        assert admin.execute('select count(*) total from public.semantic_scenario_steps where scenario_id=%s', (scenario_id,)).fetchone()['total'] == 4


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_worker_rehashed_string_rule_version_cannot_issue_native_authority(native_pg):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as admin:
        resource, row, stored_hash = retained_result(admin)
        before = authority_counts(admin)
        with psycopg.connect(native_pg, autocommit=True) as worker:
            worker.execute('set session authorization adlog_semantic_worker')
            assert worker.execute('select public.read_file_acl_result_by_id(%s::jsonb,%s,%s)',
                                  (json.dumps(resource), row['result_id'], stored_hash)).fetchone()[0]['status'] == 'verified'
            malformed = row | {'rule_version': '1'}
            admin.execute('''update sli_plugin_file_audit.rule_results set result=%s::jsonb,
                result_sha256=encode(sha256(convert_to((%s::jsonb)::text,'UTF8')),'hex')''',
                (json.dumps(malformed), json.dumps(malformed)))
            bad_hash = admin.execute('select result_sha256 from sli_plugin_file_audit.rule_results').fetchone()[0]
            verdict = worker.execute('select public.read_file_acl_result_by_id(%s::jsonb,%s,%s)',
                                     (json.dumps(resource), row['result_id'], bad_hash)).fetchone()[0]
            assert verdict['status'] == 'blocked_result_detail_subset', 'JSON string1 must not receive native SQL authority'
            with worker.transaction(force_rollback=True), pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute('select public.prepare_file_acl_portion_v265(%s::jsonb,%s::jsonb)',
                    (json.dumps(resource), json.dumps([{'result_id': row['result_id'], 'result_sha256': bad_hash}])))
            assert authority_counts(admin) == before
            admin.execute('''update sli_plugin_file_audit.rule_results set result=%s::jsonb,
                result_sha256=encode(sha256(convert_to((%s::jsonb)::text,'UTF8')),'hex')''',
                (json.dumps(row), json.dumps(row)))
            portion = worker.execute('select public.prepare_file_acl_portion_v265(%s::jsonb,%s::jsonb)',
                (json.dumps(resource), json.dumps([{'result_id': row['result_id'], 'result_sha256': stored_hash}]))).fetchone()[0]
            from server.sli.semantic.file_acl_input import signal_from_portion
            assert signal_from_portion(portion).signal_id == portion['signal_id']


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_worker_numeric_scope_cannot_poison_string_root_before_typed_positive(native_pg, monkeypatch):
    import psycopg
    from tests.migrations import test_file_audit_acl_bridge_migration264 as bridge

    monkeypatch.setattr(bridge, 'SCOPE', '123')
    with psycopg.connect(native_pg, autocommit=True) as admin:
        resource, row, stored_hash = retained_result(admin)
        assert resource['collection_scope_id'] == '123'
        before = authority_counts(admin)
        members = json.dumps([{'result_id': row['result_id'], 'result_sha256': stored_hash}])
        with psycopg.connect(native_pg, autocommit=True) as worker:
            worker.execute('set session authorization adlog_semantic_worker')
            with worker.transaction(force_rollback=True), pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute('select public.prepare_file_acl_portion_v265(%s::jsonb,%s::jsonb)',
                               (json.dumps(resource | {'collection_scope_id': 123}), members))
            assert authority_counts(admin) == before, 'invalid typed resource must not write proof or bindings'
            portion = worker.execute('select public.prepare_file_acl_portion_v265(%s::jsonb,%s::jsonb)',
                                     (json.dumps(resource), members)).fetchone()[0]
            from psycopg.rows import dict_row
            from server.sli.semantic.file_acl_input import signal_from_portion
            from server.sli.semantic.file_acl_runtime import verify_signal
            signal = signal_from_portion(portion)
            assert verify_signal(worker.cursor(row_factory=dict_row), signal).signal_id == portion['signal_id']


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
def test_default_policy_uses_actual029_draft_guard_and_public_before_temp(native_pg):
    import psycopg
    from server.sli.semantic import default_detections, file_acl_input

    with psycopg.connect(native_pg, autocommit=True) as admin:
        resource, _, _ = retained_result(admin)
        policy = file_acl_input.risk_policy(resource, policy_id=default_detections.policy_id(file_acl_input.execution(resource)))
        for role in ('adlog_user', 'adlog_semantic_worker'):
            assert not admin.execute("select has_schema_privilege(%s,'public','CREATE')", (role,)).fetchone()[0]
        assert admin.execute("""select not exists(select 1 from pg_namespace n,
            lateral aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
            where n.nspname='public' and a.grantee=0 and a.privilege_type='CREATE')""").fetchone()[0]
        trigger_before = admin.execute("select pg_get_functiondef('public.enforce_semantic_risk_subscription_draft_only()'::regprocedure)").fetchone()[0]
        with psycopg.connect(native_pg, autocommit=True) as worker:
            worker.execute('set session authorization adlog_semantic_worker')
            # A caller-owned pg_temp relation must not replace the protected
            # public policy relation in029's existing unqualified SELECT.
            worker.execute('create temp table semantic_risk_policies(policy_id text,policy_version integer,lifecycle_status text)')
            worker.execute("insert into pg_temp.semantic_risk_policies values(%s,1,'enabled')", (policy.policy_id,))
            assert worker.execute('select public.ensure_default_qw_policy(%s,1,%s)',
                                  (policy.policy_id, policy.definition_json)).fetchone()[0] is True
            assert admin.execute('select lifecycle_status from public.semantic_risk_policies where policy_id=%s',
                                 (policy.policy_id,)).fetchone()[0] == 'shadow'
            with admin.transaction(force_rollback=True), pytest.raises(psycopg.errors.RaiseException, match='immutable outside draft'):
                admin.execute("update public.semantic_risk_policy_subscriptions set selector_value='forged' where policy_id=%s",
                              (policy.policy_id,))
            admin.execute("update public.semantic_policy_admission set enabled=false,updated_by='synthetic-owner' where policy_id=%s", (policy.policy_id,))
            assert worker.execute('select public.ensure_default_qw_policy(%s,1,%s)',
                                  (policy.policy_id, policy.definition_json)).fetchone()[0] is False
        assert admin.execute("select pg_get_functiondef('public.enforce_semantic_risk_subscription_draft_only()'::regprocedure)").fetchone()[0] == trigger_before
        for function in ('file_acl_resource_allowed_v265(jsonb)', 'file_acl_native_verdict_v265(jsonb,text,text)',
                         'file_acl_dacl_mask_v265(text,text[])'):
            assert admin.execute('select proconfig from pg_proc where oid=%s::regprocedure', (function,)).fetchone()[0] == ['search_path=pg_catalog, pg_temp']


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
def test_server_issues_only_native_medium_portion_and_direct_insert_rejects_mutations(native_pg):
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as admin:
        resource, row, stored_hash = retained_result(admin)
        with psycopg.connect(native_pg, autocommit=True) as worker:
            worker.execute('set session authorization adlog_semantic_worker')
            assert admin.execute("select to_regprocedure('public.prepare_file_acl_portion_v265(jsonb,jsonb)')").fetchone()[0], \
                'trusted portion issuer missing'
            portion = worker.execute('select public.prepare_file_acl_portion_v265(%s::jsonb,%s::jsonb)',
                (json.dumps(resource), json.dumps([{'result_id': row['result_id'], 'result_sha256': stored_hash}]))).fetchone()[0]
            doc = portion['document']
            from server.sli.semantic.file_acl_input import signal_from_portion
            native_signal = signal_from_portion(portion)
            assert native_signal.signal_id == portion['signal_id']
            assert json.loads(json.dumps(native_signal.document)) == doc
            from psycopg.rows import dict_row
            from server.sli.semantic.file_acl_runtime import verify_signal
            assert verify_signal(worker.cursor(row_factory=dict_row), native_signal).signal_id == native_signal.signal_id
            assert doc['effective_severity'] == doc['base_severity'] == 'medium'
            assert worker.execute('select public.file_acl_qw_document_allowed_v265(%s::jsonb)',
                                  (json.dumps(doc),)).fetchone()[0]
            for field, replacement in [('kind', 'threshold'), ('effective_severity', 'high'),
                                       ('rule_id', 'qw.file-acl-direct-write'), ('entity_key', 'e' * 64)]:
                forged = doc | {field: replacement}
                with worker.transaction(force_rollback=True), pytest.raises(psycopg.errors.InsufficientPrivilege):
                    worker.execute('insert into semantic_qw_signals(signal_id,evaluation_mode,document_json) values(%s,%s,%s::jsonb)',
                                   ('a' * 64, 'enabled', json.dumps(forged)))
            worker.execute('insert into semantic_qw_signals(signal_id,evaluation_mode,document_json) values(%s,%s,%s::jsonb)',
                           (portion['signal_id'], 'enabled', json.dumps(doc)))
            assert worker.execute('select count(*) from semantic_qw_signals').fetchone()[0] == 1
            from server.sli.semantic import file_acl_input, default_detections, qw_input
            from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition, compile_risk_policy
            from server.sli.semantic.semantic_risk import ScenarioSourceKind
            policy = file_acl_input.risk_policy(resource, policy_id=default_detections.policy_id(native_signal.execution))
            assert worker.execute('select public.ensure_default_qw_policy(%s,1,%s)',
                                  (policy.policy_id, policy.definition_json)).fetchone()[0]
            high = dict(policy.definition) | {'risk': dict(policy.definition['risk']) | {'class': 'high'}}
            with worker.transaction(force_rollback=True), pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute('select public.ensure_default_qw_policy(%s,1,%s)',
                               (policy.policy_id, json.dumps(high)))
            compiled = compile_risk_policy(RiskPolicyDefinition(policy_id=policy.policy_id, policy_version=1,
                source_kind=ScenarioSourceKind.QW_SIGNAL, definition=high))
            with pytest.raises(RuntimeError, match='file_acl_medium_policy_required'):
                qw_input.qw_signal_proposal(worker.cursor(row_factory=dict_row), policy=compiled, source_id=native_signal.signal_id)
            proposal = qw_input.qw_signal_proposal(worker.cursor(row_factory=dict_row),
                policy=compile_risk_policy(policy), source_id=native_signal.signal_id)
            from dataclasses import replace
            from server.sli.semantic.event_semantic_contract import MachineRisk
            assert proposal.contribution.risk_class is MachineRisk.MEDIUM
            with pytest.raises(RuntimeError, match='file_acl_medium_proposal_required'):
                qw_input.verify_qw_proposal(worker.cursor(row_factory=dict_row), proposal=replace(proposal,
                    contribution=replace(proposal.contribution, risk_class=MachineRisk.HIGH)))
            with worker.transaction(force_rollback=True), pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute('select public.advance_file_acl_checkpoint_v265(%s::jsonb,%s,%s)',
                    (json.dumps(resource), portion['portion_id'], native_signal.signal_id))
            admin.execute('insert into semantic_risk_evaluation_jobs values(%s,1,\'qw_signal\',%s,\'enabled\')',
                          (policy.policy_id, native_signal.signal_id))
            assert worker.execute('select public.advance_file_acl_checkpoint_v265(%s::jsonb,%s,%s)',
                (json.dumps(resource), portion['portion_id'], native_signal.signal_id)).fetchone()[0]
            assert worker.execute('select public.read_pending_file_acl_portions_v265(%s::jsonb)',
                                  (json.dumps(resource),)).fetchone()[0] == []
            admin.execute('update semantic_policy_admission set enabled=false,updated_by=\'synthetic-owner\'')
            assert worker.execute('select public.ensure_default_qw_policy(%s,1,%s)',
                                  (policy.policy_id, policy.definition_json)).fetchone()[0] is False
            assert admin.execute('select count(*) from semantic_control_audit where actor=\'system:defaults\'').fetchone()[0] == 1
            for table in ('semantic_file_acl_portions', 'semantic_file_acl_members', 'semantic_file_acl_episodes'):
                assert not admin.execute('select has_table_privilege(%s,%s,\'INSERT,UPDATE,DELETE,TRUNCATE\')',
                                         ('adlog_semantic_worker', 'public.' + table)).fetchone()[0]
            # A manifest is not a reusable authority after native facts change.
            admin.execute("update sli_plugin_file_audit.access_snapshots set snapshot_sha256=repeat('0',64)")
            assert worker.execute('select public.file_acl_qw_document_allowed_v265(%s::jsonb)',
                                  (json.dumps(doc),)).fetchone()[0] is False


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
