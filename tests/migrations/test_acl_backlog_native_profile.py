"""Actual269 upgrade/exact-byte oracle and bounded native ACL/full-query regression."""
import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from uuid import NAMESPACE_URL, uuid5

import pytest

from server.sli.plugins.file_audit.rules import permission_findings
from server.sli.semantic import semantic_risk_runtime_repository as repository
from server.sli.semantic.file_acl_input import execution
from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
from sli_agent.envelope import canonical, digest
from tests.migrations.test_file_acl_semantic_migration265 import native_pg as native_pg
from tests.migrations.test_file_audit_acl_bridge_migration264 import (
    AGENT, COMMAND, INSTALLATION, SCOPE, SOURCE, acl_pg as acl_pg, seed,
)
from tests.migrations.test_risk_backlog_mode_materialization import query
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
FUNCTIONS = ('file_audit_snapshot_canonical_v264', 'file_audit_snapshot_quote_v264',
             'file_audit_snapshot_provenance_v264', 'file_acl_native_verdict_v265',
             'file_acl_qw_document_allowed_v265', 'semantic_policy_mode_v160')


def section(name, start, end):
    text = (ROOT / 'config/postgres_migrations' / name).read_text('utf-8-sig')
    return text[text.index(start):text.index(end, text.index(start))]


@pytest.fixture
def profile_pg(native_pg, postgres_semantic_worker_dsn):
    import psycopg
    from psycopg import sql
    with psycopg.connect(native_pg, autocommit=True) as admin:
        assert_disposable_database(admin)
        admin.execute(sql.SQL("alter database {} set track_functions='all'").format(
            sql.Identifier(admin.info.dbname)))
        admin.execute('set role adlog_storage_owner')
        # Extend only this reduced fixture's empty non-ACL branch targets.
        admin.execute('''alter table canonical_actions add action_kind text,add action_status text,add occurred_at_utc timestamptz;
          alter table semantic_correlation_candidates add relation_kind text,add candidate_status text,add first_matched_at timestamptz;
          alter table semantic_detection_matches add rule_id text,add evaluation_mode text,add document_json jsonb,add occurred_at_utc timestamptz''')
        admin.execute(section('029_semantic_risk_runtime.sql',
                              'create table if not exists semantic_control_health_observations',
                              'create table if not exists semantic_risk_evaluation_jobs'))
        # The native265 fixture queue is a five-column placeholder. Replace its
        # empty relation with actual029/053/220/228 queue DDL, retaining all guards.
        admin.execute('drop table semantic_risk_evaluation_jobs')
        admin.execute(section('029_semantic_risk_runtime.sql',
                              'create table if not exists semantic_risk_evaluation_jobs',
                              'create table if not exists semantic_risk_evaluation_results'))
        admin.execute(section('053_semantic_canonical_action_risk.sql',
                              'alter table semantic_risk_evaluation_jobs', 'insert into schema_migrations'))
        for name in ('220_detection_match_risk.sql', '228_qw_semantic_input.sql'):
            text = (ROOT / 'config/postgres_migrations' / name).read_text('utf-8-sig')
            start = text.index('alter table public.semantic_risk_evaluation_jobs\n')
            admin.execute(text[start:].split(';', 1)[0] + ';')
        # Existing050 table privileges,153 admission read; no native table grant.
        admin.execute('''grant select,insert,update on semantic_risk_policies,semantic_risk_evaluation_jobs to adlog_semantic_worker;
          grant select on semantic_risk_policy_subscriptions,semantic_policy_admission,canonical_actions,
            semantic_correlation_candidates,semantic_detection_matches,semantic_control_health_observations to adlog_semantic_worker;
          revoke all on function semantic_policy_mode_v160(text,integer,text) from public;
          grant execute on function semantic_policy_mode_v160(text,integer,text) to adlog_semantic_worker;
          revoke all on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) from public;
          grant execute on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) to adlog_semantic_worker''')
        admin.execute('reset role')
        admin.execute("insert into schema_migrations values(266,'file_audit_source_lookup_index'),(267,'file_audit_discovery_join'),(268,'agent_packet_path_lookup_index')")
        before = function_catalog(admin)
        quote = admin.execute("select pg_get_functiondef('public.file_audit_snapshot_quote_v264(text)'::regprocedure)").fetchone()[0]
        admin.execute((ROOT / 'config/postgres_migrations/269_file_audit_canonical_aggregation.sql').read_text('utf-8-sig'))
        assert function_catalog(admin) == before
        assert admin.execute("select pg_get_functiondef('public.file_audit_snapshot_quote_v264(text)'::regprocedure)").fetchone()[0] == quote
        assert admin.execute("select name from schema_migrations where version=269").fetchone()[0] == 'file_audit_canonical_aggregation'
    return native_pg, postgres_semantic_worker_dsn


def retained(admin, near):
    item = seed(admin)
    template = deepcopy(item['objects'][0])
    template.update(path='C:\\synthetic\\file-0000', object_id='object-0000')
    item['objects'] = [template]
    if near:
        for i in range(1, 256):
            part = template | {'path': f'C:\\synthetic\\file-{i:04d}', 'object_id': f'object-{i:04d}'}
            candidate = item | {'objects': item['objects'] + [part]}
            if len(canonical(candidate)) > 48900:
                break
            item = candidate
    assert len(canonical(item)) < 49152
    item['snapshot_sha256'] = digest({k: v for k, v in item.items() if k not in ('snapshot_id', 'snapshot_sha256')})
    item['snapshot_id'] = str(uuid5(NAMESPACE_URL, COMMAND + item['snapshot_sha256']))
    admin.execute('''update sli_plugin_file_audit.access_snapshots set snapshot_id=%s,snapshot_sha256=%s,snapshot=%s::jsonb''',
                  (item['snapshot_id'], item['snapshot_sha256'], json.dumps(item)))
    config = admin.execute('select policy from sli_plugin_file_audit.policy_revisions').fetchone()[0]
    config['service_account_exclusions'] = []
    row = permission_findings(item | {'agent_id': AGENT, 'source_instance_id': SOURCE}, config=config)[0]
    admin.execute('insert into public.findings values(1)')
    admin.execute('''insert into sli_plugin_file_audit.rule_results values(
      %s,1,%s,%s,%s,%s,1,'observed',%s,%s::jsonb,repeat('0',64))''',
                  (row['result_id'], AGENT, SOURCE, SCOPE, row['rule_code'], row['observed_at'], json.dumps(row)))
    admin.execute('''update sli_plugin_file_audit.rule_results set result_sha256=encode(sha256(convert_to(result::text,'UTF8')),'hex')''')
    admin.execute('insert into sli_plugin_file_audit.rule_snapshots values(%s,%s)', (row['result_id'], item['snapshot_id']))
    native_hash = admin.execute('select result_sha256 from sli_plugin_file_audit.rule_results').fetchone()[0]
    resource = dict(installation_id=INSTALLATION, plugin_id='sli.file-audit', agent_id=AGENT,
                    source_instance_id=SOURCE, collection_scope_id=SCOPE)
    return item, resource, row['result_id'], native_hash


def stats(worker):
    rows = worker.execute('''select p.proname,coalesce(s.calls,0) as calls,coalesce(s.total_time,0) as total_ms,
       coalesce(s.self_time,0) as self_ms from pg_proc p left join pg_stat_xact_user_functions s on s.funcid=p.oid
       where p.proname=any(%s)''', (list(FUNCTIONS),)).fetchall()
    return {r['proname']: {k: r[k] for k in ('calls', 'total_ms', 'self_ms')} for r in rows}


def measured(worker, label, call):
    before = stats(worker)
    start = perf_counter()
    result = call()
    elapsed = (perf_counter() - start) * 1000
    after = stats(worker)
    record = {'stage': label, 'elapsed_ms': round(elapsed, 3), 'functions': {
        name: {k: round(after[name][k] - before[name][k], 3) for k in before[name]} for name in before}}
    print('ACL_NATIVE_PROFILE ' + json.dumps(record, sort_keys=True))
    return result


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize('near', [False, True], ids=['small-ascii', 'near49k-ascii'])
def test_actual_acl_full_backlog_profile_and_fresh_denial(profile_pg, near):
    import psycopg
    from psycopg.rows import dict_row
    admin_dsn, worker_dsn = profile_pg
    source = (ROOT / 'server/sli/semantic/semantic_risk_runtime_repository.py').read_bytes().replace(b'\r\n', b'\n')
    assert sha256(source).hexdigest() == '236b821eb338975c046dc9ec754387030309e62646f4cb67a0dcf81c1ede2141'
    with psycopg.connect(admin_dsn) as admin:
        item, resource, result_id, result_hash = retained(admin, near)
        with psycopg.connect(worker_dsn) as login:
            principal = login.execute('select session_user').fetchone()[0]
        admin.execute('''update finding_evidence_source_bindings set principal_oid=(select oid from pg_roles where rolname=%s),principal_name=%s''',
                      (principal, principal))
    with psycopg.connect(worker_dsn, row_factory=dict_row) as worker:
        # The established disposable LOGIN is NOINHERIT; select its sole normal
        # semantic role, preserving physical session_user/OID native binding.
        worker.execute('set role adlog_semantic_worker')
        worker.execute("set local statement_timeout='30s'")
        worker.execute("set local lock_timeout='2s'")
        check = assert_semantic_worker_least_privilege(worker.cursor())
        assert check['exclusive_worker_membership'] and not check['elevated_privileges']
        assert worker.execute('show track_functions').fetchone()['track_functions'] == 'all'
        print('ACL_NATIVE_PROFILE ' + json.dumps({'shape': 'near49k-ascii' if near else 'small-ascii',
              'canonical_bytes': len(canonical(item)), 'objects': len(item['objects']),
              'physical_nonowner_login': True, 'sole_semantic_role': True}))
        for table in ('sli_plugin_file_audit.access_snapshots', 'sli_plugin_file_audit.rule_results'):
            with pytest.raises(psycopg.errors.InsufficientPrivilege), worker.transaction(force_rollback=True):
                worker.execute('select 1 from ' + table)
        portion = measured(worker, 'actual_native_portion_issuance', lambda: worker.execute(
            'select public.prepare_file_acl_portion_v265(%s::jsonb,%s::jsonb) as value',
            (json.dumps(resource), json.dumps([dict(result_id=result_id, result_sha256=result_hash)]))).fetchone()['value'])
        pin_execution = execution(resource)
        with psycopg.connect(admin_dsn) as admin:
            definition = {'source_selector': {'execution': pin_execution}}
            pin = sha256(json.dumps(definition, sort_keys=True).encode()).digest()
            admin.execute('''insert into semantic_risk_policies(policy_id,policy_version,source_kind,definition_json,definition_sha256)
              values('profile-acl',1,'qw_signal',%s::jsonb,%s)''', (json.dumps(definition), pin))
            admin.execute('''insert into semantic_risk_policy_subscriptions values('profile-acl',1,'qw_signal','qw.file-acl-broad-write',%s)''', (pin,))
            admin.execute("update semantic_risk_policies set lifecycle_status='enabled' where policy_id='profile-acl'")
            admin.execute("insert into semantic_policy_admission values('profile-acl',1,true,'fixture')")
        measured(worker, 'actual_qw_insert_rls', lambda: worker.execute(
            "insert into semantic_qw_signals values(%s,'enabled',%s::jsonb,now())", (portion['signal_id'], json.dumps(portion['document']))))
        sql, params = query(limit=100)
        plan = measured(worker, 'exact_backlog_explain_analyze', lambda: worker.execute(
            'explain(analyze,buffers,format json) ' + sql, params).fetchone()['QUERY PLAN'])
        pending = [plan[0]['Plan']]; safe = []
        while pending:
            node = pending.pop(); pending.extend(node.get('Plans', []))
            safe.append({k: node[k] for k in ('Node Type', 'Actual Rows', 'Actual Loops') if k in node})
        print('ACL_NATIVE_PROFILE ' + json.dumps({'stage': 'bounded_plan', 'execution_ms': plan[0]['Execution Time'], 'nodes': safe}))
        jobs = measured(worker, 'exact_enqueue', lambda: repository.enqueue_risk_backlog(worker.cursor(), limit=100))
        assert len(jobs) == 1
        assert measured(worker, 'already_jobbed_empty', lambda: repository.enqueue_risk_backlog(worker.cursor(), limit=100)) == ()
        worker.commit()
        # A new transaction must consult changed retained native content again.
        with psycopg.connect(admin_dsn) as admin:
            admin.execute("update sli_plugin_file_audit.access_snapshots set snapshot=jsonb_set(snapshot,'{share,dacl}','\"D:\"')")
        worker.execute("set local statement_timeout='30s'")
        assert measured(worker, 'fresh_changed_native_qw_denial', lambda: worker.execute(
            'select signal_id from semantic_qw_signals').fetchall()) == []
        assert worker.execute('select count(*) as n from semantic_risk_evaluation_jobs').fetchone()['n'] == 1


def function_catalog(conn):
    return conn.execute("select oid,proowner,proacl,provolatile,prosecdef,proconfig,pronargdefaults,proisstrict,proleakproof,proparallel,procost,prorows,prorettype,proargtypes,prolang from pg_proc where oid='public.file_audit_snapshot_canonical_v264(jsonb,integer)'::regprocedure").fetchone()


def canonical_definitions():
    import re
    text = (ROOT / 'config/postgres_migrations/264_file_audit_acl_bridge.sql').read_text('utf-8-sig')
    original = re.search(r'create function public\.file_audit_snapshot_canonical_v264\(.*?end \$\$;', text, re.S).group()
    frozen = original.replace('public.file_audit_snapshot_canonical_v264', 'public.fixture_acl_old_canonical_v264')
    assert 'public.file_audit_snapshot_canonical_v264' not in frozen
    return original, frozen


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_actual269_canonical_exact_bytes_bounds_and_catalog(profile_pg):
    import psycopg
    admin_dsn, _ = profile_pg
    original, frozen = canonical_definitions()
    with psycopg.connect(admin_dsn) as admin:
        admin.execute('set local role adlog_storage_owner')
        admin.execute(frozen)
        admin.execute("set local statement_timeout='30s'")
        good = [None, True, False, 0, -9007199254740991, 9007199254740991, [], {}, [[], {}],
                ''.join(chr(i) for i in range(1, 128)), '\\"/\b\f\n\r\t',
                ['кириллица', '漢字', 'e\u0301', '\u0080\u07ff\u0800\uffff', '😀𝄞'],
                {'😀': 1, '\uffff': 2, 'a': {'я': 3}}, 'x' * 30000 + 'я']
        deep = 1
        for _ in range(16):
            deep = [deep]
        good.append(deep)
        for kind, overhead in [('string', 2), ('array', 4), ('object', 8)]:
            text = 'x' * (49152 - overhead)
            good.append(text if kind == 'string' else [text] if kind == 'array' else {'a': text})
        # Canonical below49KiB while JSONB presentation exceeds49KiB.
        good.append([{'a': 0, 'b': 0} for _ in range(2800)])
        for value in good:
            rows = admin.execute('select public.file_audit_snapshot_canonical_v264(%s::jsonb),public.fixture_acl_old_canonical_v264(%s::jsonb)',
                                 (json.dumps(value), json.dumps(value))).fetchone()
            assert rows[0] == rows[1] and rows[0].encode('ascii') == canonical(value)
            digest_sql = admin.execute('select encode(sha256(convert_to(%s,\'UTF8\')),\'hex\')', (rows[0],)).fetchone()[0]
            assert digest_sql == sha256(canonical(value)).hexdigest()
            assert str(admin.execute('select public.file_audit_snapshot_uuid_v264(%s,%s)', (COMMAND, digest_sql)).fetchone()[0]) == str(uuid5(NAMESPACE_URL, COMMAND + digest_sql))
        bad = [1.0, 1.5, 9007199254740992, 'x' * 49151, ['x' * 49149], {'a': 'x' * 49145},
               [deep], ['x' * 50000, {'a': 'invalid-child'}], ['x' for _ in range(25000)], ['x' * 98300], ['x' * 98301]]
        for value in bad:
            for function in ('file_audit_snapshot_canonical_v264', 'fixture_acl_old_canonical_v264'):
                with pytest.raises(psycopg.errors.RaiseException, match='file_audit_snapshot_content_invalid'), admin.transaction(force_rollback=True):
                    admin.execute('select public.' + function + '(%s::jsonb)', (json.dumps(value),))
        for function in ('file_audit_snapshot_canonical_v264', 'fixture_acl_old_canonical_v264'):
            for expression in ('null::jsonb,0', "'{}'::jsonb,null", "'{}'::jsonb,-1", "'{}'::jsonb,17"):
                with pytest.raises(psycopg.errors.RaiseException, match='file_audit_snapshot_content_invalid'), admin.transaction(force_rollback=True):
                    admin.execute('select public.' + function + '(' + expression + ')')
        # Every array child is evaluated once: direct child strings each invoke
        # the real unchanged quote exactly once; no duplicate length expression.
        assert admin.execute("show track_functions").fetchone()[0] == 'all'
        before = admin.execute("select coalesce(sum(calls),0) from pg_stat_xact_user_functions where funcid='public.file_audit_snapshot_quote_v264(text)'::regprocedure").fetchone()[0]
        admin.execute('select public.file_audit_snapshot_canonical_v264(%s::jsonb)', (json.dumps(['x'] * 20),))
        after = admin.execute("select coalesce(sum(calls),0) from pg_stat_xact_user_functions where funcid='public.file_audit_snapshot_quote_v264(text)'::regprocedure").fetchone()[0]
        assert after - before == 20
        object_before = after
        admin.execute('select public.file_audit_snapshot_canonical_v264(%s::jsonb)', (json.dumps({str(i): 'x' for i in range(10)}),))
        object_after = admin.execute("select coalesce(sum(calls),0) from pg_stat_xact_user_functions where funcid='public.file_audit_snapshot_quote_v264(text)'::regprocedure").fetchone()[0]
        assert object_after - object_before == 20
        presentation_bounds = [admin.execute('select octet_length(%s::jsonb::text)', (json.dumps(['x' * length]),)).fetchone()[0] for length in (98300, 98301)]
        assert presentation_bounds == [98304, 98305]
        print('ACL_NATIVE_PROFILE ' + json.dumps({'stage': 'actual269_exactness', 'good_cases': len(good),
              'bad_cases_both': len(bad) + 4, 'quote_child_calls': int(after - before), 'object_key_value_quote_calls': int(object_after - object_before), 'presentation_bound_cases': presentation_bounds,
              'catalog_oid_acl_owner_volatility_security_defaults_preserved': True,
              'unchanged_quote': True, 'old_reference_self_recursive': True}))
