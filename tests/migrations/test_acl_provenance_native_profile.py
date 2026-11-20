#!/usr/bin/env python3
"""Actual269 provenance/RLS baseline only; synthetic disposable PG, no candidate."""
import json
import re
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from statistics import median
from time import perf_counter
from uuid import NAMESPACE_URL, uuid5

import pytest

from server.sli.semantic import semantic_risk_runtime_repository as repository
from server.sli.semantic.file_acl_input import execution
from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
from sli_agent.envelope import canonical, digest
from tests.migrations.test_acl_backlog_native_profile import (
    acl_pg as acl_pg, native_pg as native_pg, profile_pg as profile_pg, retained,
)
from tests.migrations.test_file_audit_acl_bridge_migration264 import AGENT, COMMAND, INSTALLATION, SCOPE, SOURCE
from tests.migrations.test_risk_backlog_mode_materialization import query

ROOT = Path(__file__).resolve().parents[2]
NAMES = (
    'resolve_finding_evidence_ref', 'file_audit_snapshot_canonical_v264',
    'file_audit_snapshot_quote_v264', 'file_audit_snapshot_uuid_v264',
    'file_audit_path_in_root_v264', 'file_audit_snapshot_provenance_v264',
    'file_acl_native_verdict_v265', 'file_acl_qw_document_allowed_v265',
    'file_acl_resource_allowed_v265', 'file_acl_dacl_mask_v265',
    'qw_signal_evidence_allowed', 'prepare_file_acl_portion_v265',
)
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def definitions():
    bodies = {}
    for name in ('264_file_audit_acl_bridge.sql', '265_file_acl_semantic_bridge.sql',
                 '269_file_audit_canonical_aggregation.sql'):
        text = (ROOT / 'config/postgres_migrations' / name).read_text('utf-8-sig')
        pattern = r'create (?:or replace )?function public\.([a-z0-9_]+)\([^;]*?as \$\$(.*?)\$\$;'
        current = {}
        for match in re.finditer(pattern, text, re.S | re.I):
            current.setdefault(match[1], set()).add(sha256(match[2].encode()).hexdigest())
        bodies.update(current)
    return bodies


def catalog(admin):
    expected = definitions()
    functions = []
    for row in admin.execute('''select p.oid,p.proname,p.oid::regprocedure::text,
      pg_get_userbyid(p.proowner),p.proacl::text,p.prosecdef,p.provolatile,p.proconfig,
      p.pronargdefaults,p.proisstrict,p.proleakproof,p.proparallel,p.prosrc
      from pg_proc p join pg_namespace n on n.oid=p.pronamespace
      where n.nspname='public' and p.proname=any(%s) order by p.oid''', (list(NAMES),)).fetchall():
        body_hash = sha256(row[-1].encode()).hexdigest()
        assert body_hash in expected[row[1]]
        if row[1] == 'file_audit_snapshot_canonical_v264':
            assert body_hash == 'c01376962c1efff5a4010707d21af0930de0cedb07b28ac4816ddd9beb74c8b4'
        functions.append(dict(oid=row[0], name=row[1], signature=row[2], owner=row[3], acl=row[4],
                              security_definer=row[5], volatility=row[6], config=row[7], defaults=row[8],
                              strict=row[9], leakproof=row[10], parallel=row[11], body_sha256=body_hash))
    assert {f['name'] for f in functions} == set(NAMES)
    assert len([f for f in functions if f['name'] == 'file_acl_dacl_mask_v265']) == 2
    relations = admin.execute('''select n.nspname,c.relname,pg_get_userbyid(c.relowner),
      c.relacl::text,c.relrowsecurity,c.relforcerowsecurity from pg_class c
      join pg_namespace n on n.oid=c.relnamespace where c.oid in (
      'public.servers'::regclass,'sli_plugin_file_audit.access_snapshots'::regclass,
      'sli_plugin_file_audit.audit_commands'::regclass,'sli_plugin_file_audit.audit_receipts'::regclass,
      'sli_plugin_file_audit.policy_revisions'::regclass,'sli_plugin_file_audit.rule_results'::regclass,
      'sli_plugin_file_audit.rule_snapshots'::regclass,'semantic_qw_signals'::regclass,
      'semantic_file_acl_portions'::regclass,'semantic_file_acl_members'::regclass,
      'finding_evidence_source_bindings'::regclass) order by c.oid''').fetchall()
    indexes = admin.execute('''select c.relname,i.indisvalid,i.indisready,pg_get_indexdef(c.oid)
      from pg_index i join pg_class c on c.oid=i.indexrelid where i.indrelid in (
      'sli_plugin_file_audit.access_snapshots'::regclass,'sli_plugin_file_audit.audit_commands'::regclass,
      'sli_plugin_file_audit.audit_receipts'::regclass,'sli_plugin_file_audit.policy_revisions'::regclass,
      'sli_plugin_file_audit.rule_results'::regclass,'sli_plugin_file_audit.rule_snapshots'::regclass,
      'semantic_file_acl_portions'::regclass,'semantic_file_acl_members'::regclass,
      'semantic_qw_signals'::regclass,'finding_evidence_source_bindings'::regclass) order by c.oid''').fetchall()
    assert admin.execute("select pg_get_userbyid(relowner) from pg_class where oid='public.servers'::regclass").fetchone()[0] == 'adlog_user'
    assert not admin.execute("select has_table_privilege('adlog_storage_owner','public.servers','SELECT')").fetchone()[0]
    for column in ('hostname', 'is_active', 'domain_id'):
        assert admin.execute("select has_column_privilege('adlog_storage_owner','public.servers',%s,'SELECT')", (column,)).fetchone()[0]
    return dict(functions=functions, relations=relations, indexes=indexes)


def stats(admin, worker):
    worker.execute('select pg_stat_force_next_flush()')
    admin.execute('select pg_stat_clear_snapshot()')
    return {r[0]:dict(signature=r[1], name=r[2], calls=r[3], total_ms=r[4], self_ms=r[5])
            for r in admin.execute('''select p.oid,p.oid::regprocedure::text,p.proname,
              coalesce(s.calls,0),coalesce(s.total_time,0),coalesce(s.self_time,0)
              from pg_proc p left join pg_stat_user_functions s on s.funcid=p.oid
              where p.proname=any(%s)''', (list(NAMES),)).fetchall()}


def measure(admin, worker, call):
    before = stats(admin, worker)
    started = perf_counter()
    value = call()
    elapsed = (perf_counter()-started)*1000
    after = stats(admin, worker)
    delta = {str(oid):dict(signature=r['signature'], name=r['name'], **{
        key:r[key]-before[oid][key] for key in ('calls', 'total_ms', 'self_ms')}) for oid,r in after.items()}
    return value, dict(wall_ms=elapsed, functions=delta)


def calls(record, name):
    return sum(r['calls'] for r in record['functions'].values() if r['name'] == name)


def public_read(worker, item):
    return worker.execute('''select public.resolve_finding_evidence_ref(
      %s,'sli.file-audit',%s,%s,%s,'file_audit_snapshot',%s,%s) as verified''',
      (INSTALLATION, SOURCE, 'audit-command:'+COMMAND, SCOPE,
       item['snapshot_id'], item['snapshot_sha256'])).fetchone()['verified']


def reset_snapshot(admin, item):
    admin.execute('''update sli_plugin_file_audit.access_snapshots
      set snapshot_id=%s,snapshot_sha256=%s,snapshot=%s::jsonb''',
      (item['snapshot_id'],item['snapshot_sha256'],json.dumps(item)))


@pytest.mark.parametrize('near', [False, True], ids=['one-object', '256-objects'])
def test_actual269_provenance_public_native_rls_baseline(profile_pg, near):
    import psycopg
    from psycopg.rows import dict_row
    admin_dsn, worker_dsn = profile_pg
    assert sha256((ROOT/'server/sli/semantic/semantic_risk_runtime_repository.py').read_bytes().replace(b'\r\n',b'\n')).hexdigest() == '236b821eb338975c046dc9ec754387030309e62646f4cb67a0dcf81c1ede2141'
    result = dict(scope='synthetic actual269 provenance baseline; no candidate/SPI count', stages={})
    with psycopg.connect(admin_dsn, autocommit=True) as admin, psycopg.connect(worker_dsn, autocommit=True, row_factory=dict_row) as worker:
        worker.execute('set role adlog_semantic_worker')  # Physical fixture LOGIN is NOINHERIT.
        worker.execute("set statement_timeout='30s'")
        worker.execute("set lock_timeout='2s'")
        check = assert_semantic_worker_least_privilege(worker.cursor())
        assert check['exclusive_worker_membership'] and not check['elevated_privileges']
        assert worker.execute('show track_functions').fetchone()['track_functions'] == 'all'
        item, resource, result_id, result_hash = retained(admin, near)
        expected_objects = 256 if near else 1
        assert len(item['objects']) == expected_objects
        compact = len(canonical(item))
        presentation = admin.execute('select octet_length(snapshot::text) from sli_plugin_file_audit.access_snapshots').fetchone()[0]
        assert compact <= 49152 and presentation <= 98304
        result.update(objects=expected_objects, canonical_bytes=compact, jsonb_presentation_bytes=presentation,
                      physical_nonowner_login=True, selected_semantic_role=True)
        principal = worker.execute('select session_user as principal').fetchone()['principal']
        admin.execute('''update finding_evidence_source_bindings
          set principal_oid=(select oid from pg_roles where rolname=%s),principal_name=%s''', (principal,principal))
        before_catalog = catalog(admin)
        result['catalog_before'] = before_catalog
        for table in ('sli_plugin_file_audit.access_snapshots','sli_plugin_file_audit.rule_results',
                      'sli_plugin_file_audit.audit_commands','sli_plugin_file_audit.audit_receipts',
                      'sli_plugin_file_audit.policy_revisions'):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute('select 1 from '+table)
        for sql in ("select public.file_audit_snapshot_provenance_v264(%s,%s)",
                    "select public.file_audit_snapshot_canonical_v264(%s::jsonb)"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute(sql, (AGENT,item['snapshot_id']) if 'provenance' in sql else ('{}',))
        positive, known = measure(admin, worker, lambda: public_read(worker,item))
        assert positive is True
        assert calls(known,'file_audit_snapshot_provenance_v264') == 1
        assert calls(known,'file_audit_path_in_root_v264') == expected_objects
        result['known_call_control'] = known
        public = []
        for _ in range(5):
            positive, record = measure(admin, worker, lambda: public_read(worker,item))
            assert positive is True
            public.append(record)
        result['stages']['public_read'] = public
        portion, record = measure(admin, worker, lambda: worker.execute(
            'select public.prepare_file_acl_portion_v265(%s::jsonb,%s::jsonb) as value',
            (json.dumps(resource),json.dumps([dict(result_id=result_id,result_sha256=result_hash)]))).fetchone()['value'])
        result['stages']['native_portion_issuance_once'] = record
        definition = {'source_selector':{'execution':execution(resource)}}
        pin = sha256(json.dumps(definition,sort_keys=True).encode()).digest()
        admin.execute('''insert into semantic_risk_policies(policy_id,policy_version,source_kind,definition_json,definition_sha256)
          values('provenance-profile',1,'qw_signal',%s::jsonb,%s)''',(json.dumps(definition),pin))
        admin.execute("insert into semantic_risk_policy_subscriptions values('provenance-profile',1,'qw_signal','qw.file-acl-broad-write',%s)",(pin,))
        admin.execute("update semantic_risk_policies set lifecycle_status='enabled' where policy_id='provenance-profile'")
        admin.execute("insert into semantic_policy_admission values('provenance-profile',1,true,'fixture')")
        _, record = measure(admin, worker, lambda: worker.execute("insert into semantic_qw_signals values(%s,'enabled',%s::jsonb,now())",(portion['signal_id'],json.dumps(portion['document']))))
        result['stages']['qw_insert_rls_once'] = record
        sql,params = query(limit=100)
        plan,record = measure(admin,worker,lambda:worker.execute('explain(analyze,buffers,format json,timing off) '+sql,params).fetchone()['QUERY PLAN'])
        nodes=[]
        pending=[plan[0]['Plan']]
        while pending:
            node=pending.pop()
            pending.extend(node.get('Plans',[]))
            nodes.append({key:node[key] for key in ('Node Type','Actual Rows','Actual Loops') if key in node})
        record['outer_plan'] = dict(execution_ms=plan[0]['Execution Time'], nodes=nodes,
                                    inner_provenance_statement_attribution=False)
        result['stages']['full_backlog_explain_once'] = record
        jobs, record = measure(admin,worker,lambda:repository.enqueue_risk_backlog(worker.cursor(),limit=100))
        assert len(jobs)==1
        result['stages']['actual_enqueue_once'] = record
        empty, warm = measure(admin,worker,lambda:repository.enqueue_risk_backlog(worker.cursor(),limit=100))
        assert empty == ()
        result['empty_warmup'] = warm
        empty_records=[]
        for _ in range(5):
            empty,record=measure(admin,worker,lambda:repository.enqueue_risk_backlog(worker.cursor(),limit=100))
            assert empty == ()
            empty_records.append(record)
        result['stages']['already_jobbed_empty'] = empty_records
        # Each admin mutation commits before a new autocommit worker proof.
        admin.execute("update sli_plugin_file_audit.access_snapshots set snapshot=jsonb_set(snapshot,'{objects,0,dacl}','\"D:\"')")
        assert public_read(worker,item) is False
        assert worker.execute('select signal_id from semantic_qw_signals').fetchall() == []
        assert worker.execute('select count(*) as n from semantic_risk_evaluation_jobs').fetchone()['n'] == 1
        reset_snapshot(admin,item)
        assert public_read(worker,item) is True
        assert len(worker.execute('select signal_id from semantic_qw_signals').fetchall()) == 1
        invalid=deepcopy(item)
        invalid['objects'][0]['owner_sid']=None
        invalid['snapshot_sha256']=digest({key:value for key,value in invalid.items() if key not in ('snapshot_id','snapshot_sha256')})
        invalid['snapshot_id']=str(uuid5(NAMESPACE_URL,COMMAND+invalid['snapshot_sha256']))
        admin.execute('''insert into sli_plugin_file_audit.access_snapshots
          select %s,agent_id,source_instance_id,collection_scope_id,%s,%s::jsonb,
            observed_at,completeness,unread_objects,contract_version
          from sli_plugin_file_audit.access_snapshots where snapshot_id=%s''',
          (invalid['snapshot_id'],invalid['snapshot_sha256'],json.dumps(invalid),item['snapshot_id']))
        # Public resolver receives NEW matching hash/UUID, so denial is not a stale caller hash/link.
        assert public_read(worker,invalid) is False
        admin.execute('delete from sli_plugin_file_audit.access_snapshots where snapshot_id=%s',(invalid['snapshot_id'],))
        reset_snapshot(admin,item)
        assert public_read(worker,item) is True
        assert worker.execute('select count(*) as n from semantic_risk_evaluation_jobs').fetchone()['n'] == 1
        result['fresh_negative_and_restore'] = dict(raw_mutation_denied=True,qw_hidden=True,
            rehashed_invalid_owner_denied=True,restored_positive=True,durable_jobs=1)
        assert catalog(admin)==before_catalog
        for stage in ('public_read','already_jobbed_empty'):
            values=[r['wall_ms'] for r in result['stages'][stage]]
            result[stage+'_summary']=dict(median_ms=median(values),min_ms=min(values),max_ms=max(values))
        result['counting_limits']='OID-separated pg_proc calls/self/total, flushed observer deltas; no SPI/builtin statement counts'
        print('ACL_PROVENANCE_PROFILE_RESULT='+json.dumps(result,sort_keys=True,default=str))