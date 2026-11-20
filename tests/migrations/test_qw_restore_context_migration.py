"""Full migrated-schema directory restore and retained runtime ingress guards."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest

from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / 'config/postgres_migrations/276_qw_restore_context_guards.sql'


def test_context_checks_are_moved_without_replacing_authority_functions():
    text = MIGRATION.read_text('utf-8')
    assert 'drop constraint semantic_qw_acl_identity_v265' in text
    assert 'drop constraint password_v2_qw_identity' in text
    assert 'before insert or update on public.semantic_qw_signals' in text
    assert 'security invoker' in text
    assert 'security definer' not in text.lower()
    assert 'file_acl_qw_row_allowed_v265(NEW.signal_id,NEW.evaluation_mode,NEW.document_json)' in text
    assert 'password_v2_qw_allowed(NEW.signal_id,NEW.evaluation_mode,NEW.document_json)' in text
    assert 'grant ' not in text.lower()
    assert 'create role ' not in text.lower()
    assert 'enable always trigger aa_qw_context_guard_v276' in text
    assert 'session_replication_role' not in text


def seed_native_acl(admin):
    """Retained synthetic native evidence, then the real issuer under worker identity."""
    from psycopg.types.json import Jsonb

    from server.sli.plugins.file_audit.rules import permission_findings
    from tests.migrations.test_file_audit_acl_bridge_migration264 import inventory

    agent, source = str(uuid4()), str(uuid4())
    item = inventory()
    scope = item['collection_scope_id']
    policy = {'policy_revision': '1', 'source_name': 'restore-fixture.example.invalid',
              'roots': [{'collection_scope_id': scope, 'path': 'C:\\synthetic',
                         'share_name': 'synthetic', 'important': True}], 'service_account_exclusions': []}
    admin.execute('''insert into public.sli_agents(id,host_id,key_fingerprint,status,assigned_modules)
      values(%s,%s,repeat('0',64),'active',%s)''',
                  (agent, source, Jsonb([{'module_id': 'sli.file-audit', 'enabled': True, 'config': policy}])))
    domain = admin.execute('select id from public.domains order by id limit 1').fetchone()[0]
    admin.execute('insert into public.servers(domain_id,hostname) values(%s,%s)',
                  (domain, policy['source_name']))
    admin.execute('''insert into sli_plugin_file_audit.policy_revisions
      (agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
      values(%s,%s,1,now(),'session',1,%s,encode(sha256(convert_to(%s::jsonb::text,'UTF8')),'hex'))''',
                  (agent, source, Jsonb(policy), Jsonb(policy)))
    admin.execute('''insert into sli_plugin_file_audit.audit_commands
      (command_id,agent_id,source_instance_id,policy_revision,action,collection_scope_ids,
       requested_at,actor_kind,actor_id,command_sha256)
      values('synthetic-command',%s,%s,1,'check',array[%s],now(),'session',1,
       encode(sha256(convert_to(jsonb_build_object('contract_id','sli.file-audit.audit-command.v1',
        'command_id','synthetic-command','action','check','policy_revision','1',
        'collection_scope_ids',jsonb_build_array(%s::text))::text,'UTF8')),'hex'))''',
                  (agent, source, scope, scope))
    admin.execute('''insert into sli_plugin_file_audit.audit_receipts
      (receipt_id,command_id,agent_id,source_instance_id,policy_revision,action,collection_scope_id,
       state,observed_at,result_sha256) values(%s,'synthetic-command',%s,%s,1,'check',%s,
       'verified',%s,repeat('0',64))''', (uuid4(), agent, source, scope, item['observed_at_utc']))
    admin.execute('''insert into sli_plugin_file_audit.access_snapshots
      (snapshot_id,agent_id,source_instance_id,collection_scope_id,observed_at,contract_version,
       completeness,snapshot_sha256,snapshot,unread_objects)
      values(%s,%s,%s,%s,%s,1,%s,%s,%s,0)''',
                  (item['snapshot_id'], agent, source, scope, item['observed_at_utc'],
                   item['completeness'], item['snapshot_sha256'], Jsonb(item)))
    row = permission_findings(item | {'agent_id': agent, 'source_instance_id': source}, config=policy)[0]
    finding = admin.execute('''insert into public.findings(fingerprint,rule_code,title,severity)
      values(%s,%s,'Synthetic ACL restore fixture','medium') returning id''',
                            (row['result_id'], row['rule_code'])).fetchone()[0]
    stored_hash = admin.execute('''insert into sli_plugin_file_audit.rule_results
      (result_id,finding_id,agent_id,source_instance_id,collection_scope_id,rule_code,rule_version,
       conclusion_state,observed_at,result,result_sha256)
      values(%s,%s,%s,%s,%s,%s,1,'observed',%s,%s,encode(sha256(convert_to(%s::jsonb::text,'UTF8')),'hex'))
      returning result_sha256''', (row['result_id'], finding, agent, source, scope, row['rule_code'],
                                   row['observed_at'], Jsonb(row), Jsonb(row))).fetchone()[0]
    admin.execute('insert into sli_plugin_file_audit.rule_snapshots(result_id,snapshot_id) values(%s,%s)',
                  (row['result_id'], item['snapshot_id']))
    installation = str(admin.execute('select installation_id from public.semantic_default_installation').fetchone()[0])
    resource = {'installation_id': installation, 'plugin_id': 'sli.file-audit', 'agent_id': agent,
                    'source_instance_id': source, 'collection_scope_id': scope}
    return agent, resource, [{'result_id': row['result_id'], 'result_sha256': stored_hash}]


def pg_cli(tool, *arguments):
    # Never echo raw stderr, SQL, row values or a connection string on failure.
    result = subprocess.run([tool, '--no-password', *arguments], capture_output=True, timeout=180, check=False)
    assert result.returncode == 0, f'{tool} failed (exit {result.returncode}); raw output withheld'


@pytest.mark.postgres_integration
def test_full_migrations_acl_directory_dump_parallel_restore_and_runtime_guards(tmp_path):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from psycopg.types.json import Jsonb

    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('disposable migrated PostgreSQL not configured')
    assert shutil.which('pg_dump') and shutil.which('pg_restore'), 'CI requires PostgreSQL client tools'
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert_disposable_database(admin)
        assert admin.execute("select name from schema_migrations where version=276").fetchone() == ('qw_restore_context_guards',)
        agent, resource, results = seed_native_acl(admin)
        with psycopg.connect(dsn, autocommit=True) as worker:
            # Existing cluster role; no fixture grants, role creation or credentials.
            worker.execute('set session authorization adlog_semantic_worker')
            assert worker.execute('select current_user=session_user').fetchone()[0]
            portion = worker.execute('select public.prepare_file_acl_portion_v265(%s,%s)',
                                     (Jsonb(resource), Jsonb(results))).fetchone()[0]
            insert = 'insert into public.semantic_qw_signals(signal_id,evaluation_mode,document_json) values(%s,%s,%s)'
            values = (portion['signal_id'], 'enabled', Jsonb(portion['document']))
            worker.execute(insert, values)
            worker.execute(insert + ' on conflict(signal_id) do nothing', values)
            for suffix in ('', ' on conflict(signal_id) do nothing'):
                with pytest.raises(psycopg.errors.CheckViolation) as rejected:
                    worker.execute(insert + suffix, (portion['signal_id'], 'enabled', Jsonb(portion['document'] | {'quality': 'bad'})))
                assert rejected.value.diag.constraint_name == 'semantic_qw_acl_identity_v265'
            # UPDATE remains ungranted: PostgreSQL checks it before any trigger.
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute(insert + ' on conflict(signal_id) do update set document_json=excluded.document_json',
                               (portion['signal_id'], 'enabled', Jsonb(portion['document'] | {'quality': 'bad'})))
            # A direct update remains forbidden by the existing immutable input boundary.
            with pytest.raises(psycopg.Error):
                worker.execute('update public.semantic_qw_signals set evaluation_mode=\'shadow\' where signal_id=%s',
                               (portion['signal_id'],))
        # Even an owner-bypassing-RLS admin cannot impersonate the issuing login,
        # including duplicate keys that would otherwise reach ON CONFLICT.
        assert admin.execute('select public.file_acl_qw_row_allowed_v265(%s,%s,%s)', values).fetchone()[0] is False
        for suffix in ('', ' on conflict(signal_id) do nothing',
                       ' on conflict(signal_id) do update set document_json=excluded.document_json'):
            with pytest.raises(psycopg.errors.CheckViolation) as rejected:
                admin.execute(insert + suffix, values)
            assert rejected.value.diag.constraint_name == 'semantic_qw_acl_identity_v265'
        # Row-local shape checks still reject malformed non-ACL rows.
        with pytest.raises(psycopg.errors.CheckViolation):
            admin.execute(insert, ('b' * 64, 'enabled', Jsonb({'evaluation_mode': 'enabled', 'evidence_refs': []})))
        # Password-v2 contextual validation was also moved, not silently dropped.
        with pytest.raises(psycopg.errors.CheckViolation) as rejected:
            admin.execute(insert, ('c' * 64, 'enabled', Jsonb({'evaluation_mode': 'enabled', 'rule_version': 1, 'password_context': {},
                                                                           'evidence_refs': [{}]})))
        assert rejected.value.diag.constraint_name == 'password_v2_qw_identity'
        # Current source authority may disappear without erasing immutable history.
        admin.execute("update public.sli_agents set status='disabled' where id=%s", (agent,))
        dump = tmp_path / 'directory-dump'
        pg_cli('pg_dump', '--format=directory', '--file=' + str(dump), '--dbname=' + dsn)
        target = 'sli_test_restore_' + uuid4().hex
        target_dsn = make_conninfo(dsn, dbname=target)
        with psycopg.connect(make_conninfo(dsn, dbname='postgres'), autocommit=True) as control:
            control.execute(sql.SQL('create database {} template template0').format(sql.Identifier(target)))
            try:
                pg_cli('pg_restore', '--exit-on-error', '--jobs=2', '--format=directory',
                       '--dbname=' + target_dsn, str(dump))
                with psycopg.connect(target_dsn, autocommit=True) as restored:
                    assert_disposable_database(restored)
                    assert restored.execute('select signal_id,evaluation_mode,document_json from semantic_qw_signals').fetchall() == [
                        (portion['signal_id'], 'enabled', portion['document'])]
                    assert restored.execute('select public.file_acl_qw_row_allowed_v265(%s,%s,%s)', values).fetchone()[0] is False
                    with pytest.raises(psycopg.errors.CheckViolation):
                        restored.execute(insert + ' on conflict(signal_id) do nothing', values)
                    with pytest.raises(psycopg.Error):
                        restored.execute('update semantic_qw_signals set document_json=document_json where signal_id=%s',
                                         (portion['signal_id'],))
                    assert not restored.execute('''select conname from pg_constraint where contype='c'
                      and conrelid='public.semantic_qw_signals'::regclass
                      and conname in ('semantic_qw_acl_identity_v265','password_v2_qw_identity')''').fetchall()
                    assert restored.execute('''select count(*) from pg_trigger where tgrelid='public.semantic_qw_signals'::regclass
                      and tgname='aa_qw_context_guard_v276' and tgenabled='A' ''').fetchone()[0] == 1
            finally:
                control.execute(sql.SQL('drop database {} with (force)').format(sql.Identifier(target)))
