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

from tests.postgres_integration_guard import assert_disposable_database

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


def assignment(enabled=True, expected=1):
    return dict(agent_id=AGENT, module_id='sli.file-audit', enabled=enabled, expected_revision=expected,
                config=dict(source_name='fixture-server', mass_operation_files=25, mass_operation_seconds=60,
                    roots=[dict(collection_scope_id='scope:one', share_name='fixture-share', path='C:\\fixture',
                        important=True, sacl=dict(trustee_sids=['S-1-1-0'], inherit_files=True, inherit_directories=True))]))


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
