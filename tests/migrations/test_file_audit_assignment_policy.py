"""Migration 272 catalog and runtime privileges on disposable PostgreSQL."""
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.migrations.historical_postgres import historical_connection

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT/'config/postgres_migrations'
PATH = MIGRATIONS/'272_file_audit_assignment_policy.sql'
AGENT = '00000000-0000-4000-8000-000000000071'
WORKER = 'sli_test_file_policy_worker272'
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_owned_cluster]


@contextmanager
def connect(dsn, user=None):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row
    with psycopg.connect(make_conninfo(dsn, **({'user': user} if user else {})), row_factory=dict_row) as conn:
        yield conn


@pytest.fixture
def installed(tmp_path, monkeypatch):
    from psycopg import sql

    with historical_connection(tmp_path, monkeypatch, (271, "account_watch_source_prefilter")) as predecessor:
        worker = sql.Identifier(WORKER)
        predecessor.execute(sql.SQL('create role {} login inherit').format(worker))
        predecessor.execute(sql.SQL('grant adlog_semantic_worker to {}').format(worker))
        predecessor.execute(sql.SQL('grant connect on database {} to {}').format(
            sql.Identifier(predecessor.info.dbname), worker))
        dsn = predecessor.info.dsn
        with connect(dsn) as admin:
            read_results = (
                "select pg_get_functiondef("
                "'public.read_file_ransom_results(jsonb,uuid,text,text,integer,integer)'::regprocedure) as body"
            )
            before = admin.execute(read_results).fetchone()
            admin.execute(PATH.read_text('utf-8-sig'))
            assert admin.execute(read_results).fetchone() == before
        yield dsn


def test_private_catalog_and_no_extra_app_or_worker_table_rights(installed):
    import psycopg
    dsn = installed
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
    with connect(dsn, WORKER) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.execute('select sli_plugin_file_audit.retain_assignment_policy(%s,%s,%s)', (AGENT, 'session', 1))
