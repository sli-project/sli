"""Prospective normal AD issuer on real disposable273/274; no native source calls."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
from pathlib import Path
from threading import Event
from time import monotonic, sleep
from uuid import uuid4

import pytest


pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'config/postgres_migrations/274_agent_ad_binding_issuer.sql'
CONFIG = dict(source_name='fixture-dc', connect_address='fixture-endpoint')


@pytest.fixture
def issuer_base(coverage_pg):
    """Real273 candidate with unrelated269/270/271/272 synthetic predecessor markers; restore exact169 history and assignment grants."""
    dsn = coverage_pg[0][0]
    import psycopg
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute('delete from finding_evidence_source_bindings')
        admin.execute('delete from sli_agent_module_bindings')
        admin.execute("update sli_agents set assigned_modules='[]',policy_revision=1")
        admin.execute('set role adlog_storage_owner')
        source = (PATH.parent / '169_agent_collection_control.sql').read_text('utf-8-sig')
        admin.execute(source[source.index('create table public.sli_agent_policy_history'):source.index('-- Preserve actions')])
        admin.execute('grant select on sli_agents to adlog_user')
        admin.execute('grant update(assigned_modules,policy_revision) on sli_agents to adlog_user')
        # Existing163/169 audit choices, preserving actual273 added choice.
        admin.execute("""do $$ declare prior text; begin
          select pg_get_expr(conbin,conrelid) into strict prior from pg_constraint
          where conrelid='sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
          alter table sli_agent_audit drop constraint sli_agent_audit_action_check;
          execute format('alter table sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action=''module_assign'')',prior);
          end $$""")
        admin.execute('reset role')
    return dsn, coverage_pg[1], coverage_pg[0][1]


@pytest.fixture
def issuer_pg(issuer_base):
    import psycopg
    if PATH.exists():
        with psycopg.connect(issuer_base[0], autocommit=True) as admin:
            admin.execute(PATH.read_text('utf-8-sig'))
    return issuer_base


@contextmanager
def connection(source, *, web=False, semantic=False):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row
    login = source[2] if semantic else source[1]
    dsn = make_conninfo(source[0], user=login) if web or semantic else source[0]
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        if web or semantic:
            assert conn.execute('select session_user as u').fetchone()['u'] == login
        if semantic:
            conn.execute('set role adlog_semantic_worker')
        yield conn


@pytest.mark.parametrize('unsafe', ['grant', 'trigger'])
def test_migration_rejects_unexpected_history_mutability(issuer_base, unsafe):
    import psycopg
    with connection(issuer_base) as admin:
        if unsafe == 'grant':
            admin.execute('grant update on sli_agent_policy_history to adlog_user')
        else:
            admin.execute("create function fixture_history_writer() returns trigger language plpgsql as $$begin return new;end$$")
            admin.execute('create trigger fixture_history_writer before insert on sli_agent_policy_history for each row execute function fixture_history_writer()')
        with pytest.raises(psycopg.Error, match='agent_ad_issuer_preflight'):
            admin.execute(PATH.read_text('utf-8-sig'))
        admin.execute('rollback')
        assert not admin.execute('select 1 from schema_migrations where version=274').fetchone()
        assert not admin.execute("select 1 from pg_attribute where attrelid='sli_agent_policy_history'::regclass and attname='staged_xact_id'").fetchone()


def test_column_and_private_function_contract(issuer_pg):
    with connection(issuer_pg) as admin:
        row = admin.execute("""select a.atttypid='xid8'::regtype as correct,not a.attnotnull as nullable,d.oid is null as no_default
          from pg_attribute a left join pg_attrdef d on d.adrelid=a.attrelid and d.adnum=a.attnum
          where a.attrelid='sli_agent_policy_history'::regclass and a.attname='staged_xact_id'""").fetchone()
        assert row == dict(correct=True, nullable=True, no_default=True)
        assert not admin.execute("""select 1 from pg_proc p cross join lateral aclexplode(p.proacl) a
          where p.proname in('agent_ad_stamp_history','agent_ad_issue_binding') and a.grantee<>p.proowner""").fetchone()
        assert all(row['ok'] for row in admin.execute("""select prosecdef and provolatile='v' and proowner='adlog_storage_owner'::regrole
          and proconfig=array['search_path=pg_catalog, pg_temp'] as ok from pg_proc where proname in('agent_ad_stamp_history','agent_ad_issue_binding')""").fetchall())


@pytest.mark.parametrize('guard', ['missing273', 'unauthorized'])
def test_migration_predecessor_and_runtime_install_denial(issuer_base, guard):
    import psycopg
    with connection(issuer_base) as admin:
        if guard == 'missing273':
            admin.execute('delete from schema_migrations where version=273')
    with connection(issuer_base, web=guard == 'unauthorized') as conn:
        with pytest.raises(psycopg.Error):
            conn.execute(PATH.read_text('utf-8-sig'))
        conn.execute('rollback')
    with connection(issuer_base) as admin:
        assert not admin.execute('select 1 from schema_migrations where version=274').fetchone()
        assert not admin.execute("select 1 from pg_attribute where attrelid='sli_agent_policy_history'::regclass and attname='staged_xact_id'").fetchone()
