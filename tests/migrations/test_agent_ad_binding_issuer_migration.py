"""Migration 274 issuer catalog and authorization on disposable PostgreSQL."""
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.migrations.historical_postgres import historical_connection


pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_owned_cluster]
ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'config/postgres_migrations/274_agent_ad_binding_issuer.sql'


@pytest.fixture
def issuer_base(tmp_path, monkeypatch):
    with historical_connection(tmp_path, monkeypatch, (273, "password_attacks_v2")) as admin:
        yield admin.info.dsn


@pytest.fixture
def issuer_pg(issuer_base):
    with connection(issuer_base) as admin:
        admin.execute(PATH.read_text('utf-8-sig'))
    return issuer_base


@contextmanager
def connection(dsn, *, web=False):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row

    if web:
        dsn = make_conninfo(dsn, user='adlog_user')
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        if web:
            assert conn.execute('select session_user as u').fetchone()['u'] == 'adlog_user'
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
