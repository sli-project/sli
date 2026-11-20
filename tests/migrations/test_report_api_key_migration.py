import os
from pathlib import Path

import pytest

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


@pytest.fixture
def postgres_connection():
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Disposable PostgreSQL required")
    import psycopg
    with psycopg.connect(dsn) as conn:
        yield conn


def test_report_key_nullable_association_and_fk(postgres_connection, monkeypatch):
    """Run against the disposable database provided by the focused test harness."""
    conn = postgres_connection
    conn.execute("do $$ begin if not exists(select 1 from pg_roles where rolname='adlog_storage_owner') then create role adlog_storage_owner nologin; end if; end $$")
    conn.execute("create table schema_migrations(version int primary key,name text)")
    conn.execute("create table auth_users(id bigint primary key,is_active boolean not null default true)")
    conn.execute("""create table auth_api_keys(id bigint primary key,key_prefix text,key_hash text,label text,
        role text default 'viewer',is_active boolean default true,expires_at timestamptz,
        revoked_at timestamptz,last_used_at timestamptz)""")
    conn.execute("insert into auth_api_keys values(1)")
    conn.commit()
    migration = Path("config/postgres_migrations/180_report_api_key.sql").read_text()
    conn.execute(migration)
    assert conn.execute("select report_subject_id from auth_api_keys where id=1").fetchone()[0] is None
    conn.execute("insert into auth_users values(42)")
    conn.execute("insert into auth_api_keys(id,report_subject_id) values(2,42)")
    conn.commit()
    from psycopg.errors import ForeignKeyViolation
    with pytest.raises(ForeignKeyViolation), conn.transaction():
        conn.execute("insert into auth_api_keys(id,report_subject_id) values(3,999)")
    assert conn.execute("select name from schema_migrations where version=180").fetchone()[0] == "report_api_key"
    from psycopg import connect
    from psycopg.rows import dict_row

    from server.sli.access import auth

    conn.execute("update auth_api_keys set key_prefix='test',label='synthetic',key_hash=%s where id=1", (auth._digest('adl_legacy'),))
    conn.execute("update auth_api_keys set key_prefix='test',label='synthetic',key_hash=%s,expires_at=now()+interval '1 day' where id=2", (auth._digest('adl_report'),))
    conn.commit()
    monkeypatch.setattr(auth, '_connect', lambda: connect(os.environ['ADLOG_TEST_PG_DSN'], row_factory=dict_row))
    assert 'report_subject_id' not in auth.authenticate_api_key('adl_legacy')
    assert auth.authenticate_api_key('adl_report')['report_subject_id'] == 42
    conn.execute('update auth_users set is_active=false where id=42')
    conn.commit()
    assert auth.authenticate_api_key('adl_report') is None
    conn.execute('update auth_users set is_active=true where id=42')
    conn.execute("update auth_api_keys set expires_at=now()-interval '1 second' where id=2")
    conn.commit()
    assert auth.authenticate_api_key('adl_report') is None
