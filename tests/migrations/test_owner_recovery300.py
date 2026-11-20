"""Owner recovery SQL/transaction checks on an explicit disposable clone."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from server.sli.access import auth, owner_recovery
from server.sli.access.login_throttle import AccountAttempt, LoginThrottled
from tests.migrations.test_login_account_throttle299 import (
    database as throttle_database,  # noqa: F401
    predecessor,  # noqa: F401
)

MIGRATIONS = Path("config/postgres_migrations")


def test_migration_owner_grants_and_runtime_guard():
    forward = (MIGRATIONS / "300_owner_recovery.sql").read_text("utf-8")
    rollback = (MIGRATIONS / "300_owner_recovery.rollback.sql").read_text("utf-8")
    for sql, operation in ((forward, "create table"), (rollback, "drop table")):
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert sql.index("set local role adlog_storage_owner;") < sql.index(operation) < sql.index("reset role;")
    assert "grant select, insert, update, delete on public.auth_owner_recovery to adlog_user;" in forward
    assert "references public.auth_users(id) on delete cascade" in forward
    guard = Path("server/sli/access/auth.py").read_text("utf-8")
    assert 'require_table_columns("auth_owner_recovery"' in guard
    assert "minimum_schema_version=300" in guard


@pytest.fixture
def predecessor_database(throttle_database):
    connect = throttle_database
    password_hash = auth.PASSWORD_HASHER.hash("synthetic-owner-password")
    with connect() as conn:
        conn.execute("""
            create table auth_users(id bigint primary key, username text not null,
                password_hash text not null, role text not null, is_active boolean not null,
                last_login_at timestamptz, previous_login_at timestamptz);
            grant references on auth_users to adlog_storage_owner;
            create table access_platform_owners(user_id bigint primary key references auth_users(id));
            create table auth_audit(id bigint generated always as identity primary key,
                actor_type text, actor_id bigint, action text, outcome text, remote_address text,
                created_at timestamptz default now());
            grant select, update on auth_users to adlog_user;
            grant select on access_platform_owners to adlog_user;
            grant insert, select on auth_audit to adlog_user;
        """)
        for user_id, username in [(1, "owner"), (2, "other")]:
            conn.execute("insert into auth_users values(%s,%s,%s,'admin',true,null,null)", (user_id, username, password_hash))
        conn.execute("insert into access_platform_owners values(1)")
    return connect


@pytest.fixture
def database(predecessor_database, monkeypatch):
    connect = predecessor_database
    with connect() as conn:
        conn.execute((MIGRATIONS / "300_owner_recovery.sql").read_text("utf-8"))

    def runtime_connect():
        conn = connect()
        conn.execute("set role adlog_user")
        return conn

    monkeypatch.setattr(auth, "_connect", runtime_connect)
    monkeypatch.setattr(auth, "ensure_auth_schema", lambda: None)
    monkeypatch.setattr(owner_recovery.os, "geteuid", lambda: 0, raising=False)
    from server.sli.sources import administrative_activity_producer
    monkeypatch.setattr(administrative_activity_producer, "mirror_auth_audit_if_enabled", lambda **_: None)
    return connect


pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def test_database_at_previous_maximum_299_accepts_300(predecessor_database):
    from psycopg.rows import tuple_row

    from deploy.linux.migrate import apply_pending
    from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

    migration = next(item for item in forward_migration_inventory(MIGRATIONS) if item.version == 300)
    with predecessor_database(row_factory=tuple_row, autocommit=True) as conn:
        before = conn.execute("select version,name from schema_migrations order by version").fetchall()
        assert max(version for version, _ in before) == 299
        assert conn.execute("select to_regclass('auth_owner_recovery')").fetchone()[0] is None

        def execute(paths):
            for path in paths:
                conn.execute(path.read_text("utf-8"))

        expected = dict(before) | {300: "owner_recovery"}
        apply_pending(conn, [migration], expected, execute, baseline_version=299)
        assert conn.execute("select version,name from schema_migrations order by version").fetchall() == sorted(expected.items())
        conn.execute((MIGRATIONS / "300_owner_recovery.rollback.sql").read_text("utf-8"))
        assert conn.execute("select version,name from schema_migrations order by version").fetchall() == before


def test_grants_marker_replay_and_rollback(database):
    with database() as conn:
        assert conn.execute("select name from schema_migrations where version=300").fetchone()["name"] == "owner_recovery"
        assert conn.execute("""select pg_get_userbyid(relowner) as owner
            from pg_class where oid='public.auth_owner_recovery'::regclass""").fetchone()["owner"] == "adlog_storage_owner"
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
            assert conn.execute("select has_table_privilege('adlog_user','auth_owner_recovery',%s) as allowed",
                                (privilege,)).fetchone()["allowed"] == (privilege in {"SELECT", "INSERT", "UPDATE", "DELETE"})
        assert conn.execute("""select count(*) as n from pg_class c, lateral aclexplode(c.relacl) a
            where c.oid='auth_owner_recovery'::regclass and a.grantee=0""").fetchone()["n"] == 0
    with pytest.raises(Exception, match="already applied"), database() as conn:
        conn.execute((MIGRATIONS / "300_owner_recovery.sql").read_text("utf-8"))
    with database() as conn:
        conn.execute((MIGRATIONS / "300_owner_recovery.rollback.sql").read_text("utf-8"))
        assert conn.execute("select to_regclass('auth_owner_recovery') as t").fetchone()["t"] is None
        assert conn.execute("select count(*) as n from schema_migrations where version=300").fetchone()["n"] == 0


def test_exact_predecessor_and_rollback_successor_guards(database):
    with database() as conn:
        conn.execute("insert into schema_migrations(version,name) values(301,'synthetic_successor')")
    with pytest.raises(Exception, match="no successors"), database() as conn:
        conn.execute((MIGRATIONS / "300_owner_recovery.rollback.sql").read_text("utf-8"))
    with database() as conn:
        conn.execute("delete from schema_migrations where version=301")
        conn.execute((MIGRATIONS / "300_owner_recovery.rollback.sql").read_text("utf-8"))
        conn.execute("update schema_migrations set name='foreign' where version=299")
    with pytest.raises(Exception, match="exact migration 299"), database() as conn:
        conn.execute((MIGRATIONS / "300_owner_recovery.sql").read_text("utf-8"))


def test_locked_and_inflight_owner_recovers_once_without_clearing_block(database, caplog):
    code = owner_recovery.issue_owner_recovery_code("owner")
    for _ in range(5):
        assert auth.authenticate_password("owner", "incorrect") is None
    with pytest.raises(LoginThrottled):
        auth.authenticate_password("owner", "synthetic-owner-password")
    # Even an in-flight attack holding the regular advisory lock cannot deny
    # recovery. Use another account attempt before imposing the durable block.
    with database() as conn, conn.cursor() as cur:
        conn.execute("update auth_login_throttle set blocked_until=null")
        AccountAttempt(cur, "owner")
        assert auth.authenticate_password("owner", "synthetic-owner-password", recovery_code=code)["id"] == 1
    assert auth.authenticate_password("owner", "synthetic-owner-password", recovery_code=code) is None
    with database() as conn:
        rows = conn.execute("select action,outcome from auth_audit order by id").fetchall()
        assert rows == [{"action": "owner_recovery_issued:1", "outcome": "ok"},
                        {"action": "owner_recovery_login", "outcome": "ok"},
                        {"action": "owner_recovery_login", "outcome": "failed"}]
        assert conn.execute("select count(*) as n from auth_login_throttle").fetchone()["n"] == 1
    assert code not in caplog.text + str(rows)


def test_simultaneous_requests_cannot_both_consume_code(database, monkeypatch):
    code = owner_recovery.issue_owner_recovery_code("owner")
    barrier = threading.Barrier(2)
    verify = auth.PASSWORD_HASHER.verify

    def simultaneous(*args):
        result = verify(*args)
        barrier.wait(timeout=10)
        return result

    monkeypatch.setattr(auth, "PASSWORD_HASHER", SimpleNamespace(verify=simultaneous))
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [pool.submit(auth.authenticate_password, "owner", "synthetic-owner-password", recovery_code=code) for _ in range(2)]
        results = [future.result(timeout=15) for future in pending]
    assert sum(result is not None for result in results) == 1


@pytest.mark.parametrize("case", ["expired", "foreign", "wrong", "nonowner", "disabled", "password"])
def test_rejects_expired_foreign_wrong_and_revoked_owner(database, case):
    code = owner_recovery.issue_owner_recovery_code("owner")
    username, password = "owner", "synthetic-owner-password"
    with database() as conn:
        if case == "expired":
            conn.execute("update auth_owner_recovery set expires_at=clock_timestamp()-interval '1 second'")
        elif case == "foreign":
            username = "other"
        elif case == "wrong":
            code = "incorrect"
        elif case == "nonowner":
            conn.execute("delete from access_platform_owners")
        elif case == "disabled":
            conn.execute("update auth_users set is_active=false where id=1")
        elif case == "password":
            password = "incorrect"
    assert auth.authenticate_password(username, password, recovery_code=code) is None
    with database() as conn:
        assert conn.execute("select count(*) as n from auth_owner_recovery").fetchone()["n"] == 1


def test_expiry_is_rechecked_after_password_verification(database, monkeypatch):
    code = owner_recovery.issue_owner_recovery_code("owner")
    verify = auth.PASSWORD_HASHER.verify

    def expires_during_verify(*args):
        result = verify(*args)
        with database() as conn:
            conn.execute("update auth_owner_recovery set expires_at=clock_timestamp()-interval '1 second'")
        return result

    monkeypatch.setattr(auth, "PASSWORD_HASHER", SimpleNamespace(verify=expires_during_verify))
    assert auth.authenticate_password("owner", "synthetic-owner-password", recovery_code=code) is None
