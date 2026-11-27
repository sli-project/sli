"""Migration and transaction checks on an explicitly disposable empty clone."""
import os
from pathlib import Path

import pytest


MIGRATIONS = Path("config/postgres_migrations")


def test_migration_uses_storage_owner_and_exact_runtime_grant():
    forward = (MIGRATIONS / "299_login_account_throttle.sql").read_text("utf-8")
    rollback = (MIGRATIONS / "299_login_account_throttle.rollback.sql").read_text("utf-8")
    for sql, operation in ((forward, "create table"), (rollback, "drop table")):
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert sql.index("set local role adlog_storage_owner;") < sql.index(operation)
        assert sql.index("reset role;") > sql.index(operation)
    assert "grant select, insert, update, delete on public.auth_login_throttle to adlog_user;" in forward
    assert "revoke all on public.auth_login_throttle from public, adlog_user;" in forward


@pytest.fixture
def predecessor(isolated_postgres_integration_database):
    dsn = os.environ.get("ADLOG_TEST_PG_EMPTY_DSN")
    if not dsn:
        pytest.skip("Explicit empty disposable PostgreSQL required; never use runtime DSN")
    # The isolation fixture publishes the per-test clone here, not in EMPTY_DSN.
    dsn = os.environ["ADLOG_TEST_PG_DSN"]
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    from tests.postgres_integration_guard import assert_disposable_database

    def connect(**kwargs):
        kwargs.setdefault("row_factory", dict_row)
        return psycopg.connect(dsn, **kwargs)

    with connect() as conn:
        assert_disposable_database(conn)
        if not conn.execute("select to_regrole('adlog_user') as role").fetchone()["role"]:
            pytest.skip("Disposable cluster needs the existing adlog_user role")
        if not conn.execute("select to_regrole('adlog_storage_owner') as role").fetchone()["role"]:
            pytest.skip("Disposable cluster needs the existing adlog_storage_owner role")
        # Minimal schema with the previous main maximum. Independent migrations
        # must keep their markers when the login budget is added or rolled back.
        conn.execute("create table schema_migrations(version integer primary key, name text not null)")
        conn.execute("alter table schema_migrations owner to adlog_storage_owner")
        conn.execute("grant usage, create on schema public to adlog_storage_owner")
        conn.execute("insert into schema_migrations values(280,'service_account_origin')")
        conn.execute("insert into schema_migrations values(297,'agent_stream_import_health')")
    return connect


@pytest.fixture
def database(predecessor):
    connect = predecessor
    with connect() as conn:
        conn.execute((MIGRATIONS / "299_login_account_throttle.sql").read_text("utf-8"))
    return connect


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("reserved_predecessor", [False, True])
def test_apply_pending_accepts_299_after_main_297(predecessor, reserved_predecessor):
    from psycopg.rows import tuple_row

    from deploy.linux.migrate import apply_pending
    from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

    expected = {280: "service_account_origin", 297: "agent_stream_import_health"}
    if reserved_predecessor:
        with predecessor() as conn:
            conn.execute("insert into schema_migrations values(298,'synthetic_parallel_predecessor')")
        expected[298] = "synthetic_parallel_predecessor"
    before = sorted(expected.items())
    migration = next(item for item in forward_migration_inventory(MIGRATIONS) if item.version == 299)
    expected[299] = "login_account_throttle"
    with predecessor(row_factory=tuple_row, autocommit=True) as conn:
        def execute(paths):
            for path in paths:
                conn.execute(path.read_text("utf-8"))

        apply_pending(conn, [migration], expected, execute, baseline_version=max(version for version, _ in before))
        rows = conn.execute("select version,name from schema_migrations order by version").fetchall()
        assert rows == sorted(expected.items())
        conn.execute((MIGRATIONS / "299_login_account_throttle.rollback.sql").read_text("utf-8"))
        rows = conn.execute("select version,name from schema_migrations order by version").fetchall()
        assert rows == before


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_migration_grants_marker_replay_guard_and_rollback(database):
    with database() as conn:
        row = conn.execute("""select
            has_table_privilege('adlog_user','auth_login_throttle','SELECT,INSERT,UPDATE,DELETE') as access,
            (select name from schema_migrations where version=299) as marker
        """).fetchone()
        assert row == {"access": True, "marker": "login_account_throttle"}
        assert conn.execute("""select pg_get_userbyid(relowner) as owner
            from pg_class where oid='public.auth_login_throttle'::regclass
        """).fetchone()["owner"] == "adlog_storage_owner"
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
            assert conn.execute(
                "select has_table_privilege('adlog_user','public.auth_login_throttle',%s) as allowed",
                (privilege,),
            ).fetchone()["allowed"] == (privilege in {"SELECT", "INSERT", "UPDATE", "DELETE"})
        assert conn.execute("""select count(*) as n from pg_class c,
            lateral aclexplode(c.relacl) a
            where c.oid='public.auth_login_throttle'::regclass and a.grantee=0
        """).fetchone()["n"] == 0
    with pytest.raises(Exception, match="already applied"), database() as conn:
        conn.execute((MIGRATIONS / "299_login_account_throttle.sql").read_text("utf-8"))
    with database() as conn:
        conn.execute((MIGRATIONS / "299_login_account_throttle.rollback.sql").read_text("utf-8"))
    with database() as conn:
        assert conn.execute("select to_regclass('auth_login_throttle') as t").fetchone()["t"] is None
        assert conn.execute("select count(*) as n from schema_migrations where version=299").fetchone()["n"] == 0
