"""Lifecycle rollback cleans one database without changing another installation."""
from pathlib import Path

import pytest

from tests.migrations.historical_postgres import historical_connection

ROOT = Path(__file__).resolve().parents[2] / "config/postgres_migrations"
ROLES = [f"adlog_storage_lifecycle_{name}" for name in ("worker", "delete", "guard")]
pytestmark = pytest.mark.postgres_integration


def test_rollback_clears_local_dependencies_and_reuses_shared_roles(tmp_path, monkeypatch):
    import psycopg
    from psycopg import sql

    with historical_connection(tmp_path, monkeypatch, (319, "storage_lifecycle_roles")) as conn:
        peer_db = "sli_test_lifecycle_peer"
        conn.execute(sql.SQL("create database {} template {}").format(
            sql.Identifier(peer_db), sql.Identifier(conn.info.dbname),
        ))
        peer_oid, = conn.execute("select oid from pg_database where datname=%s", (peer_db,)).fetchone()

        def dependencies(local):
            return conn.execute("""select s.* from pg_shdepend s
                where refclassid='pg_authid'::regclass and refobjid=any(
                    select oid from pg_roles where rolname=any(%s))
                  and (dbid=(select oid from pg_database where datname=current_database()))=%s
                order by dbid,classid,objid,objsubid,refobjid,deptype""", (ROLES, local)).fetchall()

        def memberships():
            return conn.execute("""select * from pg_auth_members
                where roleid=any(select oid from pg_roles where rolname=any(%s))
                   or member=any(select oid from pg_roles where rolname=any(%s))
                order by oid""", (ROLES, ROLES)).fetchall()

        shared = dependencies(False)
        assert any(row[0] == peer_oid for row in shared), "the peer retains its own dependencies"
        members = memberships()
        conn.execute((ROOT / "319_storage_lifecycle_roles.rollback.sql").read_text("utf-8"))
        assert dependencies(True) == []  # Includes table/column/default ACL and ownership.
        assert dependencies(False) == shared
        assert memberships() == members
        assert conn.execute("select max(version) from schema_migrations").fetchone() == (318,)

        # A retained role must still be closed before it may be reused.
        conn.execute("alter role adlog_storage_lifecycle_guard login")
        try:
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="storage_lifecycle_319_role_invalid"):
                conn.execute((ROOT / "319_storage_lifecycle_roles.sql").read_text("utf-8"))
            conn.rollback()
        finally:
            conn.execute("alter role adlog_storage_lifecycle_guard nologin")
        conn.execute((ROOT / "319_storage_lifecycle_roles.sql").read_text("utf-8"))
        assert dependencies(False) == shared
        assert memberships() == members
        assert conn.execute("select max(version) from schema_migrations").fetchone() == (319,)
