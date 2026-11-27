"""Forward migration contracts using static checks and an isolated test database."""
import os
import re
from pathlib import Path

import psycopg
import pytest
from psycopg import sql

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/196_agent_msi_update_result.sql"
SQL = PATH.read_text("utf-8")


def test_exact_owner_predecessor_and_next_unique_migration():
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "version=195 and name='ad_snapshot_history_composition'" in SQL and "version>=196" in SQL
    assert "hashtext('sli_agent_msi_update_result_v196')" in SQL
    assert "values(196,'agent_msi_update_result')" in SQL
    assert list(PATH.parent.glob("196_*.sql")) == [PATH]
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    position = pairs.index((196, "agent_msi_update_result"))
    assert pairs[position - 1] == (195, "ad_snapshot_history_composition")
    assert len(pairs) == len({version for version, _ in pairs})


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_migration_extends_existing_constraints_after_exact_predecessor():
    """Catch broken predecessor checks, SQL execution or lost allowed reasons."""
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("isolated PostgreSQL template is not configured")
    tables = ("sli_agent_update_results", "sli_agent_update_wave_members")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("create table public.schema_migrations (version integer primary key, name text)")
        conn.execute("insert into public.schema_migrations values (195, 'wrong_predecessor')")
        for table in tables:
            conn.execute(sql.SQL(
                "create table public.{} (reason text constraint {} "
                "check (reason in ('agent_update_download_failed', 'agent_update_timeout')))"
            ).format(sql.Identifier(table), sql.Identifier(f"{table}_reason_check")))
            conn.execute(sql.SQL("alter table public.{} owner to adlog_storage_owner").format(
                sql.Identifier(table)
            ))
            conn.execute(sql.SQL("insert into public.{} values ('agent_update_download_failed')").format(
                sql.Identifier(table)
            ))

        with pytest.raises(psycopg.errors.RaiseException, match="requires exact migration 195"):
            conn.execute(SQL)
        conn.execute("rollback")
        assert conn.execute("select version, name from public.schema_migrations").fetchall() == [
            (195, "wrong_predecessor")
        ]
        conn.execute("update public.schema_migrations set name='ad_snapshot_history_composition' where version=195")
        conn.execute(SQL)
        assert conn.execute("select version, name from public.schema_migrations order by version").fetchall() == [
            (195, "ad_snapshot_history_composition"), (196, "agent_msi_update_result")
        ]
        for table in tables:
            for reason in ("agent_update_timeout", "agent_update_msi_required", None):
                conn.execute(sql.SQL("insert into public.{} values (%s)").format(
                    sql.Identifier(table)
                ), (reason,))
            assert conn.execute(sql.SQL("select reason from public.{}").format(
                sql.Identifier(table)
            )).fetchall() == [
                ("agent_update_download_failed",), ("agent_update_timeout",),
                ("agent_update_msi_required",), (None,),
            ]
            with pytest.raises(psycopg.errors.CheckViolation):
                conn.execute(sql.SQL("insert into public.{} values ('unknown_reason')").format(
                    sql.Identifier(table)
                ))
        with pytest.raises(psycopg.errors.RaiseException, match="unused version 196"):
            conn.execute(SQL)
        conn.execute("rollback")
