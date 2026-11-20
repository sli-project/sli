"""Additive recovery contracts and disposable PostgreSQL migration readback."""
import os
from pathlib import Path

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.events.event_catalog import event_noise_classification
from sli_agent.file_audit_policy import EVENT_IDS, OPTIONAL_EVENT_IDS, PROVIDER

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/207_agent_packet_projection_recovery.sql"
SQL = PATH.read_text(encoding="utf-8")


@pytest.mark.parametrize("event_id", (*EVENT_IDS, *OPTIONAL_EVENT_IDS))
def test_registers_exact_revision_emitted_by_file_event_projection(event_id):
    _classification, version = event_noise_classification(event_id, "Security", PROVIDER)
    assert version == "1.0.0"
    assert f"insert into public.event_catalog_revisions(version) values('{version}')" in SQL
    assert "on conflict(version) do nothing" in SQL
    assert "create or replace function" not in SQL and "drop trigger" not in SQL


def test_exact_predecessor_owner_and_non_destructive_quarantine_contract():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((207, "agent_packet_projection_recovery")) - 1] == (
        206, "file_audit_catalog_revision")
    assert len(pairs) == len({version for version, _ in pairs})
    assert list(PATH.parent.glob("207_*.sql")) == [PATH]
    assert "version=206 and name='file_audit_catalog_revision'" in SQL
    assert "where version>=207" in SQL
    assert "values(207,'agent_packet_projection_recovery')" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "set local role adlog_storage_owner" in SQL
    assert "packet_id uuid primary key references public.sli_agent_packet_inbox(packet_id)" in SQL
    assert "source_event_allocation_hash_mismatch" in SQL and "published_source_event_hash_mismatch" in SQL
    assert "grant select,insert on public.sli_agent_packet_quarantine to adlog_user;" in SQL
    assert "grant select on public.sli_agent_packet_quarantine to adlog_nps_agent_import_worker;" in SQL
    assert not any(keyword in SQL.lower() for keyword in ("update ", "delete ", "drop "))
    assert SQL.strip().endswith("commit;")


@pytest.mark.postgres_integration
def test_recovery_migration_preserves_catalogue_and_restricts_quarantine_privileges():
    from tools.e2e.scenario import admin_connection

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable migrated PostgreSQL required")
    with admin_connection(dsn) as conn:
        before = conn.execute("select * from event_catalog_revisions order by id").fetchall()
        conn.execute("drop table sli_agent_packet_quarantine")
        # Reapply from the exact predecessor in this disposable per-test clone.
        conn.execute("delete from schema_migrations where version>=207")
        conn.commit()
        conn.execute(SQL)
        assert conn.execute("select name from schema_migrations where version=207").fetchone()["name"] == "agent_packet_projection_recovery"
        assert conn.execute("select * from event_catalog_revisions order by id").fetchall() == before
        for role, allowed in [("adlog_user", {"SELECT", "INSERT"}),
                              ("adlog_nps_agent_import_worker", {"SELECT"})]:
            for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                assert conn.execute("select has_table_privilege(%s,'sli_agent_packet_quarantine',%s) as allowed",
                                    (role, privilege)).fetchone()["allowed"] == (privilege in allowed)
        constraints = {row["definition"] for row in conn.execute(
            "select pg_get_constraintdef(oid) as definition from pg_constraint "
            "where conrelid='sli_agent_packet_quarantine'::regclass")}
        assert "PRIMARY KEY (packet_id)" in constraints
        assert "FOREIGN KEY (packet_id) REFERENCES sli_agent_packet_inbox(packet_id)" in constraints
        assert "CHECK ((event_ordinal >= 0))" in constraints
        assert any("source_event_allocation_hash_mismatch" in item
                   and "published_source_event_hash_mismatch" in item for item in constraints)


@pytest.mark.postgres_integration
def test_recovery_migration_rejects_wrong_predecessor_without_partial_schema():
    import psycopg

    from tools.e2e.scenario import admin_connection

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable migrated PostgreSQL required")
    with admin_connection(dsn) as conn:
        conn.execute("drop table sli_agent_packet_quarantine")
        # Later markers must not mask rejection of the wrong predecessor.
        conn.execute("delete from schema_migrations where version>=207")
        conn.execute("update schema_migrations set name='fixture-wrong-predecessor' where version=206")
        conn.commit()
        with pytest.raises(psycopg.errors.RaiseException, match="migration 207 prerequisites failed"):
            conn.execute(SQL)
        conn.rollback()
        assert conn.execute("select to_regclass('sli_agent_packet_quarantine') as relation").fetchone()["relation"] is None
        assert conn.execute("select count(*) as n from schema_migrations where version=207").fetchone()["n"] == 0
