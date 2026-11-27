"""Ordered claim access path; applied migrations and queue identities stay intact."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory


PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/235_semantic_claim_order_index.sql"
SQL = PATH.read_text("utf-8")


def test_new_forward_migration_is_atomic_owner_gated_and_registered():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    position = pairs.index((235, "semantic_claim_order_index"))
    assert pairs[position - 1] == (233, "ad_operation_credentials")
    for fragment in (
        "begin;", "pg_advisory_xact_lock",
        "pg_has_role(session_user,'adlog_storage_owner','MEMBER')",
        "version=233 and name='ad_operation_credentials'", "where version>=235",
        "set local role adlog_storage_owner;",
        "values(235,'semantic_claim_order_index')",
    ):
        assert fragment in SQL
    assert SQL.strip().endswith("commit;")
    assert "update public.semantic_processing_outbox" not in SQL
    assert "grant " not in SQL and "delete " not in SQL
