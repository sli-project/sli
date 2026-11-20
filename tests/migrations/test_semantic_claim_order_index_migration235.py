"""Ordered claim access path; applied migrations and queue identities stay intact."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.semantic.semantic_processing_repository import claim_semantic_jobs


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


def test_claim_predicate_and_fifo_order_match_the_partial_index():
    class Cursor:
        def execute(self, query, params):
            self.query, self.params = query, params

        def fetchall(self):
            return []

    cur = Cursor()
    claim_semantic_jobs(cur)
    predicate = "status in ('queued','failed','leased') and attempt_count < max_attempts"
    assert predicate in SQL
    assert "and attempt_count < max_attempts" in cur.query
    assert "and status in ('queued','failed','leased')" in cur.query
    assert "(semantic_contract_version,processor_id,available_at,created_at,job_id)" in SQL
    assert "order by available_at,created_at,job_id for update skip locked limit %s" in cur.query
    assert "status='leased' and lease_until < now()" in cur.query
    assert "available_at <= now()" in cur.query
