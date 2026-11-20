"""The update may reset only known, exhausted current normalization failures."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory


PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/216_semantic_quarantine_requeue.sql"
SQL = PATH.read_text("utf-8")


def test_migration_is_a_new_forward_step_with_owner_and_predecessor_gates():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    position = pairs.index((216, "semantic_quarantine_requeue"))
    assert pairs[position - 1] == (215, "directory_change_catalog_revision")
    assert len(pairs) == len(set(version for version, _ in pairs))
    assert "version=215 and name='directory_change_catalog_revision'" in SQL
    assert "where version>=216" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "set local role adlog_storage_owner;" in SQL
    assert SQL.strip().startswith("-- Retry") and SQL.strip().endswith("commit;")


def test_requeue_preserves_job_identity_and_excludes_other_terminal_failures():
    for scope in (
        "status='quarantined' and job_kind='normalize_event'",
        "semantic_contract_version=1 and processor_id='semantic-shadow'",
        "processor_version='1.4+identity-1.0'", "attempt_count>=max_attempts",
        "source_identity_json->>'id'=source_event_id::text",
        "source_identity_json->>'normalized_hash' ~ '^[0-9a-f]{64}$'",
        "last_error_code='UniqueViolation'", "last_error_code='KeyError'",
        "canonical_actions_pkey([^[:alnum:]_]|$)",
        "format('published archive block not found for event %s',source_event_id)",
    ):
        assert scope in SQL
    assert "for update" in SQL
    update = SQL.split("update public.semantic_processing_outbox job", 1)[1].split("returning job.job_id", 1)[0]
    assert "status='queued',attempt_count=0,available_at=now()" in update
    assert "from candidates old where job.job_id=old.job_id" in update
    for immutable in ("payload_json=", "source_identity_json=", "job_id=", "idempotency_key="):
        assert immutable not in update.split("from candidates", 1)[0]
    assert "delete from" not in SQL and "alter table" not in SQL


def test_terminal_receipt_is_atomic_payload_free_and_prevents_retry_budget_loops():
    assert "with candidates as materialized" in SQL
    assert "insert into public.semantic_control_audit(action,target,actor,details)" in SQL
    assert "from candidates old join requeued using(job_id)" in SQL
    assert "audit.action='semantic_quarantine_requeue_v216' and audit.target=job.job_id::text" in SQL
    receipt = SQL.split("jsonb_build_object(", 1)[1].split("from candidates old join", 1)[0]
    for key in ("original_attempt_count", "original_max_attempts", "original_error_code", "original_quarantined_at"):
        assert f"'{key}'" in receipt
    assert "encode(sha256(convert_to(old.last_error_detail,'UTF8')),'hex')" in receipt
    assert "'original_error_detail'," not in receipt
    assert "source_identity_json" not in receipt
    assert "'outcome','requeued','reason',old.reason" in receipt
