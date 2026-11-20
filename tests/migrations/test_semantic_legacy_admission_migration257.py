"""Legacy admission/backlog repair contracts; no runtime database required."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory


PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/257_semantic_legacy_admission.sql"
SQL = PATH.read_text("utf-8")


def test_new_atomic_owner_gated_migration():
    migrations = [(row.version, row.name) for row in forward_migration_inventory(PATH.parent)]
    assert (257, "semantic_legacy_admission") in migrations
    for fragment in (
        "pg_advisory_xact_lock", "set local lock_timeout='5s'",
        "pg_has_role(session_user,'adlog_storage_owner','MEMBER')",
        "version=255 and name='workstation_protection_predecessor'",
        "version=246 and name='semantic_throughput'",
        "where version>=257", "set local role adlog_storage_owner",
        "values(257,'semantic_legacy_admission')",
    ):
        assert fragment in SQL
    assert SQL.strip().endswith("commit;")


def test_backfill_preserves_revocations_and_never_promotes_other_policies():
    admission = SQL.split("insert into public.semantic_policy_admission", 1)[1].split("-- Migration 246", 1)[0]
    assert "policy_id='l1-audit-policy-changed' and policy_version=2" in admission
    assert "source_kind='canonical_action' and lifecycle_status='enabled'" in admission
    assert "on conflict(policy_id,policy_version) do nothing" in admission
    assert "do update" not in admission
    assert "for update;" in SQL.split("insert into public.semantic_policy_admission", 1)[0]
    assert "update public.semantic_risk_policies" not in SQL
    assert "update public.semantic_policy_admission" not in SQL
    assert "'shadow'" not in SQL and "'test'" not in SQL
    assert "grant " not in SQL and "delete from" not in SQL


def test_retry_is_bounded_exact_admitted_and_has_no_committed_result():
    for fragment in (
        "policy.policy_id='l1-audit-policy-changed' and policy.policy_version=2",
        "policy.source_kind='canonical_action' and policy.lifecycle_status='enabled'",
        "admission.enabled is true",
        "job.evaluation_status='quarantined' and job.source_kind='canonical_action'",
        "job.evaluation_mode='enabled' and job.attempt_count>=job.max_attempts",
        "job.last_error_code='RuntimeError'",
        "job.last_error_detail='semantic finding requires an observed enabled result'",
        "where result.job_id=job.job_id", "audit.target=job.job_id::text",
        "limit 128 for update of job skip locked",
        "from candidates old join requeued using(job_id)",
    ):
        assert fragment in SQL
    update = SQL.split("update public.semantic_risk_evaluation_jobs job", 1)[1].split("from candidates", 1)[0]
    assert "evaluation_status='queued',attempt_count=0,available_at=now()" in update
    for immutable in ("job_id=", "policy_id=", "source_reference=", "canonical_action_id=", "idempotency_key="):
        assert immutable not in update


def test_retry_retains_a_receipt_without_source_data_or_exception_text():
    receipt = SQL.split("jsonb_build_object(", 1)[1]
    assert "'original_attempt_count'" in receipt
    assert "'original_error_code'" in receipt
    assert "'original_error_detail_sha256'" in receipt
    assert "'original_quarantined_at'" in receipt
    assert "'original_error_detail'," not in receipt
    assert "payload_json" not in SQL
