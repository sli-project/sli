"""Throughput/access and fail-closed recovery contracts, without a database."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory


PATH = Path(__file__).resolve().parents[2] / 'config/postgres_migrations/246_semantic_throughput.sql'
SQL = PATH.read_text('utf-8')


class Cursor:
    def execute(self, query, params=()):
        self.query, self.params = query, params

    def fetchall(self):
        return []


def test_migration_is_new_atomic_owner_gated_step():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((246, 'semantic_throughput')) - 1] == (245, 'file_decoy')
    for fragment in (
        "pg_has_role(session_user,'adlog_storage_owner','MEMBER')",
        "version=245 and name='file_decoy'", 'where version>=246',
        'pg_advisory_xact_lock', 'set local role adlog_storage_owner;',
        "set local lock_timeout='5s';", "values(246,'semantic_throughput')",
    ):
        assert fragment in SQL
    assert SQL.strip().endswith('commit;')


def test_retry_requires_restored_admission_and_preserves_identity_and_receipt():
    for fragment in (
        "job.evaluation_status='quarantined' and job.source_kind='canonical_action'",
        "job.evaluation_mode='enabled' and job.attempt_count>=job.max_attempts",
        'admission.enabled is true', "policy.lifecycle_status)='enabled'",
        "job.last_error_code='RuntimeError'",
        "job.last_error_detail='semantic finding requires an observed enabled result'",
        'where result.job_id=job.job_id',
        "audit.action='semantic_risk_quarantine_requeue_v246' and audit.target=job.job_id::text",
        'limit 128 for update of job skip locked for share of policy skip locked',
        'from candidates old join requeued using(job_id)',
    ):
        assert fragment in SQL
    update = SQL.split('update public.semantic_risk_evaluation_jobs job')[1].split('from candidates')[0]
    assert "evaluation_status='queued',attempt_count=0,available_at=now()" in update
    for immutable in ('policy_id=', 'source_reference=', 'job_id=', 'idempotency_key=', 'canonical_action_id='):
        assert immutable not in update
    receipt = SQL.split('jsonb_build_object(')[1]
    assert "'original_error_detail_sha256'" in receipt
    assert "'original_error_detail'," not in receipt
    assert 'insert into public.semantic_policy_admission' not in SQL
    assert 'update public.semantic_policy_admission' not in SQL
    assert 'delete from' not in SQL and 'grant ' not in SQL
