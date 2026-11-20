"""Built-in L1 policies are admitted on install; explicit owner choices win."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory


PATH = Path(__file__).resolve().parents[2] / 'config/postgres_migrations/256_default_policy_admission.sql'
SQL = PATH.read_text('utf-8')


def test_migration_is_new_atomic_owner_gated_step():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((256, 'default_policy_admission')) - 1] == (255, 'workstation_protection_predecessor')
    for fragment in (
        "pg_has_role(session_user,'adlog_storage_owner','MEMBER')",
        "version=255 and name='workstation_protection_predecessor'", 'where version>=256',
        'pg_advisory_xact_lock', 'set local role adlog_storage_owner;',
        "set local lock_timeout='5s';", "values(256,'default_policy_admission')",
    ):
        assert fragment in SQL
    assert SQL.strip().endswith('commit;')


def test_admits_only_builtin_ready_policies_and_keeps_owner_choice():
    admission = SQL.split('insert into public.semantic_policy_admission')[1].split(';')[0]
    for policy in ('l1-audit-policy-changed', 'l1-eventlog-cleared',
                   'l1-privileged-group-member-added', 'l1-scheduled-task-created'):
        assert f"'{policy}'" in admission
    assert "'system:defaults'" in admission
    assert "lifecycle_status in ('shadow','enabled')" in admission
    assert 'on conflict (policy_id,policy_version) do nothing' in admission
    assert 'update public.semantic_policy_admission' not in SQL
    assert 'delete from' not in SQL and 'grant ' not in SQL


def test_retry_is_limited_to_missing_admission_quarantine_and_audited():
    for fragment in (
        "job.evaluation_status='quarantined' and job.source_kind='canonical_action'",
        "admission.updated_by='system:defaults'",
        "job.last_error_detail='semantic finding requires an observed enabled result'",
        'where result.job_id=job.job_id',
        "audit.action='semantic_risk_quarantine_requeue_v256' and audit.target=job.job_id::text",
        'from candidates old join requeued using(job_id)',
    ):
        assert fragment in SQL
    update = SQL.split('update public.semantic_risk_evaluation_jobs job')[1].split('from candidates')[0]
    for immutable in ('policy_id=', 'source_reference=', 'job_id=', 'idempotency_key=', 'canonical_action_id='):
        assert immutable not in update
