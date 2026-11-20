"""N03 schema contracts; SQL application is verified separately on disposable PG."""

from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/225_notification_outbox.sql").read_text("utf-8")


def test_new_migration_has_exact_predecessor_and_transactional_catalog_registration():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(ROOT / "config/postgres_migrations")]
    position = pairs.index((225, "notification_outbox"))
    assert pairs[position - 1] == (224, "notification_channels")
    assert sum(version == 225 for version, _ in pairs) == 1
    assert "begin;" in SQL and SQL.strip().endswith("commit;")
    assert "version=224 and name='notification_channels'" in SQL and "where version>=225" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "values(225,'notification_outbox')" in SQL
    assert SQL.index("reset role;") < SQL.index("insert into public.report_datasets_v4")
    assert "'notifications.deliveries'" in SQL and "where package_key='access_admin'" in SQL


def test_durable_jobs_have_idempotency_fenced_leases_and_bounded_safe_states():
    assert "unique(object_kind,object_id,recipient_user_id,channel)" in SQL
    assert "object_kind='test_problem'" in SQL
    assert "subscription_revision bigint not null" in SQL
    assert "lease_token uuid" in SQL and "lease_until timestamptz" in SQL
    assert "state='sending' and lease_token is not null and lease_until is not null" in SQL
    assert "state<>'sending' and lease_token is null and lease_until is null" in SQL
    assert "notification_outbox_due" in SQL and "notification_outbox_expired" in SQL
    assert "primary key(job_id,attempt)" in SQL
    assert "accepted" not in SQL and "secret" not in SQL.lower()


def test_runtime_cannot_delete_history_or_rewrite_job_identity():
    assert "from public,adlog_user" in SQL
    assert "grant select,insert" in SQL and "grant delete" not in SQL
    assert "grant update(state,attempts,lease_token,lease_until,available_at,result_code,updated_at)" in SQL
    assert "grant update(id" not in SQL and "grant update(object_id" not in SQL
    assert "grant update on public.notification_attempts" not in SQL
    for forbidden in ("password text", "token text", "recipient text", "url text", "body text", "payload json"):
        assert forbidden not in SQL.lower()
