"""N01 migration contract; actual application belongs to the final gate."""

from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/224_notification_channels.sql").read_text("utf-8")


def test_migration_is_new_transactional_and_requires_exact_predecessor():
    inventory = [(item.version, item.name) for item in forward_migration_inventory(ROOT / "config/postgres_migrations")]
    position = inventory.index((224, "notification_channels"))
    assert inventory[position - 1] == (223, "home_previous_login")
    assert sum(version == 224 for version, _ in inventory) == 1
    assert "begin;" in SQL and SQL.strip().endswith("commit;")
    assert "pg_advisory_xact_lock" in SQL and "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "version=223 and name='home_previous_login'" in SQL and "where version>=224" in SQL
    assert "values(224,'notification_channels')" in SQL


def test_schema_has_two_disabled_channels_allowlisted_refs_and_no_credential_payload():
    assert "create table public.notification_channels" in SQL
    assert "enabled boolean not null default false" in SQL
    assert "default 'not_configured' check(state='not_configured')" in SQL
    assert "('smtp','starttls','SLI_NOTIFY_SMTP_PASSWORD')" in SQL
    assert "('telegram','tls','SLI_NOTIFY_TELEGRAM_TOKEN')" in SQL
    assert "secret_ref='SLI_NOTIFY_SMTP_PASSWORD'" in SQL and "secret_ref='SLI_NOTIFY_TELEGRAM_TOKEN'" in SQL
    assert "tls_mode in ('starttls','tls')" in SQL and "kind='telegram' and tls_mode='tls'" in SQL
    for forbidden in ("password text", "token text", "jsonb not null", "host text", "recipient text", "url text"):
        assert forbidden not in SQL.lower()


def test_runtime_cannot_insert_delete_or_mark_channels_delivered():
    assert "revoke all on public.notification_channels from public,adlog_user" in SQL
    assert "grant select on public.notification_channels to adlog_user" in SQL
    assert "grant update(enabled,tls_mode,secret_ref,revision,updated_at)" in SQL
    # The legacy access catalog is owned by the application role. Populate it
    # as the migration administrator, after creating the storage-owned table.
    assert SQL.index("reset role;") < SQL.index("insert into public.report_datasets_v4")
    assert "grant update(state" not in SQL and "grant insert" not in SQL and "grant delete" not in SQL
    assert '"required_capabilities":["access.manage"]' in SQL
    assert "where package_key='access_admin'" in SQL
    assert "array['view','configure_channel']" in SQL
    assert "array['technical']" in SQL and "'restricted','published'" in SQL
