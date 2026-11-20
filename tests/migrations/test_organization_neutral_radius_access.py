from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "config/postgres_migrations/151_organization_neutral_radius_access.sql"


def test_migration_151_follows_exact_storage_bigint_contract():
    sql = MIGRATION.read_text(encoding="utf-8").lower()
    assert not list(MIGRATION.parent.glob("150_organization_neutral_radius_access*.sql"))
    assert "ad_log_organization_neutral_radius_access_v151" in sql
    assert "where version=150 and name='storage_v2_event_bigint'" in sql
    assert "migration 151 requires exact migration 150 storage_v2_event_bigint" in sql
    assert "where version=151 and name is distinct from 'organization_neutral_radius_access'" in sql
    assert "migration version 151 is already owned by another contract" in sql
    assert "values (151,'organization_neutral_radius_access')" in sql
    assert "149" not in sql


def test_existing_access_policies_are_preserved_and_package_requires_assignment():
    sql = MIGRATION.read_text(encoding="utf-8").lower()
    assert "insert into public.access_packages" in sql
    assert "package.package_key='vpn_evidence_reader'" in sql
    assert "capability.capability_key='vpn.session.evidence.read'" in sql
    for table in ("auth_users", "access_capability_assignments", "access_subject_packages", "access_role_packages"):
        assert f"insert into public.{table}" not in sql
        assert f"update public.{table}" not in sql
        assert f"delete from public.{table}" not in sql


def test_evidence_view_requires_registered_matching_source_and_keeps_security_barrier():
    sql = MIGRATION.read_text(encoding="utf-8").lower()
    assert "with (security_barrier=true)" in sql
    assert "subscription.subscription_id=delivery.subscription_id" in sql
    assert "evidence.source_instance_id=subscription.source_instance_id" in sql
    assert "observation.session_identity_key=projection.session_identity_key" in sql
    assert "observation.exact_principal_key=projection.exact_principal_key" in sql
    assert "revoke create on schema public from adlog_vpn_session_reader_owner" in sql
    assert "where version=150 and name='storage_v2_event_bigint'" in sql


def test_existing_installation_preflight_is_updated_without_changing_its_read_boundary():
    sql = MIGRATION.read_text(encoding="utf-8").lower()
    signature = "public.sli_g11a3_preflight_state_v1()"
    assert f"create or replace function {signature}" in sql
    assert "set local role adlog_radius_preflight_reader" in sql
    assert "security definer" in sql
    assert "set search_path = pg_catalog, public" in sql
    assert "registration_count<>1 or observed_revision is null" in sql
    assert "subscription.subscription_id like 'vpn-radius-session-observations-%-v1'" in sql
    assert "revoke create on schema public from adlog_radius_preflight_reader" in sql
    assert "revoke all" not in sql
    assert "grant execute" not in sql
