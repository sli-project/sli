from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/152_plugin_state.sql").read_text(encoding="utf-8")
ROLLBACK = (ROOT / "config/postgres_migrations/152_plugin_state.rollback.sql").read_text(encoding="utf-8")


def test_state_extends_canonical_registry_without_copying_activation_axes():
    table = SQL.split("create table plugin_state_v1 (")[1].split(");")[0]
    assert "references plugin_installations_v1(plugin_id)" in table
    assert "configured boolean" in table and "last_data_at_utc timestamptz" in table
    assert "desired_activation" not in table
    assert "i.package_lifecycle='registered'" in SQL
    assert "s.last_data_at_utc>now()-interval '10 minutes'" in SQL
    assert "revoke all on plugin_state_v1 from public,adlog_user" in SQL


def test_changes_use_existing_audited_transition_and_numeric_authority():
    assert "public.auth_users" in SQL and "public.access_platform_owners" in SQL
    assert "k.role='admin'" in SQL and "k.revoked_at is null" in SQL
    assert "v_current.revision<>p_revision" in SQL
    assert "case when p_enabled then 'enable' else 'drain' end" in SQL
    assert "public.execute_plugin_runtime_transition_v1(" in SQL
    original = (ROOT / "config/postgres_migrations/076_plugin_runtime_activation_executor.sql").read_text(encoding="utf-8")
    assert "append_administrative_activity_v1(" in original
    assert "when 'radius-acquisition' then 'closed' else 'drain_only' end" in original


def test_drain_finishes_only_when_queue_and_active_leases_are_empty():
    finish = SQL.split("create function finish_remote_access_plugin_drain_v1()")[1]
    assert "component_runtime<>'draining'" in finish
    assert "expires_at_utc>clock_timestamp()" in finish
    assert "read_plugin_runtime_queue_nonterminal_v1()<>0" in finish
    assert "pg_advisory_xact_lock" in finish and "for update" in finish
    assert "'system','plugin_drain'" in finish
    assert "subscription.consumer_id='sli.windows.vpn-radius'" in SQL
    assert "subscription.consumer_component_id='radius-session-observation'" in SQL


def test_migration_and_rollback_preserve_data_permissions_and_history():
    assert "version=151 and name='organization_neutral_radius_access'" in SQL
    assert "version=149" not in SQL
    assert "values(152,'plugin_state')" in SQL
    assert "delete from" not in SQL.lower()
    assert "rollback 152 refuses observed state or active drain" in ROLLBACK
    assert "drop table plugin_state_v1" in ROLLBACK
    assert "drop table plugin_installations_v1" not in ROLLBACK
    assert "access_report" not in SQL and "access_report" not in ROLLBACK


def test_migration_and_rollback_use_the_renumbered_version_consistently():
    assert "ad_log_plugin_state_v152" in SQL and "ad_log_plugin_state_v152" in ROLLBACK
    assert "migration 152 requires membership" in SQL
    assert "migration 152 requires exact migrations 151, 076 and 078" in SQL
    assert "version=152" in SQL and "migration 152 already applied" in SQL
    assert "version=152 and name='plugin_state'" in ROLLBACK
    assert "version>152" in ROLLBACK
    assert "rollback 152 prerequisites failed" in ROLLBACK
    assert "150" not in SQL and "150" not in ROLLBACK
