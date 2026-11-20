"""No-DB contracts for the additive registry-managed activation transition."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/166_registered_plugin_activation.sql").read_text(encoding="utf-8")


def test_replaces_only_guarded_state_function_with_existing_privilege_boundary():
    assert "version=152 and name='plugin_state'" in SQL
    assert "version=160 and name='agent_workstation_dispatch'" in SQL
    assert "version>=166" in SQL
    assert "values(166,'registered_plugin_activation')" in SQL
    assert "create or replace function public.set_plugin_enabled_v1(" in SQL
    assert "security definer set search_path=pg_catalog,public" in SQL
    assert "revoke all on function public.set_plugin_enabled_v1(text,boolean,bigint,text,bigint,boolean) from public" in SQL
    assert "grant execute on function public.set_plugin_enabled_v1(text,boolean,bigint,text,bigint,boolean) to adlog_user" in SQL
    assert "revoke create on schema public from adlog_plugin_lifecycle_owner" in SQL
    assert "delete from" not in SQL.lower()
    assert "grant update" not in SQL.lower()


def test_registered_plugins_use_locked_revision_and_server_owned_configuration():
    assert "if p_plugin_id is distinct from 'sli.remote-access'" not in SQL
    assert "where i.plugin_id=p_plugin_id for update" in SQL
    assert "pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'))" in SQL
    assert "v_current.revision<>p_revision" in SQL
    assert "v_current.package_lifecycle<>'registered'" in SQL
    assert "select coalesce(s.configured,false) into v_configured" in SQL
    assert "if p_enabled and not v_configured" in SQL
    for reason in (
        "plugin_not_found", "plugin_revision_conflict", "plugin_not_installed", "plugin_not_configured",
        "plugin_runtime_not_stopped", "plugin_runtime_not_running", "plugin_queue_not_drained",
        "plugin_active_leases", "plugin_runtime_transition_unsupported",
    ):
        assert f"raise exception '{reason}'" in SQL


def test_authority_and_atomic_audit_are_preserved_for_registry_only_plugins():
    assert "u.is_active and (u.role='admin' or exists(" in SQL
    assert "public.access_platform_owners o where o.user_id=u.id" in SQL
    assert "k.role='admin' and k.is_active and k.revoked_at is null" in SQL
    assert "k.expires_at is null or k.expires_at>now()" in SQL
    assert "raise insufficient_privilege using message='plugin_management_owner_or_admin_required'" in SQL
    generic = SQL.split("-- Registry-managed importers", 1)[1]
    assert "public.plugin_component_admission_v1 a where a.plugin_id=p_plugin_id" in generic
    assert "l.expires_at_utc>clock_timestamp()" in generic
    assert "desired_activation=case when p_enabled then 'enabled_manual' else 'disabled' end" in generic
    assert "component_runtime=case when p_enabled then 'running' else 'stopped' end" in generic
    assert "where i.plugin_id=p_plugin_id and i.revision=p_revision" in generic
    assert "revision=i.revision+1" in generic
    assert "insert into public.plugin_lifecycle_operations_v1(" in generic
    assert "v_operation_uid,p_plugin_id,v_action,p_revision,p_revision+1" in generic
    assert "public.append_administrative_activity_v1(" in generic
    assert "'plugin_lifecycle','plugin.'||v_action,'plugin',p_plugin_id" in generic


def test_vpn_retains_the_existing_component_executor_and_drain_action():
    vpn = SQL.split("if p_plugin_id='sli.remote-access' then", 2)[2].split("-- Registry-managed importers", 1)[0]
    assert "case when p_enabled then 'enable' else 'drain' end" in vpn
    assert "public.execute_plugin_runtime_transition_v1(" in vpn
    assert "PLUGIN-%s-SLI-REMOTE-ACCESS-R%s-%s" in vpn
    assert "execute_plugin_runtime_transition_v1(" not in SQL.split("-- Registry-managed importers", 1)[1]
