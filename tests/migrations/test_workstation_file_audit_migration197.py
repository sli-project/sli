"""Additive migration inventory and privileges; no database is contacted."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/197_workstation_file_audit.sql"


def test_source_kind_is_read_from_authored_policy_with_legacy_server_default():
    sql = PATH.read_text("utf-8")
    assert "version=196 and name='agent_msi_update_result'" in sql
    assert "where version>=197" in sql
    assert "coalesce(p.policy->>'source_kind','server')" in sql
    assert "create or replace function sli_plugin_file_audit.report_roots()" in sql
    assert "security definer set search_path=pg_catalog,pg_temp" in sql
    assert "revoke all on function sli_plugin_file_audit.report_roots() from public" in sql
    assert "grant execute on function sli_plugin_file_audit.report_roots() to adlog_user" in sql
    assert "values(197,'workstation_file_audit')" in sql
    assert "update public.sli_agents" not in sql
