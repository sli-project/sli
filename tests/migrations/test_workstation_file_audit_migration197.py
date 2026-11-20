"""Additive migration inventory and privileges; no database is contacted."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.plugins.file_audit.manifest import load_manifest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/197_workstation_file_audit.sql"


def test_next_migration_is_additive_and_manifest_checksum_is_valid():
    inventory = forward_migration_inventory(PATH.parent)
    pairs = [(entry.version, entry.name) for entry in inventory]
    position = pairs.index((197, "workstation_file_audit"))
    assert position > 0
    assert pairs[position - 1] == (196, "agent_msi_update_result")
    assert len(pairs) == len({version for version, _ in pairs})
    assert list(PATH.parent.glob("197_*.sql")) == [PATH]
    migrations = [item for item in load_manifest()["data"]["migrations"] if item["version"] == 197]
    assert len(migrations) == 1
    assert migrations[0]["name"] == "workstation_file_audit"
    assert migrations[0]["core_prerequisites"] == [196]


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
