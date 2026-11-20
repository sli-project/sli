"""Static privilege contract; no database or applied checksum mutation."""
from pathlib import Path
import re

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/173_nps_agent_import.sql").read_text("utf-8").lower()


def test_exact_predecessor_and_unique_inventory_version():
    assert "version=172 and name='agent_ad_snapshot_import'" in SQL
    assert "version>=173" in SQL
    assert "values(173,'nps_agent_import')" in SQL
    pairs = [(item.version, item.name) for item in
             forward_migration_inventory(ROOT / "config/postgres_migrations")]
    position = pairs.index((173, "nps_agent_import"))
    assert pairs[position - 1] == (172, "agent_ad_snapshot_import")
    assert [version for version, _ in pairs].count(173) == 1


def test_nps_import_role_is_narrow_and_never_assigned_to_http_runtime():
    sql = SQL
    assert re.search(r"create role adlog_nps_agent_import_worker nologin noinherit nosuperuser\s+"
                     r"nocreatedb nocreaterole noreplication nobypassrls", sql)
    assert "grant adlog_radius_accounting_worker to adlog_nps_agent_import_worker" in sql
    assert "grant update(imported_at)" in sql
    assert "read_plugin_states_v1()" in sql
    assert "to adlog_user" not in sql and "create table" not in sql
    assert "update public.sli_agents" not in sql and "grant all" not in sql
