"""Additive DC binding migration contract, without PostgreSQL connections."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/161_ad_dc_agent.sql").read_text("utf-8")


def test_exact_predecessor_and_owner_guard():
    assert "version=160 and name='agent_workstation_dispatch'" in SQL
    assert "or exists(select 1 from public.schema_migrations where version>160)" in SQL
    assert "migration 161 requires exact migration 160 agent_workstation_dispatch" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "set local role adlog_storage_owner" in SQL
    assert "version=161" in SQL and "values(161,'ad_dc_agent')" in SQL
    assert SQL.startswith("-- ") and SQL.splitlines()[1] == "begin;"
    assert SQL.strip().endswith("commit;")


def test_only_binding_allowlist_changes_without_enabling_or_rewriting_evidence():
    assert "drop constraint sli_agent_module_bindings_module_id_check" in SQL
    assert "'sli.windows-eventlog','sli.workstations','sli.windows.ad-dc'" in SQL
    for forbidden in ("update sli_agents", "insert into sli_agent_module_bindings", "delete from",
                      "drop table", "grant all", "grant insert", "grant update"):
        assert forbidden not in SQL.lower()
