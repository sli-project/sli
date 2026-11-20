"""Forward-only stage 2 schema contract; no real database."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/231_agent_gpo_plans.sql"
SQL = PATH.read_text("utf-8")


def test_forward_number_predecessor_and_owner():
    assert "version=230 and name='nps_threshold'" in SQL
    assert "version>=231" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "values(231,'agent_gpo_plans')" in SQL
    assert list(PATH.parent.glob("231_*.sql")) == [PATH]
    inventory = [(row.version, row.name) for row in forward_migration_inventory(PATH.parent)]
    assert inventory[inventory.index((231, "agent_gpo_plans")) - 1] == (230, "nps_threshold")


def test_no_implicit_assignments_and_no_runtime_grant_or_audit_mutation():
    assert "insert into public.sli_agent_gpo_deployment_grants" not in SQL
    assert "grant update(status,finished_at) on public.sli_agent_gpo_plans" in SQL
    assert "grant insert on public.sli_agent_gpo_plan_audit" in SQL
    assert "grant update on" not in SQL and "grant delete" not in SQL
    assert "security definer set search_path=pg_catalog,pg_temp" in SQL
    assert "revoke all on function public.sli_agent_gpo_plan_scope(text,bigint,text) from public" in SQL
    assert "for share" in SQL and "interval '10 minutes'" in SQL
    assert "sli_agent_group_tokens" not in SQL
    assert "sli_agent_commands" not in SQL
