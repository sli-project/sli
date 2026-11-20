"""Forward-only binding schema; no database or AD access."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/242_gpo_plan_credentials.sql"
SQL = PATH.read_text("utf-8")


def test_next_free_number_and_main_predecessor():
    assert "version=241 and name='report_schedules'" in SQL
    assert "version>=242" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "values(242,'gpo_plan_credentials')" in SQL
    assert list(PATH.parent.glob("242_*.sql")) == [PATH]
    pairs = [(r.version, r.name) for r in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((242, "gpo_plan_credentials")) - 1] == (241, "report_schedules")


def test_recipient_and_audit_cannot_be_assigned_or_changed_by_runtime():
    assert "insert into public.sli_gpo_plan_recipients" not in SQL
    assert "grant select,insert on public.sli_gpo_plan_last_credentials" in SQL
    assert "grant update(credential_id,credential_revision)" in SQL
    assert "grant update on" not in SQL and "grant delete" not in SQL
    assert "security definer set search_path=pg_catalog,pg_temp" in SQL
    assert "revoke all on function public.sli_gpo_plan_recipient(bigint) from public" in SQL
    assert "revoked_at is null" in SQL and "not_after>clock_timestamp()" in SQL
    assert "agent.status<>'active'" in SQL and "for share" in SQL
    assert "'grant_permissions',assignment.permissions" in SQL
    assert "create or replace function public.sli_agent_gpo_plan_scope" in SQL
    assert "sli_agent_commands" not in SQL and "envelope" not in SQL
