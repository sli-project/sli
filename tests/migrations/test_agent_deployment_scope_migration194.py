"""Forward migration contract only; no runtime database contact."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/194_agent_deployment_scope.sql"
SQL = PATH.read_text("utf-8")


def test_exact_predecessor_owner_and_unique_forward_number():
    assert "version=193 and name='file_audit_retention'" in SQL
    assert "version>=194" in SQL
    assert "sli_agent_deployment_scope_v194" in SQL
    assert "migration 194 prerequisites failed" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "values(194,'agent_deployment_scope')" in SQL
    assert list(PATH.parent.glob("194_*.sql")) == [PATH]
    inventory = [(row.version, row.name) for row in forward_migration_inventory(PATH.parent)]
    position = inventory.index((194, "agent_deployment_scope"))
    assert position > 0
    assert inventory[position - 1] == (193, "file_audit_retention")
    assert len({version for version, _ in inventory}) == len(inventory)


def test_domain_scope_opt_in_defaults_and_credential_rotation_grants():
    assert "between 0 and 128" in SQL
    assert "'public.sli_agent_enrollment_groups'::regclass,'public.sli_agent_group_tokens'::regclass" in SQL
    assert "computer_entity_ids bigint[] not null default '{}'" in SQL
    assert "enrollment_policy jsonb not null default '{}'" in SQL
    assert "grant update(token_hash,created_at,expires_at) on public.sli_agent_enrollment_tokens to adlog_user" in SQL
    assert "action=''group_auto_approval''" in SQL
    assert "insert into public.sli_agents" not in SQL
    assert "delete from" not in SQL and "truncate" not in SQL and "grant all" not in SQL
