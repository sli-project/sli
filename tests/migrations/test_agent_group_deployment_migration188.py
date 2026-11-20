"""Forward-only group deployment contracts; no database connection."""
from pathlib import Path
import re

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/188_agent_group_deployment.sql"
SQL = PATH.read_text("utf-8")


def test_next_migration_exact_main_predecessor_and_owner():
    assert "version=187 and name='file_audit_rules'" in SQL
    assert "version>=188" in SQL
    assert "values(188,'agent_group_deployment')" in SQL
    assert "hashtext('sli_agent_group_deployment_v188')" in SQL
    assert "migration 188 requires membership in adlog_storage_owner" in SQL
    assert "migration 188 requires exact migration 187 file_audit_rules and unused version 188" in SQL
    assert list(PATH.parent.glob("188_*.sql")) == [PATH]
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    position = pairs.index((188, "agent_group_deployment"))
    assert position > 0
    assert pairs[position - 1] == (187, "file_audit_rules")
    assert len(pairs) == len({version for version, _ in pairs})
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL


def test_group_binding_ttl_backfill_and_immutable_scope():
    assert "select id,domain_id,ou_entity_ids from public.sli_agent_group_tokens" in SQL
    assert "update public.sli_agent_group_tokens set group_id=id" in SQL
    assert "alter column group_id set not null" in SQL
    assert "foreign key(group_id,domain_id,ou_entity_ids)" in SQL
    assert "references public.sli_agent_enrollment_groups(id,domain_id,ou_entity_ids)" in SQL
    assert "interval '7 days'" in SQL and "interval '60 seconds'" in SQL
    assert "pg_get_expr(conbin,conrelid) like '%expires_at%'" in SQL
    assert "into strict ttl_constraint" in SQL


def test_approvals_membership_audit_and_minimal_privileges():
    assert "request_id uuid primary key references public.sli_agent_group_requests(id)" in SQL
    assert "enrollment_token_id uuid not null unique references public.sli_agent_enrollment_tokens(id)" in SQL
    assert "agent_id uuid primary key references public.sli_agents(id)" in SQL
    assert "status in ('pending','cancelled','approved')" in SQL
    assert "with(security_invoker=true)" in SQL
    assert "select request_id,enrollment_token_id from public.sli_agent_onboarding_copies" in SQL
    assert "revoke all on public.sli_agent_group_approval_links from public,adlog_user" in SQL
    assert "pg_get_expr(conbin,conrelid) into strict prior_check" in SQL
    assert "check ((%s) or action in" in SQL
    assert "revoke all on public.sli_agent_enrollment_groups,public.sli_agent_group_approvals,public.sli_agent_group_members from public,adlog_user" in SQL
    assert not re.search(r"grant (?:all|delete|truncate|update)|insert into .*sli_agents|sli_agent_certificates", SQL, re.I)
