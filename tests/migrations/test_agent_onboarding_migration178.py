"""Exact predecessor, unique allocation and preparation-only schema contract."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/178_agent_onboarding.sql").read_text("utf-8")


def test_exact_agent_removal_predecessor_and_unique_migration_number():
    assert "version=177 and name='agent_removal'" in SQL
    assert "version>=178" in SQL
    assert "values(178,'agent_onboarding')" in SQL
    assert "hashtext('sli_agent_onboarding_v178')" in SQL
    assert "migration 178 requires exact migration 177 agent_removal" in SQL
    assert [p.name for p in (ROOT / "config/postgres_migrations").glob("178_*.sql")] == ["178_agent_onboarding.sql"]


def test_templates_are_append_only_pinned_copies_and_no_deployment_is_enabled():
    assert "primary key(id,version)" in SQL
    assert "request_id uuid not null unique" in SQL
    assert "foreign key(template_id,template_version)" in SQL
    assert "template_sha256 text" in SQL
    assert "check(status in ('pending','cancelled','approved'))" in SQL
    assert "grant select,insert on public.sli_agent_policy_templates,public.sli_agent_onboarding_copies to adlog_user" in SQL
    assert not re.search(r"grant (?:update|delete|truncate|all).*?on public.sli_agent_policy_templates", SQL, re.I)
    assert not re.search(r"insert into (?:public\.)?sli_agents|update (?:public\.)?sli_agents set|sli_agent_certificates", SQL, re.I)
