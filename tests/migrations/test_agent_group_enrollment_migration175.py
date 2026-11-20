"""Forward-only group admission, exact predecessor and restricted grants."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/175_agent_group_enrollment.sql"
SQL = PATH.read_text("utf-8")


def test_exact_predecessor_and_unique_migration_number():
    assert "version=174 and name='agent_gpo_snapshot_import'" in SQL
    assert "version>=175" in SQL
    assert "values(175,'agent_group_enrollment')" in SQL
    assert list(PATH.parent.glob("175_*.sql")) == [PATH]
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL


def test_group_capacity_scope_and_request_dedup_constraints():
    assert "uses_count between 0 and max_uses" in SQL
    assert "max_uses between 1 and 10000" in SQL
    assert "interval '24 hours'" in SQL and "interval '60 seconds'" in SQL
    assert "token_hash text not null unique" in SQL
    assert "domain_id bigint not null references public.domains(id)" in SQL
    assert "computer_version_id bigint not null references public.ad_context_entity_versions(id)" in SQL
    assert "unique nulls not distinct(token_id,key_fingerprint,instance_name)" in SQL
    assert "status in ('pending','cancelled')" in SQL


def test_no_activation_or_broad_privileges_and_predecessor_audit_is_preserved():
    assert "pg_get_expr(conbin,conrelid) into strict prior_check" in SQL
    assert "check ((%s) or action in" in SQL
    assert "revoke all on public.sli_agent_group_tokens,public.sli_agent_group_requests from public,adlog_user" in SQL
    assert "grant update(uses_count,revoked_at)" in SQL
    assert "grant update(status)" in SQL
    assert not re.search(r"grant (?:all|delete|truncate)|insert into .*sli_agents|sli_agent_certificates", SQL, re.I)
