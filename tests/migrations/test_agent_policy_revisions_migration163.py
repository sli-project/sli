"""Additive revision schema/privilege contract, without a database."""
from pathlib import Path

SQL = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/163_agent_policy_revisions.sql").read_text(encoding="utf-8")


def test_migration_163_requires_exact_predecessor_and_storage_owner():
    preflight = SQL.split("set local role adlog_storage_owner;")[0]
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in preflight
    assert "version=162 and name='finding_risk_acceptance'" in preflight
    assert "version>162" in preflight
    assert "migration 163 requires exact migration 162 finding_risk_acceptance" in preflight
    assert "version=163" in preflight and "migration 163 already applied" in preflight
    assert "sli_agent_policy_revisions_v163" in preflight
    assert "migration 163 requires membership in adlog_storage_owner" in preflight
    assert SQL.strip().startswith("begin;") and SQL.strip().endswith("commit;")
    assert "values(163,'agent_policy_revisions')" in SQL
    assert not (Path(__file__).resolve().parents[2] / "config/postgres_migrations/162_agent_policy_revisions.sql").exists()


def test_ack_bounds_and_privileges_preserve_append_only_audit():
    assert "applied_policy_revision between 0 and policy_revision" in SQL
    assert "policy_revision between 1 and 9007199254740991" in SQL
    assert "grant update(policy_revision,applied_policy_revision,rights_probe) on public.sli_agents to adlog_user" in SQL
    assert "'module_assign','policy_ack','probe_request','probe_report'" in SQL
    assert "update on public.sli_agent_audit" not in SQL
    columns = SQL.split("alter table public.sli_agents")[1].split("grant update")[0]
    assert "delete" not in SQL and "token" not in columns
