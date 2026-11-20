"""Additive migration source/privilege contract; no real database."""
import re
from pathlib import Path

SQL = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/156_agent_registry.sql").read_text(encoding="utf-8")


def test_exact_predecessor_owner_and_ledger_contract():
    preflight = SQL.split("set local role adlog_storage_owner;")[0]
    assert "pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER')" in preflight
    assert "pg_advisory_xact_lock(hashtext('ad_log_agent_registry_v156'))" in preflight
    assert "version=155 and name='core_identity_scope'" in preflight
    assert "migration 156 requires exact migration 155 core_identity_scope" in preflight
    assert "version=156 and name <> 'agent_registry'" in preflight
    assert "grant select, insert on schema_migrations to adlog_storage_owner" in preflight
    assert "grant usage, select on sequence schema_migrations_id_seq to adlog_storage_owner" in preflight
    assert "values(156,'agent_registry')" in SQL
    assert SQL.strip().startswith("begin;") and SQL.strip().endswith("commit;")
    assert all(
        message.startswith("migration 156 ")
        for message in re.findall(r"raise exception '([^']+)'", preflight)
    )
    assert not re.search(r"\b(?:153|154)\b|v154", SQL)


def test_new_schema_has_hash_only_tokens_bounded_ttl_and_internal_fk():
    tokens = SQL.split("create table sli_agent_enrollment_tokens")[1].split("create table sli_agent_certificates")[0]
    assert "token_hash text not null unique" in tokens
    assert "interval '1 hour'" in tokens
    assert "used_at timestamptz" in tokens and "revoked_at timestamptz" in tokens
    assert "key_fingerprint text not null" in tokens
    assert "token text" not in tokens
    assert "host_id uuid not null unique" in SQL
    assert "references sli_agents(id)" in SQL
    # Only same-owner objects are referenced: no legacy REFERENCES grant needed.
    assert re.findall(r"references (\w+)\(", SQL) == ["sli_agents"]
    assert SQL.index("set local role adlog_storage_owner") < SQL.index("create table sli_agents")


def test_runtime_can_neither_ddl_nor_delete_history_or_change_audit():
    grants = re.findall(r"grant\s+[^;]+;", SQL.lower())
    runtime_grants = [g for g in grants if "to adlog_user" in g]
    assert all("delete" not in g and "create" not in g and "all" not in g for g in runtime_grants)
    audit_grants = [g for g in runtime_grants if "sli_agent_audit" in g and "sequence" not in g]
    assert audit_grants == ["grant select, insert on sli_agent_audit to adlog_user;"]
    assert "grant update(status,key_fingerprint,last_seen) on sli_agents" in SQL
    assert "grant update(revoked_at) on sli_agent_certificates" in SQL
    assert "on sli_agent_audit(id) where action='revoke'" in SQL
    assert "private_key" not in SQL and "certificate_pem" not in SQL
