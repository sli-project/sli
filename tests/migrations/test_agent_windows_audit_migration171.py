"""Audit state migration contracts without a database or checksum overrides."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/171_agent_windows_audit.sql").read_text("utf-8")


def test_exact_predecessor_owner_and_transaction():
    preflight, body = SQL.split("set local role adlog_storage_owner;")
    assert SQL.strip().startswith("begin;") and SQL.strip().endswith("commit;")
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in preflight
    assert "where version=171" in preflight and "where version>170" in preflight
    assert "where version=170 and name='agent_snapshot_stream'" in preflight
    assert "values(171,'agent_windows_audit')" in body


def test_bounded_unknown_state_and_narrow_runtime_grant():
    assert "windows_audit jsonb not null default '{}'::jsonb" in SQL
    assert "octet_length(windows_audit::text)<=16384" in SQL
    assert "grant update(windows_audit) on public.sli_agents to adlog_user" in SQL
    assert "grant update on" not in SQL and "delete" not in SQL.lower()
    assert "alter column collection_policy" not in SQL


def test_inventory_uses_next_free_version():
    inventory = forward_migration_inventory(ROOT / "config/postgres_migrations")
    # Later migrations may follow; pin only the predecessor and uniqueness.
    pairs = [(item.version, item.name) for item in inventory]
    position = pairs.index((171, "agent_windows_audit"))
    assert pairs[position - 1] == (170, "agent_snapshot_stream")
    assert [version for version, _ in pairs].count(171) == 1
