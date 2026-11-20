"""Additive per-agent control schema; no database or checksum overrides."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

SQL = (Path(__file__).resolve().parents[2] / "config/postgres_migrations/169_agent_collection_control.sql").read_text("utf-8")


def test_exact_predecessor_and_transaction_owner():
    preflight = SQL.split("set local role adlog_storage_owner;")[0]
    assert "version=168 and name='plugin_core_drain_handoff'" in preflight
    assert "version>168" in preflight and "version=169" in preflight
    assert "sli_agent_collection_control_v169" in preflight
    assert "migration 169 requires membership in adlog_storage_owner" in preflight
    assert "migration 169 already applied" in preflight
    assert "migration 169 requires exact migration 168 plugin_core_drain_handoff" in preflight
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in preflight
    assert SQL.strip().startswith("begin;") and SQL.strip().endswith("commit;")
    assert "values(169,'agent_collection_control')" in SQL


def test_forward_inventory_keeps_main_predecessors_and_unique_control_version():
    root = Path(__file__).resolve().parents[2] / "config/postgres_migrations"
    inventory = forward_migration_inventory(root)
    # Later migrations may follow; pin only the predecessors and uniqueness.
    pairs = [(item.version, item.name) for item in inventory]
    position = pairs.index((169, "agent_collection_control"))
    assert pairs[position - 3:position + 1] == [
        (166, "registered_plugin_activation"),
        (167, "agent_updates"),
        (168, "plugin_core_drain_handoff"),
        (169, "agent_collection_control"),
    ]
    assert [version for version, _ in pairs].count(169) == 1
    assert not (root / "168_agent_collection_control.sql").exists()


def test_individual_control_and_ack_state_preserve_audit_privileges():
    assert "alter table public.sli_agents" in SQL
    assert "collection_policy jsonb" in SQL and "applied_collection_state text" in SQL
    assert "grant update(collection_policy,applied_collection_state)" in SQL
    assert "'policy_update'" in SQL
    assert "primary key(agent_id,revision)" in SQL
    assert "grant select,insert on public.sli_agent_policy_history to adlog_user" in SQL
    assert "pg_get_expr(conbin,conrelid)" in SQL
    assert "update on public.sli_agent_audit" not in SQL
    assert "delete" not in SQL.lower()
