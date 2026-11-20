"""Static migration contract; runtime execution belongs to the final gate."""

from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/168_plugin_core_drain_handoff.sql"
SQL = PATH.read_text(encoding="utf-8")
HEADER = SQL.split("end $$;", 1)[0]


def test_migration_checks_membership_and_already_recorded_before_predecessor():
    assert "if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then" in HEADER
    assert "migration 168 requires membership in adlog_storage_owner" in HEADER
    assert "if exists(select 1 from public.schema_migrations where version=168) then" in HEADER
    assert "migration 168 already recorded" in HEADER
    assert HEADER.index("requires membership") < HEADER.index("already recorded")
    assert HEADER.index("already recorded") < HEADER.index("if not exists(")


def test_migration_requires_exact_agent_updates_predecessor_and_rejects_later_versions():
    assert (
        "if not exists(select 1 from public.schema_migrations where version=167 and name='agent_updates')\n"
        "       or exists(select 1 from public.schema_migrations where version>167) then\n"
        "        raise exception 'migration 168 requires exact migration 167 agent_updates';"
    ) in HEADER


def test_migration_inventory_has_unique_version_and_matching_marker():
    inventory = forward_migration_inventory(PATH.parent)
    migration = next(item for item in inventory if item.version == 168)
    assert migration.name == "plugin_core_drain_handoff"
    assert migration.path == PATH
    assert not (PATH.parent / "160_plugin_core_drain_handoff.sql").exists()
    assert not (PATH.parent / "167_plugin_core_drain_handoff.sql").exists()
    assert "values(168,'plugin_core_drain_handoff')" in SQL


def test_migration_locks_its_version_and_the_shared_runtime_boundary():
    assert "pg_advisory_xact_lock(hashtext('sli_plugin_core_drain_handoff_v168'))" in HEADER
    assert "pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'))" in HEADER
