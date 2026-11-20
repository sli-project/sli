"""No-DB contracts for registering built-in AD/GPO importers on upgrade."""
import json
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.core.job_queue import digest


ROOT = Path(__file__).resolve().parents[2]


def migration():
    return (ROOT / "config/postgres_migrations/182_bundled_ad_gpo_defaults.sql").read_text(encoding="utf-8")


def test_migration_follows_its_predecessor_with_a_unique_version():
    inventory = forward_migration_inventory(ROOT / "config/postgres_migrations")
    versions = [item.version for item in inventory]
    assert len(versions) == len(set(versions))
    pairs = [(item.version, item.name) for item in inventory]
    position = pairs.index((182, "bundled_ad_gpo_defaults"))
    assert position > 0
    assert pairs[position - 1] == (181, "ad_state_privilege_category")


def test_registers_both_bundled_packages_with_reviewed_manifest_hashes():
    sql = migration()
    for plugin in ("sli.ad", "sli.gpo"):
        manifest = json.loads((ROOT / f"config/plugin_packages/v3/{plugin}.json").read_text(encoding="utf-8"))
        assert f"'{plugin}','{plugin}.package.v3','{digest(manifest)}'" in sql
    assert "'1.0.0','registered','enabled_manual','unknown','running','drained',1,1" in sql
    assert "on conflict(plugin_id) do nothing" in sql
    assert "values('sli.ad',true),('sli.gpo',true)" in sql


def test_upgrade_preserves_explicit_lifecycle_decisions_and_live_admission():
    sql = migration()
    assert "i.plugin_id in ('sli.ad','sli.gpo')" in sql
    assert "i.package_lifecycle='registered'" in sql
    assert "i.desired_activation='disabled' and i.component_runtime='stopped'" in sql
    assert "i.queue_state='drained'" in sql
    assert "o.requested_action in ('drain','disable','detach') and o.outcome='succeeded'" in sql
    assert "l.released_at_utc is null and l.expires_at_utc>clock_timestamp()" in sql
    assert "public.plugin_component_admission_v1 a where a.plugin_id=i.plugin_id" in sql
    assert "revision=i.revision+1" in sql
    assert "delete from" not in sql.lower()
    assert "grant " not in sql.lower()


def test_migration_is_atomic_and_serializes_with_import_authorization():
    sql = migration()
    assert sql.splitlines()[1] == "begin;"
    assert sql.rstrip().endswith("commit;")
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
    assert "version=181 and name='ad_state_privilege_category'" in sql
    assert "version>=182" in sql
    assert "pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'))" in sql
    assert "set local role adlog_plugin_lifecycle_owner" in sql
    assert "values(182,'bundled_ad_gpo_defaults')" in sql
