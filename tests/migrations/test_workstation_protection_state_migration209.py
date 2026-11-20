"""Current protection snapshots keep native event evidence and grants intact."""
import hashlib
import json
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/209_workstation_protection_state.sql"


def test_protection_migration_is_unique_and_manifest_attests_its_bytes():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    position = pairs.index((209, "workstation_protection_state"))
    assert pairs[position - 1] == (208, "file_audit_collection_replay")
    assert len(pairs) == len({version for version, _ in pairs})
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.workstations.json").read_text("utf-8"))
    migration = next(m for m in manifest["data"]["migrations"] if m["version"] == 209)
    assert migration["sha256"] == hashlib.sha256(PATH.read_bytes()).hexdigest()


def test_snapshot_schema_does_not_relax_events_or_assign_access():
    sql = PATH.read_text("utf-8")
    assert "version=208 and name='file_audit_collection_replay'" in sql
    assert "version=159 and name='workstation_security'" in sql
    assert "version>=209" in sql
    assert "agent_key text not null unique" in sql
    assert "revoke all on sli_plugin_workstations.protection_state from public,adlog_user" in sql
    assert "grant select,insert,update on sli_plugin_workstations.protection_state to adlog_user" in sql
    assert "alter table" not in sql.lower()
    assert "grant delete" not in sql.lower()
    assert "insert into public.report" not in sql.lower()
