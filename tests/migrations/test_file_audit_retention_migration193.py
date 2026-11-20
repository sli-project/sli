"""Forward-only DDL and owner-only retention privileges; no live database."""
import hashlib
import json
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/193_file_audit_retention.sql"


def test_retention_migration_is_forward_only_pinned_and_does_not_enable_cleanup():
    sql = PATH.read_text("utf-8")
    assert sql.strip().endswith("commit;")
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
    assert "version=192 and name='workstation_retention_jobs'" in sql
    assert "where version>=193" in sql
    assert "values(193,'file_audit_retention')" in sql
    inventory = [(m.version, m.name) for m in forward_migration_inventory(ROOT / "config/postgres_migrations")]
    position = inventory.index((193, "file_audit_retention"))
    assert position > 0
    assert inventory[position - 1] == (192, "workstation_retention_jobs")
    assert max(version for version, _ in inventory[:position]) + 1 == 193
    assert len({version for version, _ in inventory}) == len(inventory)
    assert list(PATH.parent.glob("193_*.sql")) == [PATH]
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.file-audit.json").read_text("utf-8"))
    retention_migrations = [migration for migration in manifest["data"]["migrations"] if migration["version"] == 193]
    assert retention_migrations == [{
        "version": 193, "name": "file_audit_retention", "core_prerequisites": [192],
        "path": PATH.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(PATH.read_bytes().replace(b"\r\n", b"\n")).hexdigest()}]
    assert "retention_holds" in sql and "payload_expirations" in sql
    assert "references public.sli_agent_packet_inbox(packet_id)" in sql
    assert "references sli_plugin_file_audit.access_snapshots(snapshot_id)" in sql
    assert "source_payload_state='expired'" in sql
    assert "to adlog_user" not in sql and "to adlog_file_audit_runtime" not in sql
    assert "file_event_cleanup_enabled" not in sql
