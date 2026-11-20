"""Forward-only migration and narrow publication contracts (no live DB)."""
import hashlib
import json
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/186_file_audit_collection.sql"


def test_new_migration_is_transactional_next_number_and_manifest_pinned():
    sql = PATH.read_text("utf-8")
    assert sql.startswith("-- Stage 3:") and sql.strip().endswith("commit;")
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
    assert "version=185 and name='file_audit_management'" in sql
    assert "where version>=186" in sql
    assert "values(186,'file_audit_collection')" in sql
    pairs = [(m.version, m.name) for m in forward_migration_inventory(ROOT / "config/postgres_migrations")]
    versions = [version for version, _ in pairs]
    assert len(versions) == len(set(versions))
    position = pairs.index((186, "file_audit_collection"))
    assert position > 0
    assert pairs[position - 1] == (185, "file_audit_management")
    value = json.loads((ROOT / "config/plugin_packages/v3/sli.file-audit.json").read_text("utf-8"))
    assert value["data"]["migrations"][2] == {"version": 186, "name": "file_audit_collection",
        "core_prerequisites": [185], "path": PATH.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(PATH.read_bytes().replace(b"\r\n", b"\n")).hexdigest()}


def test_context_and_publication_are_bounded_attested_and_append_only():
    sql = PATH.read_text("utf-8")
    for name in ("collection_context", "store_collection"):
        assert f"create function sli_plugin_file_audit.{name}" in sql
    assert "security definer set search_path=pg_catalog,pg_temp" in sql
    assert "r.module_id='sli.file-audit'" in sql
    assert "i.imported_at is null" in sql
    assert "limit 1025" in sql
    assert "file_audit_replay_conflict" in sql
    assert "on conflict(action_id) do nothing" in sql
    assert "grant execute on function" in sql
    assert "to adlog_user" not in sql.split("grant select(")[1].split(";")[0]
    assert "source_xml" not in sql and "delete from" not in sql.lower()
    assert "file_event_cleanup_enabled" not in sql
