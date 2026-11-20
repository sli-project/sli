"""Independent recovery on synthetic files and fake database clients only."""

import base64
from contextlib import nullcontext
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import zipfile

import pytest

from deploy.linux import backup, restore_existing, update_checkpoint
from tests.unit.test_linux_backup_paths import full_receipt

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only recovery")
STAMP = datetime(2026, 10, 10, tzinfo=timezone.utc)
METRICS = {"items": {"row_count": 2, "max_values": {}}}
NATIVE_BACKUP_FIXTURE = Path(__file__).parents[1] / "fixtures/clickhouse_native_backup.zip.b64"


@pytest.fixture
def recovery(tmp_path, monkeypatch):
    root = tmp_path / "backups"
    root.mkdir()
    files = tmp_path / "data"
    files.mkdir()
    (files / "part").mkdir()
    (files / "part/payload.bin").write_bytes(b"synthetic payload")
    (files / "manifest.json").write_bytes(b"synthetic data manifest")
    calls = []
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(root))
    monkeypatch.setenv("SLI_BACKUP_FILES_ROOT", str(files))
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP)

    def dump(path):
        calls.append("dump")
        path.mkdir()
        (path / "toc.dat").write_bytes(b"synthetic dump")
        return {"size_bytes": 14, "migration_ledger_max_version": 1, "row_counts": {"items": 2}}

    def archive(target, path):
        calls.append("backup:" + target.name)
        with zipfile.ZipFile(path / (target.name + ".zip"), "w", compression=zipfile.ZIP_DEFLATED) as output:
            output.writestr(".backup", "<config><version>1</version></config>")
            output.writestr("metadata/fixture.sql", "CREATE DATABASE fixture ENGINE = Atomic")
            output.writestr("metadata/fixture/items.sql",
                            "CREATE TABLE fixture.items (id UInt64) ENGINE = MergeTree ORDER BY id")
            output.writestr("data/fixture/items/all_1_1_0/count.txt", "2\n")
        return {"size_bytes": 17, "archive": target.name + ".zip", "databases": ["fixture"],
                "table_names": {"fixture": ["items"]}}

    def query(target, statement):
        calls.append((target.name, statement))
        if "system.disks" in statement:
            return [{"path": "/var/lib/clickhouse/backups/", "free_space": 4 * 1024**3}]
        if 'sum(bytes_on_disk)' in statement and 'system.parts' in statement:
            return [{'size_bytes': 17}]
        if "system.databases" in statement:
            return []
        if statement.startswith("RESTORE"):
            return [{"status": "RESTORED"}]
        return []

    class Connection:
        def execute(self, statement):
            calls.append(("postgres", statement))
            self.statement = statement
            return self

        def fetchone(self):
            if self.statement == 'SELECT pg_database_size(current_database())':
                return (14,)
            return (1,) if "max(version)" in self.statement else (False,)

    monkeypatch.setattr(backup, "dump_postgres", dump)
    monkeypatch.setattr(backup.ClickHouse, "backup", archive)
    monkeypatch.setattr(backup.ClickHouse, "query", query)
    monkeypatch.setattr(backup.ClickHouse, "statistics", lambda *a: METRICS)
    monkeypatch.setattr(backup, "pg_passfile", lambda: nullcontext(Path("passfile")))
    monkeypatch.setattr(backup, "pg_connect", lambda *a, **kw: nullcontext(Connection()))
    monkeypatch.setattr(backup, "pg_tool", lambda args, _, *, watch: calls.append(("pg_restore", args)))
    monkeypatch.setattr(backup, "row_counts", lambda _: {"items": 2})
    monkeypatch.setattr(restore_existing.migrate, "migrate", lambda: pytest.fail("no candidate migrations"))
    return root, files, calls


@pytest.mark.parametrize("component", backup.COMPONENTS)
def test_each_part_recovers_without_touching_other_parts(recovery, tmp_path, component):
    root, files, calls = recovery
    path = backup.run_backup(root, components=(component,))
    assert set(json.loads((path / "manifest.json").read_bytes())["components"]) == {component}
    destination = tmp_path / "restored"
    destination.mkdir()
    calls.clear()
    restore_existing.restore_backup(path, (component,), files_root=destination)
    pg_calls = [item for item in calls if isinstance(item, tuple) and item[0] == "postgres"]
    ch_calls = [item for item in calls if isinstance(item, tuple) and item[0] in {"history", "warm"}]
    assert bool(pg_calls) == (component == "postgres")
    assert bool(ch_calls) == (component in {"history", "warm"})
    assert all(item[0] == component for item in ch_calls)
    if component == "files":
        assert backup.content_inventory(destination, exclude_manifest=False) == backup.content_inventory(files, exclude_manifest=False)
    else:
        assert not list(destination.iterdir())
    assert not list(root.glob(".restore-*"))


@pytest.mark.parametrize("profile", update_checkpoint.RECOVERY_PROFILES)
def test_checkpoint_profile_selection_and_idempotency(recovery, profile):
    root, _, calls = recovery
    nightly = backup.run_backup(root)
    full_receipt(root, nightly)
    calls.clear()
    identity = update_checkpoint.checkpoint(root, "a" * 32, "b" * 64, profile)
    path = root / identity["backup_id"]
    manifest = json.loads((path / "manifest.json").read_bytes())
    assert manifest["recovery_profile"] == profile
    assert manifest["daily_backup"] == identity["daily_backup"]
    assert identity["daily_backup"]["backup_id"] == nightly.name
    assert manifest["content_checksums"] == {}
    assert manifest["authentication"] == update_checkpoint.authenticate(manifest, "b" * 64)
    assert [item.name for item in path.iterdir()] == ["manifest.json"]
    assert not (path.parent / "last_result.json").exists()
    assert update_checkpoint.checkpoint(root, "a" * 32, "b" * 64, profile) == identity
    assert calls == []
    if profile == "ui-only":
        update_checkpoint.restore(root, operation="a" * 32, checkpoint_key="b" * 64,
                                  **{key: identity[key] for key in ("backup_id", "checkpoint_sha256")})
        assert calls == []
    with pytest.raises(ValueError, match="invalid_checkpoint"):
        update_checkpoint.checkpoint(root, "a" * 32, "b" * 64, "postgres" if profile != "postgres" else "ui-only")


@pytest.mark.parametrize("component", backup.COMPONENTS)
def test_corruption_blocks_restore_before_any_database_or_file_mutation(recovery, component):
    root, files, calls = recovery
    path = backup.run_backup(root, components=(component,))
    name = {"postgres": "postgres/toc.dat", "history": "history.zip", "warm": "warm.zip", "files": "files/part/payload.bin"}[component]
    (path / name).write_bytes(b"corrupted")
    before = backup.content_inventory(files, exclude_manifest=False)
    calls.clear()
    with pytest.raises(ValueError, match="invalid_manifest"):
        restore_existing.restore_backup(path, (component,), replace_existing=True, files_root=files)
    assert calls == []
    assert backup.content_inventory(files, exclude_manifest=False) == before


def test_files_restore_requires_explicit_replacement(recovery):
    root, files, calls = recovery
    path = backup.run_backup(root, components=("files",))
    (files / "part/payload.bin").write_bytes(b"changed")
    (files / "extra.bin").write_bytes(b"extra")
    calls.clear()
    with pytest.raises(RuntimeError, match="requires_empty_files"):
        restore_existing.restore_backup(path, ("files",), files_root=files)
    assert (files / "extra.bin").exists()
    restore_existing.restore_backup(path, ("files",), replace_existing=True, files_root=files)
    assert (files / "part/payload.bin").read_bytes() == b"synthetic payload"
    assert not (files / "extra.bin").exists() and calls == []


def test_files_backup_refuses_links(recovery, tmp_path):
    root, files, _ = recovery
    outside = tmp_path / "outside"
    outside.write_bytes(b"synthetic")
    (files / "link").symlink_to(outside)
    with pytest.raises(ValueError):
        backup.run_backup(root, components=("files",))
    assert not backup.successful_backups(root)
    assert outside.read_bytes() == b"synthetic"


def test_narrow_capture_retention_preserves_full_sets(recovery, monkeypatch):
    root, _, _ = recovery
    full = backup.run_backup(root, retention=1)
    partial = root / ".20261010T003000.000000Z.partial"
    partial.mkdir()
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP.replace(hour=1))
    narrow = backup.run_backup(root, retention=1, components=("postgres",))
    assert full in backup.successful_backups(root) and narrow in backup.successful_backups(root)
    assert partial.exists()


def test_missing_component_is_rejected_before_mutation(recovery):
    root, files, calls = recovery
    path = backup.run_backup(root, components=("postgres",))
    calls.clear()
    with pytest.raises(ValueError, match="invalid_components"):
        restore_existing.restore_backup(path, ("files",), files_root=files)
    assert calls == []


def test_full_checkpoint_restores_all_captured_parts(recovery):
    root, files, calls = recovery
    nightly = backup.run_backup(root)
    full_receipt(root, nightly)
    identity = update_checkpoint.checkpoint(root, "a" * 32, "b" * 64, "full")
    assert identity["daily_backup"]["backup_id"] == nightly.name
    (files / "extra.bin").write_bytes(b"extra")
    calls.clear()
    update_checkpoint.restore(root, operation="a" * 32, checkpoint_key="b" * 64,
                              **{key: identity[key] for key in ("backup_id", "checkpoint_sha256")})
    assert any(item[0] == "pg_restore" for item in calls if isinstance(item, tuple))
    restored = {item[0] for item in calls if isinstance(item, tuple)
                and isinstance(item[1], str) and item[1].startswith("RESTORE")}
    assert restored == {"history", "warm"}
    assert not (files / "extra.bin").exists()


@pytest.mark.parametrize("component", ["postgres", "history", "warm"])
def test_database_readback_mismatch_is_reported(recovery, monkeypatch, component):
    root, _, _ = recovery
    path = backup.run_backup(root, components=(component,))
    if component == "postgres":
        monkeypatch.setattr(backup, "row_counts", lambda _: {"items": 3})
    else:
        monkeypatch.setattr(backup.ClickHouse, "statistics", lambda self, database: (
            METRICS if database.startswith("sli_backup_manifest_") else {}))
    with pytest.raises(RuntimeError, match="readback_failed"):
        restore_existing.restore_backup(path, (component,))


def test_native_backup_fixture_passes_sanitary_gate(tmp_path):
    from scripts.maintenance.github_sanitary_check import scan

    shutil.copyfile(NATIVE_BACKUP_FIXTURE, tmp_path / NATIVE_BACKUP_FIXTURE.name)
    result = scan(tmp_path)
    assert result["status"] == "ok", result["findings"]


def test_component_restore_reads_real_native_deflated_backup(recovery, monkeypatch):
    root, _, calls = recovery
    # Synthetic native ClickHouse archive from upstream (Apache-2.0), unchanged bytes
    # stored as Base64 to keep binary archives out of the repository:
    # https://github.com/ClickHouse/ClickHouse/blob/7f7a30ec42513416265e2b7fba442f914feeb74d/
    # tests/integration/test_backups_from_disk/backups/old_backup_with_matview_inner_table_metadata.zip
    metrics = {name: {"row_count": 3, "max_values": {}} for name in (".inner.mv", "src")}

    def archive(target, path):
        destination = path / (target.name + ".zip")
        encoded = "".join(NATIVE_BACKUP_FIXTURE.read_text(encoding="ascii").split())
        destination.write_bytes(base64.b64decode(encoded, validate=True))
        return {"size_bytes": destination.stat().st_size, "archive": destination.name,
                "databases": ["mydb"], "table_names": {"mydb": [".inner.mv", "src"]}}

    def query(target, statement):
        calls.append((target.name, statement))
        if "ENGINE = Backup" in statement:
            raise RuntimeError("CANNOT_SEEK_THROUGH_FILE")
        if "system.disks" in statement:
            return [{"path": "/var/lib/clickhouse/backups/", "free_space": 4 * 1024**3}]
        if statement.startswith("RESTORE"):
            import re

            disk_path = re.search(r"Disk\('backups', 'scheduled/([^']+)'\)", statement)[1]
            with zipfile.ZipFile(root / disk_path) as handle:
                assert handle.getinfo(".backup").compress_type == zipfile.ZIP_DEFLATED
                assert handle.getinfo("data/mydb/src/all_1_1_0/Timestamp.bin").compress_type == zipfile.ZIP_DEFLATED
                assert handle.read("metadata/mydb.sql").startswith(b"CREATE DATABASE mydb")
                assert handle.read("data/mydb/%2Einner%2Emv/all_1_1_0/count.txt") == b"3"
            return [{"status": "RESTORED"}]
        return []

    monkeypatch.setattr(backup.ClickHouse, "backup", archive)
    monkeypatch.setattr(backup.ClickHouse, "query", query)
    monkeypatch.setattr(backup.ClickHouse, "statistics", lambda *a: metrics)
    path = backup.run_backup(root, components=("history",))
    before = backup.content_inventory(path)
    calls.clear()
    restore_existing.restore_backup(path, ("history",))
    statements = [statement for _, statement in calls]
    assert sum(statement.startswith("RESTORE") for statement in statements) == 2
    assert any(statement.startswith("DROP DATABASE IF EXISTS `sli_backup_manifest_") for statement in statements)
    assert not any("ENGINE = Backup" in statement for statement in statements)
    assert backup.content_inventory(path) == before
    assert not list(root.glob(".restore-*"))


@pytest.mark.parametrize("component", ["history", "warm"])
@pytest.mark.parametrize("objects", ["empty", "table", "dictionary"])
def test_restore_accepts_existing_empty_database_but_preserves_objects(recovery, monkeypatch, component, objects):
    root, _, calls = recovery
    path = backup.run_backup(root, components=(component,))
    original = backup.ClickHouse.query

    def query(target, statement):
        if "system.databases" in statement:
            calls.append((target.name, statement))
            return [{"name": "fixture"}]
        if "system.tables" in statement or "system.dictionaries" in statement:
            calls.append((target.name, statement))
            assert "database IN ('fixture')" in statement
            assert "system.tables" in statement and "system.dictionaries" in statement
            return [] if objects == "empty" else [{"occupied": 1}]
        return original(target, statement)

    monkeypatch.setattr(backup.ClickHouse, "query", query)
    calls.clear()
    if objects == "empty":
        restore_existing.restore_backup(path, (component,))
        assert sum(statement.startswith("RESTORE") for _, statement in calls) == 2
        assert not any(statement.startswith("DROP DATABASE IF EXISTS `fixture`") for _, statement in calls)
    else:
        with pytest.raises(RuntimeError, match="requires_empty_clickhouse"):
            restore_existing.restore_backup(path, (component,))
        assert not any(statement.startswith(("RESTORE", "DROP")) for _, statement in calls)
    assert not list(root.glob(".restore-*"))
