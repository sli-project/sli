"""ClickHouse disk/host mapping through real backup and checkpoint orchestration."""
import ast
import hashlib
from datetime import datetime, timezone
from contextlib import nullcontext
from importlib import import_module
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
from xml.etree import ElementTree

import pytest

from deploy.linux import backup, update_checkpoint

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only backup service")

STAMP = datetime(2026, 10, 7, 1, tzinfo=timezone.utc)
MOUNT = Path("/var/lib/clickhouse/backups/scheduled")
ROOT = Path(__file__).resolve().parents[2]
DISK = ElementTree.parse(ROOT / "config/stage7_clickhouse_backup.xml").findtext(
    "storage_configuration/disks/backups/path")


def setup_backup(monkeypatch, root, *, disk=DISK, mismatch=None, missing_archive=None):
    calls = []
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(root))
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP)

    def pg(destination):
        calls.append(("dump", destination))
        destination.mkdir()
        (destination / "toc.dat").write_bytes(b"synthetic dump")
        return {"size_bytes": 14, "migration_ledger_max_version": 166, "row_counts": {}}

    def query(self, statement):
        calls.append((self.name, statement))
        if "system.disks" in statement:
            return [{"path": "/unmapped/backups" if self.name == mismatch else disk}]
        if 'sum(bytes_on_disk)' in statement and 'system.parts' in statement:
            return [{'size_bytes': 17}]
        if statement.startswith("SELECT version"):
            return [{"version": "25.8"}]
        if "system.databases" in statement:
            return [{"name": "fixture"}]
        if "system.tables" in statement:
            return []
        if statement.startswith("BACKUP"):
            requested = re.search(r"Disk\('backups', '([^']+)'\)", statement)[1]
            # Model the real bind mount from Compose. Create the archive where
            # ClickHouse actually writes, not at the helper's expected path.
            host_path = root / (Path(disk) / requested).relative_to(MOUNT)
            if self.name != missing_archive:
                host_path.write_bytes(b"synthetic archive")
            return [{"status": "BACKUP_CREATED"}]
        pytest.fail("unexpected ClickHouse query")

    monkeypatch.setattr(backup, "dump_postgres", pg)
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(Path('synthetic-passfile')))
    connection = SimpleNamespace(execute=lambda q: SimpleNamespace(fetchone=lambda: (14,)))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a: nullcontext(connection))
    monkeypatch.setattr(backup.ClickHouse, "query", query)
    return calls


def full_receipt(root, path):
    """Model the successful nightly drill for this exact synthetic set."""
    backup.write_json(root / "restore_check.json", {
        "backup_id": path.name, "status": "verified", "verification": "full",
        "completed_at_utc": backup.utc_now().isoformat(),
        "manifest_sha256": hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest(),
        "components": {name: {"status": "verified"} for name in ("postgres", "history", "warm")},
    })


@pytest.mark.parametrize("checkpoint", [False, True])
@pytest.mark.parametrize("disk", [DISK, str(MOUNT) + "/"])
def test_nightly_disk_paths_and_update_reference_the_same_set(tmp_path, monkeypatch, checkpoint, disk):
    root = tmp_path / "backups"
    root.mkdir()
    calls = setup_backup(monkeypatch, root, disk=disk)
    operation = "a" * 32
    final = backup.run_backup(root)
    stamp = STAMP.strftime("%Y%m%dT%H%M%S.%fZ")
    prefix = MOUNT.relative_to(Path(disk))
    statements = [q for name, q in calls if name != "dump" and q.startswith("BACKUP")]
    assert len(statements) == 2
    for name in ("history", "warm"):
        expected = (prefix / f".{stamp}.partial" / f"{name}.zip").as_posix()
        assert any(f"Disk('backups', '{expected}')" in q for q in statements)
        assert (final / f"{name}.zip").read_bytes() == b"synthetic archive"
    assert (final / "postgres/toc.dat").exists()
    manifest = json.loads((final / "manifest.json").read_text())
    for name in ("history", "warm"):
        assert manifest["components"][name]["live_tables"] == {"fixture": {}}
        assert manifest["components"][name]["table_names"] == {"fixture": []}
        assert "tables" not in manifest["components"][name]
    assert not any(q.startswith(("CREATE", "RESTORE", "DROP")) for name, q in calls if name != "dump")
    # Every target's disk preflight precedes the first dump/archive write.
    assert all("system.disks" in q for _, q in calls[:2])
    if checkpoint:
        full_receipt(root, final)
        before = list(calls)
        identifier = update_checkpoint.checkpoint(root, operation, "b" * 64)
        assert identifier["daily_backup"]["backup_id"] == final.name
        receipt = root / identifier["backup_id"]
        assert [item.name for item in receipt.iterdir()] == ["manifest.json"]
        assert backup.successful_backups(root) == [final]
        assert update_checkpoint.checkpoint(root, operation, "b" * 64) == identifier
        assert calls == before


def test_nightly_publication_retries_and_checkpoint_never_recaptures(tmp_path, monkeypatch):
    root = tmp_path / "backups"
    root.mkdir()
    calls = setup_backup(monkeypatch, root)
    rename = Path.rename
    attempts, delays = [], []

    def flaky_rename(path, destination):
        attempts.append(destination)
        if len(attempts) == 1:
            raise PermissionError("synthetic")
        return rename(path, destination)

    monkeypatch.setattr(Path, "rename", flaky_rename)
    monkeypatch.setattr(backup.time, "sleep", delays.append)
    operation = "a" * 32
    final = backup.run_backup(root)
    assert attempts == [final, final]
    assert delays == [0.25]
    assert backup.successful_backups(final.parent) == [final]
    assert not list(final.parent.glob(".*.partial"))
    assert len([q for name, q in calls if name != "dump" and q.startswith("BACKUP")]) == 2
    assert sum(name == "dump" for name, _ in calls) == 1
    assert not any(q.startswith(("CREATE", "RESTORE", "DROP")) for name, q in calls if name != "dump")
    full_receipt(root, final)
    before = list(calls)
    identifier = update_checkpoint.checkpoint(root, operation, "b" * 64)
    assert identifier["daily_backup"]["backup_id"] == final.name
    assert update_checkpoint.checkpoint(root, operation, "b" * 64) == identifier
    assert calls == before


@pytest.mark.parametrize("mismatch", ["history", "warm"])
def test_nightly_disk_mismatch_blocks_capture_and_update(tmp_path, monkeypatch, mismatch):
    root = tmp_path / "backups"
    root.mkdir()
    calls = setup_backup(monkeypatch, root, mismatch=mismatch)
    with pytest.raises(RuntimeError, match="disk_path_mismatch"):
        backup.run_backup(root)
    before = list(calls)
    with pytest.raises(RuntimeError, match="update_fresh_daily_backup_required"):
        update_checkpoint.checkpoint(root, "a" * 32, "b" * 64)
    assert calls == before
    assert not any(name == "dump" or q.startswith("BACKUP") for name, q in calls)
    assert not list(root.rglob("*.partial"))
    assert not list(root.rglob("manifest.json"))


def test_success_response_without_archive_never_admits_update(tmp_path, monkeypatch):
    root = tmp_path / "backups"
    root.mkdir()
    setup_backup(monkeypatch, root, missing_archive="warm")
    with pytest.raises(RuntimeError, match="clickhouse_incomplete"):
        backup.run_backup(root)
    with pytest.raises(RuntimeError, match="update_fresh_daily_backup_required"):
        update_checkpoint.checkpoint(root, "a" * 32, "b" * 64)
    target = root / "update-checkpoints" / ("a" * 32)
    assert not backup.successful_backups(target)
    assert not list(target.rglob("manifest.json"))
    assert list(root.glob(".*.partial/history.zip"))  # Failed nightly evidence is preserved.
    assert list(root.glob(".*.partial/failure.json"))


@pytest.mark.parametrize("disks", [[], [{"path": "relative"}], [{"path": "/other"}],
                                    [{"path": "/var/lib/clickhouse/backups/../backups"}],
                                    [{"path": DISK}, {"path": DISK}]])
def test_invalid_live_disk_mapping_fails_closed(tmp_path, monkeypatch, disks):
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(tmp_path))
    monkeypatch.setattr(backup.ClickHouse, "query", lambda *a: disks)
    target = backup.clickhouse_targets()[0]
    with pytest.raises(RuntimeError, match="disk_path_mismatch"):
        target.backup_disk_path(tmp_path / "checkpoint" / "history.zip")


def test_archive_outside_mapped_root_is_rejected_before_clickhouse_query(tmp_path, monkeypatch):
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(tmp_path / "backups"))
    monkeypatch.setattr(backup.ClickHouse, "query", lambda *a: pytest.fail("must not query"))
    with pytest.raises(RuntimeError, match="disk_path_mismatch"):
        backup.clickhouse_targets()[0].backup_disk_path(tmp_path / "history.zip")
