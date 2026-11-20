"""Fast update admission and nightly recovery drills; no real databases."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import zipfile
from contextlib import nullcontext
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup, update_checkpoint
from deploy.linux import backup_restore_check as drill
from tests.unit.test_linux_backup import COUNTS, STAMP, fake_components

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only backup service")


def full_receipt(root, *, age=timedelta(days=1), status="verified", name="restore_check.json"):
    receipt = {"backup_id": "20261005T010000.000000Z", "verification": "full", "status": status,
               "completed_at_utc": (STAMP - age).isoformat(),
               "components": {name: {"status": "verified"} for name in ("postgres", "history", "warm")}}
    backup.write_json(root / name, receipt)
    return receipt


@pytest.mark.parametrize("age,expected", [
    (timedelta(0), True), (timedelta(days=7), True),
    (timedelta(days=7, microseconds=1), False), (timedelta(seconds=-1), False),
])
@pytest.mark.parametrize("name", ["restore_check.json", "last_full_restore_check.json"])
def test_full_receipt_age_is_bounded(tmp_path, monkeypatch, age, expected, name):
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP)
    full_receipt(tmp_path, age=age, name=name)
    assert drill.recent_full_check(tmp_path) is expected


@pytest.mark.parametrize("defect", [
    "missing", "invalid_json", "list", "failed", "skipped", "running", "legacy", "naive",
    "missing_component", "skipped_component", "bad_components", "bad_time", "symlink",
])
@pytest.mark.parametrize("name", ["restore_check.json", "last_full_restore_check.json"])
def test_invalid_full_receipt_never_allows_fast_path(tmp_path, monkeypatch, defect, name):
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP)
    result = full_receipt(tmp_path, name=name)
    receipt = tmp_path / name
    if defect == "missing":
        receipt.unlink()
    elif defect == "invalid_json":
        receipt.write_text("invalid")
    elif defect == "list":
        backup.write_json(receipt, [])
    elif defect == "symlink":
        receipt.rename(tmp_path / "other.json")
        receipt.symlink_to(tmp_path / "other.json")
    else:
        if defect in {"failed", "skipped", "running"}:
            result["status"] = defect
        elif defect == "legacy":
            del result["verification"]
        elif defect == "naive":
            result["completed_at_utc"] = STAMP.replace(tzinfo=None).isoformat()
        elif defect == "missing_component":
            del result["components"]["warm"]
        elif defect == "skipped_component":
            result["components"]["history"]["status"] = "skipped"
        elif defect == "bad_components":
            result["components"] = ["postgres", "history", "warm"]
        elif defect == "bad_time":
            result["completed_at_utc"] = "invalid"
        backup.write_json(receipt, result)
    assert not drill.recent_full_check(tmp_path)


def integrity_set(root, monkeypatch):
    fake_components(monkeypatch, root)
    path = backup.run_backup(root)
    manifest = json.loads((path / "manifest.json").read_bytes())
    for name in ("history", "warm"):
        with zipfile.ZipFile(path / (name + ".zip"), "w") as archive:
            archive.writestr(".backup", "<backup/>")
            archive.writestr("data/synthetic.bin", b"payload-marker")
        manifest["components"][name].update(archive=name + ".zip", databases=["synthetic"])
    manifest["content_checksums"] = backup.content_inventory(path)
    backup.write_json(path / "manifest.json", manifest)
    monkeypatch.setattr(backup, "pg_passfile", lambda: nullcontext(Path("unused")))
    monkeypatch.setattr(backup, "pg_connect", lambda *a, **kw: pytest.fail("fast path must not connect"))
    monkeypatch.setattr(backup.ClickHouse, "query", lambda *a: pytest.fail("fast path must not restore"))
    return path, manifest


def test_integrity_only_lists_postgres_and_reads_all_clickhouse_archives(tmp_path, monkeypatch):
    path, _ = integrity_set(tmp_path, monkeypatch)
    commands = []
    monkeypatch.setattr(backup, "pg_tool", lambda command, *_, **kwargs: commands.append(command))
    assert drill.integrity_check(path) == {"status": "verified"}
    assert commands == [["pg_restore", "--list", "--format=directory", str(path / "postgres")]]


def test_integrity_accepts_native_clickhouse_zip_fixture(tmp_path, monkeypatch):
    path, manifest = integrity_set(tmp_path, monkeypatch)
    fixture = Path(__file__).resolve().parents[1] / "fixtures/clickhouse_native_backup.zip.b64"
    for name in ("history", "warm"):
        (path / (name + ".zip")).write_bytes(base64.b64decode(fixture.read_bytes()))
    manifest["content_checksums"] = backup.content_inventory(path)
    backup.write_json(path / "manifest.json", manifest)
    monkeypatch.setattr(backup, "pg_tool", lambda *a: None)
    assert drill.integrity_check(path) == {"status": "verified"}


@pytest.mark.parametrize("defect", ["hash", "missing_file", "bad_zip", "crc", "no_metadata", "archive_name", "pg_list"])
def test_integrity_failure_blocks_update(tmp_path, monkeypatch, defect):
    path, manifest = integrity_set(tmp_path, monkeypatch)
    monkeypatch.setattr(backup, "pg_tool", lambda *a: None)
    if defect == "hash":
        (path / "postgres/toc.dat").write_bytes(b"changed")
    elif defect == "missing_file":
        (path / "warm.zip").unlink()
    elif defect in {"bad_zip", "crc", "no_metadata"}:
        archive = path / "warm.zip"
        if defect == "bad_zip":
            archive.write_bytes(b"broken")
        elif defect == "crc":
            archive.write_bytes(archive.read_bytes().replace(b"payload-marker", b"payload-broken", 1))
        else:
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("data/only", "synthetic")
        manifest["content_checksums"] = backup.content_inventory(path)
        backup.write_json(path / "manifest.json", manifest)
    elif defect == "archive_name":
        manifest["components"]["warm"]["archive"] = "other.zip"
        backup.write_json(path / "manifest.json", manifest)
    else:
        def fail(*a):
            raise RuntimeError("synthetic_list_failure")
        monkeypatch.setattr(backup, "pg_tool", fail)
    with pytest.raises((RuntimeError, zipfile.BadZipFile)):
        drill.integrity_check(path)


def verified_set(root, monkeypatch):
    path, manifest = integrity_set(root, monkeypatch)
    manifest["completed_at_utc"] = STAMP.isoformat()
    backup.write_json(path / "manifest.json", manifest)
    receipt = full_receipt(root, age=timedelta(0))
    receipt.update(backup_id=path.name, manifest_sha256=hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest())
    backup.write_json(root / "restore_check.json", receipt)
    return path, manifest, receipt


@pytest.mark.parametrize("age,allowed", [
    (timedelta(0), True), (timedelta(hours=26), True),
    (timedelta(hours=26, microseconds=1), False), (timedelta(seconds=-1), False),
])
def test_update_uses_only_daily_metadata_with_26_hour_capture_start_bound(tmp_path, monkeypatch, age, allowed):
    path, _, _ = verified_set(tmp_path, monkeypatch)
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP + age)
    def forbidden(*a, **kw):
        pytest.fail("update must not capture, copy, hash artifacts or exercise restore")
    for module, names in [(backup, ["run_backup", "content_inventory"]),
                          (drill, ["restore_check", "integrity_check"]), (update_checkpoint, ["snapshot"])]:
        for name in names:
            monkeypatch.setattr(module, name, forbidden)
    if allowed:
        result = update_checkpoint.check_backup(tmp_path, "a" * 32, "b" * 64)
        assert result["verification"] == "nightly"
        assert result["daily_backup"]["backup_id"] == path.name
        assert result["daily_backup"]["backup_started_at_utc"] == STAMP.isoformat()
    else:
        with pytest.raises(RuntimeError, match="update_fresh_daily_backup_required"):
            update_checkpoint.check_backup(tmp_path, "a" * 32, "b" * 64)


@pytest.mark.parametrize("full_age,allowed", [
    (timedelta(days=7), True), (timedelta(days=7, microseconds=1), False),
    (timedelta(seconds=-1), False), (None, False),
])
def test_once_publishes_light_receipt_and_requires_recent_full_check(tmp_path, monkeypatch, full_age, allowed):
    path, _ = integrity_set(tmp_path, monkeypatch)
    previous = full_receipt(tmp_path, age=full_age) if full_age is not None else None
    commands = []
    monkeypatch.setattr(backup, "pg_tool", lambda command, *_, **kwargs: commands.append(command))
    assert backup.main(["--once"]) == 0
    receipt = json.loads((tmp_path / "restore_check.json").read_bytes())
    assert receipt["verification"] == "light" and receipt["status"] == "verified"
    assert receipt["backup_id"] == path.name
    assert receipt["manifest_sha256"] == hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest()
    assert commands == [["pg_restore", "--list", "--format=directory", str(path / "postgres")]]
    if allowed:
        assert json.loads((tmp_path / "last_full_restore_check.json").read_bytes()) == previous
        # A second manual check must retain the original full check's age.
        assert backup.main(["--once"]) == 0
        monkeypatch.setattr(drill, "integrity_check", lambda *a: pytest.fail("no update rehash"))
        selected = update_checkpoint.check_backup(tmp_path, "a" * 32, "b" * 64)["daily_backup"]
        assert selected["backup_id"] == path.name
        assert update_checkpoint.checkpoint(tmp_path, "a" * 32, "b" * 64,
                                            daily_backup=selected)["daily_backup"] == selected
    else:
        with pytest.raises(RuntimeError, match="update_fresh_daily_backup_required"):
            drill.verified_daily_backup(tmp_path)


def test_once_checks_a_new_capture_before_reporting_success(tmp_path, monkeypatch):
    fake_components(monkeypatch, tmp_path)
    full_receipt(tmp_path)
    capture = backup.ClickHouse.backup
    calls = []

    def archive(target, staging):
        component = capture(target, staging)
        path = staging / (target.name + ".zip")
        with zipfile.ZipFile(path, "w") as handle:
            handle.writestr(".backup", "<backup/>")
        return {**component, "archive": path.name, "databases": ["synthetic"], "size_bytes": path.stat().st_size}

    def list_postgres(command, *_):
        # The set must be published before pg_restore can inspect it.
        path = Path(command[-1]).parent
        assert path in backup.successful_backups(tmp_path)
        calls.append(command[:2])

    monkeypatch.setattr(backup.ClickHouse, "backup", archive)
    monkeypatch.setattr(backup, "pg_passfile", lambda: nullcontext(Path("unused")))
    monkeypatch.setattr(backup, "pg_tool", list_postgres)
    monkeypatch.setattr(backup, "pg_connect", lambda *a, **kw: pytest.fail("no restore connection"))
    monkeypatch.setattr(drill, "restore_check", lambda *a, **kw: pytest.fail("no full drill during --once"))
    assert not backup.successful_backups(tmp_path)
    assert backup.main(["--once"]) == 0
    assert calls == [["pg_restore", "--list"]]
    assert drill.verified_daily_backup(tmp_path)["backup_id"] == backup.successful_backups(tmp_path)[0].name


@pytest.mark.parametrize("age,allowed", [
    (timedelta(hours=26), True), (timedelta(hours=26, microseconds=1), False),
])
def test_light_daily_backup_age_is_bounded(tmp_path, monkeypatch, age, allowed):
    path, _ = integrity_set(tmp_path, monkeypatch)
    full_receipt(tmp_path)
    monkeypatch.setattr(backup, "pg_tool", lambda *a: None)
    drill.light_check(tmp_path, selected=path)
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP + age)
    if allowed:
        assert drill.verified_daily_backup(tmp_path)["backup_id"] == path.name
    else:
        with pytest.raises(RuntimeError, match="update_fresh_daily_backup_required"):
            drill.verified_daily_backup(tmp_path)


@pytest.mark.parametrize("defect", ["hash", "missing_digest", "manifest_changed", "failed", "no_light"])
def test_light_receipt_cannot_bypass_daily_integrity(tmp_path, monkeypatch, defect):
    path, manifest = integrity_set(tmp_path, monkeypatch)
    previous = full_receipt(tmp_path)
    monkeypatch.setattr(backup, "pg_tool", lambda *a: None)
    if defect == "hash":
        (path / "postgres/toc.dat").write_bytes(b"corrupt")
        assert backup.main(["--once"]) == 1
        assert backup.read_result(tmp_path)["last_result"] == "failed"
    else:
        receipt = drill.light_check(tmp_path, selected=path)
        if defect == "missing_digest":
            del receipt["manifest_sha256"]
        elif defect == "manifest_changed":
            backup.write_json(path / "manifest.json", {**manifest, "duration_seconds": 999})
        elif defect == "failed":
            receipt["status"] = "failed"
        if defect == "no_light":
            (tmp_path / "restore_check.json").unlink()
        else:
            backup.write_json(tmp_path / "restore_check.json", receipt)
    assert json.loads((tmp_path / "last_full_restore_check.json").read_bytes()) == previous
    assert drill.recent_full_check(tmp_path)
    with pytest.raises(RuntimeError, match="update_fresh_daily_backup_required"):
        drill.verified_daily_backup(tmp_path)


@pytest.mark.parametrize("defect", [
    "missing", "failed", "skipped", "integrity_only", "other_set", "manifest_changed",
    "missing_component", "failed_component", "future_receipt", "before_capture",
    "missing_archive", "symlink_receipt", "symlink_manifest", "symlink_set", "partial_set",
    "later_failed_capture", "later_unchecked_capture",
])
def test_no_daily_verification_means_wait_without_new_backup(tmp_path, monkeypatch, defect):
    path, manifest, receipt = verified_set(tmp_path, monkeypatch)
    receipt_path = tmp_path / "restore_check.json"
    if defect == "missing":
        receipt_path.unlink()
    elif defect in {"failed", "skipped"}:
        receipt["status"] = defect
    elif defect == "integrity_only":
        receipt["verification"] = "integrity"
    elif defect == "other_set":
        receipt["backup_id"] = "20261005T010000.000000Z"
    elif defect == "manifest_changed":
        manifest["duration_seconds"] = 999
        backup.write_json(path / "manifest.json", manifest)
    elif defect == "missing_component":
        receipt["components"].pop("warm")
    elif defect == "failed_component":
        receipt["components"]["warm"]["status"] = "failed"
    elif defect == "future_receipt":
        receipt["completed_at_utc"] = (STAMP + timedelta(seconds=1)).isoformat()
    elif defect == "before_capture":
        receipt["completed_at_utc"] = (STAMP - timedelta(seconds=1)).isoformat()
    elif defect == "missing_archive":
        (path / "warm.zip").unlink()
    elif defect in {"symlink_receipt", "symlink_manifest"}:
        item = receipt_path if defect == "symlink_receipt" else path / "manifest.json"
        destination = item.with_suffix(".saved")
        item.rename(destination)
        item.symlink_to(destination)
    elif defect == "symlink_set":
        destination = path.with_name("saved")
        path.rename(destination)
        path.symlink_to(destination, target_is_directory=True)
    elif defect == "partial_set":
        manifest["components"].pop("warm")
        backup.write_json(path / "manifest.json", manifest)
        receipt["manifest_sha256"] = hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest()
    elif defect in {"later_failed_capture", "later_unchecked_capture"}:
        last = backup.read_result(tmp_path)
        if defect == "later_failed_capture":
            last["last_result"] = "failed"
        else:
            last["last_success"] = "20261006T020000.000000Z"
        backup.write_json(tmp_path / "last_result.json", last)
    if defect not in {"missing", "symlink_receipt"}:
        backup.write_json(receipt_path, receipt)
    monkeypatch.setattr(backup, "run_backup", lambda *a, **kw: pytest.fail("no pre-update backup"))
    with pytest.raises(RuntimeError, match="update_fresh_daily_backup_required"):
        update_checkpoint.check_backup(tmp_path, "a" * 32, "b" * 64)


@pytest.mark.parametrize("status", ["verified", "failed", "skipped", "exception"])
def test_nightly_capture_is_followed_by_exact_set_drill_and_logs_result(tmp_path, monkeypatch, capsys, status):
    selected = tmp_path / "update-checkpoints" / ("a" * 32) / "20261006T010000.000000Z"
    calls = []
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP)
    def capture(root, retention, **kwargs):
        assert root == tmp_path and retention == 7
        assert kwargs == {"reuse_recent": True, "scheduled_interval": 86400}
        calls.append("capture")
        backup.record_result(root, backup.default_components(), "success", selected)
        return selected
    def restore(root, **kwargs):
        assert root == tmp_path and kwargs == {"selected": selected}
        calls.append("full")
        if status == "exception":
            raise RuntimeError("synthetic private detail")
        return cycle_drill_receipt(selected, status=status)
    monkeypatch.setattr(backup, "run_backup", capture)
    monkeypatch.setattr(drill, "restore_check", restore)
    if status == "verified":
        assert backup.scheduled_backup(tmp_path, 7, reuse_recent=True, scheduled_interval=86400) == selected
    else:
        with pytest.raises(RuntimeError):
            backup.scheduled_backup(tmp_path, 7, reuse_recent=True, scheduled_interval=86400)
    assert calls == ["capture", "full"]
    assert capsys.readouterr().out == "linux_backup_restore_check_" + ("verified" if status == "verified" else "failed") + "\n"


def test_real_full_drill_preserves_success_across_failed_rerun(tmp_path, monkeypatch):
    from tests.unit.test_linux_backup_capacity import prepare_capacity

    path, manifest = integrity_set(tmp_path, monkeypatch)
    admin = prepare_capacity(tmp_path, path, monkeypatch)
    manifest = json.loads((path / "manifest.json").read_bytes())
    full_receipt(tmp_path)
    registry = {"installation_key": "c" * 64, "inventory": {"version": "1.0.0"}}
    connection = SimpleNamespace(execute=lambda query: SimpleNamespace(fetchone=lambda: (
        registry if isinstance(query, str) and "json_build_object" in query else 2,)))
    monkeypatch.setattr(backup, "pg_connect", lambda passfile, database="sli", **kw: nullcontext(admin if database == "sli" else connection))
    monkeypatch.setattr(backup, "pg_tool", lambda *a: None)
    monkeypatch.setattr(backup, "row_counts", lambda *a: COUNTS)
    monkeypatch.setattr(drill, "restore_clickhouse", lambda *a: {"status": "verified"})
    monkeypatch.setattr(drill.restore_sandbox, "restore", lambda *a: registry)
    manifest["components"]["history"]["table_names"] = {"synthetic": []}
    manifest["components"]["warm"]["table_names"] = {"synthetic": []}
    backup.write_json(path / "manifest.json", manifest)
    result = drill.restore_check(tmp_path, selected=path)
    assert result["completed_at_utc"] == STAMP.isoformat()
    assert result["manifest_sha256"] == hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest()
    assert result["installed_release"] == registry
    assert drill.verified_daily_backup(tmp_path)["installed_release"] == registry
    assert drill.recent_full_check(tmp_path)
    def mismatch(*args):
        raise RuntimeError('linux_backup_restore_mismatch')
    monkeypatch.setattr(drill.restore_sandbox, 'restore', mismatch)
    with pytest.raises(RuntimeError, match="mismatch"):
        drill.restore_check(tmp_path, selected=path)
    assert json.loads((tmp_path / "restore_check.json").read_bytes())["status"] == "failed"
    assert json.loads((tmp_path / "last_full_restore_check.json").read_bytes()) == result
    assert drill.recent_full_check(tmp_path)
    # The failed attempt cannot admit the set, but a manual integrity check can.
    with pytest.raises(RuntimeError, match="update_fresh_daily_backup_required"):
        drill.verified_daily_backup(tmp_path)
    assert backup.main(["--once"]) == 0
    assert drill.verified_daily_backup(tmp_path)["backup_id"] == path.name
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP + timedelta(days=7, microseconds=1))
    assert not drill.recent_full_check(tmp_path)


def test_daily_checkpoint_is_metadata_only_idempotent_and_pins_retention(tmp_path, monkeypatch):
    monkeypatch.setenv("SLI_BACKUP_WEEKLY_RETENTION", "0")
    path, manifest, _ = verified_set(tmp_path, monkeypatch)
    monkeypatch.setattr(backup, "run_backup", lambda *a, **kw: pytest.fail("no update capture"))
    monkeypatch.setattr(backup, "content_inventory", lambda *a, **kw: pytest.fail("no update rehash"))
    identity = {"operation": "a" * 32, "checkpoint_key": "b" * 64, "recovery_profile": "full"}
    first = update_checkpoint.checkpoint(tmp_path, **identity)
    assert update_checkpoint.checkpoint(tmp_path, **identity) == first
    receipt = tmp_path / first["backup_id"]
    assert [item.name for item in receipt.iterdir()] == ["manifest.json"]
    assert first["daily_backup"]["backup_id"] == path.name
    newer = tmp_path / "20261007T010000.000000Z"
    (newer / "postgres").mkdir(parents=True)
    (newer / "postgres/toc.dat").write_bytes(b"synthetic")
    backup.write_json(newer / "manifest.json", {**manifest, "backup_id": newer.name})
    # A newer full drill releases the independent last-verified-set pin.
    full_receipt = json.loads((tmp_path / "restore_check.json").read_bytes())
    backup.write_json(tmp_path / "restore_check.json", {**full_receipt, "backup_id": newer.name})
    backup.prune(tmp_path, 1, newer)
    assert path.exists() and newer.exists()
    (receipt / "manifest.json").unlink()
    backup.prune(tmp_path, 1, newer)
    assert not path.exists() and newer.exists()


def test_restorelight_receipt_can_bootstrap_new_updater_without_new_backup_or_drill(tmp_path, monkeypatch):
    path, _, receipt = verified_set(tmp_path, monkeypatch)
    receipt.pop("manifest_sha256")
    backup.write_json(tmp_path / "restore_check.json", receipt)
    def forbidden(*a, **kw):
        pytest.fail("legacy receipt must not require another capture, hash scan or drill")
    monkeypatch.setattr(backup, "run_backup", forbidden)
    monkeypatch.setattr(backup, "content_inventory", forbidden)
    monkeypatch.setattr(drill, "restore_check", forbidden)
    selected = update_checkpoint.check_backup(tmp_path, "a" * 32, "b" * 64)["daily_backup"]
    result = update_checkpoint.checkpoint(tmp_path, "a" * 32, "b" * 64, daily_backup=selected)
    assert result["daily_backup"]["backup_id"] == path.name
    assert selected["manifest_sha256"] == hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest()


@pytest.mark.parametrize("defect", ["invalid", "symlink"])
def test_unreadable_or_linked_rollback_receipt_cannot_authorize_pruning(tmp_path, monkeypatch, defect):
    path, manifest, _ = verified_set(tmp_path, monkeypatch)
    result = update_checkpoint.checkpoint(tmp_path, "a" * 32, "b" * 64)
    receipt = tmp_path / result["backup_id"] / "manifest.json"
    if defect == "invalid":
        receipt.write_text("invalid")
    else:
        saved = tmp_path / "saved.json"
        receipt.rename(saved)
        receipt.symlink_to(saved)
    newer = tmp_path / "20261007T010000.000000Z"
    (newer / "postgres").mkdir(parents=True)
    (newer / "postgres/toc.dat").write_bytes(b"synthetic")
    backup.write_json(newer / "manifest.json", {**manifest, "backup_id": newer.name})
    backup.prune(tmp_path, 1, newer)
    assert path.exists() and newer.exists()


@pytest.mark.parametrize("profile,components", [
    ("ui-only", ()), ("postgres", ("postgres",)),
    ("history", ("history", "warm")), (None, ("postgres",)),
])
def test_rollback_reads_the_selected_daily_set_even_after_26_hours(tmp_path, monkeypatch, profile, components):
    from deploy.linux import restore_existing

    path, _, _ = verified_set(tmp_path, monkeypatch)
    identity = {"operation": "a" * 32, "checkpoint_key": "b" * 64}
    result = update_checkpoint.checkpoint(tmp_path, **identity, recovery_profile=profile)
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP + timedelta(days=2))
    calls = []
    def restore(private, root, manifest, selected, **kwargs):
        assert root == tmp_path and private != path
        assert manifest["backup_id"] == path.name
        assert (private / "postgres/toc.dat").read_bytes() == (path / "postgres/toc.dat").read_bytes()
        assert kwargs == {"replace_existing": True, "files_root": None}
        calls.append(selected)
    monkeypatch.setattr(restore_existing, "restore_components", restore)
    update_checkpoint.restore(tmp_path, **identity, **{key: result[key] for key in ("backup_id", "checkpoint_sha256")})
    assert calls == ([components] if components else [])


@pytest.mark.parametrize("defect", ["manifest", "artifact", "link", "receipt", "wrong_key"])
def test_daily_rollback_refuses_changed_inputs_before_destructive_restore(tmp_path, monkeypatch, defect):
    from deploy.linux import restore_existing

    path, _, _ = verified_set(tmp_path, monkeypatch)
    identity = {"operation": "a" * 32, "checkpoint_key": "b" * 64}
    result = update_checkpoint.checkpoint(tmp_path, **identity, recovery_profile="postgres")
    if defect == "manifest":
        (path / "manifest.json").write_bytes(b"{}")
    elif defect == "artifact":
        (path / "postgres/toc.dat").write_bytes(b"changed")
    elif defect == "link":
        (path / "postgres/toc.dat").unlink()
        (path / "postgres/toc.dat").symlink_to(path / "manifest.json")
    elif defect == "receipt":
        (tmp_path / result["backup_id"] / "manifest.json").write_bytes(b"{}")
    else:
        identity["checkpoint_key"] = "c" * 64
    monkeypatch.setattr(restore_existing, "restore_components", lambda *a, **kw: pytest.fail("no destructive restore"))
    with pytest.raises((OSError, ValueError), match="checkpoint"):
        update_checkpoint.restore(tmp_path, **identity, **{key: result[key] for key in ("backup_id", "checkpoint_sha256")})


def test_daily_selection_is_rechecked_before_pinning(tmp_path, monkeypatch):
    verified_set(tmp_path, monkeypatch)
    selected = update_checkpoint.check_backup(tmp_path, "a" * 32, "b" * 64)["daily_backup"]
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP + timedelta(hours=27))
    with pytest.raises(RuntimeError, match="update_fresh_daily_backup_required"):
        update_checkpoint.checkpoint(tmp_path, "a" * 32, "b" * 64, daily_backup=selected)


@pytest.mark.parametrize("action,method", [("check", "check_backup"), ("backup", "checkpoint")])
def test_helper_reports_fixed_wait_reason_without_triggering_recovery(monkeypatch, capsys, action, method):
    def refuse(*a, **kw):
        raise RuntimeError("update_fresh_daily_backup_required")
    monkeypatch.setattr(update_checkpoint, method, refuse)
    monkeypatch.setattr(sys, "argv", ["checkpoint", action, json.dumps({"operation": "a" * 32,
                                                                         "checkpoint_key": "b" * 64})])
    assert update_checkpoint.main() == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out) == {"status": "waiting", "reason_code": "update_fresh_daily_backup_required"}


def test_legacy_full_receipt_from_previous_release_is_admitted(tmp_path, monkeypatch):
    # Releases before restorelight wrote only backup_id/status/components after a full restore.
    path, _, receipt = verified_set(tmp_path, monkeypatch)
    legacy = {key: receipt[key] for key in ("backup_id", "status", "components")}
    receipt_path = tmp_path / "restore_check.json"
    backup.write_json(receipt_path, legacy)
    os.utime(receipt_path, (STAMP.timestamp(), STAMP.timestamp()))
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP + timedelta(hours=1))
    result = update_checkpoint.check_backup(tmp_path, "a" * 32, "b" * 64)
    assert result["daily_backup"]["backup_id"] == path.name


def test_legacy_receipt_still_requires_verified_status(tmp_path, monkeypatch):
    _, _, receipt = verified_set(tmp_path, monkeypatch)
    legacy = {key: receipt[key] for key in ("backup_id", "components")} | {"status": "failed"}
    backup.write_json(tmp_path / "restore_check.json", legacy)
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP + timedelta(hours=1))
    with pytest.raises(RuntimeError, match="update_fresh_daily_backup_required"):
        update_checkpoint.check_backup(tmp_path, "a" * 32, "b" * 64)


# Scheduled worker health uses synthetic captures and drill receipts only.
def cycle_drill_receipt(path, *, status="verified"):
    return {"status": status, "verification": "full", "backup_id": path.name,
            "started_at_utc": STAMP.isoformat(), "completed_at_utc": STAMP.isoformat(),
            "components": {name: {"status": "verified"} for name in ("postgres", "history", "warm")}}


def fake_scheduled_cycle(root, monkeypatch):
    selected = root / "20261006T010000.000000Z"
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP)
    monkeypatch.setattr(backup.os, "getpid", lambda: 1)
    monkeypatch.setattr(backup, "native_mode", lambda: False)

    def capture(*args, **kwargs):
        backup.record_result(root, backup.default_components(), "success", selected)
        return selected

    monkeypatch.setattr(backup, "run_backup", capture)
    monkeypatch.setattr(drill, "restore_check", lambda *a, **kw: cycle_drill_receipt(selected))
    return selected


def run_scheduled_cycle(root):
    return backup.scheduled_backup(root, 7, reuse_recent=True, scheduled_interval=86400)


@pytest.mark.parametrize("failure", ["exception", "failed", "skipped", "other_set", "stale", "light", "component"])
def test_failed_required_drill_survives_heartbeat_restart_and_manual_capture(tmp_path, monkeypatch, failure):
    selected = fake_scheduled_cycle(tmp_path, monkeypatch)
    run_scheduled_cycle(tmp_path)  # A prior successful cycle must not conceal a new failure.
    receipt = cycle_drill_receipt(selected)
    if failure in {"failed", "skipped"}:
        receipt["status"] = failure
    elif failure == "other_set":
        receipt["backup_id"] = "20261005T010000.000000Z"
    elif failure == "stale":
        receipt["started_at_utc"] = (STAMP - timedelta(seconds=1)).isoformat()
    elif failure == "light":
        receipt["verification"] = "light"
    elif failure == "component":
        receipt["components"]["warm"]["status"] = "skipped"

    def restore(*args, **kwargs):
        if failure == "exception":
            raise RuntimeError("synthetic")
        return receipt

    monkeypatch.setattr(drill, "restore_check", restore)
    with pytest.raises(RuntimeError):
        run_scheduled_cycle(tmp_path)
    assert backup.read_result(tmp_path)["last_result"] == "success"  # Capture remains distinct.
    persisted = (tmp_path / "scheduled_cycle.json").read_bytes()
    for status in ("failed", "waiting", "running"):
        # Empty process-local result models restart; the persisted failure is authoritative.
        backup.heartbeat(tmp_path, status, None)
        assert not backup.healthy(tmp_path)
        assert json.loads((tmp_path / "heartbeat.json").read_bytes())["last_result"] == "failed"
    backup.record_result(tmp_path, backup.default_components(), "success", selected)
    backup.refresh_heartbeat(tmp_path)
    assert not backup.healthy(tmp_path)
    assert (tmp_path / "scheduled_cycle.json").read_bytes() == persisted
    monkeypatch.setattr(drill, "restore_check", lambda *a, **kw: cycle_drill_receipt(selected))
    run_scheduled_cycle(tmp_path)
    backup.heartbeat(tmp_path, "waiting", None)
    assert backup.healthy(tmp_path)


@pytest.mark.parametrize("stage", ["capture", "light"])
def test_capture_or_light_failure_cannot_reuse_previous_cycle_health(tmp_path, monkeypatch, stage):
    selected = fake_scheduled_cycle(tmp_path, monkeypatch)
    run_scheduled_cycle(tmp_path)
    if stage == "capture":
        def capture(*a, **kw):
            backup.record_result(tmp_path, backup.default_components(), "failed")
            raise RuntimeError("synthetic capture")
        monkeypatch.setattr(backup, "run_backup", capture)
        with pytest.raises(RuntimeError, match="synthetic capture"):
            run_scheduled_cycle(tmp_path)
    else:
        # This is the same failure receipt emitted by light_check's tested error path.
        backup.record_result(tmp_path, backup.default_components(), "failed")
    backup.heartbeat(tmp_path, "waiting", None)
    assert not backup.healthy(tmp_path)
    backup.record_result(tmp_path, backup.default_components(), "success", selected)
    backup.heartbeat(tmp_path, "waiting", None)
    assert not backup.healthy(tmp_path)  # New capture alone cannot recover.


@pytest.mark.parametrize("state", ["absent", "corrupt", "running"])
def test_missing_or_incomplete_cycle_is_not_verified_after_restart(tmp_path, monkeypatch, state):
    selected = fake_scheduled_cycle(tmp_path, monkeypatch)
    backup.record_result(tmp_path, backup.default_components(), "success", selected)
    if state == "corrupt":
        (tmp_path / "scheduled_cycle.json").write_text("{broken")
    elif state == "running":
        backup.write_json(tmp_path / "scheduled_cycle.json", {
            "format_version": 1, "status": "running", "started_at_utc": STAMP.isoformat()})
    backup.heartbeat(tmp_path, "waiting", None)
    assert not backup.healthy(tmp_path)
    beat = json.loads((tmp_path / "heartbeat.json").read_bytes())
    assert beat["cycle_status"] == {"absent": "unknown", "corrupt": "unavailable", "running": "running"}[state]


def test_native_capture_health_does_not_require_docker_cycle(tmp_path, monkeypatch):
    selected = fake_scheduled_cycle(tmp_path, monkeypatch)
    monkeypatch.setattr(backup, "native_mode", lambda: True)
    backup.record_result(tmp_path, backup.default_components(), "success", selected)
    backup.heartbeat(tmp_path, "waiting", None)
    assert backup.healthy(tmp_path)


def test_interrupted_cycle_remains_incomplete_after_restart(tmp_path, monkeypatch):
    fake_scheduled_cycle(tmp_path, monkeypatch)

    def interrupt(*a, **kw):
        raise KeyboardInterrupt

    monkeypatch.setattr(drill, "restore_check", interrupt)
    with pytest.raises(KeyboardInterrupt):
        run_scheduled_cycle(tmp_path)
    backup.heartbeat(tmp_path, "waiting", None)
    assert backup.read_cycle_result(tmp_path)["status"] == "running"
    assert not backup.healthy(tmp_path)


def test_failed_terminal_cycle_write_cannot_publish_success(tmp_path, monkeypatch):
    fake_scheduled_cycle(tmp_path, monkeypatch)
    write = backup.write_json

    def unavailable(path, value):
        if path.name == "scheduled_cycle.json" and value["status"] != "running":
            raise OSError("synthetic disk failure")
        write(path, value)

    monkeypatch.setattr(backup, "write_json", unavailable)
    with pytest.raises(OSError, match="synthetic disk failure"):
        run_scheduled_cycle(tmp_path)
    backup.heartbeat(tmp_path, "waiting", None)
    assert backup.read_cycle_result(tmp_path)["status"] == "running"
    assert not backup.healthy(tmp_path)


def test_initial_cycle_write_failure_does_not_inherit_old_success(tmp_path, monkeypatch):
    fake_scheduled_cycle(tmp_path, monkeypatch)
    run_scheduled_cycle(tmp_path)
    write = backup.write_json

    def unavailable(path, value):
        if path.name == "scheduled_cycle.json":
            raise OSError("synthetic disk failure")
        write(path, value)

    monkeypatch.setattr(backup, "write_json", unavailable)
    with pytest.raises(OSError, match="synthetic disk failure"):
        run_scheduled_cycle(tmp_path)
    backup.heartbeat(tmp_path, "failed", None, "failed")
    assert not backup.healthy(tmp_path)

    # Restart discards process-local failure but retains the failed heartbeat.
    backup.heartbeat(tmp_path, "waiting", None)
    assert not backup.healthy(tmp_path)
    backup.refresh_heartbeat(tmp_path)
    assert not backup.healthy(tmp_path)
    monkeypatch.setattr(backup, "write_json", write)
    run_scheduled_cycle(tmp_path)
    backup.heartbeat(tmp_path, "waiting", None)
    assert backup.healthy(tmp_path)


@pytest.mark.parametrize("defect", ["list", "missing_time", "future_time", "naive_time", "missing_capture"])
def test_malformed_success_cycle_is_unavailable(tmp_path, monkeypatch, defect):
    fake_scheduled_cycle(tmp_path, monkeypatch)
    run_scheduled_cycle(tmp_path)
    cycle = json.loads((tmp_path / "scheduled_cycle.json").read_bytes())
    if defect == "list":
        cycle = []
    elif defect == "missing_time":
        del cycle["completed_at_utc"]
    elif defect == "future_time":
        cycle["completed_at_utc"] = (STAMP + timedelta(seconds=1)).isoformat()
    elif defect == "naive_time":
        cycle["completed_at_utc"] = STAMP.replace(tzinfo=None).isoformat()
    elif defect == "missing_capture":
        del cycle["capture_result"]
    backup.write_json(tmp_path / "scheduled_cycle.json", cycle)
    backup.heartbeat(tmp_path, "waiting", None)
    assert backup.read_cycle_result(tmp_path) == {"status": "unavailable"}
    assert not backup.healthy(tmp_path)


def test_old_success_heartbeat_without_receipts_is_unknown(tmp_path, monkeypatch):
    fake_scheduled_cycle(tmp_path, monkeypatch)
    backup.heartbeat(tmp_path, "success", None, "success")
    assert not backup.healthy(tmp_path)
    assert json.loads((tmp_path / "heartbeat.json").read_bytes())["last_result"] == "unknown"



def test_refresh_of_running_cycle_does_not_create_a_new_failure_binding(tmp_path, monkeypatch):
    selected = fake_scheduled_cycle(tmp_path, monkeypatch)

    def restore(*args, **kwargs):
        backup.heartbeat(tmp_path, "running", None)
        backup.refresh_heartbeat(tmp_path)
        assert backup.read_cycle_failure(tmp_path) is None
        return cycle_drill_receipt(selected)

    monkeypatch.setattr(drill, "restore_check", restore)
    run_scheduled_cycle(tmp_path)
    backup.heartbeat(tmp_path, "success", selected.name, "success")
    assert backup.healthy(tmp_path)
