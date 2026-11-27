"""Real file receipts/CLI/health path; synthetic archives, no database or Docker."""

import hashlib
import json
from contextlib import nullcontext
from datetime import timedelta
from types import SimpleNamespace

import pytest

from deploy.linux import backup
from deploy.linux import backup_restore_check as drill
from tests.unit.test_linux_backup import STAMP
from tests.unit.test_linux_backup_verification import integrity_set, run_scheduled_cycle

pytestmark = pytest.mark.posix_only


def captured(root, monkeypatch):
    path, _ = integrity_set(root, monkeypatch)
    monkeypatch.setattr(backup.os, "getpid", lambda: 1)
    monkeypatch.setattr(backup, "native_mode", lambda: False)
    monkeypatch.setattr(backup, "pg_tool", lambda *a, **kw: None)
    return path


def test_manual_light_cli_keeps_liveness_but_not_full_assurance(
    tmp_path, monkeypatch, capsys
):
    path = captured(tmp_path, monkeypatch)
    backup.heartbeat(tmp_path, "waiting", None)
    before = json.loads((tmp_path / "heartbeat.json").read_bytes())
    monkeypatch.setattr(backup, "backup_root", lambda: tmp_path)
    monkeypatch.setattr(backup, "run_backup", lambda *a, **kw: path)
    assert backup.main(["--once"]) == 0
    beat = json.loads((tmp_path / "heartbeat.json").read_bytes())
    assert backup.main(["--healthcheck"]) == 0
    assert beat["heartbeat_at_utc"] == before["heartbeat_at_utc"]
    assert beat["process_pid"] == before["process_pid"]
    assert beat["restore_assurance"] == "pending"
    assert beat["warning_reason"] == "full_check_pending"
    assert beat["cycle_status"] == "unknown"
    with pytest.raises(RuntimeError, match="update_fresh_daily_backup_required"):
        drill.verified_daily_backup(tmp_path)
    output = capsys.readouterr().out
    assert "Копия создана" in output and "Backup created" in output


@pytest.mark.parametrize(
    "defect",
    ["missing", "digest", "capture_id", "time", "failed", "component", "symlink"],
)
def test_invalid_light_evidence_does_not_heal(tmp_path, monkeypatch, defect):
    path = captured(tmp_path, monkeypatch)
    receipt = drill.light_check(tmp_path, selected=path)
    file = tmp_path / "restore_check.json"
    if defect == "missing":
        file.unlink()
    elif defect == "symlink":
        file.rename(tmp_path / "other.json")
        file.symlink_to(tmp_path / "other.json")
    else:
        if defect == "digest":
            receipt["manifest_sha256"] = "0" * 64
        if defect == "capture_id":
            receipt["capture_receipt_id"] = "different"
        if defect == "time":
            receipt["completed_at_utc"] = (STAMP + timedelta(seconds=1)).isoformat()
        if defect == "failed":
            receipt["status"] = "failed"
        if defect == "component":
            receipt["components"]["warm"]["status"] = "skipped"
        backup.write_json(file, receipt)
    backup.heartbeat(tmp_path, "waiting", None)
    assert not backup.healthy(tmp_path)


@pytest.mark.parametrize(
    "reason",
    [
        "postgres_capacity_unavailable",
        "postgres_size_estimate_unavailable",
        "insufficient_disk_space",
        "postgres_restore_busy",
    ],
)
def test_safe_deferred_cycle_is_warning_not_verified(tmp_path, monkeypatch, reason):
    path = captured(tmp_path, monkeypatch)
    monkeypatch.setattr(backup, "run_backup", lambda *a, **kw: path)
    receipt = {
        "status": "skipped",
        "verification": "full",
        "backup_id": path.name,
        "reason": reason,
        "manifest_sha256": hashlib.sha256(
            (path / "manifest.json").read_bytes()
        ).hexdigest(),
        "started_at_utc": STAMP.isoformat(),
        "completed_at_utc": STAMP.isoformat(),
        "components": {"postgres": {"status": "skipped", "reason": reason}},
    }

    def restore(*a, **kw):
        backup.write_json(tmp_path / "restore_check.json", receipt)
        return receipt

    monkeypatch.setattr(drill, "restore_check", restore)
    run_scheduled_cycle(tmp_path)
    backup.heartbeat(tmp_path, "success", path.name, "success")
    assert backup.healthy(tmp_path)
    beat = json.loads((tmp_path / "heartbeat.json").read_bytes())
    assert beat["cycle_status"] == "deferred"
    assert beat["restore_assurance"] == "deferred"
    assert beat["warning_reason"] == reason
    assert drill.recent_full_check(tmp_path) is False
    assert json.loads((tmp_path / "restore_check.json").read_bytes()) == receipt
    with pytest.raises(RuntimeError):
        drill.verified_daily_backup(tmp_path)


@pytest.mark.parametrize("failure", ["token", "cycle", "corrupt", "running"])
def test_manual_light_does_not_clear_real_failure(tmp_path, monkeypatch, failure):
    path = captured(tmp_path, monkeypatch)
    if failure == "token":
        backup.heartbeat(tmp_path, "failed", None, "failed")
    elif failure == "corrupt":
        (tmp_path / "scheduled_cycle.json").write_text("{")
    else:
        backup.write_json(
            tmp_path / "scheduled_cycle.json",
            {
                "format_version": 1,
                "status": "failed" if failure == "cycle" else "running",
            },
        )
    drill.light_check(tmp_path, selected=path)
    backup.heartbeat(tmp_path, "waiting", None)
    assert not backup.healthy(tmp_path)


@pytest.mark.parametrize("reason", ["capacity", "space", "busy", "cleanup"])
def test_actual_restore_admission_to_heartbeat_without_create(
    tmp_path, monkeypatch, reason
):
    from tests.unit.test_linux_backup_capacity import GIB, Admin, receipt

    path = captured(tmp_path, monkeypatch)
    manifest = json.loads((path / "manifest.json").read_bytes())
    manifest["components"]["postgres"]["database_size_bytes"] = 20 * GIB
    backup.write_json(path / "manifest.json", manifest)
    admin = Admin(acquired=reason != "busy")
    monkeypatch.setattr(backup, "pg_connect", lambda *a, **kw: nullcontext(admin))
    monkeypatch.setattr(backup, "run_backup", lambda *a, **kw: path)
    if reason == "space":
        backup.write_json(tmp_path / ".postgres-capacity.json", receipt(free=1))
    if reason == "cleanup":
        (tmp_path / ".restore-runs").mkdir()
        (tmp_path / ".restore-runs" / ("a" * 32 + ".json")).write_text("{}")
        with pytest.raises(RuntimeError, match='linux_backup_restore_cleanup_required'):
            run_scheduled_cycle(tmp_path)
    else:
        run_scheduled_cycle(tmp_path)
    backup.heartbeat(tmp_path, "waiting", None)
    assert backup.healthy(tmp_path) is (reason != "cleanup")
    assert not any(
        "CREATE DATABASE" in query or "DROP DATABASE" in query
        for query in admin.queries
    )
    assert not drill.recent_full_check(tmp_path)
    with pytest.raises(RuntimeError):
        drill.verified_daily_backup(tmp_path)


def test_deferred_cannot_clear_failure_binding(tmp_path, monkeypatch):
    from tests.unit.test_linux_backup_capacity import Admin

    path = captured(tmp_path, monkeypatch)
    backup.heartbeat(tmp_path, "failed", None, "failed")
    token = backup.read_cycle_failure(tmp_path)
    monkeypatch.setattr(
        backup, "pg_connect", lambda *a, **kw: nullcontext(Admin(acquired=False))
    )
    monkeypatch.setattr(backup, "run_backup", lambda *a, **kw: path)
    run_scheduled_cycle(tmp_path)
    backup.heartbeat(tmp_path, "success", path.name, "success")
    assert not backup.healthy(tmp_path)
    assert backup.read_cycle_failure(tmp_path) == token


@pytest.mark.parametrize(
    "defect", ["unknown", "cleanup", "digest", "component", "time", "capture"]
)
def test_unproven_deferral_is_failure(tmp_path, monkeypatch, defect):
    path = captured(tmp_path, monkeypatch)
    monkeypatch.setattr(backup, "run_backup", lambda *a, **kw: path)
    result = {
        "status": "skipped",
        "verification": "full",
        "backup_id": path.name,
        "reason": "postgres_restore_busy",
        "manifest_sha256": hashlib.sha256(
            (path / "manifest.json").read_bytes()
        ).hexdigest(),
        "started_at_utc": STAMP.isoformat(),
        "completed_at_utc": STAMP.isoformat(),
        "components": {
            "postgres": {"status": "skipped", "reason": "postgres_restore_busy"}
        },
    }
    if defect == "unknown":
        result["reason"] = "new_unknown_reason"
    if defect == "cleanup":
        result["reason"] = "postgres_restore_cleanup_pending"
    if defect == "digest":
        result["manifest_sha256"] = "0" * 64
    if defect == "component":
        result["components"]["warm"] = {"status": "failed"}
    if defect == "time":
        result["completed_at_utc"] = (STAMP + timedelta(seconds=1)).isoformat()
    if defect == "capture":
        backup.record_result(tmp_path, backup.default_components(), "failed")
    monkeypatch.setattr(drill, "restore_check", lambda *a, **kw: result)
    with pytest.raises(RuntimeError):
        run_scheduled_cycle(tmp_path)
    backup.heartbeat(tmp_path, "waiting", None)
    assert not backup.healthy(tmp_path)


def test_manual_success_reports_prior_failure_honestly(tmp_path, monkeypatch, capsys):
    path = captured(tmp_path, monkeypatch)
    backup.heartbeat(tmp_path, "failed", None, "failed")
    monkeypatch.setattr(backup, "backup_root", lambda: tmp_path)
    monkeypatch.setattr(backup, "run_backup", lambda *a, **kw: path)
    assert backup.main(["--once"]) == 0
    assert not backup.healthy(tmp_path)
    text = capsys.readouterr().out
    assert "Предыдущий сбой" in text and "Previous failure" in text
    assert "full_check_pending" not in text


def test_manual_new_set_after_deferred_set_retention_is_not_a_failure(
    tmp_path, monkeypatch
):
    import shutil

    from tests.unit.test_linux_backup_capacity import Admin

    old = captured(tmp_path, monkeypatch)
    monkeypatch.setattr(
        backup, "pg_connect", lambda *a, **kw: nullcontext(Admin(acquired=False))
    )
    monkeypatch.setattr(backup, "run_backup", lambda *a, **kw: old)
    run_scheduled_cycle(tmp_path)
    backup.heartbeat(tmp_path, "waiting", None)
    new = tmp_path / "20261006T020000.000000Z"
    shutil.copytree(old, new)
    manifest = json.loads((new / "manifest.json").read_bytes())
    manifest["backup_id"] = new.name
    backup.write_json(new / "manifest.json", manifest)
    backup.record_result(tmp_path, backup.default_components(), "success", new)
    drill.light_check(tmp_path, selected=new)
    shutil.rmtree(old)  # Synthetic retention of the older set only.
    backup.refresh_heartbeat(tmp_path)
    assert backup.healthy(tmp_path)
    assert (
        json.loads((tmp_path / "heartbeat.json").read_bytes())["restore_assurance"]
        == "pending"
    )


def test_deferral_never_temporarily_publishes_verified_admission(tmp_path, monkeypatch):
    from tests.unit.test_linux_backup_capacity import Admin

    path = captured(tmp_path, monkeypatch)
    monkeypatch.setattr(
        backup, "pg_connect", lambda *a, **kw: nullcontext(Admin(acquired=False))
    )
    monkeypatch.setattr(backup, "run_backup", lambda *a, **kw: path)
    write = backup.write_json
    admissions = []

    def observe(file, value):
        if file == tmp_path / "restore_check.json":
            admissions.append(value.copy())
        write(file, value)

    monkeypatch.setattr(backup, "write_json", observe)
    run_scheduled_cycle(tmp_path)
    assert not any(item.get("status") == "verified" for item in admissions)



def legacy_startup_files(root, monkeypatch):
    """Old manual capture, old failed/unknown heartbeat, earlier successful drill."""
    path = captured(root, monkeypatch)
    capture = backup.read_result(root)
    old_id = "20261005T020028.000000Z"
    old_time = STAMP - timedelta(days=1)
    old_capture = dict(capture, last_success=old_id, receipt_id="nightly-capture",
                       completed_at_utc=old_time.isoformat())
    backup.write_json(root / "scheduled_cycle.json", {
        "format_version": 1, "status": "success", "backup_id": old_id,
        "capture_result": old_capture, "started_at_utc": old_time.isoformat(),
        "completed_at_utc": old_time.isoformat(),
    })
    full = {
        "status": "verified", "verification": "full", "backup_id": old_id,
        "started_at_utc": old_time.isoformat(), "completed_at_utc": old_time.isoformat(),
        "components": {name: {"status": "verified"} for name in ("postgres", "history", "warm")},
    }
    backup.write_json(root / "restore_check.json", full)
    backup.write_json(root / "heartbeat.json", {"status": "failed", "last_result": "unknown"})
    return path, full


def run_startup(root, monkeypatch):
    import time
    from deploy.linux.sli_core import shutdown

    polls = []
    monkeypatch.setattr(drill, "startup_restore_cleanup", lambda _: None)
    monkeypatch.setattr(backup, "scheduled_backup", lambda *a, **kw: pytest.fail("startup must not capture/restore"))
    monkeypatch.setattr(shutdown, "requested", lambda: len(polls) >= 30)

    def wait(*args, **kwargs):
        polls.append(backup.healthy(root))
        time.sleep(0.005)

    monkeypatch.setattr(shutdown, "wait", wait)
    backup.serve(root, interval=86400, delay=300, retention=7)
    return json.loads((root / "heartbeat.json").read_bytes())


@pytest.mark.parametrize("defect", ["capture", "artifact", "cycle", "token", "receipt", "receipt_id"])
def test_startup_does_not_repair_real_failed_or_damaged_evidence(tmp_path, monkeypatch, defect):
    path, _ = legacy_startup_files(tmp_path, monkeypatch)
    if defect == "capture":
        backup.record_result(tmp_path, backup.default_components(), "failed")
    elif defect == "artifact":
        (path / "postgres" / "toc.dat").write_bytes(b"damaged")
    elif defect == "cycle":
        (tmp_path / "scheduled_cycle.json").write_text("{")
    elif defect == "token":
        backup.write_json(tmp_path / "heartbeat.json", {
            "status": "failed", "last_result": "failed", "cycle_failure_id": "unresolved",
        })
    elif defect == "receipt":
        (tmp_path / "restore_check.json").write_text("{")
    else:
        receipt = backup.read_result(tmp_path)
        receipt.pop("receipt_id")
        backup.write_json(tmp_path / "last_result.json", receipt)
    run_startup(tmp_path, monkeypatch)
    assert backup.main(["--healthcheck"]) == 1
    if defect == "token":
        assert backup.read_cycle_failure(tmp_path) == "unresolved"


def test_startup_reuses_bound_light_receipt_without_scanning(tmp_path, monkeypatch):
    path, _ = legacy_startup_files(tmp_path, monkeypatch)
    drill.light_check(tmp_path, selected=path)
    before = (tmp_path / "restore_check.json").read_bytes()
    monkeypatch.setattr(drill, "integrity_check", lambda *_: pytest.fail("already checked"))
    for _ in range(2):
        run_startup(tmp_path, monkeypatch)
        assert backup.healthy(tmp_path)
        assert (tmp_path / "restore_check.json").read_bytes() == before


@pytest.mark.parametrize("changed", ["capture", "failed_capture", "cycle", "receipt", "token"])
def test_startup_revalidates_selection_under_capture_lock(tmp_path, monkeypatch, changed):
    from contextlib import contextmanager

    path, _ = legacy_startup_files(tmp_path, monkeypatch)
    capture = drill.startup_capture(tmp_path)
    real_lock = backup.backup_lock
    original = (tmp_path / "restore_check.json").read_bytes()

    @contextmanager
    def lock(root, **kwargs):
        with real_lock(root, **kwargs):
            if changed in {"capture", "failed_capture"}:
                backup.record_result(root, backup.default_components(),
                                     "failed" if changed == "failed_capture" else "success", path)
            elif changed == "cycle":
                backup.write_json(root / "scheduled_cycle.json", {"format_version": 1, "status": "running"})
            elif changed == "receipt":
                (root / "restore_check.json").write_text("{")
            else:
                backup.write_json(root / "heartbeat.json", {"cycle_failure_id": "new-failure"})
            yield

    monkeypatch.setattr(backup, "backup_lock", lock)
    monkeypatch.setattr(drill, "integrity_check", lambda *_: pytest.fail("stale selection must not scan"))
    assert drill.startup_light_check(tmp_path, capture) is None
    assert (tmp_path / "restore_check.json").read_bytes() == (b"{" if changed == "receipt" else original)


def test_startup_scan_keeps_unknown_liveness_and_shutdown_cancels_worker(tmp_path, monkeypatch):
    import threading
    from deploy.linux.sli_core import shutdown

    path, full = legacy_startup_files(tmp_path, monkeypatch)
    entered, finished = threading.Event(), threading.Event()
    stopping = []

    def integrity(selected, **kwargs):
        entered.set()
        try:
            while True:
                kwargs["check"]()
                threading.Event().wait(0.005)
        finally:
            finished.set()

    def wait(*args, **kwargs):
        assert entered.wait(5)
        beat = json.loads((tmp_path / "heartbeat.json").read_bytes())
        assert beat["process_pid"] == 1
        assert beat["last_result"] == "unknown"
        assert not backup.healthy(tmp_path)
        assert not finished.is_set()
        stopping.append(True)

    monkeypatch.setattr(drill, "integrity_check", integrity)
    monkeypatch.setattr(drill, "startup_restore_cleanup", lambda _: None)
    monkeypatch.setattr(backup, "scheduled_backup", lambda *a, **kw: pytest.fail("worker lane occupied"))
    monkeypatch.setattr(shutdown, "requested", lambda: bool(stopping))
    monkeypatch.setattr(shutdown, "wait", wait)
    backup.serve(tmp_path, interval=86400, delay=300, retention=7)
    assert finished.is_set()  # Shutdown cancels and joins; no abandoned receipt writes.
    assert not backup.light_evidence(tmp_path, backup.read_result(tmp_path))
    assert json.loads((tmp_path / "restore_check.json").read_bytes()) == full
    assert backup.read_result(tmp_path)["last_success"] == path.name


def test_startup_lock_wait_is_cancelled_without_rewriting_receipts(tmp_path, monkeypatch):
    import threading
    from deploy.linux.sli_core import shutdown

    legacy_startup_files(tmp_path, monkeypatch)
    capture = drill.startup_capture(tmp_path)
    before = {name: (tmp_path / name).read_bytes() for name in
              ("last_result.json", "restore_check.json", "scheduled_cycle.json")}
    cancelled = threading.Event()
    monkeypatch.setattr(shutdown, "requested", cancelled.is_set)
    result = []
    with backup.backup_lock(tmp_path):
        thread = threading.Thread(target=lambda: result.append(drill.startup_light_check(tmp_path, capture)))
        thread.start()
        cancelled.set()
        thread.join(0.5)
        stopped_while_locked = not thread.is_alive()
    thread.join(2)  # Baseline cleanup only; never leak a test thread.
    assert stopped_while_locked
    assert result == [None]
    assert before == {name: (tmp_path / name).read_bytes() for name in before}


@pytest.mark.parametrize("phase", ["hash", "zip", "deadline"])
def test_startup_budget_interrupts_real_chunked_reads_without_receipt_changes(tmp_path, monkeypatch, phase):
    import zipfile
    from deploy.linux.sli_core import shutdown

    path, _ = legacy_startup_files(tmp_path, monkeypatch)
    capture = drill.startup_capture(tmp_path)
    (path / "postgres/toc.dat").write_bytes(b"synthetic" * 100000)
    manifest = json.loads((path / "manifest.json").read_bytes())
    manifest["content_checksums"] = backup.content_inventory(path)
    backup.write_json(path / "manifest.json", manifest)
    before = {name: (tmp_path / name).read_bytes() for name in
              ("last_result.json", "restore_check.json", "scheduled_cycle.json")}
    cancelled, reads = [], []
    monkeypatch.setattr(shutdown, "requested", lambda: bool(cancelled))
    if phase == "hash":
        original_sha256 = backup.hashlib.sha256

        class Hash:
            def __init__(self):
                self.digest = original_sha256()

            def update(self, data):
                reads.append(len(data))
                self.digest.update(data)
                cancelled.append(True)

            def hexdigest(self):
                return self.digest.hexdigest()

        monkeypatch.setattr(backup.hashlib, "sha256", lambda *args: original_sha256(*args) if args else Hash())
    elif phase == "zip":
        original_read = zipfile.ZipExtFile.read

        def read(stream, size=-1):
            reads.append(size)
            data = original_read(stream, size)
            cancelled.append(True)
            return data

        monkeypatch.setattr(zipfile.ZipExtFile, "read", read)
    else:
        clock = iter([0, 21600])
        monkeypatch.setattr(drill.time, "monotonic", lambda: next(clock))
    assert drill.startup_light_check(tmp_path, capture) is None
    assert before == {name: (tmp_path / name).read_bytes() for name in before}
    if phase != "deadline":
        assert reads and all(size <= 256 * 1024 for size in reads)
    assert not (tmp_path / "last_full_restore_check.json").exists()


def test_bounded_pg_tool_cancels_and_reaps_child(tmp_path, monkeypatch):
    import subprocess
    import sys

    children, calls = [], []
    original = subprocess.Popen

    def popen(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    def check():
        calls.append(True)
        if len(calls) >= 3:
            raise drill.StartupCheckDeferred("synthetic cancellation")
        return 1

    monkeypatch.setattr(backup.subprocess, "Popen", popen)
    monkeypatch.setattr(backup, "pg_environment", lambda _: {})
    with pytest.raises(drill.StartupCheckDeferred):
        backup.pg_tool([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path / "unused", check=check)
    assert len(children) == 1 and children[0].returncode is not None
