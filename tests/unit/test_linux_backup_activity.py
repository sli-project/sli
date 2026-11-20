"""Maintenance probes never modify backups or contact a database."""
import json
import sys

import pytest

from deploy.linux.backup_activity import activity

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux flock")


@pytest.mark.parametrize("name", [".backup.lock", ".scheduled-backup.lock"])
def test_busy_lock_without_heartbeat_is_detected_and_not_modified(tmp_path, name):
    import fcntl

    lock = tmp_path / name
    lock.write_bytes(b"unchanged")
    with lock.open("rb") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        assert activity(tmp_path) == {"busy": True, "next_backup_at_utc": None}
    assert lock.read_bytes() == b"unchanged"
    assert list(tmp_path.iterdir()) == [lock]


@pytest.mark.parametrize("status,busy", [("running", True), ("waiting", False), ("success", False), ("failed", False)])
def test_pending_scheduler_and_idle_states(tmp_path, status, busy):
    path = tmp_path / "heartbeat.json"
    value = {"status": status, "next_backup_at_utc": "2026-10-20T02:00:00+00:00"}
    path.write_text(json.dumps(value))
    before = path.read_bytes()
    assert activity(tmp_path) == {"busy": busy, "next_backup_at_utc": value["next_backup_at_utc"]}
    assert path.read_bytes() == before and list(tmp_path.iterdir()) == [path]


def test_missing_or_invalid_heartbeat_is_not_idle(tmp_path):
    with pytest.raises(FileNotFoundError):
        activity(tmp_path)
    (tmp_path / "heartbeat.json").write_text('{}')
    with pytest.raises(ValueError, match="backup_activity_unavailable"):
        activity(tmp_path)


def test_scheduled_lock_spans_capture_and_restore_and_releases_on_failure(tmp_path, monkeypatch):
    from deploy.linux import backup, backup_restore_check

    selected = tmp_path / "synthetic"
    calls = []

    def capture(*args, **kwargs):
        assert activity(tmp_path)["busy"] is True
        calls.append("capture")
        return selected

    def restore(*args, **kwargs):
        assert activity(tmp_path)["busy"] is True
        calls.append("restore")
        raise RuntimeError("synthetic")

    monkeypatch.setattr(backup, "run_backup", capture)
    monkeypatch.setattr(backup_restore_check, "restore_check", restore)
    with pytest.raises(RuntimeError, match="synthetic"):
        backup.scheduled_backup(tmp_path, 7, reuse_recent=True, scheduled_interval=86400)
    (tmp_path / "heartbeat.json").write_text('{"status": "waiting"}')
    assert activity(tmp_path)["busy"] is False
    assert calls == ["capture", "restore"]
    assert backup.read_cycle_result(tmp_path)["status"] == "failed"
    backup.heartbeat(tmp_path, "waiting", None)
    assert activity(tmp_path)["busy"] is False
    assert not backup.healthy(tmp_path)
