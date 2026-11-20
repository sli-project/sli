"""Persistent full-backup scheduling; synthetic artifacts, no database connections."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from deploy.linux import backup, update_checkpoint
from server.sli.ops import shutdown
from tests.unit.test_linux_backup import STAMP, fake_components
from tests.unit.test_linux_backup_paths import full_receipt

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only backup service")


def instant(value):
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def server_timezone(monkeypatch):
    with monkeypatch.context() as context:
        context.setenv("TZ", "UTC")
        time.tzset()
        yield
    time.tzset()


@pytest.mark.parametrize("now,last,expected", [
    ("2026-10-18T09:41", "2026-10-18T08:53", "2026-10-19T02:00"),
    ("2026-10-18T09:41", "2026-10-17T02:00", "2026-10-19T02:00"),
    ("2026-10-18T01:00", "2026-10-17T02:00", "2026-10-18T02:00"),
    ("2026-10-18T02:00", "2026-10-17T02:00", "2026-10-18T02:00"),
    ("2026-10-18T09:41", None, "2026-10-19T02:00"),
    ("2026-10-18T01:00", None, "2026-10-18T02:00"),
])
def test_daily_schedule_uses_next_calendar_date(now, last, expected):
    result = backup.next_backup_time(instant(now), instant(last) if last else None, 86400, (2, 0))
    assert result == instant(expected)


def test_schedule_uses_configured_time_and_server_timezone(monkeypatch):
    monkeypatch.setenv("SLI_BACKUP_TIME", "01:30")
    monkeypatch.setenv("TZ", "Etc/GMT-7")
    time.tzset()
    assert backup.next_backup_time(instant("2026-10-18T09:41"), None, 86400, backup.backup_time()) == instant(
        "2026-10-18T18:30")


def test_schedule_converts_next_calendar_day_across_dst(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/Berlin")
    time.tzset()
    result = backup.next_backup_time(instant("2026-03-28T23:00"), None, 86400, (4, 0))
    assert result == instant("2026-03-29T02:00")  # 04:00 after the spring transition.


@pytest.mark.parametrize("value", ["00:00", "02:00", "23:59", "24:00", "2:00", "02:60", "02:00\n", ""])
def test_backup_time_validation(monkeypatch, value):
    monkeypatch.setenv("SLI_BACKUP_TIME", value)
    if value in {"00:00", "02:00", "23:59"}:
        assert backup.backup_time() == tuple(map(int, value.split(":")))
    else:
        with pytest.raises(ValueError, match="linux_backup_invalid_settings"):
            backup.backup_time()


def test_latest_success_uses_manifest_completion_not_reuse_or_failure_receipt(tmp_path, monkeypatch):
    fake_components(monkeypatch, tmp_path)
    path = backup.run_backup(tmp_path)
    manifest = json.loads((path / "manifest.json").read_bytes())
    completed = STAMP + timedelta(minutes=12)
    manifest["completed_at_utc"] = completed.isoformat()
    backup.write_json(path / "manifest.json", manifest)
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP + timedelta(hours=1))
    backup.record_result(tmp_path, backup.default_components(), "failed")
    assert backup.latest_full_backup(tmp_path) == (path, completed)
    assert backup.recent_backup(tmp_path, backup.default_components()) is None
    (tmp_path / "last_result.json").write_text("invalid")
    assert backup.latest_full_backup(tmp_path) == (path, completed)


@pytest.mark.parametrize("defect", ["partial", "missing", "failed", "future", "naive", "symlink"])
def test_invalid_full_backup_cannot_postpone_schedule(tmp_path, monkeypatch, defect):
    fake_components(monkeypatch, tmp_path)
    path = backup.run_backup(tmp_path, components=("postgres",) if defect == "partial" else None)
    manifest = json.loads((path / "manifest.json").read_bytes())
    if defect == "missing":
        (path / "warm.zip").unlink()
    elif defect == "failed":
        manifest["status"] = "failed"
    elif defect == "future":
        manifest["completed_at_utc"] = (STAMP + timedelta(days=1)).isoformat()
    elif defect == "naive":
        manifest["completed_at_utc"] = STAMP.replace(tzinfo=None).isoformat()
    elif defect == "symlink":
        (path / "warm.zip").unlink()
        (path / "warm.zip").symlink_to(path / "history.zip")
    backup.write_json(path / "manifest.json", manifest)
    assert backup.latest_full_backup(tmp_path) is None


@pytest.mark.parametrize("profile", ["full", "ui-only", "postgres", "history", "files"])
def test_update_without_nightly_copy_cannot_capture_or_postpone_schedule(tmp_path, monkeypatch, profile):
    fake_components(monkeypatch, tmp_path)
    monkeypatch.setattr(backup, "run_backup", lambda *a, **kw: pytest.fail("update must not capture"))
    with pytest.raises(RuntimeError, match="update_fresh_daily_backup_required"):
        update_checkpoint.checkpoint(tmp_path, "a" * 32, "b" * 64, recovery_profile=profile)
    assert backup.latest_full_backup(tmp_path) is None
    assert not list(tmp_path.rglob("manifest.json"))
    assert not (tmp_path / "last_result.json").exists()


@pytest.mark.parametrize("profile", ["full", "ui-only", "postgres", "history", "files"])
def test_update_checkpoint_does_not_change_nightly_schedule(tmp_path, monkeypatch, profile):
    fake_components(monkeypatch, tmp_path)
    monkeypatch.setenv("SLI_BACKUP_FILES_ROOT", str(tmp_path.parent / "synthetic-files"))

    def files(destination):
        destination.mkdir()
        (destination / "fixture").write_bytes(b"synthetic")
        return {"size_bytes": 9, "format": "directory"}

    monkeypatch.setattr(backup, "backup_files", files)
    nightly = backup.run_backup(tmp_path)
    full_receipt(tmp_path, nightly)
    latest = backup.latest_full_backup(tmp_path)
    assert latest == (nightly, STAMP)
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP + timedelta(hours=1))
    monkeypatch.setattr(backup, "capture_backup", lambda *a, **kw: pytest.fail("update must not capture"))
    next_run = backup.next_backup_time(backup.utc_now(), latest[1], 86400, (2, 0))
    receipt = update_checkpoint.checkpoint(tmp_path, "a" * 32, "b" * 64, recovery_profile=profile)
    assert receipt["daily_backup"]["backup_id"] == nightly.name
    assert backup.latest_full_backup(tmp_path) == latest
    assert backup.next_backup_time(backup.utc_now(), latest[1], 86400, (2, 0)) == next_run
    assert backup.run_backup(tmp_path, scheduled_interval=86400) == nightly
    assert json.loads((tmp_path / "last_result.json").read_bytes())["last_result"] == "success"


@pytest.mark.parametrize("initial,expected_first", [
    (STAMP - timedelta(days=1), "2026-10-07T02:00"),
    (STAMP.replace(hour=8, minute=53), "2026-10-07T02:00"),
])
def test_scheduler_rechecks_external_success_and_publishes_next_time(tmp_path, monkeypatch, initial, expected_first):
    now = [STAMP.replace(hour=9, minute=41)]
    fake_components(monkeypatch, tmp_path, stamp=initial)
    path = backup.run_backup(tmp_path)
    monkeypatch.setattr(backup, "utc_now", lambda: now[0])
    monkeypatch.setattr(backup, "run_backup", lambda *a, **kw: pytest.fail("no dump after restart"))
    monkeypatch.setattr(shutdown, "requested", lambda: False)
    beats = []

    class EndLoop(Exception):
        pass

    def wait(*args, **kwargs):
        if len(beats) == 1:
            # A --once capture completes while the scheduler is waiting.
            manifest = json.loads((path / "manifest.json").read_bytes())
            manifest["completed_at_utc"] = now[0].isoformat()
            backup.write_json(path / "manifest.json", manifest)
            now[0] += timedelta(seconds=30)
        else:
            raise EndLoop

    original_heartbeat = backup.heartbeat
    monkeypatch.setattr(shutdown, "wait", wait)
    monkeypatch.setattr(backup, "heartbeat", lambda *a, **kw:
                        (beats.append(kw["next_backup"]), original_heartbeat(*a, **kw)))
    with pytest.raises(EndLoop):
        backup.serve(tmp_path, interval=86400, delay=300, retention=7)
    assert beats == [instant(expected_first), instant("2026-10-07T02:00")]
    receipt = json.loads((tmp_path / "heartbeat.json").read_bytes())
    assert receipt["next_backup_at_utc"] == beats[-1].isoformat()
    assert receipt["last_success"] == path.name


def test_scheduler_starts_at_nightly_slot_after_startup_grace(tmp_path, monkeypatch):
    now = [STAMP.replace(hour=1, minute=54)]
    starts = []
    monkeypatch.setattr(backup, "utc_now", lambda: now[0])
    monkeypatch.setattr(shutdown, "requested", lambda: False)

    class EndLoop(Exception):
        pass

    class Executor:
        def __init__(self, max_workers):
            assert max_workers == 1

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def submit(self, function, root, retention, **kwargs):
            assert kwargs == {"reuse_recent": True, "scheduled_interval": 86400}
            starts.append(now[0])
            return SimpleNamespace(done=lambda: False)

    def wait(*args, **kwargs):
        if starts:
            raise EndLoop
        now[0] += timedelta(seconds=30)

    monkeypatch.setattr(backup, "ThreadPoolExecutor", Executor)
    monkeypatch.setattr(shutdown, "wait", wait)
    with pytest.raises(EndLoop):
        backup.serve(tmp_path, interval=86400, delay=300, retention=7)
    assert starts == [instant("2026-10-06T02:00")]


def test_external_publication_cannot_shorten_startup_grace(tmp_path, monkeypatch):
    now = STAMP.replace(hour=1, minute=59)
    observations = iter([None, None, (tmp_path / "synthetic", now - timedelta(minutes=1))])
    beats = []
    monkeypatch.setattr(backup, "utc_now", lambda: now)
    monkeypatch.setattr(backup, "latest_full_backup", lambda root: next(observations))
    monkeypatch.setattr(shutdown, "requested", lambda: len(beats) == 2)
    monkeypatch.setattr(shutdown, "wait", lambda *a, **kw: None)
    monkeypatch.setattr(backup, "heartbeat", lambda *a, **kw: beats.append(kw["next_backup"]))
    backup.serve(tmp_path, interval=60, delay=600, retention=7)
    assert beats == [instant("2026-10-07T02:00")] * 2


@pytest.mark.parametrize("failed", [False, True])
def test_after_worker_finishes_success_uses_capture_time_and_failure_uses_retry_interval(tmp_path, monkeypatch, failed):
    now = [STAMP.replace(hour=2)]
    capture = (tmp_path / "synthetic", STAMP - timedelta(hours=15))  # Previous day at 10:00.
    starts, beats = [], []

    class Future:
        def done(self):
            return True

        def result(self):
            if failed:
                raise RuntimeError("synthetic")
            return capture[0]

    class Executor:
        def __init__(self, max_workers):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def submit(self, *args, **kwargs):
            starts.append(now[0])
            return Future()

    monkeypatch.setattr(backup, "utc_now", lambda: now[0])
    monkeypatch.setattr(backup, "latest_full_backup", lambda root: capture if starts else None)
    monkeypatch.setattr(backup, "ThreadPoolExecutor", Executor)
    monkeypatch.setattr(shutdown, "requested", lambda: len(beats) == 2)
    monkeypatch.setattr(shutdown, "wait", lambda *a, **kw: now.__setitem__(0, now[0] + timedelta(seconds=30)))
    monkeypatch.setattr(backup, "heartbeat", lambda *a, **kw: beats.append(kw["next_backup"]))
    backup.serve(tmp_path, interval=86400, delay=0, retention=7)
    assert len(starts) == 1
    assert beats == [None, instant("2026-10-08T02:00" if failed else "2026-10-07T02:00")]


def test_pg_restore_does_not_receive_dump_priority_wrapper(tmp_path, monkeypatch):
    commands = []
    monkeypatch.setattr(backup.subprocess, "run", lambda command, **kw:
                        (commands.append(command), SimpleNamespace(returncode=0))[1])
    backup.pg_tool(["pg_restore", "--jobs=2"], tmp_path / "pgpass")
    assert commands == [["pg_restore", "--jobs=2"]]


@pytest.mark.parametrize("name,completed,now,expected", [
    ("20261019T020000.000000Z", "2026-10-19T02:30", "2026-10-19T02:30", "2026-10-20T02:00"),
    ("20261019T020000.000000Z", "2026-10-19T02:00:01", "2026-10-20T01:59", "2026-10-20T02:00"),
    ("20261019T020000.000000Z", "2026-10-19T02:30", "2026-10-20T02:01", "2026-10-21T02:00"),
    ("20261019T230000.000000Z", "2026-10-20T00:30", "2026-10-20T00:30", "2026-10-20T02:00"),
    ("20261019T020000.000000Z", "2026-10-22T03:00", "2026-10-22T03:00", "2026-10-23T02:00"),
    ("manual", "2026-10-19T02:30", "2026-10-19T02:30", "2026-10-20T02:00"),
    ("20261020T020000.000000Z", "2026-10-19T02:30", "2026-10-19T02:30", "2026-10-20T02:00"),
])
def test_daily_anchor_survives_restart_and_missed_slots(tmp_path, name, completed, now, expected):
    latest = (tmp_path / name, instant(completed))
    anchor = backup.schedule_anchor(latest, 86400)
    assert backup.next_backup_time(instant(now), anchor, 86400, (2, 0)) == instant(expected)


@pytest.mark.parametrize("interval,expected", [(3600, "2026-10-20T02:00"), (90000, "2026-10-21T02:00")])
def test_nondefault_interval_keeps_completion_spacing(tmp_path, interval, expected):
    completed = instant("2026-10-19T02:30")
    latest = (tmp_path / "20261019T020000.000000Z", completed)
    assert backup.schedule_anchor(latest, interval) == completed
    assert backup.next_backup_time(
        completed, backup.schedule_anchor(latest, interval), interval, (2, 0)) == instant(expected)


@pytest.mark.parametrize("completed,now,expected", [
    ("2026-03-28T01:30", "2026-03-28T23:00", "2026-03-29T01:00"),
    ("2026-10-24T00:30", "2026-10-24T23:00", "2026-10-25T00:00"),
    ("2026-10-25T00:30", "2026-10-25T01:00", "2026-10-26T01:00"),
])
def test_daily_dst_keeps_server_local_gap_fold_conversion(monkeypatch, completed, now, expected):
    monkeypatch.setenv("TZ", "Europe/Berlin")
    time.tzset()
    # Preserve naive datetime.astimezone's gap normalization / first fold;
    # a success on the fold day must not schedule its second occurrence.
    assert backup.next_backup_time(instant(now), instant(completed), 86400, (2, 0)) == instant(expected)


def test_daily_start_anchor_is_converted_to_server_calendar_day(tmp_path, monkeypatch):
    monkeypatch.setenv("TZ", "Etc/GMT-7")
    time.tzset()
    latest = (tmp_path / "20261019T230000.000000Z", instant("2026-10-20T00:30"))
    assert backup.next_backup_time(latest[1], backup.schedule_anchor(latest, 86400), 86400, (2, 0)) == instant(
        "2026-10-20T19:00")


@pytest.mark.parametrize("start,completed", [
    ("2026-10-19T02:00", "2026-10-19T02:30"),
    ("2026-10-19T23:00", "2026-10-20T01:50"),
])
def test_daily_under_lock_does_not_reuse_yesterdays_capture(tmp_path, monkeypatch, start, completed):
    started = instant(start)
    fake_components(monkeypatch, tmp_path, stamp=started)
    previous = backup.run_backup(tmp_path)
    manifest = json.loads((previous / "manifest.json").read_bytes())
    manifest["completed_at_utc"] = instant(completed).isoformat()
    backup.write_json(previous / "manifest.json", manifest)
    fake_components(monkeypatch, tmp_path, stamp=instant("2026-10-20T02:00"))
    captured = backup.run_backup(tmp_path, reuse_recent=True, scheduled_interval=86400)
    assert captured != previous
    # A contending worker sees today's success under the same capture lock.
    assert backup.run_backup(tmp_path, reuse_recent=True, scheduled_interval=86400) == captured
