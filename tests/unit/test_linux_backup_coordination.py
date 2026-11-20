"""Backup contention, safe diagnostics and shared service state; no database connections."""
from __future__ import annotations

import errno
import json
import multiprocessing
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from types import SimpleNamespace

import pytest

from deploy.linux import backup, backup_restore_check as drill
from tests.unit.test_linux_backup import STAMP, fake_components

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only backup service")


def read(path):
    return json.loads(path.read_text())


def test_contending_process_waits_then_reuses_first_capture(tmp_path, monkeypatch):
    fake_components(monkeypatch, tmp_path)
    context = multiprocessing.get_context("fork")
    entered, release, trying, finished = (context.Event() for _ in range(4))
    outputs = context.Queue()
    dump = backup.dump_postgres

    def blocked_dump(path):
        entered.set()
        assert release.wait(5)
        return dump(path)

    monkeypatch.setattr(backup, "dump_postgres", blocked_dump)

    def run(waiter):
        if waiter:
            # An independent descriptor must observe the first process's lock.
            import fcntl
            with (tmp_path / ".backup.lock").open("a") as handle:
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    trying.set()
                else:
                    raise AssertionError("capture lock was not held")
        try:
            outputs.put(("success", backup.run_backup(tmp_path, reuse_recent=True).name))
        except Exception:
            outputs.put(("failed", None))
        finally:
            if waiter:
                finished.set()

    first = context.Process(target=run, args=(False,))
    second = context.Process(target=run, args=(True,))
    first.start()
    try:
        assert entered.wait(5)
        second.start()
        assert trying.wait(5)
        assert not finished.is_set()
        release.set()
        first.join(5)
        second.join(5)
        assert first.exitcode == second.exitcode == 0
        results = [outputs.get(timeout=2), outputs.get(timeout=2)]
        assert results == [("success", "20261006T010000.000000Z")] * 2
        assert len(backup.successful_backups(tmp_path)) == 1
        assert not list(tmp_path.glob(".*.partial"))
    finally:
        release.set()
        for process in (first, second):
            if process.pid is not None:
                if process.is_alive():
                    process.terminate()
                process.join(5)


def test_heartbeat_remains_live_while_capture_lock_is_held(tmp_path, monkeypatch):
    fake_components(monkeypatch, tmp_path)
    monkeypatch.setattr(backup.os, "getpid", lambda: 1)
    with backup.backup_lock(tmp_path):
        with ThreadPoolExecutor(max_workers=1) as executor:
            executor.submit(backup.heartbeat, tmp_path, "running", None).result(timeout=2)
    assert backup.healthy(tmp_path)


@pytest.mark.parametrize("age,reused", [(0, True), (1800, True), (1801, False), (-1, False)])
def test_reuse_age_boundary(tmp_path, monkeypatch, age, reused):
    fake_components(monkeypatch, tmp_path)
    previous = backup.run_backup(tmp_path)
    fake_components(monkeypatch, tmp_path, stamp=STAMP + timedelta(seconds=age))
    result = backup.run_backup(tmp_path, reuse_recent=True)
    assert (result == previous) is reused


@pytest.mark.parametrize("defect", ["missing_archive", "symlink_archive", "components", "timestamp", "naive", "failed"])
def test_invalid_or_incomplete_success_is_never_reused(tmp_path, monkeypatch, defect):
    fake_components(monkeypatch, tmp_path)
    previous = backup.run_backup(tmp_path)
    manifest = read(previous / "manifest.json")
    if defect == "missing_archive":
        (previous / "warm.zip").unlink()
    elif defect == "symlink_archive":
        (previous / "warm.zip").unlink()
        (previous / "warm.zip").symlink_to(previous / "history.zip")
    elif defect == "components":
        manifest["components"].pop("warm")
    elif defect == "timestamp":
        manifest["completed_at_utc"] = "invalid"
    elif defect == "naive":
        manifest["completed_at_utc"] = STAMP.replace(tzinfo=None).isoformat()
    else:
        manifest["status"] = "failed"
    backup.write_json(previous / "manifest.json", manifest)
    fake_components(monkeypatch, tmp_path, stamp=STAMP + timedelta(seconds=1))
    assert backup.run_backup(tmp_path, reuse_recent=True) != previous


def test_once_repairs_capture_but_requires_full_cycle_for_service_health(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(drill, "integrity_check", lambda *a: {"status": "verified"})
    fake_components(monkeypatch, tmp_path, failing="warm")
    monkeypatch.setattr(backup.os, "getpid", lambda: 1)
    with pytest.raises(RuntimeError):
        backup.run_backup(tmp_path)
    backup.heartbeat(tmp_path, "failed", None, "failed")
    original = read(tmp_path / "heartbeat.json")
    assert not backup.healthy(tmp_path)
    fake_components(monkeypatch, tmp_path, stamp=STAMP + timedelta(seconds=1))
    monkeypatch.setattr(backup.os, "getpid", lambda: 42)
    assert backup.main(["--once"]) == 0
    assert capsys.readouterr().out == (
        "Копия создана. Предыдущий сбой или незавершённая проверка восстановления не устранены / "
        "Backup created. Previous failure or incomplete restore check remains unresolved "
        "[restore_check_unresolved]\n"
        "linux_backup_succeeded\n"
    )
    beat = read(tmp_path / "heartbeat.json")
    assert beat["last_result"] == "failed" and beat["status"] == "failed"
    assert beat["process_pid"] == original["process_pid"] == 1
    assert beat["heartbeat_at_utc"] == original["heartbeat_at_utc"]
    assert beat["last_success"] == "20261006T010001.000000Z"
    assert not backup.healthy(tmp_path)
    monkeypatch.setattr(backup.os, "getpid", lambda: 1)
    backup.heartbeat(tmp_path, "failed", None, "failed")  # Scheduler still remembers the older failure.
    assert not backup.healthy(tmp_path)
    assert read(tmp_path / "heartbeat.json")["last_result"] == "failed"
    assert backup.read_result(tmp_path)["last_result"] == "success"


def test_once_does_not_renew_stopped_service_liveness(tmp_path, monkeypatch):
    monkeypatch.setattr(drill, "integrity_check", lambda *a: {"status": "verified"})
    fake_components(monkeypatch, tmp_path)
    monkeypatch.setattr(backup.os, "getpid", lambda: 1)
    backup.heartbeat(tmp_path, "failed", None, "failed")
    fake_components(monkeypatch, tmp_path, stamp=STAMP + timedelta(seconds=91))
    monkeypatch.setattr(backup.os, "getpid", lambda: 42)
    assert backup.main(["--once"]) == 0
    assert read(tmp_path / "heartbeat.json")["last_result"] == "failed"
    assert backup.read_result(tmp_path)["last_result"] == "success"
    assert not backup.healthy(tmp_path)


def test_partial_once_cannot_repair_full_backup_health(tmp_path, monkeypatch):
    fake_components(monkeypatch, tmp_path, failing="warm")
    monkeypatch.setattr(backup.os, "getpid", lambda: 1)
    with pytest.raises(RuntimeError):
        backup.run_backup(tmp_path)
    backup.heartbeat(tmp_path, "failed", None, "failed")
    fake_components(monkeypatch, tmp_path, stamp=STAMP + timedelta(seconds=1))
    assert backup.main(["--once", "--component", "postgres"]) == 0
    assert read(tmp_path / "last_result.json")["last_result"] == "failed"
    assert not backup.healthy(tmp_path)


def test_fresh_full_backup_including_files_is_reused(tmp_path, monkeypatch):
    fake_components(monkeypatch, tmp_path)
    monkeypatch.setenv("SLI_BACKUP_FILES_ROOT", str(tmp_path.parent / "source"))
    copies = []

    def files(destination):
        copies.append(destination)
        destination.mkdir()
        (destination / "fixture").write_bytes(b"synthetic")
        return {"size_bytes": 9, "format": "directory"}

    monkeypatch.setattr(backup, "backup_files", files)
    previous = backup.run_backup(tmp_path)
    assert backup.run_backup(tmp_path, reuse_recent=True) == previous
    assert len(copies) == 1
    (previous / "files").rename(previous / "removed-files")
    fake_components(monkeypatch, tmp_path, stamp=STAMP + timedelta(seconds=1))
    assert backup.run_backup(tmp_path, reuse_recent=True) != previous
    assert len(copies) == 2


def test_new_failure_overrides_older_success(tmp_path, monkeypatch):
    fake_components(monkeypatch, tmp_path)
    previous = backup.run_backup(tmp_path)
    fake_components(monkeypatch, tmp_path, stamp=STAMP + timedelta(seconds=1), failing="history")
    with pytest.raises(RuntimeError):
        backup.run_backup(tmp_path)
    monkeypatch.setattr(backup.os, "getpid", lambda: 1)
    backup.heartbeat(tmp_path, "success", previous.name, "success")
    assert not backup.healthy(tmp_path)
    assert read(tmp_path / "heartbeat.json")["last_success"] == previous.name


def test_write_json_concurrent_publish_uses_unique_temporaries(tmp_path):
    path = tmp_path / "heartbeat.json"
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda index: backup.write_json(path, {"index": index}), range(40)))
    assert read(path)["index"] in range(40)
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("step", ["postgres", "history", "warm", "files"])
def test_once_records_step_and_machine_errno_without_private_text(tmp_path, monkeypatch, capsys, step):
    fake_components(monkeypatch, tmp_path)

    def fail(*args):
        raise PermissionError(errno.EACCES, "PRIVATE_SENTINEL")

    if step == "postgres":
        monkeypatch.setattr(backup, "dump_postgres", fail)
    elif step == "files":
        monkeypatch.setenv("SLI_BACKUP_FILES_ROOT", str(tmp_path.parent / "source"))
        monkeypatch.setattr(backup, "backup_files", fail)
    else:
        original = backup.ClickHouse.backup
        monkeypatch.setattr(backup.ClickHouse, "backup", lambda target, staging:
                            fail() if target.name == step else original(target, staging))
    assert backup.main(["--once"]) == 1
    output = capsys.readouterr().err
    assert f"error_code=linux_backup_os_error step={step} errno=13" in output
    failure = read(tmp_path / "failure.json")
    assert failure["step"] == step and failure["errno"] == 13
    assert "PRIVATE_SENTINEL" not in output + json.dumps(failure)


def test_preflight_failure_records_code_without_partial_or_dump(tmp_path, monkeypatch, capsys):
    fake_components(monkeypatch, tmp_path)
    monkeypatch.setattr(backup.ClickHouse, "query", lambda *args: [{"path": "/other"}])
    monkeypatch.setattr(backup, "dump_postgres", lambda *args: pytest.fail("dump must not start"))
    assert backup.main(["--once"]) == 1
    assert "error_code=linux_backup_clickhouse_disk_path_mismatch step=preflight_history" in capsys.readouterr().err
    assert read(tmp_path / "failure.json")["step"] == "preflight_history"
    assert not list(tmp_path.glob(".*.partial"))


@pytest.mark.parametrize("header", ["598", "598 PRIVATE_SENTINEL"])
def test_clickhouse_numeric_code_and_status_without_body_or_credentials(monkeypatch, header):
    response = SimpleNamespace(status=500, getheader=lambda *args: header,
                               read=lambda *args: pytest.fail("error body must not be read"))
    connection = SimpleNamespace(request=lambda *args, **kwargs: None, getresponse=lambda: response,
                                 close=lambda: None)
    monkeypatch.setattr(backup.http.client, "HTTPConnection", lambda *args, **kwargs: connection)
    monkeypatch.setattr(backup, "read_secret", lambda *args: "PRIVATE_SENTINEL")
    with pytest.raises(backup.BackupError) as caught:
        backup.clickhouse_targets()[0].query("SELECT version()")
    expected = {"error_code": "linux_backup_clickhouse_failed", "step": "history", "http_status": 500}
    if header == "598":
        expected["clickhouse_code"] = 598
    assert backup.failure_diagnostic(caught.value, "history") == expected


def test_receipt_write_failure_preserves_original_diagnostic(tmp_path, monkeypatch, capsys):
    fake_components(monkeypatch, tmp_path)

    def fail(*args):
        raise PermissionError(errno.EACCES, "PRIVATE_SENTINEL")

    def receipt(*args):
        raise OSError(errno.ENOSPC, "PRIVATE_SENTINEL")

    monkeypatch.setattr(backup, "dump_postgres", fail)
    monkeypatch.setattr(backup, "write_json", receipt)
    assert backup.main(["--once"]) == 1
    output = capsys.readouterr().err
    assert "error_code=linux_backup_os_error step=postgres errno=13" in output
    assert "PRIVATE_SENTINEL" not in output


def test_pg_tool_includes_exit_code_and_safe_unclassified_reason(monkeypatch, tmp_path):
    monkeypatch.setattr(backup.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=2))
    with pytest.raises(backup.BackupError) as caught:
        backup.pg_tool(["pg_dump"], tmp_path / "pgpass")
    assert backup.failure_diagnostic(caught.value, "postgres") == {
        "error_code": "linux_backup_pg_tool_failed", "step": "postgres", "returncode": 2,
        "pg_reason": "unclassified",
    }


def test_database_sqlstate_is_safe_and_message_is_discarded():
    error = backup.psycopg.errors.InsufficientPrivilege("PRIVATE_SENTINEL")
    assert backup.failure_diagnostic(error, "postgres") == {
        "error_code": "linux_backup_database_error", "step": "postgres", "sqlstate": "42501",
    }
