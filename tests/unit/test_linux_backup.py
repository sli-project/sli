from __future__ import annotations

import base64
import json
import sys
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from deploy.linux import backup
from deploy.linux import backup_restore_check as drill
from tests.unit.linux_operation_process import completed
from tests.unit.test_linux_helper_runtime_root import runtime_tree  # noqa: F401 -- trusted synthetic helper root

# The backup service runs only in the Linux container (flock, POSIX modes, atomic renames).
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only backup service")

ROOT = Path(__file__).resolve().parents[2]
STAMP = datetime(2026, 10, 6, 1, 0, tzinfo=timezone.utc)
COUNTS = dict.fromkeys(backup.KEY_TABLES, 3)


def successful(root, stamp):
    path = root / stamp
    (path / "postgres").mkdir(parents=True)
    (path / "postgres/toc.dat").write_bytes(b"fake")
    backup.write_json(path / "manifest.json", {
        "status": "success", "backup_id": stamp, "migration_ledger_max_version": 2,
        "components": {"postgres": {"row_counts": COUNTS}, "history": {}, "warm": {}},
    })
    return path


@pytest.mark.parametrize("retention", [1, 2, 7])
def test_retention_keeps_newest_success_and_ignores_foreign_partial_and_invalid(tmp_path, retention):
    paths = [successful(tmp_path, f"2026100{day}T010000.000000Z") for day in range(1, 5)]
    unknown = tmp_path / "operator-files"
    unknown.mkdir()
    partial = tmp_path / ".20261005T010000.000000Z.partial"
    partial.mkdir()
    invalid = tmp_path / "20261005T010000.000000Z"
    invalid.mkdir()
    (invalid / "manifest.json").write_text("invalid", encoding="utf-8")
    backup.prune(tmp_path, retention, paths[-1])
    assert backup.successful_backups(tmp_path) == paths[-retention:]
    assert unknown.is_dir() and partial.is_dir() and invalid.is_dir()


def test_pruning_requires_new_success_and_preserves_newest_on_clock_rollback(tmp_path):
    older = successful(tmp_path, "20261001T010000.000000Z")
    newer = successful(tmp_path, "20261002T010000.000000Z")
    backup.prune(tmp_path, 1, tmp_path / "missing")
    assert older.exists() and newer.exists()
    backup.prune(tmp_path, 1, older)
    assert older.exists() and newer.exists()
    with pytest.raises(ValueError):
        backup.prune(tmp_path, 0, newer)


def test_retention_removes_only_stale_partials_after_new_success(tmp_path):
    old = successful(tmp_path, "20261001T010000.000000Z")
    stale = tmp_path / ".20261002T010000.000000Z.partial"
    stale.mkdir()
    (stale / "history.zip").write_bytes(b"synthetic")
    backup.write_json(stale / "failure.json", {"status": "failed", "backup_id": stale.name[1:-8]})
    interrupted = tmp_path / ".20261003T010000.000000Z.partial"
    interrupted.mkdir()  # Process termination may leave no failure.json.
    future = tmp_path / ".20261006T010000.000000Z.partial"
    future.mkdir()
    foreign = tmp_path / ".operator.partial"
    foreign.mkdir()
    link = tmp_path / ".20261001T020000.000000Z.partial"
    link.symlink_to(old, target_is_directory=True)

    backup.prune(tmp_path, 7, tmp_path / "missing")
    assert stale.exists() and interrupted.exists()
    newest = successful(tmp_path, "20261005T010000.000000Z")
    backup.prune(tmp_path, 7, newest)
    assert not stale.exists() and not interrupted.exists()
    assert future.exists() and foreign.exists() and link.is_symlink()
    assert backup.successful_backups(tmp_path) == [old, newest]


def test_default_calendar_retention_keeps_weeklies_and_last_full_check(tmp_path, monkeypatch):
    monkeypatch.delenv('SLI_BACKUP_WEEKLY_RETENTION', raising=False)
    stamps = ['20260913', '20260920', '20260927', '20261004', '20261011', '20261018',
              '20261019', '20261020', '20261021', '20261022', '20261023', '20261024', '20261025']
    paths = [successful(tmp_path, stamp + 'T010000.000000Z') for stamp in stamps]
    newest = successful(tmp_path, '20261025T020000.000000Z')
    backup.write_json(tmp_path / 'last_full_restore_check.json', {
        'backup_id': paths[1].name, 'status': 'verified', 'verification': 'full',
    })
    backup.prune(tmp_path, 7, newest)
    # Four completed weeks, six prior daily sets, today's latest, and the pin.
    assert backup.successful_backups(tmp_path) == paths[1:-1] + [newest]
    assert not paths[0].exists() and not paths[-1].exists()


def fake_components(monkeypatch, root, *, failing=None, stamp=STAMP):
    monkeypatch.setattr(backup, 'capture_admission', lambda root: None)
    monkeypatch.setattr(backup, 'backup_output_admission', lambda root: None)
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(root))
    monkeypatch.setattr(backup.ClickHouse, "query", lambda *a: [{"path": "/var/lib/clickhouse/backups/"}])
    name = stamp.strftime("%Y%m%dT%H%M%S.%fZ")

    def pg(path):
        assert not (path.parent.parent / name).exists()
        if failing == "postgres":
            raise RuntimeError("synthetic private error")
        path.mkdir()
        (path / "toc.dat").write_bytes(b"dump")
        return {"size_bytes": 4, "duration_seconds": 0.1, "server_version": "18.6",
                "migration_ledger_max_version": 2, "row_counts": COUNTS}

    def ch(self, staging):
        assert staging.name == f".{name}.partial"
        assert not (staging.parent / name).exists()
        if failing == self.name:
            raise RuntimeError("synthetic private error")
        (staging / f"{self.name}.zip").write_bytes(b"zip")
        return {"size_bytes": 3, "duration_seconds": 0.2, "server_version": "25.8"}

    monkeypatch.setattr(backup, "utc_now", lambda: stamp)
    monkeypatch.setattr(backup, "dump_postgres", pg)
    monkeypatch.setattr(backup.ClickHouse, "backup", ch)


@pytest.mark.parametrize("components", [("postgres", "postgres"), ("unknown",), ("postgres", "unknown")])
def test_invalid_components_are_rejected_before_mutation(tmp_path, components):
    with pytest.raises(ValueError, match="linux_backup_invalid_components"):
        backup.run_backup(tmp_path, components=components)
    assert not list(tmp_path.iterdir())


def test_atomic_publication_manifest_and_retention(tmp_path, monkeypatch):
    monkeypatch.setenv("SLI_BACKUP_WEEKLY_RETENTION", "0")
    old = successful(tmp_path, "20261001T010000.000000Z")
    fake_components(monkeypatch, tmp_path)
    result = backup.run_backup(tmp_path, retention=1)
    assert result.name == "20261006T010000.000000Z"
    assert not old.exists()
    assert not list(tmp_path.glob("*.partial"))
    manifest = json.loads((result / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "success"
    assert manifest["backup_id"] == result.name
    assert manifest["size_bytes"] == 10
    assert manifest["duration_seconds"] >= 0
    assert manifest["migration_ledger_max_version"] == 2
    assert set(manifest["components"]) == {"postgres", "history", "warm"}
    assert manifest["components"]["postgres"]["row_counts"] == COUNTS
    assert manifest["format_version"] == 3
    assert manifest["consistency_point"]["writers_fenced"] is False
    assert manifest['consistency_point']['max_capture_skew_seconds'] >= manifest['duration_seconds']
    assert all(item["server_version"] for item in manifest["components"].values())


@pytest.mark.parametrize("denials", [1, 3])
def test_publication_retries_permission_denied_before_pruning(tmp_path, monkeypatch, denials):
    monkeypatch.setenv("SLI_BACKUP_WEEKLY_RETENTION", "0")
    old = successful(tmp_path, "20261001T010000.000000Z")
    fake_components(monkeypatch, tmp_path)
    rename = Path.rename
    attempts, delays = [], []

    def flaky_rename(path, destination):
        assert old.exists()
        attempts.append(destination)
        if len(attempts) <= denials:
            raise PermissionError("synthetic")
        return rename(path, destination)

    monkeypatch.setattr(Path, "rename", flaky_rename)
    monkeypatch.setattr(backup.time, "sleep", delays.append)
    result = backup.run_backup(tmp_path, retention=1)
    assert attempts == [result] * (denials + 1)
    assert len(delays) == denials and all(0 < delay <= 1 for delay in delays)
    assert delays == sorted(delays)
    assert backup.successful_backups(tmp_path) == [result]
    assert not list(tmp_path.glob(".*.partial"))
    assert not (tmp_path / "failure.json").exists()


@pytest.mark.parametrize("cleanup_blocked", [False, True])
def test_publication_permission_denied_exhausts_retries_and_records_cleanup(tmp_path, monkeypatch, cleanup_blocked):
    old = successful(tmp_path, "20261001T010000.000000Z")
    fake_components(monkeypatch, tmp_path)
    attempts, delays = [], []
    rename = Path.rename
    rmtree = backup.operation_wait.remove_tree

    def denied_rename(path, destination):
        attempts.append(destination)
        raise PermissionError("synthetic private error")

    def cleanup(path):
        if cleanup_blocked:
            raise PermissionError("synthetic private error")
        rmtree(path)

    monkeypatch.setattr(Path, "rename", denied_rename)
    monkeypatch.setattr(backup.time, "sleep", delays.append)
    monkeypatch.setattr(backup.operation_wait, "remove_tree", cleanup)
    with pytest.raises(PermissionError):
        backup.run_backup(tmp_path, retention=1)
    assert len(attempts) == 4 and len(delays) == 3
    assert backup.successful_backups(tmp_path) == [old]
    assert not (tmp_path / "20261006T010000.000000Z").exists()
    failure = json.loads((tmp_path / "failure.json").read_text())
    assert failure == {
        "status": "failed", "backup_id": "20261006T010000.000000Z",
        "error_code": "linux_backup_os_error", "step": "publication",
        "cleanup": "pending" if cleanup_blocked else "completed",
    }
    partial = tmp_path / ".20261006T010000.000000Z.partial"
    assert partial.exists() is cleanup_blocked
    if cleanup_blocked:
        assert json.loads((partial / "failure.json").read_text()) == failure
        monkeypatch.setattr(Path, "rename", rename)
        monkeypatch.setattr(backup.operation_wait, "remove_tree", rmtree)
        fake_components(monkeypatch, tmp_path, stamp=STAMP + timedelta(seconds=1))
        result = backup.run_backup(tmp_path, retention=7)
        assert old.exists() and result.exists()
        assert not partial.exists()


def test_publication_does_not_retry_other_filesystem_errors(tmp_path, monkeypatch):
    fake_components(monkeypatch, tmp_path)

    def rename(path, destination):
        raise FileExistsError("synthetic")

    monkeypatch.setattr(Path, "rename", rename)
    monkeypatch.setattr(backup.time, "sleep", lambda *a: pytest.fail("must not retry"))
    with pytest.raises(FileExistsError):
        backup.run_backup(tmp_path)
    assert not backup.successful_backups(tmp_path)


@pytest.mark.parametrize("failing", ["postgres", "history", "warm"])
def test_failure_keeps_all_old_backups_and_never_publishes(tmp_path, monkeypatch, failing):
    old = [successful(tmp_path, f"2026100{day}T010000.000000Z") for day in (1, 2)]
    fake_components(monkeypatch, tmp_path, failing=failing)
    with pytest.raises(RuntimeError):
        backup.run_backup(tmp_path, retention=1)
    assert backup.successful_backups(tmp_path) == old
    partial = tmp_path / ".20261006T010000.000000Z.partial"
    assert json.loads((partial / "failure.json").read_text()) == {
        "status": "failed", "backup_id": "20261006T010000.000000Z",
        "error_code": "linux_backup_unexpected_error", "step": failing,
    }
    assert not (tmp_path / "20261006T010000.000000Z").exists()


def test_failed_run_keeps_staging_until_next_success_then_retention_reclaims_it(tmp_path, monkeypatch):
    old = successful(tmp_path, "20261001T010000.000000Z")
    fake_components(monkeypatch, tmp_path, failing="warm")
    with pytest.raises(RuntimeError):
        backup.run_backup(tmp_path, retention=7)
    stale = tmp_path / ".20261006T010000.000000Z.partial"
    assert (stale / "history.zip").exists()
    fake_components(monkeypatch, tmp_path, stamp=STAMP + timedelta(seconds=1))
    result = backup.run_backup(tmp_path, retention=7)
    assert old.exists() and result.exists()
    assert (result / "history.zip").exists() and (result / "warm.zip").exists()
    assert not stale.exists()


def test_consistency_window_overrun_does_not_publish_or_prune(tmp_path, monkeypatch):
    old = successful(tmp_path, "20261001T010000.000000Z")
    fake_components(monkeypatch, tmp_path)
    import itertools
    times = itertools.chain([0], itertools.repeat(backup.TIMEOUT + 1))
    monkeypatch.setattr(backup.time, "monotonic", lambda: next(times))
    with pytest.raises(RuntimeError, match='linux_backup_consistency_window_exceeded'):
        backup.run_backup(tmp_path, retention=1)
    assert old.exists()
    assert not (tmp_path / '20261006T010000.000000Z').exists()


def test_fenced_capture_ignores_consistency_window(tmp_path, monkeypatch):
    fake_components(monkeypatch, tmp_path)
    import itertools
    times = itertools.chain([0], itertools.repeat(backup.TIMEOUT + 1))
    monkeypatch.setattr(backup.time, 'monotonic', lambda: next(times))
    path = backup.run_backup(tmp_path, retention=1, writers_fenced=True)
    point = json.loads((path / 'manifest.json').read_text())['consistency_point']
    assert point['writers_fenced'] and point['mode'] == 'fenced'


def secret_file(tmp_path, monkeypatch, setting="SLI_PG_ADMIN_PASSWORD"):
    path = tmp_path / setting
    path.write_text("synthetic:password\\value\n", encoding="utf-8")
    monkeypatch.delenv(setting, raising=False)
    monkeypatch.setenv(setting + "_FILE", str(path))
    return path


def test_file_only_password_private_escaped_passfile_and_cleanup(tmp_path, monkeypatch):
    secret_file(tmp_path, monkeypatch)
    with backup.pg_passfile() as path:
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.read_text() == "postgres:5432:*:postgres:synthetic\\:password\\\\value\n"
    assert not path.exists()
    monkeypatch.setenv("SLI_PG_ADMIN_PASSWORD", "synthetic-inline")
    with pytest.raises(ValueError, match="inline_secret_forbidden"):
        backup.read_secret("SLI_PG_ADMIN_PASSWORD")


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.usefixtures("runtime_tree")
def test_dump_counts_and_ledger_share_exported_snapshot(tmp_path, monkeypatch, native):
    monkeypatch.setattr(backup.operation_wait, 'history_path', lambda: tmp_path / '.status/summary.json')
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native" if native else "docker")
    host, port, user = ("127.0.0.1", 5543, "synthetic_admin") if native else ("postgres", 5432, "postgres")
    monkeypatch.setenv("SLI_PG_HOST", host)
    monkeypatch.setenv("SLI_PG_PORT", str(port))
    monkeypatch.setenv("SLI_PG_ADMIN_USER", user)
    secret_file(tmp_path, monkeypatch)
    queries, commands = [], []

    class Connection:
        def execute(self, statement):
            query = statement if isinstance(statement, str) else statement.as_string()
            queries.append(query)
            if "clock_timestamp" in query:
                return SimpleNamespace(fetchone=lambda: (STAMP.isoformat(), "0/123", "3:5:"))
            value = "fake-snapshot" if "pg_export_snapshot" in query else (
                "18.6" if "server_version" in query else 3)
            return SimpleNamespace(fetchone=lambda: (value,))

    monkeypatch.setattr(backup, "pg_connect", lambda passfile: nullcontext(Connection()))

    def run(command, **kwargs):
        commands.append((command, kwargs))
        assert command[:8] == ["ionice", "-c", "2", "-n", "7", "nice", "-n", "10"]
        assert {f"--host={host}", f"--port={port}", f"--username={user}"} <= set(command)
        dump = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--file=")))
        if command[8] == "pg_dumpall":
            dump.write_text("CREATE ROLE synthetic_role;\n")
        else:
            dump.mkdir()
            (dump / "toc.dat").write_bytes(b"fake")
        passfile = Path(kwargs["env"]["PGPASSFILE"])
        if native:
            assert passfile.is_relative_to(backup.helper_temporary_root())
        assert passfile.read_text().startswith(f"{host}:{port}:*:{user}:")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(backup.subprocess, "run", run)
    monkeypatch.setattr(backup.subprocess, 'Popen', lambda *a, **kw: completed(run(*a, **kw)))
    monkeypatch.setenv("PGPASSWORD", "synthetic-inherited")
    manifest = backup.dump_postgres(tmp_path / "dump")
    assert queries[:2] == ["SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY", "SELECT pg_export_snapshot()"]
    assert manifest["row_counts"] == COUNTS
    assert manifest["migration_ledger_max_version"] == 3
    assert manifest["database_size_bytes"] == 3
    assert manifest["consistency_point"] == {
        "snapshot_at_utc": STAMP.isoformat(), "wal_lsn": "0/123", "xact_snapshot": "3:5:",
        "max_event_db_id": 3,
    }
    roles_command, roles_options = commands[0]
    assert roles_command[8] == "pg_dumpall"
    assert {"--roles-only", "--no-role-passwords", "--no-password"} <= set(roles_command)
    assert "PGPASSWORD" not in roles_options["env"]
    assert manifest["roles_file"] == "roles.sql" and manifest["role_passwords"] is False
    assert (tmp_path / "roles.sql").is_file()
    command, kwargs = commands[1]
    assert {"--jobs=2", "--compress=gzip:3", "--format=directory", "--snapshot=fake-snapshot"}.issubset(command)
    assert "PGPASSWORD" not in kwargs["env"]
    assert 'statement_timeout=21600000' in kwargs['env']['PGOPTIONS']
    assert kwargs["stdout"] == backup.subprocess.DEVNULL
    assert kwargs["stderr"].closed  # Private tool spool is closed, never inherited stderr.


@pytest.mark.parametrize("status", ["BACKUP_CREATED", "BACKUP_FAILED", "CREATING_BACKUP"])
def test_clickhouse_sql_disk_backups_quote_names_and_require_completion(tmp_path, monkeypatch, status):
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(tmp_path.parent))
    statements = []
    target = backup.ClickHouse("history", "clickhouse", "test_user", "TEST_PASSWORD")

    def query(self, statement):
        statements.append(statement)
        if "system.disks" in statement:
            return [{"path": "/var/lib/clickhouse/backups/"}]
        if statement.startswith("SELECT version"):
            return [{"version": "25.8"}]
        if statement.startswith("SELECT name"):
            return [{"name": "test`db"}]
        (tmp_path / "history.zip").write_bytes(b"zip")
        return [{"status": status}]

    monkeypatch.setattr(backup.ClickHouse, "query", query)
    monkeypatch.setattr(backup.ClickHouse, "statistics", lambda *a: {})
    if status == "BACKUP_CREATED":
        assert target.backup(tmp_path)["size_bytes"] == 3
    else:
        with pytest.raises(RuntimeError, match="incomplete"):
            target.backup(tmp_path)
    assert "DATABASE `test\\`db`" in statements[-1]
    assert f"Disk('backups', 'scheduled/{tmp_path.name}/history.zip')" in statements[-1]
    assert "max_threads=2" in statements[-1]
    assert "os_thread_priority=10" in statements[-1]
    assert "max_local_read_bandwidth=16777216" in statements[-1]
    assert "max_local_write_bandwidth=16777216" in statements[-1]


@pytest.mark.parametrize("http_status", [200, 403])
def test_clickhouse_http_secret_headers_and_redacted_failure(tmp_path, monkeypatch, http_status):
    secret_file(tmp_path, monkeypatch, "TEST_PASSWORD")
    calls = []
    response = SimpleNamespace(status=http_status, read=lambda limit: b'{"data": [{"version": "25.8"}]}',
                               getheader=lambda *args: "")
    connection = SimpleNamespace(request=lambda *a, **kw: calls.append((a, kw)), getresponse=lambda: response,
                                 close=lambda: calls.append("closed"))
    monkeypatch.setattr(backup.http.client, "HTTPConnection", lambda host, port, **kw: connection)
    target = backup.ClickHouse("warm", "warm-tier", "test_user", "TEST_PASSWORD")
    if http_status == 200:
        assert target.query("SELECT version()") == [{"version": "25.8"}]
    else:
        with pytest.raises(RuntimeError, match="^linux_backup_clickhouse_failed$"):
            target.query("SELECT version()")
    args, kwargs = calls[0]
    assert args == ("POST", "/?default_format=JSON")
    authorization = kwargs["headers"]["Authorization"]
    assert authorization.startswith("Basic ")
    assert base64.b64decode(authorization.removeprefix("Basic ")).decode("utf-8") == "test_user:synthetic:password\\value"
    assert calls[-1] == "closed"


@pytest.mark.parametrize("age,status,pid,expected", [
    (0, "waiting", 1, True), (0, "running", 1, True), (0, "success", 1, False),
    (91, "success", 1, False), (-1, "success", 1, False),
    (0, "failed", 1, False), (0, "success", 2, False),
])
def test_heartbeat_health(tmp_path, monkeypatch, age, status, pid, expected):
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP)
    monkeypatch.setattr(backup.os, "getpid", lambda: pid)
    backup.heartbeat(tmp_path, status, None)
    beat = json.loads((tmp_path / "heartbeat.json").read_text())
    beat["heartbeat_at_utc"] = (STAMP - timedelta(seconds=age)).isoformat()
    backup.write_json(tmp_path / "heartbeat.json", beat)
    assert backup.healthy(tmp_path) is expected


@pytest.mark.parametrize("failure", [None, "restore", "counts", "ledger"])
def test_restore_uses_private_cluster_without_create_drop_on_source(tmp_path, monkeypatch, failure):
    newest = successful(tmp_path, "20261002T010000.000000Z")
    secret_file(tmp_path, monkeypatch)
    from tests.unit.test_linux_backup_capacity import prepare_capacity
    admin = prepare_capacity(tmp_path, newest, monkeypatch)
    # Capacity setup seeds 25 GiB; override afterwards to test exact size forwarding.
    manifest = json.loads((newest / 'manifest.json').read_text())
    manifest['components']['postgres']['database_size_bytes'] = 123
    backup.write_json(newest / 'manifest.json', manifest)
    calls = []
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **kw: nullcontext(admin))
    def restore(root, archive, counts, ledger, database_size, backup_root):
        calls.append(archive)
        assert root == tmp_path / '.restore-check' and counts == COUNTS and ledger == 2
        assert database_size == 123
        assert backup_root == tmp_path
        if failure:
            raise RuntimeError('synthetic restore failure')
    monkeypatch.setattr(drill.restore_sandbox, 'restore', restore)
    if failure:
        with pytest.raises(RuntimeError):
            drill.restore_check(tmp_path)
    else:
        drill.restore_check(tmp_path)
    assert calls == [newest / 'postgres']
    assert not any(q.startswith(('CREATE', 'DROP', 'COMMENT', 'REVOKE')) for q in admin.queries)
    assert newest.exists()


def test_restore_refuses_missing_backup_without_connecting(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "pg_connect", lambda *a, **kw: pytest.fail("must not connect"))
    with pytest.raises(RuntimeError, match="no_dump"):
        drill.restore_check(tmp_path)


def test_clis_redact_exceptions(tmp_path, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic private database error")

    monkeypatch.setenv("SLI_BACKUP_ROOT", str(tmp_path))
    monkeypatch.setattr(backup, "run_backup", fail)
    monkeypatch.setattr(drill, "restore_check", fail)
    assert backup.main(["--once"]) == 1
    assert drill.main() == 1
    assert capsys.readouterr().err == (
        "linux_backup_failed\n"
        "linux_backup_diagnostic error_code=linux_backup_unexpected_error step=once\n"
        "linux_backup_restore_check_failed\n")


@pytest.mark.parametrize("first_fails", [False, True])
def test_scheduler_delays_first_run_retries_after_interval_and_beats_while_running(tmp_path, monkeypatch, first_fails):
    clock, starts, beats = [0], [], []

    class EndLoop(Exception):
        pass

    class Future:
        def done(self):
            return True

        def result(self):
            if first_fails and len(starts) == 1:
                raise RuntimeError("synthetic private error")
            return Path("20261006T010000.000000Z")

    class Executor:
        def __init__(self, max_workers):
            assert max_workers == 1

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def submit(self, function, root, retention, *, reuse_recent, scheduled_interval):
            assert function is backup.scheduled_backup and root == tmp_path and retention == 7
            assert reuse_recent is True
            assert scheduled_interval == 90
            starts.append(clock[0])
            return Future()

    def sleep(seconds):
        assert seconds == 30
        clock[0] += seconds
        if clock[0] > 210:
            raise EndLoop

    monkeypatch.setattr(backup.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP + timedelta(seconds=clock[0]))
    monkeypatch.setattr(backup, "next_backup_time", lambda earliest, *args: earliest)
    monkeypatch.setattr(backup.time, "sleep", sleep)
    monkeypatch.setattr(backup, "ThreadPoolExecutor", Executor)
    monkeypatch.setattr(backup, "heartbeat", lambda root, status, last, result, **kw:
                        beats.append((clock[0], status, result)))
    with pytest.raises(EndLoop):
        backup.serve(tmp_path, interval=90, delay=60, retention=7)
    assert starts == [60, 180]
    assert beats[:3] == [(0, "waiting", None), (30, "waiting", None), (60, "running", None)]
    assert beats[3][1:] == (("failed", "failed") if first_fails else ("success", "success"))
    assert beats[-2][1:] == ("running", "failed" if first_fails else "success")
    assert beats[-1][1:] == ("success", "success")


def test_running_retry_remains_unhealthy_after_failed_attempt(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP)
    monkeypatch.setattr(backup.os, "getpid", lambda: 1)
    backup.heartbeat(tmp_path, "running", None, "failed")
    assert not backup.healthy(tmp_path)


def test_pg_tool_failure_is_redacted(tmp_path, monkeypatch):
    monkeypatch.setattr(backup.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1))
    with pytest.raises(RuntimeError, match="^linux_backup_pg_tool_failed$"):
        backup.pg_tool(["pg_dump"], tmp_path / "pgpass")


def test_administrator_guide_passes_sanitary_gate(tmp_path):
    from scripts.maintenance.github_sanitary_check import scan

    relative = Path("docs/ADMIN_GUIDE.md")
    document = tmp_path / relative
    document.parent.mkdir()
    document.write_bytes((ROOT / relative).read_bytes())

    assert scan(tmp_path)["findings"] == []


@pytest.mark.legacy
def test_compose_backup_permissions_secrets_storage_and_limits():
    compose = yaml.safe_load((ROOT / "deploy/linux/docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["backup"]
    assert service["entrypoint"] == ["python", "-m", "deploy.linux.backup"]
    assert service["command"] == []
    assert service["read_only"] and service["cap_drop"] == ["ALL"]
    assert service["volumes"] == ["${SLI_BACKUP_DIR:?Set absolute backup directory}:/backups",
                                  "${SLI_RESTORE_CHECK_DIR:-${SLI_BACKUP_DIR}/.restore-check}:/restore-check",
                                  "sli-data:/var/lib/sli"]
    assert service["environment"]["SLI_BACKUP_FILES_ROOT"] == "/var/lib/sli"
    assert set(service["secrets"]) == {"postgres_password", "history_password", "warm_password"}
    assert service["environment"]["SLI_BACKUP_RETENTION"] == "${SLI_BACKUP_RETENTION:-7}"
    assert service["environment"]["SLI_BACKUP_INTERVAL_SECONDS"] == "${SLI_BACKUP_INTERVAL_SECONDS:-86400}"
    assert service["environment"]["SLI_BACKUP_START_DELAY_SECONDS"] == "${SLI_BACKUP_START_DELAY_SECONDS:-300}"
    assert service["environment"]["SLI_BACKUP_TIME"] == "${SLI_BACKUP_TIME:-02:00}"
    assert service["environment"]["TZ"] == "${TZ:-UTC}"
    dockerfile = (ROOT / "deploy/linux/Dockerfile").read_text()
    # T086: the server (initdb/pg_ctl for the restore sandbox) is its own image layer, so no
    # layer exceeds the 128 MiB update-package limit.
    assert "postgresql-client-18 util-linux" in dockerfile
    assert "install -y --no-install-recommends postgresql-18 " in dockerfile
    assert service["cpus"] == "2.0" and service["mem_limit"] == "1g"
    assert service["healthcheck"]["test"][-1] == "--healthcheck"
    assert "docker.sock" not in json.dumps(compose)
    for name in ("clickhouse", "warm-tier"):
        ch = compose["services"][name]
        assert ch["group_add"] == ["10001"]
        assert ch["environment"]["CLICKHOUSE_GID"] == "10001"
        assert ch["environment"]["CLICKHOUSE_DO_NOT_CHOWN"] == "1"
        assert "${SLI_BACKUP_DIR:?Set absolute backup directory}:/var/lib/clickhouse/backups/scheduled" in ch["volumes"]
        assert "../../config/stage7_clickhouse_backup.xml:/etc/clickhouse-server/config.d/012_history_backup.xml:ro" in ch["volumes"]
        assert "../../config/clickhouse/012_backup_limits.xml:/etc/clickhouse-server/config.d/013_backup_limits.xml:ro" in ch["volumes"]
    allowed = (ROOT / "deploy/linux/Dockerfile.dockerignore").read_text()
    assert "!deploy/linux/backup.py" in allowed and "!deploy/linux/backup_restore_check.py" in allowed


def test_graceful_stop_drains_one_scheduled_cycle_without_another_submission(tmp_path, monkeypatch):
    from deploy.linux.sli_core import shutdown

    submissions, drained = [], []
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP)
    monkeypatch.setattr(backup, "latest_full_backup", lambda root: None)
    monkeypatch.setattr(backup, "next_backup_time", lambda earliest, *a: earliest)
    monkeypatch.setattr(shutdown, "requested", lambda: bool(submissions))
    monkeypatch.setattr(shutdown, "wait", lambda *a, **kw: None)

    class Executor:
        def __init__(self, max_workers):
            assert max_workers == 1

        def __enter__(self):
            return self

        def submit(self, function, *args, **kwargs):
            submissions.append((function, args, kwargs))
            return SimpleNamespace(done=lambda: False)

        def __exit__(self, *args):
            # Model ThreadPoolExecutor's wait=True context exit. No real capture.
            assert len(submissions) == 1
            assert submissions[0][0] is backup.scheduled_backup
            drained.append(True)

    monkeypatch.setattr(backup, "ThreadPoolExecutor", Executor)
    backup.serve(tmp_path, interval=86400, delay=0, retention=7)
    assert drained == [True]
    assert len(submissions) == 1
    assert json.loads((tmp_path / "heartbeat.json").read_bytes())["status"] == "running"
