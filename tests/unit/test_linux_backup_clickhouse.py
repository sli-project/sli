# ruff: noqa: F811 -- imported pytest fixtures are intentionally named as parameters
from __future__ import annotations

import json
import sys
import zipfile
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup
from deploy.linux import backup_restore_check as drill
from tests.unit.test_linux_backup_capacity import (
    private_postgres,  # noqa: F401 -- shared fixture
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Linux-only backup service")

STATS = {"events": {"row_count": 3, "max_values": {"event_db_id": "7", "time_created_utc": "2026-10-06 00:00:00"}}}


def archive(path):
    with zipfile.ZipFile(path, "w") as handle:
        handle.writestr("data.bin", b"synthetic")


def target():
    return backup.ClickHouse("history", "clickhouse", "test_user", "TEST_PASSWORD")


def component(path):
    archive(path / "history.zip")
    return {"archive": "history.zip", "databases": ["test`db"], "tables": {"test`db": STATS}}


@pytest.fixture
def backup_set(tmp_path, monkeypatch):
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(tmp_path))
    path = tmp_path / "20261006T010000.000000Z"
    path.mkdir()
    return path


@pytest.mark.parametrize("name", ["history", "warm"])
def test_backup_records_live_counts_and_watermarks_without_opening_archive(tmp_path, monkeypatch, name):
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(tmp_path.parent))
    statements = []

    def query(self, statement):
        statements.append(statement)
        if "system.disks" in statement:
            return [{"path": "/var/lib/clickhouse/backups/"}]
        if statement.startswith("SELECT version"):
            return [{"version": "25.8"}]
        if "system.databases" in statement:
            return [{"name": "test`db"}]
        if "system.tables" in statement:
            assert "database='test`db'" in statement
            return [{"name": "events"}]
        if "system.columns" in statement:
            assert "database='test`db'" in statement
            return [{"name": "event_db_id", "type": "UInt64"},
                    {"name": "time_created_utc", "type": "DateTime64(6, 'UTC')"}]
        if "count()" in statement:
            assert "FROM `test\\`db`.`events`" in statement
            assert backup.CH_BACKUP_LIMITS in statement
            return [{"row_count": "3", "max_0": "7", "max_1": "2026-10-06 00:00:00"}]
        if statement.startswith("BACKUP"):
            archive(tmp_path / f"{name}.zip")
            return [{"status": "BACKUP_CREATED"}]
        pytest.fail("unexpected backup query")

    monkeypatch.setattr(backup.ClickHouse, "query", query)
    result = replace(target(), name=name).backup(tmp_path)
    assert result["table_names"] == {"test`db": ["events"]}
    assert result["live_tables"] == {"test`db": STATS}
    assert "tables" not in result
    assert result["snapshot_started_at_utc"] <= result["snapshot_completed_at_utc"]
    assert not any("ENGINE = Backup" in q or "sli_backup_manifest_" in q for q in statements)
    assert statements[-1].startswith("BACKUP")
    assert backup.CH_BACKUP_LIMITS in statements[-1]


def test_live_statistics_failure_never_publishes_backup(tmp_path, monkeypatch):
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(tmp_path))
    clock, statements = [0], []
    bounded = replace(target(), deadline=5)

    def query(self, statement):
        statements.append(statement)
        if "system.disks" in statement:
            return [{"path": "/var/lib/clickhouse/backups/"}]
        if 'sum(bytes_on_disk)' in statement and 'system.parts' in statement:
            return [{'size_bytes': 9}]
        if statement.startswith("SELECT version"):
            return [{"version": "25.8"}]
        if "system.databases" in statement:
            return [{"name": "test_db"}]
        if "system.tables" in statement:
            return [{"name": "events"}]
        if "system.columns" in statement:
            return [{"name": "event_db_id", "type": "UInt64"}]
        if "count()" in statement:
            clock[0] += 6
            assert self.deadline is not None and clock[0] > self.deadline
            raise RuntimeError("linux_backup_clickhouse_failed")
        if statement.startswith("BACKUP"):
            staging = next(tmp_path.glob(".*.partial"))
            archive(staging / f"{self.name}.zip")
            return [{"status": "BACKUP_CREATED"}]
        return []

    def pg(destination):
        destination.mkdir()
        (destination / "toc.dat").write_bytes(b"synthetic")
        return {"size_bytes": 9, "row_counts": dict.fromkeys(backup.KEY_TABLES, 3),
                "migration_ledger_max_version": 2}

    monkeypatch.setattr(backup.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(backup.ClickHouse, "query", query)
    monkeypatch.setattr(backup, "dump_postgres", pg)
    monkeypatch.setattr(backup, 'pg_passfile', lambda: nullcontext(Path('synthetic-passfile')))
    connection = SimpleNamespace(execute=lambda q: SimpleNamespace(fetchone=lambda: (9,)))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a: nullcontext(connection))
    monkeypatch.setattr(backup, "clickhouse_targets", lambda: (bounded, replace(bounded, name="warm")))
    with pytest.raises(RuntimeError, match="linux_backup_clickhouse_failed"):
        backup.run_backup(tmp_path)
    assert not backup.successful_backups(tmp_path)
    assert not any(q.startswith("BACKUP") or "ENGINE = Backup" in q for q in statements)
    partial = next(tmp_path.glob(".*.partial"))
    assert json.loads((partial / "failure.json").read_text())["status"] == "failed"


def test_archive_statistics_drops_disposable_database_on_read_failure(monkeypatch):
    statements = []
    monkeypatch.setattr(backup.ClickHouse, "query", lambda self, q: statements.append(q) or (
        [{"status": "RESTORED"}] if q.startswith("RESTORE") else []))

    def fail(*a):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(backup.ClickHouse, "statistics", fail)
    with pytest.raises(RuntimeError):
        drill.archive_statistics(target(), ["test_db"], "scheduled/test/history.zip")
    assert statements[0].startswith("RESTORE DATABASE `test_db` AS `sli_backup_manifest_")
    assert statements[-1].startswith("DROP DATABASE IF EXISTS `sli_backup_manifest_")


@pytest.mark.parametrize("failure", [None, "restore", "incomplete", "statistics", "cleanup"])
def test_deflated_native_archive_metrics_use_physical_restore_and_clean_every_database(
        tmp_path, monkeypatch, failure):
    archive_path = tmp_path / "history.zip"
    # Native BACKUP layout, ZIP compression used by ClickHouse.backup(); no live DB.
    metadata = "CREATE DATABASE fixture ENGINE = Atomic"
    table = "CREATE TABLE fixture.events (event_db_id UInt64) ENGINE = MergeTree ORDER BY event_db_id"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=3) as handle:
        handle.writestr(".backup", "<config><version>1</version></config>")
        handle.writestr("metadata/fixture.sql", metadata)
        handle.writestr("metadata/fixture/events.sql", table)
        handle.writestr("data/fixture/events/all_1_1_0/count.txt", "3\n")
        handle.writestr("metadata/empty.sql", "CREATE DATABASE empty ENGINE = Atomic")
    restored, statements = {}, []

    def query(self, statement):
        statements.append(statement)
        if "ENGINE = Backup" in statement:
            raise RuntimeError("CANNOT_SEEK_THROUGH_FILE")
        if statement.startswith("RESTORE"):
            import re

            renames = re.findall(r"DATABASE `([^`]+)` AS `([^`]+)`", statement)
            assert {name for name, _ in renames} == {"fixture", "empty"}
            assert "Disk('backups', 'scheduled/fixture/history.zip')" in statement
            with zipfile.ZipFile(archive_path) as handle:
                assert all(item.compress_type == zipfile.ZIP_DEFLATED for item in handle.infolist())
                assert handle.read("metadata/fixture/events.sql").decode() == table
                for source, destination in renames:
                    restored[destination] = ({"events": {"row_count": int(handle.read(
                        "data/fixture/events/all_1_1_0/count.txt")), "max_values": {}}}
                        if source == "fixture" else {})
            if failure == "restore":
                raise RuntimeError("synthetic_restore_failed")
            return [{"status": "RESTORE_FAILED" if failure == "incomplete" else "RESTORED"}]
        if statement.startswith("DROP"):
            destination = statement.split("`")[1]
            assert destination.startswith("sli_backup_manifest_")
            restored.pop(destination, None)
            if failure == "cleanup" and sum(q.startswith("DROP") for q in statements) == 1:
                raise RuntimeError("synthetic_cleanup_failed")
            return []
        pytest.fail("unexpected archive query")

    def statistics(self, database):
        if failure == "statistics":
            raise RuntimeError("synthetic_statistics_failed")
        return restored[database]

    monkeypatch.setattr(backup.ClickHouse, "query", query)
    monkeypatch.setattr(backup.ClickHouse, "statistics", statistics)
    if failure:
        with pytest.raises(RuntimeError):
            drill.archive_statistics(target(), ["fixture", "empty"], "scheduled/fixture/history.zip")
    else:
        assert drill.archive_statistics(target(), ["fixture", "empty"], "scheduled/fixture/history.zip") == {
            "fixture": {"events": {"row_count": 3, "max_values": {}}}, "empty": {},
        }
    assert len([q for q in statements if q.startswith("DROP")]) == 2
    assert not restored


def test_archive_scan_deadline_failure_uses_independent_cleanup_budget(monkeypatch):
    clock, calls = [0], []

    def query(self, statement):
        calls.append((statement, self.deadline, self.timeout))
        return [{"status": "RESTORED"}] if statement.startswith("RESTORE") else []

    def statistics(self, database):
        clock[0] = 6
        raise TimeoutError("linux_backup_clickhouse_deadline_exceeded")

    monkeypatch.setattr(backup.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(backup.ClickHouse, "query", query)
    monkeypatch.setattr(backup.ClickHouse, "statistics", statistics)
    with pytest.raises(TimeoutError, match="deadline_exceeded"):
        drill.archive_statistics(replace(target(), deadline=5), ["test_db"], "scheduled/test/history.zip")
    assert calls[-1][0].startswith("DROP DATABASE IF EXISTS `sli_backup_manifest_")
    assert calls[-1][1:] == (None, 30)


@pytest.mark.parametrize("failure", ["scan", "table_names"])
def test_structural_manifest_drill_requires_successful_scan_and_matching_tables(backup_set, monkeypatch, failure):
    data = component(backup_set)
    data["table_names"] = {name: list(tables) for name, tables in data.pop("tables").items()}
    statements = []
    def query(self, statement):
        statements.append(statement)
        if "restore_check" in statement:
            assert self.host == "clickhouse-restore"
            return [{"free_space": str(100 * 1024**3), "path": "/var/lib/clickhouse/restore-check/"}]
        if "name='backups'" in statement:
            return [{"path": "/var/lib/clickhouse/backups/"}]
        if "free_space" in statement:
            return [{"free_space": str(100 * 1024**3)}]
        pytest.fail("must reject before verification RESTORE")

    monkeypatch.setattr(backup.ClickHouse, "query", query)

    def scan(target, names, disk_path, *, storage_policy):
        assert target.host == "clickhouse-restore" and storage_policy == "restore_check"
        if failure == "scan":
            raise TimeoutError("linux_backup_clickhouse_deadline_exceeded")
        return {"test`db": {}}

    monkeypatch.setattr(drill, "archive_statistics", scan, raising=False)
    with pytest.raises((RuntimeError, TimeoutError)):
        drill.restore_clickhouse(target(), backup_set, data)
    assert not any(q.startswith("RESTORE") for q in statements)


@pytest.mark.parametrize("archive_kind", ["missing", "empty"])
def test_backup_rejects_missing_or_empty_archive(tmp_path, monkeypatch, archive_kind):
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(tmp_path))

    def query(self, statement):
        if "system.disks" in statement:
            return [{"path": "/var/lib/clickhouse/backups/"}]
        if statement.startswith("SELECT version"):
            return [{"version": "25.8"}]
        if "system.databases" in statement:
            return [{"name": "test_db"}]
        if archive_kind == "empty":
            (tmp_path / "history.zip").touch()
        return [{"status": "BACKUP_CREATED"}]

    monkeypatch.setattr(backup.ClickHouse, "query", query)
    monkeypatch.setattr(backup.ClickHouse, "statistics", lambda *a: {})
    with pytest.raises(RuntimeError, match="incomplete"):
        target().backup(tmp_path)


def test_statistics_counts_empty_tables_and_serializes_only_watermarks(monkeypatch):
    statements = []

    def query(self, statement):
        statements.append(statement)
        if "system.tables" in statement:
            return [{"name": "events"}]
        if "system.columns" in statement:
            return [{"name": "event_db_id", "type": "UInt64"},
                    {"name": "time_created_utc", "type": "DateTime64(6, 'UTC')"},
                    {"name": "core_json", "type": "String"}]
        return [{"row_count": "0", "max_0": None, "max_1": None}]

    monkeypatch.setattr(backup.ClickHouse, "query", query)
    assert target().statistics("sli_backup_check_fake") == {
        "events": {"row_count": 0, "max_values": {"event_db_id": None, "time_created_utc": None}},
    }
    assert "core_json" not in statements[-1]
    assert "maxOrNull" in statements[-1]


def test_statistics_server_limit_uses_remaining_deadline(monkeypatch):
    statements = []

    def query(self, statement):
        statements.append(statement)
        if "system.tables" in statement:
            return [{"name": "events"}]
        if "system.columns" in statement:
            return []
        return [{"row_count": "3"}]

    monkeypatch.setattr(backup.time, "monotonic", lambda: 5)
    monkeypatch.setattr(backup.ClickHouse, "query", query)
    replace(target(), deadline=10).statistics("sli_backup_check_fake")
    assert "max_execution_time=5.000" in statements[-1]


@pytest.mark.parametrize("failure", [None, "restore", "incomplete", "counts", "max", "statistics"])
@pytest.mark.parametrize("metrics", ["manifest", "drill", "live"])
def test_restore_renames_all_databases_compares_archive_metrics_and_drops(backup_set, monkeypatch, failure, metrics):
    data = component(backup_set)
    data["databases"].append("second")
    data["tables"]["second"] = {}
    expected = data["tables"]
    if metrics in {"drill", "live"}:
        data["table_names"] = {name: list(tables) for name, tables in data.pop("tables").items()}
        if metrics == "live":
            # Writers can advance live metrics relative to the immutable archive.
            data["live_tables"] = {"test`db": {"events": {"row_count": 100, "max_values": {}}}, "second": {}}
    statements, observed = [], []
    archive_reads = []

    def archive_statistics(self, names, disk_path, *, storage_policy):
        assert storage_policy == "restore_check"
        archive_reads.append(disk_path)
        assert self.timeout == drill.RESTORE_TIMEOUT
        assert self.deadline is None and self.operation_size > 0
        assert not any(q.startswith("RESTORE") for q in statements)
        assert names == data["databases"]
        return expected

    def query(self, statement):
        statements.append(statement)
        if "system.disks" in statement:
            return [{"free_space": str(100 * 1024**3), "path": "/var/lib/clickhouse/restore-check/" if "restore_check" in statement else "/var/lib/clickhouse/backups/"}]
        if statement.startswith("RESTORE"):
            if failure == "restore":
                raise RuntimeError("synthetic")
            if failure == "incomplete":
                return [{"status": "RESTORE_FAILED"}]
            return [{"status": "RESTORED"}]
        return []

    def statistics(self, database):
        observed.append(database)
        if failure == "statistics":
            raise RuntimeError("synthetic")
        if len(observed) == 2:
            return {}
        if failure in {"counts", "max"}:
            changed = json.loads(json.dumps(STATS))
            if failure == "counts":
                changed["events"]["row_count"] = 4
            else:
                changed["events"]["max_values"]["event_db_id"] = "8"
            return changed
        return STATS

    monkeypatch.setattr(backup.ClickHouse, "query", query)
    monkeypatch.setattr(backup.ClickHouse, "statistics", statistics, raising=False)
    monkeypatch.setattr(drill, "archive_statistics", archive_statistics, raising=False)
    if failure:
        with pytest.raises(RuntimeError):
            drill.restore_clickhouse(target(), backup_set, data)
    else:
        result = drill.restore_clickhouse(target(), backup_set, data)
        assert result["status"] == "verified"
        assert result["tables"] == expected
    assert archive_reads == ([f"scheduled/{backup_set.name}/history.zip"] if metrics != "manifest" else [])
    restore = next(q for q in statements if q.startswith("RESTORE"))
    assert "DATABASE `test\\`db` AS `sli_backup_check_" in restore
    assert "DATABASE `second` AS `sli_backup_check_" in restore
    assert "max_execution_time=" in restore and "max_threads=2" in restore
    drops = [q for q in statements if q.startswith("DROP")]
    assert len(drops) == 2
    assert all(q.startswith("DROP DATABASE IF EXISTS `sli_backup_check_") for q in drops)
    assert all("SYNC" in q for q in drops)


@pytest.mark.parametrize("metrics", ["manifest", "drill"])
def test_restore_checks_uncompressed_archive_size_before_creating_database(backup_set, monkeypatch, metrics):
    data = component(backup_set)
    if metrics == "drill":
        data["table_names"] = {name: list(tables) for name, tables in data.pop("tables").items()}
    statements = []

    def query(self, statement):
        statements.append(statement)
        return [{"free_space": str(100 * 1024**3) if "default" in statement else "0",
                 "path": "/var/lib/clickhouse/restore-check/"}]

    monkeypatch.setattr(backup.ClickHouse, "query", query)
    monkeypatch.setattr(drill, "archive_statistics", lambda *a: pytest.fail("must not scan before admission"), raising=False)
    assert drill.restore_clickhouse(target(), backup_set, data)["status"] == 'skipped_insufficient_space'
    assert not any(q.startswith(("CREATE", "RESTORE", "DROP")) for q in statements)


@pytest.mark.parametrize('mode', ['drill', 'restore'])
@pytest.mark.parametrize('enough', [False, True])
def test_large_restore_uses_actual_capacity_instead_of_32gib_ceiling(backup_set, monkeypatch, mode, enough):
    from deploy.linux import backup_policy, restore_existing

    data = component(backup_set)
    data['table_names'] = {name: list(tables) for name, tables in data['tables'].items()}
    expanded = 64 * 1024**3
    required = backup_policy.space_estimate(expanded_ch_bytes=expanded)['clickhouse_bytes']
    free = required if enough else required - 1
    queries = []
    monkeypatch.setattr(zipfile, 'ZipFile', lambda *a, **kw: nullcontext(SimpleNamespace(
        infolist=lambda: [SimpleNamespace(file_size=expanded)])))

    def query(self, statement):
        queries.append(statement)
        if 'system.disks' in statement:
            return [{'free_space': str(free), 'path': '/var/lib/clickhouse/restore-check/'}]
        return [{'status': 'RESTORED'}] if statement.startswith('RESTORE') else []

    monkeypatch.setattr(backup.ClickHouse, 'query', query)
    monkeypatch.setattr(backup.ClickHouse, 'statistics', lambda *a: STATS)
    monkeypatch.setattr(backup.ClickHouse, 'readable_archive', lambda *a, **kw: nullcontext('synthetic.zip'))
    monkeypatch.setattr(drill, 'archive_statistics', lambda *a, **kw: data['tables'])
    if mode == 'drill':
        result = drill.restore_clickhouse(target(), backup_set, data)
        assert result['status'] == ('verified' if enough else 'skipped_insufficient_space')
        if not enough:
            assert result['required_bytes'] == required and result['free_bytes'] == free
    elif enough:
        restore_existing.restore_clickhouse(backup_set, backup_set.parent, target(), data, replace_existing=False)
    else:
        with pytest.raises(RuntimeError, match='^linux_restore_clickhouse_insufficient_space$'):
            restore_existing.restore_clickhouse(backup_set, backup_set.parent, target(), data, replace_existing=False)
    assert any(q.startswith('RESTORE') for q in queries) is enough


@pytest.mark.parametrize("archive_name", ["../history.zip", "/history.zip", "warm.zip"])
def test_restore_rejects_archive_path_override(backup_set, monkeypatch, archive_name):
    data = component(backup_set)
    data["archive"] = archive_name
    monkeypatch.setattr(backup.ClickHouse, "query", lambda *a: pytest.fail("must not query"))
    with pytest.raises(ValueError):
        drill.restore_clickhouse(target(), backup_set, data)


def test_expired_clickhouse_deadline_fails_before_opening_http(monkeypatch):
    from dataclasses import replace

    monkeypatch.setattr(backup.time, "monotonic", lambda: 5)
    monkeypatch.setattr(backup.http.client, "HTTPConnection", lambda *a, **kw: pytest.fail("must not connect"))
    with pytest.raises(TimeoutError, match="deadline_exceeded"):
        replace(target(), deadline=4).query("SELECT 1")


def test_http_timeout_cancels_only_generated_restore_query(monkeypatch):
    from dataclasses import replace
    from urllib.parse import parse_qs, urlsplit

    requests = []

    class Connection:
        def request(self, method, endpoint, **kwargs):
            requests.append((endpoint, kwargs["body"].decode()))
            if len(requests) == 1:
                raise TimeoutError("synthetic")

        def getresponse(self):
            return SimpleNamespace(status=200, read=lambda *a: b'{"data": []}')

        def close(self):
            pass

    monkeypatch.setattr(backup.time, "monotonic", lambda: 5)
    monkeypatch.setattr(backup, "read_secret", lambda *a: "synthetic")
    monkeypatch.setattr(backup.http.client, "HTTPConnection", lambda *a, **kw: Connection())
    with pytest.raises(TimeoutError):
        replace(target(), deadline=10).query("RESTORE DATABASE test")
    parameters = parse_qs(urlsplit(requests[0][0]).query)
    query_id = parameters['query_id'][0]
    assert query_id.startswith("sli_backup_query_")
    assert parameters['max_execution_time'] == ['0']
    assert requests[1][1] == f"KILL QUERY WHERE query_id='{query_id}' SYNC"


def test_restore_attempts_all_cleanup_even_if_first_drop_fails(backup_set, monkeypatch):
    data = component(backup_set)
    data["databases"].append("second")
    data["tables"]["second"] = STATS
    statements = []

    def query(self, statement):
        statements.append(statement)
        if "system.disks" in statement:
            return [{"free_space": str(100 * 1024**3), "path": "/var/lib/clickhouse/restore-check/" if "restore_check" in statement else "/var/lib/clickhouse/backups/"}]
        if statement.startswith("RESTORE"):
            return [{"status": "RESTORED"}]
        if sum(q.startswith("DROP") for q in statements) == 1:
            raise RuntimeError("synthetic")
        return []

    monkeypatch.setattr(backup.ClickHouse, "query", query)
    monkeypatch.setattr(backup.ClickHouse, "statistics", lambda *a: STATS)
    with pytest.raises(RuntimeError, match="cleanup_failed"):
        drill.restore_clickhouse(target(), backup_set, data)
    assert len([q for q in statements if q.startswith("DROP")]) == 2


@pytest.mark.parametrize("outcome", ["legacy", "verified", "structural", "skipped_insufficient_space", "failed"])
def test_combined_drill_receipt_requires_both_components_from_selected_set(tmp_path, monkeypatch, outcome, private_postgres):
    from tests.unit.test_linux_backup_capacity import prepare_capacity

    newest = tmp_path / "20261006T010000.000000Z"
    (newest / "postgres").mkdir(parents=True)
    (newest / "postgres/toc.dat").write_bytes(b"synthetic")
    manifest = {
        "backup_id": newest.name, "status": "success", "migration_ledger_max_version": 2,
        "components": {"postgres": {"row_counts": dict.fromkeys(backup.KEY_TABLES, 3)}},
    }
    if outcome != "legacy":
        inventory = {"table_names": {"test_db": ["events"]}} if outcome == "structural" else {"tables": STATS}
        manifest["components"].update({"history": inventory, "warm": inventory})
    backup.write_json(newest / "manifest.json", manifest)
    admin = prepare_capacity(tmp_path, newest, monkeypatch)
    monkeypatch.setattr(backup, "pg_passfile", lambda: nullcontext(Path("fake")))
    monkeypatch.setattr(backup, "pg_connect", lambda *a, **kw: nullcontext(admin))
    monkeypatch.setattr(backup, "pg_tool", lambda *a: None)
    monkeypatch.setattr(backup, "row_counts", lambda *a: dict.fromkeys(backup.KEY_TABLES, 3))
    seen = []

    def restore(target, selected, component):
        seen.append(target.name)
        assert selected == newest and component == manifest["components"][target.name]
        if outcome == "failed" and target.name == "warm":
            raise RuntimeError("synthetic")
        return {"status": "verified" if target.name == "history" or outcome == "structural" else outcome}

    monkeypatch.setattr(drill, "restore_clickhouse", restore)
    if outcome == "failed":
        with pytest.raises(RuntimeError):
            drill.restore_check(tmp_path)
    else:
        result = drill.restore_check(tmp_path)
        assert result["status"] == ("verified" if outcome in {"verified", "structural"} else "skipped")
    receipt = json.loads((tmp_path / "restore_check.json").read_text())
    assert receipt["backup_id"] == newest.name
    assert receipt["components"]["postgres"]["status"] == "verified"
    if outcome == "legacy":
        assert not seen
        assert receipt["components"]["history"]["status"] == "skipped_missing_manifest_metrics"
        assert receipt["components"]["warm"]["status"] == "skipped_missing_manifest_metrics"
    else:
        assert seen == ["history", "warm"]
        assert receipt["components"]["history"]["status"] == "verified"
        assert receipt["components"]["warm"]["status"] == ("verified" if outcome == "structural" else outcome)


@pytest.mark.parametrize("status,exit_code", [("verified", 0), ("skipped", 2)])
def test_cli_skips_never_claim_verification(monkeypatch, capsys, status, exit_code):
    monkeypatch.setattr(drill, "restore_check", lambda *a: {"status": status})
    assert drill.main() == exit_code
    assert capsys.readouterr().out == f"linux_backup_restore_check_{status}\n"


@pytest.mark.parametrize("body", [b"", b"\n"])
@pytest.mark.parametrize("statement", [
    "CREATE DATABASE synthetic ENGINE = Backup('a', Disk('backups', 'b'))",
    "DROP DATABASE IF EXISTS synthetic SYNC",
])
def test_ddl_with_empty_http_body_returns_no_rows(monkeypatch, body, statement):
    # ClickHouse answers CREATE/DROP DATABASE with an empty body, not JSON.
    class Connection:
        def request(self, method, endpoint, **kwargs):
            pass

        def getresponse(self):
            return SimpleNamespace(status=200, read=lambda *a: body)

        def close(self):
            pass

    monkeypatch.setattr(backup, "read_secret", lambda *a: "synthetic")
    monkeypatch.setattr(backup.http.client, "HTTPConnection", lambda *a, **kw: Connection())
    assert target().query(statement) == []
