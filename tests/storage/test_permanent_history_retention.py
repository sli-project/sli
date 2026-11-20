from datetime import datetime, timezone

import pytest

from server.sli.storage.permanent_history_retention import retain_batch
from server.sli.storage import purge_audit


@pytest.fixture(autouse=True)
def receipts(tmp_path, monkeypatch):
    monkeypatch.setattr(purge_audit, "AUDIT_DIR", tmp_path / "purge")


class Cursor:
    def __init__(self, rows, unknown=False, fault=None):
        self.rows = rows
        self.unknown = unknown
        self.executed = []
        self.fault = fault

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def execute(self, sql, params=()):
        self.sql = sql
        self.params = params
        self.executed.append(sql)

    def fetchall(self):
        if "history_retention_dependencies" in self.sql:
            return [{"dependent_relation": "unknown_cascade", "delete_action": "c"}] if self.unknown else []
        if "history_retention_candidates" in self.sql:
            return self.rows
        if "history_retention_locked_holds" in self.sql:
            return [{"id": 41}] if self.fault == "hold" else []
        if "history_retention_delete_readback" in self.sql:
            return [{"id": 41}] if self.fault == "readback" else []
        if "select source_event_id,status" in self.sql:
            return [{"source_event_id": row["id"], "status": "pending" if self.fault == "semantic" else "completed"} for row in self.rows if row["classification"] == "eligible"]
        if "select event_id,pg_column_size" in self.sql:
            return [{"event_id": row["id"], "row_bytes": 80} for row in self.rows if row["classification"] == "eligible"]
        if "for update nowait" in self.sql:
            if self.fault == "count":
                return []
            return [{"id": row["id"], "normalized_hash": b"changed" if self.fault == "hash" else row["normalized_hash"], "row_bytes": 120} for row in self.rows if row["classification"] == "eligible"]
        if "delete from events_v2_core" in self.sql:
            return [] if self.fault == "delete" else [{"id": i} for i in self.params[0]]
        return []


class Connection:
    def __init__(self, rows, unknown=False, fault=None):
        self.cur = Cursor(rows, unknown, fault)
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return self.cur

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def run(connection, **kwargs):
    return retain_batch(connection, cutoff=datetime(2026, 9, 20, tzinfo=timezone.utc), **kwargs)


def test_unfinished_semantics_and_evidence_are_held_but_scan_advances():
    connection = Connection([
        {"id": 41, "normalized_hash": b"a" * 32, "classification": "semantic_pending"},
        {"id": 42, "normalized_hash": b"b" * 32, "classification": "evidence_reference"},
    ])
    result = run(connection, preservation_check=lambda rows: pytest.fail("held rows verified"))
    assert result["deleted_count"] == 0
    assert result["last_scanned_id"] == 42
    assert result["held_reasons"] == {"semantic_pending": 1, "evidence_reference": 1}
    assert not any("delete from events_v2_core" in sql for sql in connection.cur.executed)


@pytest.mark.parametrize("event_id", [41, 2_147_483_648])
def test_only_verified_exact_candidates_are_deleted(event_id):
    connection = Connection([{"id": event_id, "normalized_hash": b"a" * 32, "classification": "eligible"}])

    def verify(rows):
        assert rows[0]["id"] == event_id
        assert not any("delete from events_v2_core" in sql for sql in connection.cur.executed)
        assert any("lock table event_entity_link_blocks_v2" in sql for sql in connection.cur.executed)
        assert any("lock table investigation_events" in sql for sql in connection.cur.executed)
        assert connection.cur.executed.index("lock table events_v2_core in row exclusive mode nowait") < next(
            index for index, sql in enumerate(connection.cur.executed) if "history_retention_dependencies" in sql
        )

    result = run(connection, preservation_check=verify)
    assert result["deleted_count"] == 1
    assert connection.commits == 1
    assert result["tables"]["events_v2_core"]["deleted_count"] == 1
    assert result["tables"]["event_facts_v2"]["deleted_count"] == 1
    assert result["logical_bytes_deleted"] == 200
    assert result["bytes_reclaimed"] == 0
    receipt = purge_audit.last_purge_runs()["runs"][0]
    assert receipt["transaction"] == "committed"
    assert receipt["duration_ms"] >= 0
    for sql in connection.cur.executed:
        if "any(" in sql or "as manifest(id,normalized_hash)" in sql:
            assert "::bigint[]" in sql


def test_failed_preservation_never_deletes_or_commits():
    connection = Connection([{"id": 41, "normalized_hash": b"a" * 32, "classification": "eligible"}])
    def verify(rows):
        raise RuntimeError("history incomplete")
    with pytest.raises(RuntimeError, match="history incomplete"):
        run(connection, preservation_check=verify)
    assert connection.commits == 0
    assert connection.rollbacks == 1
    receipt = purge_audit.last_purge_runs()["runs"][0]
    assert receipt["status"] == "blocked"
    assert receipt["reason"] == "purge_verification_or_io_failed"
    assert "history incomplete" not in str(receipt)
    assert not any("delete from events_v2_core" in sql for sql in connection.cur.executed)


def test_unknown_cascading_dependency_blocks_deletion():
    connection = Connection([], unknown=True)
    result = run(connection, preservation_check=lambda rows: None)
    assert result["status"] == "blocked"
    assert result["reason"] == "unknown_event_dependency"
    assert connection.commits == 0


def test_file_descriptors_are_opt_in_and_guard_source_payload_before_hot_delete(monkeypatch):
    conn = Connection([])
    monkeypatch.setenv("SLI_FILE_AUDIT_RETENTION_ENABLED", "0")
    run(conn, preservation_check=lambda _: None)
    query = next(sql for sql in conn.cur.executed if "history_retention_candidates" in sql)
    assert "sli_plugin_file_audit" not in query
    monkeypatch.setenv("SLI_FILE_AUDIT_RETENTION_ENABLED", "1")
    conn = Connection([])
    run(conn, preservation_check=lambda _: None)
    assert 4663 in conn.cur.params[1]
    query = next(sql for sql in conn.cur.executed if "history_retention_candidates" in sql)
    assert "payload_expirations" in query and "file_payload_pending" in query
    assert "rule_actions" in query
    assert "lock table sli_plugin_file_audit.rule_actions in share mode nowait" in conn.cur.executed


def test_end_of_scan_restarts_without_claiming_held_rows_were_deleted():
    result = run(Connection([]), after_id=99, preservation_check=lambda rows: None)
    assert result["status"] == "complete"
    assert result["last_scanned_id"] == 0
    assert result["deleted_count"] == 0


@pytest.mark.parametrize("fault,reason", [
    ("hash", "history_retention_source_changed"),
    ("count", "history_retention_source_changed"),
    ("semantic", "history_retention_semantic_state_changed"),
    ("hold", "history_retention_evidence_changed"),
    ("delete", "history_retention_delete_mismatch"),
    ("readback", "history_retention_delete_readback_mismatch"),
])
def test_guard_failure_rolls_back_and_records_reason(fault, reason):
    connection = Connection([{"id": 41, "normalized_hash": b"a" * 32, "classification": "eligible"}], fault=fault)
    with pytest.raises(RuntimeError, match=reason):
        run(connection, preservation_check=lambda rows: None)
    assert connection.commits == 0
    assert connection.rollbacks == 1
    receipt = purge_audit.last_purge_runs()["runs"][0]
    assert receipt["reason"] == reason
    assert receipt["deleted_count"] == 0


@pytest.mark.parametrize("hold", ["evidence_reference", "investigation_evidence", "legal_hold",
                                  "semantic_missing", "semantic_pending", "continuity_missing"])
def test_protected_rows_never_reach_preservation_or_delete(hold):
    connection = Connection([{"id": 41, "normalized_hash": b"a" * 32, "classification": hold}])
    result = run(connection, preservation_check=lambda rows: pytest.fail("protected row admitted"))
    assert result["held_reasons"] == {hold: 1}
    assert result["deleted_count"] == 0
    sql = next(sql for sql in connection.cur.executed if "history_retention_candidates" in sql)
    assert "from investigation_events" in sql
    assert "from finding_evidence" in sql
    assert "when c.legal_hold then 'legal_hold'" in sql
    assert not any("delete from events_v2_core" in sql for sql in connection.cur.executed)


def test_budget_is_clamped_and_sql_time_is_bounded():
    connection = Connection([])
    run(connection, batch_size=99999, preservation_check=lambda rows: None)
    assert connection.cur.params[-2] == 1000
    assert "set local statement_timeout = '5000ms'" in connection.cur.executed


def test_receipt_checkpoint_failure_prevents_commit_and_rolls_back(monkeypatch):
    connection = Connection([{"id": 41, "normalized_hash": b"a" * 32, "classification": "eligible"}])
    original = purge_audit._write
    calls = []

    def write(path, payload):
        calls.append(payload["status"])
        if payload["status"] == "verified_pending_commit":
            raise OSError("fixture receipt failure")
        original(path, payload)

    monkeypatch.setattr(purge_audit, "_write", write)
    with pytest.raises(OSError):
        run(connection, preservation_check=lambda rows: None)
    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert calls == ["running", "verified_pending_commit", "blocked"]
    receipt = purge_audit.last_purge_runs()["runs"][0]
    assert receipt["deleted_count"] == 0
    assert receipt["logical_bytes_deleted"] == 0
    assert receipt["transaction"] == "rolled_back"
