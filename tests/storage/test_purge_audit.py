from __future__ import annotations

from datetime import datetime, timezone

import pytest

from server.sli.storage import purge_audit, storage_policy
from server.sli.storage.permanent_history_retention import retain_batch


@pytest.fixture(autouse=True)
def receipts(tmp_path, monkeypatch):
    monkeypatch.setattr(purge_audit, "AUDIT_DIR", tmp_path / "purge")


def test_crash_leaves_running_receipt_and_history_is_bounded(monkeypatch):
    monkeypatch.setattr(purge_audit, "MAX_RUNS", 3)
    purge_audit.PurgeRun("event_history")
    assert purge_audit.last_purge_runs()["runs"][0]["status"] == "running"
    for _ in range(5):
        run = purge_audit.PurgeRun("event_history")
        run.finish({"status": "complete"})
    rows = purge_audit.last_purge_runs()["runs"]
    assert len(rows) == len(list(purge_audit.AUDIT_DIR.glob("*.json"))) == 3
    assert all(row["duration_ms"] >= 0 and row["bytes_reclaimed"] == 0 for row in rows)


def test_unreadable_receipt_is_unavailable_without_exposing_contents():
    run = purge_audit.PurgeRun("event_history")
    run.path.write_text("invalid receipt", encoding="utf-8")
    assert purge_audit.last_purge_runs() == {
        "status": "unavailable", "reason": "purge_receipts_unreadable", "runs": [],
    }


def test_missing_audit_write_permission_prevents_purge(monkeypatch):
    def fail(*args):
        raise OSError("fixture write failure")
    monkeypatch.setattr(purge_audit, "_write", fail)
    class Connection:
        def cursor(self):
            pytest.fail("purge SQL executed without receipt")
    with pytest.raises(OSError):
        retain_batch(Connection(), cutoff=datetime(2026, 9, 20, tzinfo=timezone.utc),
                     preservation_check=lambda rows: pytest.fail("verification executed"))


@pytest.mark.parametrize("sqlstate,reason", [
    ("57014", "purge_statement_timeout"), ("55P03", "purge_lock_unavailable"),
    ("42501", "purge_permission_denied"), ("23503", "purge_dependency_changed"),
])
def test_database_failure_reason_uses_sqlstate_without_private_exception_text(sqlstate, reason):
    error = RuntimeError("fixture private query text")
    error.sqlstate = sqlstate
    assert purge_audit.failure_reason(error) == reason


def test_storage_status_exposes_last_runs_even_when_database_metrics_are_unavailable(monkeypatch):
    run = purge_audit.PurgeRun("event_history")
    run.finish({"status": "blocked", "reason": "history_retention_delete_mismatch"})
    monkeypatch.setattr(storage_policy, "load_storage_policy", storage_policy.StoragePolicy)
    monkeypatch.setattr(storage_policy, "_bounded_dir_size", lambda *a, **kw: {})
    monkeypatch.setattr(storage_policy, "disk_pressure_status", lambda *a: {"status": "ok"})
    for name in ("build_storage_cleanup_plan", "get_capacity_plan", "_legacy_sqlite_lifecycle",
                 "get_postgres_operations_status", "_read_last_cleanup", "_capacity_state"):
        monkeypatch.setattr(storage_policy, name, lambda *a, **kw: {})
    monkeypatch.setattr(storage_policy, "_operator_guidance", lambda *a: [])
    monkeypatch.setattr("server.sli.storage.storage_lifecycle.get_storage_lifecycle_status",
                        lambda **kw: {"status": "unavailable"})
    monkeypatch.setattr("server.sli.storage.runtime_storage.get_runtime_storage_summary",
                        lambda *a: {})
    result = storage_policy.get_storage_health()
    assert result["purge_runs"]["runs"][0]["reason"] == "history_retention_delete_mismatch"
    assert result["storage_lifecycle"]["status"] == "unavailable"
