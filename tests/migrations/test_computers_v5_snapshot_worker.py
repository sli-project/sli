from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.runtime.computers_report_v5_snapshot_worker import (
    RETENTION_DAYS,
    SNAPSHOT_INTERVAL_SECONDS,
    persist_computers_v5_snapshot,
    snapshot_bucket_start,
    snapshot_retention_cutoff,
)


NOW = datetime(2026, 8, 29, 17, 45, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[2]


class FakeCursor:
    def __init__(self, *, inserted: bool = True, readback_matches: bool = True) -> None:
        self.inserted = inserted
        self.readback_matches = readback_matches
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self._phase = ""
        self.rowcount = 0

    def execute(self, sql: str, params: tuple[object, ...] = ()) -> None:
        self.statements.append((sql, params))
        if "insert into computers_report_v5_snapshots" in sql:
            self._phase = "insert"
        elif "select object_count,payload_sha256" in sql:
            self._phase = "readback"
        elif "delete from computers_report_v5_snapshots" in sql:
            self._phase = "delete"
            self.rowcount = 2

    def fetchone(self):
        if self._phase == "insert":
            return {"snapshot_id": 5} if self.inserted else None
        if self._phase == "readback":
            insert_params = next(params for sql, params in self.statements if "insert into computers_report_v5_snapshots" in sql)
            object_count = int(insert_params[8])
            payload_sha256 = insert_params[10]
            return {
                "object_count": object_count if self.readback_matches else object_count + 1,
                "payload_sha256": payload_sha256,
            }
        return None


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self.cursor_value = cursor

    def cursor(self):
        cursor = self.cursor_value

        class Context:
            def __enter__(self):
                return cursor

            def __exit__(self, *_args):
                return False

        return Context()


def _report(state: str = "available") -> dict[str, object]:
    return {
        "contract_id": "sli.computers-report.v5",
        "report_key": "ad.computers.v5",
        "state": state,
        "view": "all",
        "items": [
            {"entity_id": 1, "display_name": "WS-01", "enabled": True},
            {"entity_id": 2, "display_name": "WS-02", "enabled": False},
        ],
        "coverage": {
            "state": "complete",
            "latest_observed_at_utc": "2026-08-29T17:00:00Z",
            "domains": [{"domain_id": 1, "run_id": "00000000-0000-0000-0000-000000000029"}],
        },
        "summary": {"total_computers": 2},
        "semantic": {"link_contract": "exact_finding_entity_id_to_ad_computer"},
    }


def test_v5_snapshot_schedule_and_retention_are_owner_fixed() -> None:
    assert SNAPSHOT_INTERVAL_SECONDS == 12 * 60 * 60
    assert RETENTION_DAYS == 365
    assert snapshot_bucket_start(datetime(2026, 8, 29, 11, 59, tzinfo=timezone.utc)) == datetime(2026, 8, 29, 0, 0, tzinfo=timezone.utc)
    assert snapshot_bucket_start(datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)) == datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
    assert snapshot_retention_cutoff(NOW) == NOW - timedelta(days=365)


def test_v5_snapshot_readback_happens_before_retention() -> None:
    cursor = FakeCursor()
    result = persist_computers_v5_snapshot(FakeConnection(cursor), report=_report(), domain_id=1, captured_at=NOW)

    assert result == {"status": "captured", "snapshot_id": 5, "object_count": 2, "retired_snapshots": 2}
    statements = [sql for sql, _params in cursor.statements]
    assert "insert into computers_report_v5_snapshots" in statements[0]
    assert "select object_count,payload_sha256" in statements[1]
    assert "delete from computers_report_v5_snapshots" in statements[2]
    assert "interval '365 days'" not in statements[2]
    assert cursor.statements[2][1] == (snapshot_retention_cutoff(NOW),)


def test_v5_snapshot_is_idempotent_per_twelve_hour_bucket() -> None:
    cursor = FakeCursor(inserted=False)
    result = persist_computers_v5_snapshot(FakeConnection(cursor), report=_report(), domain_id=1, captured_at=NOW)

    assert result == {"status": "already_captured", "object_count": 2, "retired_snapshots": 0}
    assert not any("delete from computers_report_v5_snapshots" in sql for sql, _params in cursor.statements)


def test_v5_snapshot_rejects_unavailable_source_and_readback_mismatch() -> None:
    unavailable = FakeCursor()
    with pytest.raises(RuntimeError, match="snapshot_source_not_usable"):
        persist_computers_v5_snapshot(FakeConnection(unavailable), report=_report("unavailable"), domain_id=1, captured_at=NOW)
    assert unavailable.statements == []

    mismatch = FakeCursor(readback_matches=False)
    with pytest.raises(RuntimeError, match="snapshot_readback_mismatch"):
        persist_computers_v5_snapshot(FakeConnection(mismatch), report=_report(), domain_id=1, captured_at=NOW)
    assert not any("delete from computers_report_v5_snapshots" in sql for sql, _params in mismatch.statements)


def test_migration_109_registers_snapshot_worker_heartbeat_without_losing_existing_workers() -> None:
    migration = (ROOT / "config/postgres_migrations/109_computers_v5_snapshot_heartbeat.sql").read_text(encoding="utf-8")
    normalized = "".join(migration.split()).casefold()

    for worker in (
        "collection", "ad_context_snapshot", "computers_v5_snapshot", "storage_v2_outbox",
        "storage_lifecycle", "post_collection", "entity_state", "semantic",
    ):
        assert f"'{worker}'" in normalized
    assert "version=108andname='computers_report_v5'" in normalized
    assert "values(109,'computers_v5_snapshot_heartbeat')" in normalized
