from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path


def test_migration_033_is_append_only_local_and_fail_closed() -> None:
    forward = Path("config/postgres_migrations/033_semantic_calibration_reviews.sql").read_text(encoding="utf-8").lower()
    rollback = Path("config/postgres_migrations/033_semantic_calibration_reviews.rollback.sql").read_text(encoding="utf-8").lower()
    assert "version=32 and name='runtime_worker_heartbeats'" in forward
    assert "pg_has_role(session_user, 'adlog_storage_owner', 'member')" in forward
    assert "set local role adlog_storage_owner" in forward
    assert "semantic_scenario_reviews" in forward
    assert "review_request_id uuid not null unique" in forward
    assert "scenario_snapshot_sha256" in forward
    assert "before update or delete" in forward
    assert "grant select,insert" in forward
    assert "values (33,'semantic_calibration_reviews')" in forward
    assert "rollback 033 refused" in rollback
    assert "pg_has_role(session_user, 'adlog_storage_owner', 'member')" in rollback
    assert "set local role adlog_storage_owner" in rollback
    for forbidden in ("insert into events_v2_core", "insert into findings", "update findings", "delete from findings", "collection_channel_state", "update runtime_worker_heartbeats"):
        assert forbidden not in forward
