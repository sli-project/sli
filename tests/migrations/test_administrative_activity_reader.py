from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest



ROOT = Path(__file__).resolve().parents[2]
FORWARD = (ROOT / "config/postgres_migrations/072_administrative_activity_reader.sql").read_text(encoding="utf-8").lower()
ROLLBACK = (ROOT / "config/postgres_migrations/072_administrative_activity_reader.rollback.sql").read_text(encoding="utf-8").lower()


def _row(activity_id: int) -> dict:
    return {
        "activity_id": activity_id,
        "event_uid": UUID("11111111-1111-1111-1111-111111111111"),
        "occurred_at_utc": datetime(2026, 8, 2, tzinfo=timezone.utc),
        "recorded_at_utc": datetime(2026, 8, 2, 0, 0, 1, tzinfo=timezone.utc),
        "actor_kind": "session",
        "actor_key": "fixture-user",
        "category": "access_management",
        "action_key": "access.assignment.created",
        "target_kind": "user",
        "target_key": "fixture-target",
        "outcome": "succeeded",
        "reason_code": None,
        "details_json": {"assignment_id": 7},
        "remote_address": "127.0.0.1",
        "correlation_id": None,
        "content_hash_hex": "a" * 64,
        "previous_record_hash_hex": "b" * 64,
        "record_hash_hex": "c" * 64,
    }


def test_sql_reader_has_hard_limit_capability_and_no_direct_select_grant() -> None:
    assert "create or replace function read_administrative_activity_v1" in FORWARD
    assert "p_limit > 201" in FORWARD
    assert "security definer" in FORWARD
    assert "order by current.activity_id desc" in FORWARD
    assert "grant execute on function read_administrative_activity_v1" in FORWARD
    assert "grant select on" not in FORWARD
    assert "'administrative.activity.view'" in FORWARD
    assert "rollback 072 forbidden after capability assignment" in ROLLBACK
