from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest



UTC = timezone.utc


def _event(event_db_id: int, event_id: int, minute: int, **overrides) -> dict:
    return {
        "event_db_id": event_db_id,
        "event_record_id": event_db_id * 10,
        "event_id": event_id,
        "time_created_utc": datetime(2026, 8, 23, 10, minute, tzinfo=UTC),
        "domain_controller": "dc01.example.test",
        "subject_user_sid": "S-1-5-21-100",
        "subject_user_name": "operator",
        "membership_member_sid": "S-1-5-21-200",
        "membership_member_name": "CN=Alice,DC=example,DC=test",
        "target_user_sid": "S-1-5-21-512",
        "target_user_name": "Domain Admins",
        "source_core_sha256": b"c" * 32,
        "source_facts_sha256": b"f" * 32,
        **overrides,
    }


def _events_access() -> dict:
    return {
        "platform_owner": False,
        "capabilities": [],
        "capability_policies": [
            {
                "capability": "events.view",
                "effect": "allow",
                "scope": {"kind": "domain", "ids": [7]},
            }
        ],
    }


def test_membership_warm_facts_migration_is_source_only_and_rollback_preserves_evidence() -> None:
    root = Path(__file__).resolve().parents[2]
    forward = root / "config/postgres_migrations/087_ad_group_membership_warm_facts.sql"
    rollback = root / "config/postgres_migrations/087_ad_group_membership_warm_facts.rollback.sql"

    assert "requires migration 086" in forward.read_text(encoding="utf-8")
    assert "membership_member_sid" in forward.read_text(encoding="utf-8")
    assert "scope_json jsonb" in forward.read_text(encoding="utf-8")
    assert "rollback is unsafe while group membership facts exist" in rollback.read_text(
        encoding="utf-8"
    ).lower()
