from __future__ import annotations

from datetime import datetime, timezone
import importlib
from pathlib import Path

import pytest



UTC = timezone.utc


def _event(
    event_db_id: int,
    event_id: int,
    minute: int,
    **overrides,
) -> dict:
    return {
        "event_db_id": event_db_id,
        "event_record_id": event_db_id * 10,
        "event_id": event_id,
        "time_created_utc": datetime(2026, 8, 23, 10, minute, tzinfo=UTC),
        "domain_controller": "dc01.example.test",
        "subject_user_sid": "S-1-5-21-100",
        "subject_user_name": "operator",
        "target_user_sid": "S-1-5-21-200",
        "target_user_name": "alice",
        "source_core_sha256": b"c" * 32,
        "source_facts_sha256": b"f" * 32,
        **overrides,
    }


def _events_access() -> dict:
    return {
        "platform_owner": False,
        "capabilities": ["events.view"],
        "capability_policies": [],
        "reports": [
            {
                "report_key": "ad.state",
                "allowed": True,
                "allowed_actions": ["view"],
                "grants": [
                    {
                        "allowed_actions": ["view"],
                        "scope": {"kind": "domain", "ids": [7]},
                    }
                ],
            }
        ],
    }


def test_account_change_history_has_a_source_only_warm_fact_migration() -> None:
    root = Path(__file__).resolve().parents[2]
    forward = root / "config/postgres_migrations/086_ad_account_change_warm_facts.sql"
    rollback = root / "config/postgres_migrations/086_ad_account_change_warm_facts.rollback.sql"

    assert forward.is_file()
    assert rollback.is_file()
    assert "account_target_sid" in forward.read_text(encoding="utf-8")
    assert "account_target_name" in forward.read_text(encoding="utf-8")
    assert "account_name_before" in forward.read_text(encoding="utf-8")
    assert "account_name_after" in forward.read_text(encoding="utf-8")
    assert "rollback is unsafe while account rename facts exist" in rollback.read_text(
        encoding="utf-8"
    ).lower()
