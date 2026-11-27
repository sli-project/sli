from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest



UTC = timezone.utc
ROOT = Path(__file__).resolve().parents[2]


def _event(
    event_db_id: int,
    event_id: int,
    minute: int,
    **updates,
) -> dict:
    event = {
        "event_db_id": event_db_id,
        "event_record_id": 1000 + event_db_id,
        "event_id": event_id,
        "time_created_utc": datetime(2026, 8, 21, 10, minute, tzinfo=UTC),
        "domain_controller": "dc-02.example.test",
        "subject_user_sid": "S-1-5-21-101",
        "subject_user_name": "CORP\\operator",
        "powershell_user_name": None,
        "powershell_command_name": None,
        "powershell_script_block_text": None,
        "source_core_sha256": bytes.fromhex("aa" * 32),
        "source_facts_sha256": bytes.fromhex("bb" * 32),
    }
    event.update(updates)
    return event


def _events_access(*, domain_id: int = 7) -> dict:
    return {
        "platform_owner": False,
        "capabilities": [],
        "capability_policies": [{
            "capability_key": "events.view",
            "effect": "allow",
            "valid": True,
            "scope": {"kind": "domain", "ids": [domain_id]},
        }],
    }


def _single_security_boot_scope(boot_event_db_id: int = 15) -> dict:
    return {
        "origin_process_start_boot_event_db_id": boot_event_db_id,
        "origin_process_stop_boot_event_db_id": boot_event_db_id,
        "origin_session_start_boot_event_db_id": boot_event_db_id,
        "origin_session_end_boot_event_db_id": boot_event_db_id,
    }


def test_powershell_warm_facts_have_a_bounded_source_only_migration() -> None:
    forward_path = ROOT / "config/postgres_migrations/084_dc_powershell_warm_facts.sql"
    rollback_path = ROOT / "config/postgres_migrations/084_dc_powershell_warm_facts.rollback.sql"

    assert forward_path.is_file()
    assert rollback_path.is_file()
    forward = forward_path.read_text(encoding="utf-8").lower()
    rollback = rollback_path.read_text(encoding="utf-8").lower()
    assert "alter table event_facts_v2" in forward
    assert "powershell_command_name" in forward
    assert "powershell_script_block_text" in forward
    assert "powershell_user_name" in forward
    assert "length(powershell_script_block_text) <= 2048" in forward
    assert "insert into schema_migrations(version,name)" in forward
    assert "rollback is unsafe while powershell warm facts exist" in rollback


def test_powershell_origin_context_has_a_bounded_source_only_migration() -> None:
    forward_path = ROOT / "config/postgres_migrations/085_dc_powershell_origin_context.sql"
    rollback_path = ROOT / "config/postgres_migrations/085_dc_powershell_origin_context.rollback.sql"

    assert forward_path.is_file()
    assert rollback_path.is_file()
    forward = forward_path.read_text(encoding="utf-8").lower()
    rollback = rollback_path.read_text(encoding="utf-8").lower()
    assert "powershell_process_id" in forward
    assert "length(powershell_process_id) <= 128" in forward
    assert "migration 085 requires migration 084" in forward
    assert "rollback is unsafe while powershell process facts exist" in rollback
