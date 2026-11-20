from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest

from server.sli.reports.administrative_activity import (
    AdministrativeActivity,
    AdministrativeActivityError,
    append_administrative_activity,
    append_administrative_activity_with_cursor,
    load_administrative_activity_contract,
    validate_administrative_activity,
)


ROOT = Path(__file__).resolve().parents[2]
FORWARD = (ROOT / "config/postgres_migrations/066_administrative_activity_journal.sql").read_text(encoding="utf-8").lower()
ROLLBACK = (ROOT / "config/postgres_migrations/066_administrative_activity_journal.rollback.sql").read_text(encoding="utf-8").lower()


def _activity(**updates) -> AdministrativeActivity:
    value = AdministrativeActivity(
        event_uid=UUID("11111111-1111-1111-1111-111111111111"),
        occurred_at_utc=datetime(2026, 8, 2, tzinfo=timezone.utc),
        actor_kind="session",
        actor_key="fixture-user",
        category="access_management",
        action_key="access.assignment.created",
        outcome="succeeded",
        target_kind="user",
        target_key="fixture-target",
        details={"assignment_id": 7},
    )
    return replace(value, **updates)


def test_contract_is_prepared_only_without_production_application_claim():
    contract = load_administrative_activity_contract()
    assert contract["required_migration"] == 66
    assert "status" not in contract
    assert "production_migration_applied" not in contract
    assert contract["runtime_write_enabled"] is False
    assert contract["runtime_read_enabled"] is False
    assert contract["source_contact_allowed"] is False
    assert "production_migration_applied" not in contract["prepared_reader"]


def test_valid_flat_activity_is_normalized_without_secret_material():
    value = validate_administrative_activity(_activity())
    assert value["actor_key"] == "fixture-user"
    assert value["details_json"] == '{"assignment_id":7}'
    assert value["occurred_at_utc"].tzinfo is not None


@pytest.mark.parametrize(
    "details",
    [
        {"password": "x"},
        {"api_token_hash": "x"},
        {"safe": {"nested": "object"}},
        {"safe": ["nested"]},
    ],
)
def test_sensitive_or_nested_details_fail_closed(details):
    with pytest.raises(AdministrativeActivityError):
        validate_administrative_activity(_activity(details=details))


def test_migration_is_execute_only_hash_chained_and_append_only():
    assert "create table administrative_activity_v1" in FORWARD
    assert "security definer" in FORWARD
    assert "sha256(convert_to(v_content::text,'utf8'))" in FORWARD
    assert "sha256(v_previous_hash || v_content_hash)" in FORWARD
    assert "administrative activity idempotency conflict" in FORWARD
    assert "before update or delete" in FORWARD
    assert "before truncate" in FORWARD
    assert "grant execute on function append_administrative_activity_v1" in FORWARD
    assert "grant usage,create on schema public" in FORWARD
    assert "revoke create on schema public" in FORWARD
    assert "version=63 and name='radius_vpn_operations_read_boundary'" in FORWARD
    assert "version=65" not in FORWARD
    assert "set local role adlog_storage_owner" not in FORWARD.lower()
    assert "set local role adlog_storage_owner" not in ROLLBACK.lower()
    assert "rollback 066 requires migration superuser session" in ROLLBACK.lower()
    assert "radius_session_reconciliation_overlay" not in FORWARD
    assert "grant insert" not in FORWARD
    assert "grant update" not in FORWARD
    assert "grant delete" not in FORWARD
    assert "rollback 066 forbidden after administrative activity" in ROLLBACK
    assert "revoke usage on schema public" in ROLLBACK


def test_invalid_activity_is_rejected_before_database_contact():
    calls = []

    def connection_factory():
        calls.append(True)
        raise AssertionError("database must not be contacted")

    with pytest.raises(AdministrativeActivityError):
        append_administrative_activity(
            _activity(details={"credential": "forbidden"}),
            connection_factory=connection_factory,
        )
    assert calls == []


def test_existing_cursor_seam_keeps_write_inside_callers_transaction():
    class Cursor:
        def __init__(self):
            self.query = ""
            self.params = ()

        def execute(self, query, params):
            self.query = query
            self.params = params

        def fetchone(self):
            return {"activity_id": 17, "record_hash": "a" * 64}

    cursor = Cursor()
    result = append_administrative_activity_with_cursor(
        _activity(), cursor=cursor
    )
    assert result == {
        "activity_id": 17,
        "record_hash": "a" * 64,
        "event_uid": "11111111-1111-1111-1111-111111111111",
        "contains_sensitive_details": False,
    }
    assert "append_administrative_activity_v1" in cursor.query
    assert cursor.params[0] == result["event_uid"]
    assert cursor.params[10] == '{"assignment_id":7}'




