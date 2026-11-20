from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest

from server.api.http_server import RequestHandler, _required_read_role
from server.sli.access.access_control_v4 import route_capability
from server.sli.reports.administrative_activity import AdministrativeActivityError
from server.sli.reports import administrative_activity_reader as reader


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


def _access(allowed: bool) -> dict:
    return {
        "platform_owner": False,
        "capabilities": [reader.CAPABILITY] if allowed else [],
    }


def _enable_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    original = reader.load_administrative_activity_contract()
    monkeypatch.setattr(
        reader,
        "load_administrative_activity_contract",
        lambda: {**original, "runtime_read_enabled": True},
    )


def test_denied_reader_does_not_contact_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        reader, "_read_rows", lambda **_kwargs: pytest.fail("database contacted")
    )
    with pytest.raises(PermissionError, match="administrative_activity_access_denied"):
        reader.list_administrative_activity(_access(False))


def test_reader_is_bounded_and_uses_reverse_keyset(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_runtime(monkeypatch)
    captured = {}

    def fake_read(**kwargs):
        captured.update(kwargs)
        return [_row(9), _row(8), _row(7)]

    monkeypatch.setattr(reader, "_read_rows", fake_read)
    payload = reader.list_administrative_activity(
        _access(True), before_activity_id=10, category="access_management", limit=2
    )
    assert captured == {
        "before_activity_id": 10,
        "category": "access_management",
        "limit": 3,
    }
    assert [item["activity_id"] for item in payload["items"]] == [9, 8]
    assert payload["page"] == {
        "limit": 2,
        "has_more": True,
        "next_before_activity_id": 8,
    }
    assert payload["contains_sensitive_details"] is False


def test_authorized_reader_stays_disabled_before_separate_runtime_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reader, "_read_rows", lambda **_kwargs: pytest.fail("database contacted")
    )
    with pytest.raises(
        reader.AdministrativeActivityReaderUnavailable,
        match="administrative_activity_reader_runtime_disabled",
    ):
        reader.list_administrative_activity(_access(True))


@pytest.mark.parametrize(
    "kwargs,error",
    [
        ({"limit": 0}, "administrative_activity_reader_limit_invalid"),
        ({"limit": 201}, "administrative_activity_reader_limit_invalid"),
        ({"before_activity_id": 0}, "administrative_activity_reader_cursor_invalid"),
        ({"category": "unknown"}, "administrative_activity_reader_category_invalid"),
    ],
)
def test_invalid_query_fails_before_database(
    monkeypatch: pytest.MonkeyPatch, kwargs: dict, error: str
) -> None:
    monkeypatch.setattr(
        reader, "_read_rows", lambda **_kwargs: pytest.fail("database contacted")
    )
    with pytest.raises(AdministrativeActivityError, match=error):
        reader.list_administrative_activity(_access(True), **kwargs)


def test_sql_reader_has_hard_limit_capability_and_no_direct_select_grant() -> None:
    assert "create or replace function read_administrative_activity_v1" in FORWARD
    assert "p_limit > 201" in FORWARD
    assert "security definer" in FORWARD
    assert "order by current.activity_id desc" in FORWARD
    assert "grant execute on function read_administrative_activity_v1" in FORWARD
    assert "grant select on" not in FORWARD
    assert "'administrative.activity.view'" in FORWARD
    assert "rollback 072 forbidden after capability assignment" in ROLLBACK


def test_http_route_has_exact_capability_and_operator_floor() -> None:
    path = "/api/v1/operations/administrative-activity"
    assert route_capability(path) == "administrative.activity.view"
    assert _required_read_role(path) == "operator"


def test_handler_rejects_unknown_or_duplicate_query_without_reader() -> None:
    from server.api.routes import operations as routes_operations

    handler = object.__new__(RequestHandler)
    sent = []
    handler._send_json = lambda payload, status=200: sent.append((payload, status))
    routes_operations._handle_administrative_activity_api(handler, {"unknown": ["1"]})
    routes_operations._handle_administrative_activity_api(handler, {"limit": ["1", "2"]})
    assert [item[0]["error"] for item in sent] == [
        "administrative_activity_query_invalid",
        "administrative_activity_query_invalid",
    ]
