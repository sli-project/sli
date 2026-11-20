from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from server.api import http_server
from server.api.routes import reports as routes_reports
from server.sli.reports import ad_group_membership_reporting as membership_reporting


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


def test_exact_member_and_group_sid_boundaries_make_one_closed_interval() -> None:
    payload = membership_reporting.compose_ad_group_membership_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[
            _event(
                2,
                4729,
                20,
                controlled_group_context_evidence_id=91,
                controlled_group_context_observed_at_utc=datetime(2026, 8, 23, 9, tzinfo=UTC),
            ),
            _event(
                1,
                4728,
                10,
                controlled_group_context_evidence_id=91,
                controlled_group_context_observed_at_utc=datetime(2026, 8, 23, 9, tzinfo=UTC),
            ),
        ],
        collection_coverage={"history_event_present": True},
    )

    added, removed = payload["items"]
    assert added["change"] == {"operation": "added", "group_scope": "global"}
    assert removed["change"] == {"operation": "removed", "group_scope": "global"}
    assert added["membership_interval"] == removed["membership_interval"] == {
        "state": "closed_observed",
        "start": {
            "event_db_id": 1,
            "event_id": 4728,
            "time_created_utc": "2026-08-23T10:10:00Z",
        },
        "end": {
            "event_db_id": 2,
            "event_id": 4729,
            "time_created_utc": "2026-08-23T10:20:00Z",
        },
    }
    assert added["controlled_group"] == {
        "state": "observed",
        "basis": "exact_group_sid_in_persisted_controlled_scope",
        "context_evidence_id": 91,
        "context_observed_at_utc": "2026-08-23T09:00:00Z",
    }
    assert "rights_used" not in added


def test_multiple_exact_add_and_remove_boundaries_are_partial_without_invented_pairing() -> None:
    payload = membership_reporting.compose_ad_group_membership_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[
            _event(1, 4728, 10),
            _event(2, 4728, 20),
            _event(3, 4729, 30),
            _event(4, 4733, 40, membership_member_sid=None, target_user_sid=None),
        ],
        collection_coverage={"history_event_present": True},
    )

    first_add, second_add, removal, name_only_removal = payload["items"]
    assert first_add["membership_interval"] == second_add["membership_interval"] == removal["membership_interval"] == {
        "state": "partial",
        "reason": "multiple_exact_membership_boundaries_unpairable",
    }
    assert name_only_removal["membership_interval"] == {
        "state": "unknown",
        "reason": "membership_identity_not_observed",
    }
    assert first_add["controlled_group"] == {
        "state": "unknown",
        "reason": "group_not_observed_in_controlled_privileged_context",
    }


@pytest.mark.parametrize(
    ("events", "expected_state", "expected_reason"),
    [
        (
            [_event(1, 4728, 10), _event(2, 4729, 20)],
            "closed_observed",
            None,
        ),
        (
            [_event(1, 4729, 10), _event(2, 4728, 20)],
            "partial",
            "exact_membership_boundaries_out_of_order",
        ),
        (
            [_event(1, 4728, 10)],
            "open_observed",
            "matching_remove_not_observed_in_window",
        ),
        (
            [_event(1, 4728, 10), _event(2, 4729, 20), _event(3, 4729, 30)],
            "partial",
            "multiple_exact_membership_boundaries_unpairable",
        ),
    ],
)
def test_membership_interval_requires_one_unambiguous_exact_add_remove_pair(
    events: list[dict], expected_state: str, expected_reason: str | None
) -> None:
    payload = membership_reporting.compose_ad_group_membership_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=events,
        collection_coverage={"history_event_present": True},
    )

    intervals = [item["membership_interval"] for item in payload["items"]]
    assert all(interval["state"] == expected_state for interval in intervals)
    if expected_reason is not None:
        assert all(interval["reason"] == expected_reason for interval in intervals)
    else:
        assert intervals[0] == intervals[1]
        assert intervals[0]["start"]["event_db_id"] == 1
        assert intervals[0]["end"]["event_db_id"] == 2


def test_sid_placeholders_cannot_create_a_membership_interval() -> None:
    payload = membership_reporting.compose_ad_group_membership_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[
            _event(1, 4728, 10, membership_member_sid="-", target_user_sid="-"),
            _event(2, 4729, 20, membership_member_sid="-", target_user_sid="-"),
        ],
        collection_coverage={"history_event_present": True},
    )

    added, removed = payload["items"]
    assert added["member"] == {"state": "observed", "sid": None, "name": "CN=Alice,DC=example,DC=test"}
    assert added["group"] == {"state": "observed", "sid": None, "name": "Domain Admins"}
    assert added["membership_interval"]["state"] == "unknown"
    assert removed["membership_interval"]["state"] == "unknown"


def test_empty_membership_history_is_not_absence_proof() -> None:
    empty = membership_reporting.compose_ad_group_membership_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[],
        collection_coverage={"history_event_present": True},
    )
    not_collected = membership_reporting.compose_ad_group_membership_history(
        source_domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        events=[],
        collection_coverage={"history_event_present": False},
    )

    assert empty["state"] == "empty_unverified"
    assert empty["collection_coverage"]["source_completeness"] == "not_proven"
    assert not_collected["state"] == "not_collected"


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


def test_membership_history_denial_precedes_database_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        membership_reporting,
        "_read_ad_group_membership_history_data",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )

    payload = membership_reporting.get_ad_group_membership_history(
        {"platform_owner": False, "capabilities": [], "capability_policies": []},
        source_domain_id=7,
        time_from="2026-08-23T10:00:00Z",
        time_to="2026-08-23T11:00:00Z",
    )

    assert payload["state"] == "not_authorized"
    assert payload["items"] == []


def test_membership_history_route_delegates_bounded_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    def fake_service(access, **kwargs):
        captured["access"] = access
        captured.update(kwargs)
        return {"state": "available"}

    monkeypatch.setattr(routes_reports, "get_ad_group_membership_history", fake_service)

    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            assert status is None
            captured["payload"] = payload

    assert routes_reports.try_handle_get(
        FakeHandler(),
        "/api/v1/reports/ad.groups/membership-changes",
        {
            "domain_id": ["7"],
            "time_from": ["2026-08-23T10:00:00Z"],
            "time_to": ["2026-08-23T11:00:00Z"],
            "timezone": ["UTC"],
            "limit": ["25"],
        },
    )
    assert captured == {
        "access": {"server_built": True},
        "source_domain_id": 7,
        "time_from": "2026-08-23T10:00:00Z",
        "time_to": "2026-08-23T11:00:00Z",
        "timezone_name": "UTC",
        "limit": 25,
        "payload": {"state": "available"},
    }


def test_membership_reader_uses_exact_sid_and_controlled_context_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statements: list[str] = []

    class Cursor:
        select_count = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql, _params=None):
            statements.append(" ".join(str(sql).split()).lower())
            if str(sql).lstrip().lower().startswith("select"):
                self.select_count += 1

        def fetchall(self):
            assert self.select_count == 1
            return [_event(1, 4728, 10)]

        def fetchone(self):
            assert self.select_count == 2
            return {"history_event_present": True}

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(membership_reporting, "_connect", lambda: Connection())

    events, coverage = membership_reporting._read_ad_group_membership_history_data(
        domain_id=7,
        period_start=datetime(2026, 8, 23, 10, tzinfo=UTC),
        period_end=datetime(2026, 8, 23, 11, tzinfo=UTC),
        limit=25,
    )

    activity_sql = statements[1]
    assert events[0]["event_id"] == 4728
    assert coverage["history_event_present"] is True
    assert "alias.alias_type='object_sid'" in activity_sql
    assert "alias.normalized_value=lower(event.target_user_sid)" in activity_sql
    assert "context.source_section='privileged_membership'" in activity_sql
    assert "run.scope_json->'privileged_group_sids'" in activity_sql
    assert "lower(configured_group.sid)=lower(event.target_user_sid)" in activity_sql
    assert "group_name" not in activity_sql


def test_membership_http_denial_precedes_database_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(http_server, "auth_required", lambda: False)
    monkeypatch.setattr(
        membership_reporting,
        "_read_ad_group_membership_history_data",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )
    handler = object.__new__(http_server.RequestHandler)
    handler.path = (
        "/api/v1/reports/ad.groups/membership-changes?domain_id=7"
        "&time_from=2026-08-23T10:00:00Z&time_to=2026-08-23T11:00:00Z"
    )
    handler._access_decision = lambda: {
        "platform_owner": False,
        "capabilities": [],
        "capability_policies": [],
    }
    handler._require_capability = lambda _capability: pytest.fail("generic report gate must not run")
    sent: list[dict] = []
    handler._send_json = lambda payload, _status=None: sent.append(payload)

    handler._do_GET()

    assert sent[0]["state"] == "not_authorized"
