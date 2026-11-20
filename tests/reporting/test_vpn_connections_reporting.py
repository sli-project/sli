from __future__ import annotations


from datetime import datetime, timezone

import pytest

from server.sli.reports import vpn_connections_reporting as reporting

UTC = timezone.utc
PERIOD_START = datetime(2026, 8, 1, tzinfo=UTC)
PERIOD_END = datetime(2026, 9, 1, tzinfo=UTC)


def _session(
    row_id: str,
    start: datetime,
    stop: datetime | None,
    *,
    entity_id: int = 101,
    last_observed: datetime | None = None,
) -> dict:
    return {
        "session_row_id": row_id,
        "entity_id": entity_id,
        "domain_id": 7,
        "generation": 1,
        "lifecycle_state": "closed" if stop else "open_observed",
        "completeness": "complete" if stop else "partial",
        "started_at_utc": start,
        "last_observed_at_utc": last_observed or stop or start,
        "stopped_at_utc": stop,
        "duration_seconds": int((stop - start).total_seconds()) if stop else None,
        "observation_count": 2 if stop else 1,
        "anomalies": (),
    }


def _identity(entity_id: int = 101) -> dict:
    return {
        "entity_id": entity_id,
        "display_name": "Иванов Иван Иванович",
        "natural_key": "ad:example.test:user:internal-canonical-key",
        "sam_account_name": "ivanov",
        "netbios_name": "EXAMPLE",
        "department": "ИТ",
        "enabled": True,
        "last_logon_utc": datetime(2026, 7, 31, tzinfo=UTC),
        "privileged": False,
    }


def _compose(
    sessions: list[dict],
    *,
    identities: dict[int, dict] | None = None,
    coverage: dict | None = None,
    entitlement_rows: list[dict] | None = None,
    failed_events: list[dict] | None = None,
    failed_collection_state: str = "not_collected",
) -> dict:
    return reporting.compose_vpn_connections_report(
        source_domain_id=7,
        period_start=PERIOD_START,
        period_end=PERIOD_END,
        office_timezone="Asia/Novosibirsk",
        coverage=coverage or {
            "total_delivery_count": len(sessions),
            "queued_delivery_count": 0,
            "leased_delivery_count": 0,
            "failed_delivery_count": 0,
            "quarantined_delivery_count": 0,
            "projected_session_count": len(sessions),
            "identity_unresolved_count": 0,
            "timestamp_unresolved_count": 0,
        },
        session_rows=sessions,
        identities=identities or {101: _identity()},
        entitlement_rows=entitlement_rows or [],
        failed_events=failed_events or [],
        failed_collection_state=failed_collection_state,
    )


def test_identity_is_human_readable_and_never_an_ad_object_label() -> None:
    payload = _compose([
        _session(
            "s1",
            datetime(2026, 8, 14, 9, tzinfo=UTC),
            datetime(2026, 8, 14, 10, tzinfo=UTC),
        )
    ])
    employee = payload["employees"][0]
    assert employee["display_name"] == "Иванов Иван Иванович"
    assert employee["account_name"] == r"EXAMPLE\ivanov"
    assert employee["department"] == "ИТ"
    assert "Объект AD #" not in str(payload)


@pytest.mark.parametrize(
    ("sessions", "seconds", "overlap"),
    [
        (
            [_session("s1", datetime(2026, 8, 14, 9, tzinfo=UTC), datetime(2026, 8, 14, 10, tzinfo=UTC))],
            3600,
            False,
        ),
        (
            [_session("s1", datetime(2026, 7, 31, 8, tzinfo=UTC), datetime(2026, 9, 2, 12, tzinfo=UTC))],
            int((PERIOD_END - PERIOD_START).total_seconds()),
            False,
        ),
        (
            [
                _session("s1", datetime(2026, 8, 14, 9, tzinfo=UTC), datetime(2026, 8, 14, 10, tzinfo=UTC)),
                _session("s2", datetime(2026, 8, 14, 9, 30, tzinfo=UTC), datetime(2026, 8, 14, 11, tzinfo=UTC)),
            ],
            7200,
            True,
        ),
    ],
)
def test_closed_session_clipping_union_and_overlap(
    sessions: list[dict],
    seconds: int,
    overlap: bool,
) -> None:
    employee = _compose(sessions)["employees"][0]
    assert employee["confirmed_seconds"] == seconds
    assert employee["overlap_violation"] is overlap
    assert employee["overlap_count"] == (1 if overlap else 0)


def test_open_session_is_visible_but_never_gets_invented_duration() -> None:
    closed = _session(
        "closed",
        datetime(2026, 8, 14, 9, tzinfo=UTC),
        datetime(2026, 8, 14, 10, tzinfo=UTC),
    )
    opened = _session(
        "open",
        datetime(2026, 8, 15, 9, tzinfo=UTC),
        None,
        last_observed=datetime(2026, 8, 15, 9, 10, tzinfo=UTC),
    )
    employee = _compose([closed, opened])["employees"][0]
    assert employee["confirmed_seconds"] == 3600
    assert employee["open_session_count"] == 1
    open_row = next(item for item in employee["sessions"] if item["session_row_id"] == "open")
    assert open_row["confirmed_seconds_in_period"] is None
    assert open_row["duration_seconds"] is None
    assert open_row["overlap_violation"] is False


def test_only_open_sessions_make_confirmed_time_unknown_not_zero() -> None:
    employee = _compose([
        _session(
            "open",
            datetime(2026, 8, 15, 9, tzinfo=UTC),
            None,
            last_observed=datetime(2026, 8, 15, 9, 10, tzinfo=UTC),
        )
    ])["employees"][0]
    assert employee["confirmed_seconds"] is None
    assert employee["confirmed_minutes"] is None


def test_single_start_observation_inside_period_remains_visible() -> None:
    started = datetime(2026, 8, 15, 9, tzinfo=UTC)
    employee = _compose([
        _session("open-point", started, None, last_observed=started)
    ])["employees"][0]
    assert employee["open_session_count"] == 1
    assert employee["confirmed_seconds"] is None


def test_rounding_happens_after_exact_interval_union() -> None:
    employee = _compose([
        _session(
            "a",
            datetime(2026, 8, 14, 9, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 14, 9, 0, 31, tzinfo=UTC),
        ),
        _session(
            "b",
            datetime(2026, 8, 14, 9, 1, 0, tzinfo=UTC),
            datetime(2026, 8, 14, 9, 1, 31, tzinfo=UTC),
        ),
    ])["employees"][0]
    assert employee["confirmed_seconds"] == 62
    assert employee["confirmed_minutes"] == 1


def test_partial_coverage_keeps_projected_rows_and_unresolved_count() -> None:
    coverage = {
        "total_delivery_count": 602,
        "queued_delivery_count": 0,
        "leased_delivery_count": 0,
        "failed_delivery_count": 0,
        "quarantined_delivery_count": 0,
        "projected_session_count": 510,
        "identity_unresolved_count": 92,
        "timestamp_unresolved_count": 0,
    }
    payload = _compose([
        _session("s1", datetime(2026, 8, 14, 9, tzinfo=UTC), datetime(2026, 8, 14, 10, tzinfo=UTC))
    ], coverage=coverage)
    assert payload["state"] == "partial"
    assert len(payload["employees"]) == 1
    assert payload["coverage"]["projected_session_count"] == 510
    assert payload["coverage"]["identity_unresolved_count"] == 92


def test_period_membership_uses_interval_intersection_not_last_observed_only() -> None:
    row = _session(
        "crosses-period",
        datetime(2026, 7, 31, 23, 30, tzinfo=UTC),
        datetime(2026, 8, 1, 0, 30, tzinfo=UTC),
    )
    assert reporting.session_intersects_period(row, PERIOD_START, PERIOD_END) is True
    assert _compose([row])["employees"][0]["confirmed_seconds"] == 1800


def test_canonical_ad_account_projection_is_shared_without_natural_key_fallback() -> None:
    row = _session(
        "radius-session-row:f0f2a2ebf55900c086ad22013daaddc5291749c07edc8be6b8d2769d05024b59",
        datetime(2026, 8, 14, 8, 20, 27, tzinfo=UTC),
        datetime(2026, 8, 14, 8, 24, 2, tzinfo=UTC),
        entity_id=42369557,
    )
    identity = {
        "entity_id": 42369557,
        "display_name": "Степанова Светлана Олеговна",
        "natural_key": "ad:example.test:user:internal-canonical-key",
        "sam_account_name": "coordfrs",
        "netbios_name": "EXAMPLE",
        "department": "Не определено",
        "enabled": True,
        "last_logon_utc": None,
        "privileged": False,
    }
    failed_events = [
        {
            "event_db_id": 701,
            "event_record_id": 9001,
            "event_id": 6273,
            "time_created_utc": datetime(2026, 8, 14, 8, 19, tzinfo=UTC),
            "subject_user_name": "observed-name-must-not-win",
            "subject_domain_name": "OBSERVED",
            "reason_code": "16",
            "entity_id": 42369557,
            "source_core_sha256": b"a" * 32,
        },
        {
            "event_db_id": 702,
            "event_record_id": 9002,
            "event_id": 6273,
            "time_created_utc": datetime(2026, 8, 14, 8, 25, tzinfo=UTC),
            "subject_user_name": "unresolved-user",
            "subject_domain_name": "EVENTDOMAIN",
            "reason_code": "48",
            "entity_id": None,
            "source_core_sha256": b"b" * 32,
        },
    ]
    payload = _compose(
        [row],
        identities={42369557: identity},
        entitlement_rows=[{"entity_id": 42369557}],
        failed_events=failed_events,
        failed_collection_state="available",
    )
    employee = payload["employees"][0]
    assert employee["display_name"] == "Степанова Светлана Олеговна"
    assert employee["account_name"] == r"EXAMPLE\coordfrs"
    assert employee["confirmed_seconds"] == 215
    assert employee["confirmed_minutes"] == 4
    assert payload["entitlements"]["items"][0]["account_name"] == r"EXAMPLE\coordfrs"
    assert payload["failed_authorizations"]["items"][0]["account_name"] == r"EXAMPLE\coordfrs"
    assert payload["failed_authorizations"]["items"][0]["identity_state"] == "resolved"
    assert payload["failed_authorizations"]["items"][1]["account_name"] == r"EVENTDOMAIN\unresolved-user"
    assert payload["failed_authorizations"]["items"][1]["identity_state"] == "unresolved"


def test_missing_canonical_sam_does_not_expose_internal_natural_key() -> None:
    internal_key = "ad:example.test:user:internal-canonical-key"
    identity = {
        "entity_id": 101,
        "display_name": "Иванов Иван Иванович",
        "natural_key": internal_key,
        "sam_account_name": None,
        "netbios_name": "EXAMPLE",
    }
    payload = _compose(
        [_session("s1", datetime(2026, 8, 14, 9, tzinfo=UTC), datetime(2026, 8, 14, 10, tzinfo=UTC))],
        identities={101: identity},
    )
    assert payload["employees"][0]["account_name"] == "Не определено"
    assert internal_key not in str(payload)


def test_durable_6273_rows_resolve_identity_and_preserve_unresolved_state() -> None:
    events = [
        {
            "event_db_id": 701,
            "event_record_id": 9001,
            "event_id": 6273,
            "time_created_utc": datetime(2026, 8, 14, 9, tzinfo=UTC),
            "subject_user_sid": "S-1-5-21-example-1001",
            "subject_user_name": "ivanov",
            "subject_domain_name": "EXAMPLE",
            "reason_code": "16",
            "entity_id": 101,
            "source_core_sha256": b"a" * 32,
        },
        {
            "event_db_id": 702,
            "event_record_id": 9002,
            "event_id": 6273,
            "time_created_utc": datetime(2026, 8, 14, 10, tzinfo=UTC),
            "subject_user_sid": "S-1-5-21-example-9999",
            "subject_user_name": "unknown-user",
            "subject_domain_name": "EXAMPLE",
            "reason_code": "48",
            "entity_id": None,
            "source_core_sha256": b"b" * 32,
        },
    ]
    payload = _compose(
        [],
        failed_events=events,
        failed_collection_state="available",
    )
    items = payload["failed_authorizations"]["items"]
    assert items[0]["display_name"] == "Иванов Иван Иванович"
    assert items[0]["account_name"] == r"EXAMPLE\ivanov"
    assert items[0]["identity_state"] == "resolved"
    assert items[1]["display_name"] == "Не определено"
    assert items[1]["account_name"] == r"EXAMPLE\unknown-user"
    assert items[1]["identity_state"] == "unresolved"
    assert all(item["event_id"] == 6273 for item in items)


def test_absent_6273_collection_is_not_reported_as_zero_failures() -> None:
    failed = _compose([], failed_collection_state="not_collected")["failed_authorizations"]
    assert failed["state"] == "not_collected"
    assert failed["items"] == []
    assert failed["count"] is None


def test_failed_6273_bound_is_unavailable_not_empty_and_keeps_accounting_data() -> None:
    payload = _compose(
        [_session("s1", datetime(2026, 8, 14, 9, tzinfo=UTC), datetime(2026, 8, 14, 10, tzinfo=UTC))],
        failed_collection_state="unavailable",
    )

    assert payload["state"] == "partial"
    assert payload["employees"][0]["entity_id"] == 101
    assert payload["entitlements"]["state"] == "available"
    assert payload["failed_authorizations"] == {
        "state": "unavailable",
        "unavailable_reason": "input_event_bound_exceeded",
        "count": None,
        "items": [],
    }
    assert any("не показаны" in limitation for limitation in payload["limitations"])


def test_report_keeps_authorized_accounting_and_ad_branches_when_6273_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reporting, "get_display_timezone", lambda _timezone_name=None: (UTC, "UTC"))
    monkeypatch.setattr(
        reporting,
        "_read_report_data",
        lambda **_kwargs: {
            "coverage": {
                "total_delivery_count": 1,
                "queued_delivery_count": 0,
                "leased_delivery_count": 0,
                "failed_delivery_count": 0,
                "quarantined_delivery_count": 0,
                "projected_session_count": 1,
                "identity_unresolved_count": 0,
                "timestamp_unresolved_count": 0,
            },
            "sessions": [_session("s1", datetime(2026, 8, 14, 9, tzinfo=UTC), datetime(2026, 8, 14, 10, tzinfo=UTC))],
            "identities": {101: _identity()},
            "entitlements": [{"entity_id": 101}],
            "failed_events": [],
            "failed_collection_state": "unavailable",
            "failed_authorization_unavailable_reason": "input_event_bound_exceeded",
        },
    )
    access = {
        "platform_owner": False,
        "capabilities": ["vpn.sessions.view"],
        "capability_policies": [],
        "reports": [{
            "report_key": "vpn.audit",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{"allowed_actions": ["view"], "scope": {"kind": "domain", "ids": [7]}}],
        }],
    }

    payload = reporting.get_vpn_connections_report(
        access,
        source_domain_id=7,
        time_from="2026-08-01T00:00:00Z",
        time_to="2026-09-01T00:00:00Z",
    )

    assert payload["state"] == "partial"
    assert payload["employees"][0]["entity_id"] == 101
    assert payload["entitlements"]["items"][0]["entity_id"] == 101
    assert payload["failed_authorizations"]["state"] == "unavailable"
    assert payload["branches"]["directory"]["state"] == "available"
    assert payload["branches"]["sessions"]["state"] == "available"


def test_denied_new_report_does_not_read_postgresql(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "_read_report_data",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )
    payload = reporting.get_vpn_connections_report(
        {"platform_owner": False, "capabilities": [], "reports": []},
        source_domain_id=7,
    )
    assert payload["state"] == "not_authorized"
    assert payload["employees"] == []


def _v2_handler(sent: list):
    class FakeHandler:
        def _access_decision(self):
            return {"server_built": True, "reports": [{"report_key": "vpn.audit", "allowed": True}]}

        def _send_json(self, payload, status=None):
            sent.append((payload, int(status or 200)))

    return FakeHandler()


@pytest.mark.parametrize("tab,nps_event", [
    ("employees", None), ("daily", None), ("departments", None),
    ("entitlements", None), ("failed", None), ("authorizations", None),
    ("failed", 6273), ("authorizations", 6272), ("authorizations", 6273),
])
def test_v2_missing_accounting_coverage_is_not_collected(monkeypatch, tab, nps_event):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from server.api.routes import reports_v2
    from server.sli.reporting.v2.reports import vpn_connections

    class Cursor:
        def execute(self, sql, params=None):
            if sql == "set transaction read only":
                return
            assert "from radius_vpn_session_coverage_v1 where domain_id=%s" in sql
            assert params == (7,)

        def fetchone(self):
            return None

    connection = SimpleNamespace(cursor=lambda: nullcontext(Cursor()))
    monkeypatch.setattr(reporting, "_connect", lambda: nullcontext(connection))
    monkeypatch.setattr(vpn_connections, "_domain_options", lambda _access: [])
    nps_items = ([{"event_db_id": 9, "event_id": nps_event,
                   "authorization_result": "allowed" if nps_event == 6272 else "denied"}]
                 if nps_event else [])
    monkeypatch.setattr(vpn_connections, "get_vpn_authorization_timeline", lambda *_a, **_k: {
        "state": "available" if nps_items else "not_collected", "items": nps_items,
    })
    sent: list = []
    handler = _v2_handler(sent)
    handler._access_decision = lambda: {
        "capabilities": ["vpn.sessions.view"],
        "reports": [{
            "report_key": "vpn.audit", "allowed": True, "allowed_actions": ["view"],
            "grants": [{"allowed_actions": ["view"], "scope": {"kind": "domain", "ids": [7]}}],
        }],
    }

    assert reports_v2.try_handle_get(handler, "/api/v2/reports/vpn.connections/data", {
        "domain": ["7"], "period": ["custom"], "from": ["2026-08-01T00:00:00Z"],
        "to": ["2026-08-02T00:00:00Z"], "tz": ["UTC"], "tab": [tab],
    })
    payload, status = sent[0]
    assert status == 200
    assert payload["state"] == ("partial" if nps_items else "not_collected")
    assert payload["branches"]["accounting"]["state"] == "not_collected"
    assert payload["branches"]["accounting"]["reason"] == "no_accounting_data"
    assert payload["items"] == []
    assert payload["metrics"] == []
    assert payload["has_more"] is False
    assert payload["next_cursor"] is None
    assert payload["coverage"]["missing_sources"] == ["accounting"] + (
        ["nps"] if tab in {"failed", "authorizations"} and not nps_items else [])
    if tab != "employees":
        assert len(payload["collections"][tab]) == len(nps_items)
    if nps_items:
        assert payload["collections"][tab][0]["event_id"] == nps_event
    assert any(note["code"] == "vpn_source_unreadable" for note in payload["limitations"])


def test_v2_passes_bounded_filters_and_server_access(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.api.routes import reports_v2
    from server.sli.reporting.v2.reports import vpn_connections

    captured: dict = {}

    def fake_report(access, **kwargs):
        captured["access"] = access
        captured.update(kwargs)
        return {"state": "available", "employees": [], "employee_page": {"has_more": False}}

    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", fake_report)
    monkeypatch.setattr(vpn_connections, "_domain_options", lambda access: [])
    sent: list = []
    reports_v2.try_handle_get(_v2_handler(sent), "/api/v2/reports/vpn.connections/data", {
        "domain": ["7"], "period": ["custom"], "from": ["2026-08-01"], "to": ["2026-08-31"], "tz": ["Asia/Novosibirsk"],
        "q": ["synthetic"], "department": ["Synthetic"], "status": ["open"], "limit": ["50"], "cursor": ["10"],
    })
    assert captured == {
        "access": {"server_built": True, "reports": [{"report_key": "vpn.audit", "allowed": True}]},
        "source_domain_id": 7, "time_from": "2026-07-31T17:00:00Z", "time_to": "2026-08-31T17:00:00Z",
        "search": "synthetic", "department": "Synthetic", "status": "open", "employee_limit": 50, "employee_offset": 10,
        "include_failed_authorizations": False,
    }
    assert sent[0][1] == 200 and sent[0][0]["state"] == "empty"


@pytest.mark.parametrize("tab", [None, "employees", "daily", "departments", "entitlements",
                                 "failed", "authorizations", "windows", "windows_heatmap"])
def test_v2_thirty_day_request_contains_accounting_timeout(monkeypatch, tab):
    from psycopg.errors import QueryCanceled

    from server.api.routes import reports_v2
    from server.sli.reporting.v2.reports import vpn_connections

    def timed_out(_access, **kwargs):
        assert kwargs["source_domain_id"] == 1
        assert kwargs["include_failed_authorizations"] is False
        raise QueryCanceled("synthetic statement timeout")

    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", timed_out)
    monkeypatch.setattr(vpn_connections, "_domain_options", lambda _access: [])
    monkeypatch.setattr(vpn_connections, "log_internal_error", lambda *_a, **_k: "synthetic")
    for reader in ("get_vpn_authorization_timeline", "get_windows_authentication_report"):
        monkeypatch.setattr(vpn_connections, reader, lambda *_a, **_k: {"state": "available", "items": []})
    monkeypatch.setattr(vpn_connections, "get_windows_authentication_failure_grid",
                        lambda *_a, **_k: {"state": "available", "cells": []})
    query = {"domain": ["1"], "period": ["30d"], "overlap_complete": ["false"]}
    if tab:
        query["tab"] = [tab]
    sent = []
    assert reports_v2.try_handle_get(_v2_handler(sent), "/api/v2/reports/vpn.connections/data", query)
    payload, status = sent[0]
    assert status == 200 and payload["items"] == []
    assert payload["branches"]["accounting"]["reason"] == "source_read_timeout"
    assert payload["metrics"] == []
    assert payload["window"]["source_domain_id"] == 1
    assert payload["state"] == "partial"


def test_v2_domain_options_timeout_does_not_discard_report_rows(monkeypatch):
    from psycopg.errors import QueryCanceled

    from server.sli.reporting.v2.reports import vpn_connections

    def timed_out(_access):
        raise QueryCanceled("synthetic statement timeout")

    monkeypatch.setattr(vpn_connections, "get_vpn_session_sources", timed_out)
    monkeypatch.setattr(vpn_connections.nps_policy_denials, "domain_options", lambda _a: [])
    monkeypatch.setattr(vpn_connections, "log_internal_error", lambda *_a, **_k: "synthetic")
    assert vpn_connections._domain_options({}) == []


def test_v2_keeps_partial_report_and_unknown_open_only_time(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.api.routes import reports_v2
    from server.sli.reporting.v2.reports import vpn_connections

    monkeypatch.setattr(vpn_connections, "_domain_options", lambda access: [])
    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", lambda _access, **_kwargs: {
        "state": "partial",
        "employees": [
            {"entity_id": 101, "closed_session_count": 0, "open_session_count": 1, "confirmed_minutes": 0, "sessions": []},
            {"entity_id": 102, "closed_session_count": 2, "open_session_count": 0, "confirmed_minutes": 90, "sessions": [{"duration_seconds": 5400}]},
        ],
        "employee_page": {"has_more": False},
        "failed_authorizations": {"state": "unavailable", "unavailable_reason": "input_event_bound_exceeded", "count": None, "items": []},
    })
    sent: list = []
    reports_v2.try_handle_get(_v2_handler(sent), "/api/v2/reports/vpn.connections/data", {"domain": ["7"]})
    payload, status = sent[0]
    assert status == 200 and payload["state"] == "partial"
    assert [row["confirmed_hours"] for row in payload["items"]] == [None, 1.5]
    assert payload["items"][1]["sessions"][0]["duration_minutes"] == 90
    assert payload["collections"]["failed"] == []


def test_v2_nps_and_windows_tabs_are_built_only_when_open(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.api.routes import reports_v2
    from server.sli.reporting.v2.reports import vpn_connections

    calls: list[str] = []
    monkeypatch.setattr(vpn_connections, "_domain_options", lambda access: [])
    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", lambda _access, **_kwargs: {"state": "available", "employees": [], "employee_page": {}})
    monkeypatch.setattr(vpn_connections, "get_vpn_authorization_timeline", lambda _access, **kwargs: calls.append("nps") or {"state": "available", "items": [
        {"event_db_id": 9, "event_id": 6273, "authorization_result": "denied", "reason_code": 16, "identity_state": "ambiguous", "identity": {"observed_subject_sid": "S-1-5-21-1"}},
    ]})
    monkeypatch.setattr(vpn_connections, "get_windows_authentication_report", lambda _access, **kwargs: calls.append("windows") or {
        "state": "empty_unverified", "items": [], "limitations": ["empty_window_source_completeness_not_proven"],
        "manual_review_policy": {"conditions": {"rolling_window_minutes": 10}, "signals": [{"source_ip": "10.0.0.5", "failure_fact_count": 7, "distinct_target_sid_count": 3}]},
    })
    sent: list = []
    reports_v2.try_handle_get(_v2_handler(sent), "/api/v2/reports/vpn.connections/data", {"domain": ["7"]})
    assert calls == [] and "authorizations" not in sent[0][0]["collections"]

    reports_v2.try_handle_get(_v2_handler(sent), "/api/v2/reports/vpn.connections/data", {"domain": ["7"], "tab": ["authorizations"]})
    row = sent[1][0]["collections"]["authorizations"][0]
    assert calls == ["nps"]
    assert row["decision"] == "отказано" and row["reason"] == 16
    assert row["identity_text"] == "S-1-5-21-1" and row["identity_state_text"] == "неоднозначна"

    reports_v2.try_handle_get(_v2_handler(sent), "/api/v2/reports/vpn.connections/data", {"domain": ["7"], "tab": ["windows"]})
    texts = " ".join(item["text"] for item in sent[2][0]["limitations"])
    assert calls == ["nps", "windows"] and sent[2][0]["collections"]["windows"] == []
    assert "полнота источника не подтверждена" in texts and "10.0.0.5" in texts and "не вывод об атаке" in texts


def test_v2_windows_tab_explains_a_too_wide_window(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.api.routes import reports_v2
    from server.sli.reporting.v2.reports import vpn_connections

    def too_wide(_access, **_kwargs):
        raise reporting.TimeRangeError("windows_authentication_period_too_wide")

    monkeypatch.setattr(vpn_connections, "_domain_options", lambda access: [])
    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", lambda _access, **_kwargs: {"state": "available", "employees": [], "employee_page": {}})
    monkeypatch.setattr(vpn_connections, "get_windows_authentication_report", too_wide)
    sent: list = []
    reports_v2.try_handle_get(_v2_handler(sent), "/api/v2/reports/vpn.connections/data", {"domain": ["7"], "period": ["90d"], "tab": ["windows"]})
    assert sent[0][1] == 200
    assert any("90 дней" in item["text"] for item in sent[0][0]["limitations"])


def test_default_period_is_current_calendar_month_in_office_timezone() -> None:
    start, end = reporting._report_period(
        None,
        None,
        office_timezone="Asia/Novosibirsk",
        now=datetime(2026, 8, 14, 12, tzinfo=UTC),
    )
    assert start == datetime(2026, 7, 31, 17, tzinfo=UTC)
    assert end == datetime(2026, 8, 31, 17, tzinfo=UTC)


def test_explicit_period_cannot_exceed_hard_bound() -> None:
    with pytest.raises(reporting.TimeRangeError, match="vpn_connections_period_too_wide"):
        reporting._report_period(
            "2025-01-01",
            "2026-01-02",
            office_timezone="UTC",
        )


def test_postgresql_read_is_source_scoped_and_uses_interval_intersection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statements: list[str] = []

    class Cursor:
        index = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql, _params=None):
            statements.append(" ".join(str(sql).split()))
            self.index += 1

        def fetchone(self):
            if self.index == 2:
                return {
                    "domain_id": 7,
                    "total_delivery_count": 0,
                    "projected_session_count": 0,
                }
            if self.index == 6:
                return {"collected": False}
            raise AssertionError(f"unexpected fetchone after statement {self.index}")

        def fetchall(self):
            if self.index == 3:
                return [{"entity_id": 42369557}]
            if self.index == 4:
                return [{"entity_id": 42369557}]
            if self.index == 5:
                return []
            if self.index == 7:
                return [{
                    "entity_id": 42369557,
                    "display_name": "Степанова Светлана Олеговна",
                    "natural_key": "ad:example.test:user:internal-canonical-key",
                    "sam_account_name": "coordfrs",
                    "netbios_name": "EXAMPLE",
                }]
            raise AssertionError(f"unexpected fetchall after statement {self.index}")

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(reporting, "_connect", lambda: Connection())
    data = reporting._read_report_data(
        domain_id=7,
        period_start=PERIOD_START,
        period_end=PERIOD_END,
    )
    session_sql = next(sql for sql in statements if "from radius_vpn_session_rows_v1" in sql)
    assert "started_at_utc<%s" in session_sql
    assert "stopped_at_utc is not null and stopped_at_utc>%s" in session_sql
    assert "stopped_at_utc is null and last_observed_at_utc>=%s" in session_sql
    failed_sql = next(sql for sql in statements if "facts.result_code as reason_code" in sql)
    assert "event.event_id=6273" in failed_sql
    assert "channel.value='Security'" in failed_sql
    assert "provider.value='Microsoft-Windows-Security-Auditing'" in failed_sql
    identity_sql = next(sql for sql in statements if "from entities_v2 entity" in sql)
    assert "entity.natural_key" not in identity_sql
    assert "domain_row.netbios_name" in identity_sql
    assert "sam_account_name" in identity_sql
    assert data["identities"][42369557]["netbios_name"] == "EXAMPLE"
    assert data["identities"][42369557]["sam_account_name"] == "coordfrs"


def test_failed_6273_input_bound_is_isolated_from_accounting_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statements: list[tuple[str, tuple | None]] = []

    class Cursor:
        index = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql, params=None):
            statements.append((" ".join(str(sql).split()), params))
            self.index += 1

        def fetchone(self):
            if self.index == 2:
                return {"domain_id": 7, "total_delivery_count": 1, "projected_session_count": 1}
            if self.index == 6:
                return {"collected": True}
            raise AssertionError(f"unexpected fetchone after statement {self.index}")

        def fetchall(self):
            if self.index in {3, 4}:
                return []
            if self.index == 5:
                return [{"event_db_id": event_id} for event_id in range(reporting.MAX_FAILED_EVENT_ROWS + 1)]
            raise AssertionError(f"unexpected fetchall after statement {self.index}")

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(reporting, "_connect", lambda: Connection())
    data = reporting._read_report_data(
        domain_id=7,
        period_start=PERIOD_START,
        period_end=PERIOD_END,
    )

    failed_sql, failed_params = next(item for item in statements if "facts.result_code as reason_code" in item[0])
    assert "event.event_id=6273" in failed_sql
    assert "channel.value='Security'" in failed_sql
    assert "provider.value='Microsoft-Windows-Security-Auditing'" in failed_sql
    assert failed_params is not None and failed_params[-1] == reporting.MAX_FAILED_EVENT_ROWS + 1
    assert data["coverage"]["projected_session_count"] == 1
    assert data["entitlements"] == []
    assert data["failed_events"] == []
    assert data["failed_collection_state"] == "unavailable"
    assert data["failed_authorization_unavailable_reason"] == "input_event_bound_exceeded"


def test_accounting_reader_can_skip_nps_read_models(monkeypatch: pytest.MonkeyPatch) -> None:
    class Cursor:
        sql = ""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql, _params=None):
            self.sql = sql
            if "events_v2_core" in sql:
                pytest.fail("Accounting must not depend on NPS read privileges")

        def fetchone(self):
            return {"domain_id": 7, "projected_session_count": 1}

        def fetchall(self):
            if "radius_vpn_session_rows_v1" in self.sql:
                return [_session("synthetic-session", datetime(2026, 8, 14, 9, tzinfo=UTC), datetime(2026, 8, 14, 10, tzinfo=UTC))]
            if "from entities_v2 entity" in self.sql:
                return [{"entity_id": 101}]
            return []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(reporting, "_connect", lambda: Connection())
    data = reporting._read_report_data(domain_id=7, period_start=PERIOD_START, period_end=PERIOD_END, include_failed_authorizations=False)
    assert data["sessions"][0]["session_row_id"] == "synthetic-session"
    assert data["failed_events"] == []


def test_v2_one_chosen_day_stays_one_day_when_server_zone_differs(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.api.routes import reports_v2
    from server.sli.reporting.v2.reports import vpn_connections

    captured: dict = {}
    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", lambda _access, **kwargs: captured.update(kwargs) or {"state": "available", "employees": [], "employee_page": {}})
    monkeypatch.setattr(vpn_connections, "_domain_options", lambda access: [])
    reports_v2.try_handle_get(_v2_handler([]), "/api/v2/reports/vpn.connections/data", {
        "domain": ["7"], "period": ["custom"], "from": ["2026-09-14"], "to": ["2026-09-14"], "tz": ["Asia/Novosibirsk"],
    })
    assert (captured["time_from"], captured["time_to"]) == ("2026-09-13T17:00:00Z", "2026-09-14T17:00:00Z")


@pytest.mark.parametrize("tab", ["employees", "daily", "departments", "entitlements", "failed", "authorizations", "windows", "windows_heatmap"])
@pytest.mark.parametrize(("query", "zone", "now", "expected"), [
    ({"period": "7d"}, "Asia/Novosibirsk", datetime(2026, 10, 5, 12, 34, 56, tzinfo=UTC),
     ("2026-09-28T12:34:56Z", "2026-10-05T12:34:56Z")),
    ({"period": "7d"}, "America/New_York", datetime(2026, 3, 9, 12, tzinfo=UTC),
     ("2026-03-02T12:00:00Z", "2026-03-09T12:00:00Z")),
    ({"period": "24h"}, "Asia/Novosibirsk", datetime(2026, 10, 5, 12, 34, 56, tzinfo=UTC),
     ("2026-10-04T12:34:56Z", "2026-10-05T12:34:56Z")),
    ({"period": "custom", "from": "2026-09-14", "to": "2026-09-14"}, "Asia/Novosibirsk", None,
     ("2026-09-13T17:00:00Z", "2026-09-14T17:00:00Z")),
    ({"period": "custom", "from": "2026-09-14T11:23:45Z", "to": "2026-09-14T13:45:56Z"}, "Asia/Novosibirsk", None,
     ("2026-09-14T11:23:45Z", "2026-09-14T13:45:56Z")),
])
def test_v2_all_sources_use_the_same_exact_window(monkeypatch, tab, query, zone, now, expected) -> None:
    from server.sli.reporting.v2.definition import QueryContext, parse_params
    from server.sli.reporting.v2.reports import vpn_connections

    calls: dict = {}
    monkeypatch.setattr(reporting, "get_display_timezone", lambda _name=None: (UTC, "UTC"))
    monkeypatch.setattr(vpn_connections, "_domain_options", lambda _access: [])

    def fake_read(**kwargs):
        calls["accounting"] = (kwargs["period_start"], kwargs["period_end"])
        return {"coverage": {"projected_session_count": 1}, "sessions": [], "identities": {},
                "entitlements": [], "failed_events": [], "failed_collection_state": "not_collected"}

    def fake_source(source):
        def read(_access, **kwargs):
            calls[source] = (kwargs["time_from"], kwargs["time_to"])
            return {"state": "available", "items": [], "cells": []}
        return read

    monkeypatch.setattr(reporting, "_read_report_data", fake_read)
    monkeypatch.setattr(vpn_connections, "get_vpn_authorization_timeline", fake_source("authorizations"))
    monkeypatch.setattr(vpn_connections, "get_windows_authentication_report", fake_source("windows"))
    monkeypatch.setattr(vpn_connections, "get_windows_authentication_failure_grid", fake_source("windows_heatmap"))
    params, paging = parse_params(vpn_connections.REPORT, {
        **{key: [value] for key, value in query.items()}, "domain": ["7"], "tz": [zone], "tab": [tab],
    }, now=now)
    access = {"platform_owner": False, "capabilities": ["vpn.sessions.view"], "capability_policies": [],
              "reports": [{"report_key": "vpn.audit", "allowed": True, "allowed_actions": ["view"],
                           "grants": [{"allowed_actions": ["view"], "scope": {"kind": "domain", "ids": [7]}}]}]}
    payload = vpn_connections._query(QueryContext(access=access, params=params, domain_ids=[7], action="view", **paging))
    assert calls["accounting"] == tuple(datetime.fromisoformat(value.replace("Z", "+00:00")) for value in expected)
    if tab in {"authorizations", "windows", "windows_heatmap"}:
        assert calls[tab] == expected
    assert (payload["window"]["from_utc"], payload["window"]["to_utc_exclusive"]) == expected
    if query["period"] == "7d":
        assert (calls["accounting"][1] - calls["accounting"][0]).total_seconds() == 7 * 24 * 60 * 60


def test_failure_heatmap_is_the_full_weekday_hour_grid_of_engine_counts() -> None:
    from server.sli.reporting.v2.reports import vpn_connections

    grid = vpn_connections._failure_heatmap([
        {"isodow": 2, "hour": 6, "failures": 2},  # Tuesday 06:00
        {"isodow": 7, "hour": 23, "failures": 1},  # Sunday 23:00
        {"isodow": 9, "hour": 1, "failures": 5},  # out of range: ignored
    ])

    assert len(grid) == 7 * 24
    assert [cell["weekday"] for cell in grid[::24]] == list(vpn_connections.WEEKDAYS)
    assert [cell["hour"] for cell in grid[:24]] == [f"{hour:02d}" for hour in range(24)]
    assert [cell for cell in grid if cell["failures"]] == [
        {"hour": "06", "weekday": "Вт", "failures": 2},
        {"hour": "23", "weekday": "Вс", "failures": 1},
    ]


def test_heatmap_tab_uses_the_whole_window_aggregate_in_the_user_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reporting.v2.definition import QueryContext
    from server.sli.reporting.v2.reports import vpn_connections

    seen: dict = {}
    monkeypatch.setattr(vpn_connections, "get_windows_authentication_failure_grid",
                        lambda access, **kwargs: seen.update(kwargs) or {"state": "available", "cells": [{"isodow": 4, "hour": 21, "failures": 1}]})
    monkeypatch.setattr(vpn_connections, "get_windows_authentication_report", lambda *_a, **_k: pytest.fail("page must not be read"))
    context = QueryContext(access={}, params={"domain": "1", "period": {"from_utc": "2026-09-01T00:00:00Z", "to_utc": "2026-10-01T00:00:00Z"}},
                           domain_ids=[1], action="view", cursor=None, limit=50, timezone="Asia/Novosibirsk", tab="windows_heatmap")
    grid, branch = vpn_connections._failure_grid(context)
    assert seen["timezone_name"] == "Asia/Novosibirsk" and seen["source_domain_id"] == 1
    assert [cell for cell in grid if cell["failures"]] == [{"hour": "21", "weekday": "Чт", "failures": 1}]
    assert branch["state"] == "ok"
    assert branch["limitations"][0]["code"] == "windows_heatmap_meaning"


def test_heatmap_view_declares_its_axes_and_value_series() -> None:
    from server.sli.reporting.v2.reports import vpn_connections

    view = next(item for item in vpn_connections.REPORT.views if item.key == "windows_heatmap")
    payload = view.to_json()
    assert payload["chart"] == "heatmap" and payload["x"] == "hour" and payload["y"] == "weekday"
    assert payload["series"] == [{"label": "Отказов", "path": "failures"}]


def test_windows_outcome_comes_from_the_observed_fact_when_no_outcome_object() -> None:
    from server.sli.reporting.v2.reports import vpn_connections

    def text(fact: str, **native: str) -> str:
        return vpn_connections._outcome_text({}, {"authentication_fact": fact, "source_native": native})

    assert text("observed_failed_logon") == "отказ"
    assert text("observed_kerberos_preauth_failure") == "отказ"
    assert text("observed_successful_logon") == "успех"
    assert text("observed_credential_validation", result_code="0x0") == "успех"
    assert text("observed_credential_validation", result_code="0xC000006A") == "отказ"
    assert text("observed_credential_validation") == "не зафиксирован"
    assert text("observed_logoff") == "не зафиксирован"
    assert vpn_connections._outcome_text({"result": "failure"}, {"authentication_fact": "observed_successful_logon"}) == "отказ"


def _unreadable(*_args, **_kwargs):
    from psycopg import errors

    raise errors.InsufficientPrivilege("permission denied for table domains")


@pytest.mark.parametrize("tab", ["authorizations", "failed", "windows", "windows_heatmap"])
@pytest.mark.parametrize("accounting_state, expected_state", [
    pytest.param("unreadable", "error", id="unreadable"),
    pytest.param("not_authorized", "denied", id="not_authorized"),
    pytest.param("not_collected", "not_collected", id="not_collected"),
    pytest.param("unregistered", "error", id="unregistered"),
    pytest.param("connection_lost", "error", id="connection_lost"),
])
def test_v2_accounting_failure_keeps_independent_sources(monkeypatch, tab, accounting_state, expected_state) -> None:
    from server.sli.reporting.v2.definition import QueryContext
    from server.sli.reporting.v2.reports import vpn_connections

    monkeypatch.setattr(vpn_connections, "_domain_options", lambda _access: [])
    def accounting(*_args, **_kwargs):
        if accounting_state == "unreadable":
            return _unreadable()
        if accounting_state == "unregistered":
            raise ValueError("vpn_connections_source_domain_not_registered")
        if accounting_state == "connection_lost":
            from psycopg import OperationalError

            raise OperationalError("synthetic connection loss")
        return {"state": accounting_state, "employees": []}

    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", accounting)
    monkeypatch.setattr(vpn_connections, "get_vpn_authorization_timeline", lambda *_a, **_k: {
        "state": "available", "items": [{"event_db_id": 9, "event_id": 6273, "authorization_result": "denied"}],
    })
    monkeypatch.setattr(vpn_connections, "get_windows_authentication_report", lambda *_a, **_k: {
        "state": "available", "items": [{"event_db_id": 10, "authentication_fact": "observed_failed_logon"}],
    })
    monkeypatch.setattr(vpn_connections, "get_windows_authentication_failure_grid", lambda *_a, **_k: {
        "state": "available", "cells": [{"isodow": 1, "hour": 2, "failures": 3}],
    })
    context = QueryContext(access={}, params={"domain": "7", "period": {"from_utc": "2026-09-01T00:00:00Z", "to_utc": "2026-09-02T00:00:00Z"}},
                           domain_ids=[7], action="view", cursor=None, limit=50, timezone="UTC", tab=tab)
    payload = vpn_connections._query(context)
    branch = "nps" if tab in {"authorizations", "failed"} else tab
    assert payload["state"] == "partial"
    assert payload["items"] == [] and payload["metrics"] == []
    assert payload["collections"][tab]
    assert payload["branches"][branch]["state"] == "ok"
    assert payload["branches"]["accounting"]["state"] == expected_state
    assert payload["coverage"]["missing_sources"] == ["accounting"]
    assert payload["branches"]["accounting"]["reason"]
    assert payload["branches"]["accounting"]["limitations"]
    assert payload["branches"][branch]["limits"]["max_period_days"] > 0
    assert payload["window"]["source_domain_id"] == 7
    assert payload["window"]["timezone"] == "UTC"


@pytest.mark.parametrize("tab, branch, reader", [
    ("authorizations", "nps", "get_vpn_authorization_timeline"),
    ("windows", "windows", "get_windows_authentication_report"),
    ("windows_heatmap", "windows_heatmap", "get_windows_authentication_failure_grid"),
])
@pytest.mark.parametrize("failure, expected_state", [
    pytest.param("unreadable", "error", id="unreadable"),
    pytest.param("not_authorized", "denied", id="not_authorized"),
    pytest.param("not_collected", "not_collected", id="not_collected"),
    pytest.param("coverage_unverified", "partial", id="coverage_unverified"),
    pytest.param("too_wide", "error", id="too_wide"),
    pytest.param("connection_lost", "error", id="connection_lost"),
    pytest.param("unavailable", "error", id="unavailable"),
])
def test_v2_source_failure_keeps_accounting(monkeypatch, tab, branch, reader, failure, expected_state) -> None:
    from server.sli.reporting.v2.definition import QueryContext
    from server.sli.reporting.v2.reports import vpn_connections

    def source(*_args, **_kwargs):
        if failure == "unreadable":
            return _unreadable()
        if failure == "too_wide":
            raise reporting.TimeRangeError("period_too_wide")
        if failure == "connection_lost":
            from psycopg import OperationalError

            raise OperationalError("synthetic connection loss")
        return {"state": failure, "items": [], "cells": []}

    monkeypatch.setattr(vpn_connections, "_domain_options", lambda _access: [])
    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", lambda *_a, **_k: {
        "state": "available", "employees": [{"entity_id": 101}], "employee_page": {},
    })
    monkeypatch.setattr(vpn_connections, reader, source)
    context = QueryContext(access={}, params={"domain": "7", "period": {"from_utc": "2026-09-01T00:00:00Z", "to_utc": "2026-09-02T00:00:00Z"}},
                           domain_ids=[7], action="view", cursor=None, limit=50, timezone="UTC", tab=tab)
    payload = vpn_connections._query(context)
    assert payload["state"] == "partial"
    assert payload["items"][0]["entity_id"] == 101
    assert payload["branches"]["accounting"]["state"] == "ok"
    assert payload["branches"][branch]["state"] == expected_state
    assert payload["coverage"]["missing_sources"] == ([] if expected_state == "partial" else [branch])
    assert payload["branches"][branch]["reason"]
    assert payload["branches"][branch]["limitations"]
    assert payload["collections"][tab] == []


def test_v2_windows_truncation_keeps_rows_and_explains_partial_state(monkeypatch) -> None:
    from server.sli.reporting.v2.definition import QueryContext
    from server.sli.reporting.v2.reports import vpn_connections

    monkeypatch.setattr(vpn_connections, "_domain_options", lambda _access: [])
    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", lambda *_a, **_k: {
        "state": "available", "employees": [{"entity_id": 101}],
    })
    monkeypatch.setattr(vpn_connections, "get_windows_authentication_report", lambda *_a, **_k: {
        "state": "available", "items": [{"event_db_id": 10}],
        "result_window": {"truncated": True, "returned_event_count": 1}, "limits": {"display_limit": 1},
    })
    context = QueryContext(access={}, params={"domain": "7", "period": {"from_utc": "2026-09-01T00:00:00Z", "to_utc": "2026-09-02T00:00:00Z"}},
                           domain_ids=[7], action="view", cursor=None, limit=50, timezone="UTC", tab="windows")
    payload = vpn_connections._query(context)
    assert payload["state"] == "partial"
    assert payload["collections"]["windows"][0]["event_db_id"] == 10
    branch = payload["branches"]["windows"]
    assert branch["state"] == "partial" and branch["reason"] == "result_truncated"
    assert branch["limits"] == {"max_period_days": 90, "display_limit": 1}
    assert any(note["code"] == "windows_truncated" for note in branch["limitations"])
    assert payload["branches"]["nps"]["state"] == "not_requested"
    assert payload["branches"]["windows_heatmap"]["state"] == "not_requested"


@pytest.mark.parametrize("scope", ["whole_period", "displayed_sample"])
def test_windows_review_labels_period_sample_and_distributed_rule(monkeypatch, scope):
    from server.sli.plugins.remote_access.reports import vpn_connections
    from server.sli.reporting.v2.definition import QueryContext
    from server.sli.reporting.v2.reports import vpn_connections as compatibility_alias

    assert compatibility_alias is vpn_connections

    monkeypatch.setattr(vpn_connections, "get_windows_authentication_report", lambda *_a, **_k: {
        "state": "available", "items": [],
        "result_window": {"truncated": True, "returned_event_count": 200},
        "manual_review_policy": {
            "coverage_scope": scope, "signals_truncated": True,
            "distributed_conditions": {"rolling_window_hours": 24, "maximum_failures_per_target": 3},
            "signals": [{"rule": "distributed", "failure_fact_count": 10,
                         "distinct_target_sid_count": 10, "distinct_source_count": 5,
                         "evidence_event_db_id": 201,
                         "window": {"from_utc": "2026-08-21T00:00:00Z", "to_utc_exclusive": "2026-08-22T00:00:00Z"}}],
        },
        "limitations": ["unknown_results_remain_unknown", "source_completeness_not_proven",
                        "earlier_failure_context_displayed_sample_only"],
    })
    context = QueryContext(access={}, params={"domain": "7", "period": {
        "from_utc": "2026-08-21T00:00:00Z", "to_utc": "2026-08-22T00:00:00Z"}},
        domain_ids=[7], action="view", cursor=None, limit=50, timezone="UTC", tab="windows")
    _rows, branch = vpn_connections._windows(context)
    notes = {note["code"]: note for note in branch["limitations"]}
    assert ("windows_review_whole_period" if scope == "whole_period" else "windows_review_sample") in notes
    assert notes["windows_truncated"]["params"] == {"count": 200}
    assert "не вердикт" in notes["windows_distributed_review"]["text"]
    assert notes["windows_distributed_review"]["params"]["accounts"] == 10
    assert notes["windows_distributed_review"]["params"]["sources"] == 5
    assert "windows_review_truncated" in notes
    assert "windows_unknown_results_remain_unknown" in notes
    assert "windows_source_completeness_not_proven" in notes
    assert "windows_earlier_failure_context_displayed_sample_only" in notes
    assert ("windows_review_first_windows" in notes) == (scope == "whole_period")


def test_windows_plugin_without_signal_keeps_unverified_coverage(monkeypatch):
    from server.sli.plugins.remote_access.reports import vpn_connections
    from server.sli.reporting.v2.definition import QueryContext

    monkeypatch.setattr(vpn_connections, "get_windows_authentication_report", lambda *_a, **_k: {
        "state": "coverage_unverified", "items": [],
        "manual_review_policy": {
            "coverage_scope": "whole_period", "state": "no_observed_signal_unverified", "signals": [],
        },
        "limitations": ["source_completeness_not_proven"],
    })
    context = QueryContext(access={}, params={"domain": "7", "period": {
        "from_utc": "2026-08-21T00:00:00Z", "to_utc": "2026-08-22T00:00:00Z"}},
        domain_ids=[7], action="view", cursor=None, limit=50, timezone="UTC", tab="windows")
    rows, branch = vpn_connections._windows(context)
    notes = {note["code"] for note in branch["limitations"]}
    assert rows == []
    assert branch["state"] == "partial"
    assert {"windows_coverage_unverified", "windows_review_whole_period", "windows_review_no_signal",
            "windows_source_completeness_not_proven"} <= notes


def test_v2_clean_install_without_read_grants_opens_instead_of_http_500(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clean install: the RADIUS coverage view cannot read ``domains`` (permission denied).

    The definition (filter options) and the data endpoint must answer with the
    honest empty/unavailable contract instead of an unhandled 500.
    """
    from server.api.routes import reports_v2
    from server.sli.reporting.v2.reports import vpn_connections

    logged: list[str] = []
    monkeypatch.setattr(vpn_connections, "get_vpn_session_sources", _unreadable)
    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", _unreadable)
    monkeypatch.setattr(vpn_connections, "log_internal_error", lambda _c, event, *_a, **_k: logged.append(event) or "INT-test")

    sent: list = []
    assert reports_v2.try_handle_get(_v2_handler(sent), "/api/v2/reports/vpn.connections", {})
    definition, status = sent[0]
    assert status == 200 and definition["filter_options"]["domain"] == []

    sent.clear()
    assert reports_v2.try_handle_get(_v2_handler(sent), "/api/v2/reports/vpn.connections/data", {"domain": ["1"], "period": ["7d"]})
    payload, status = sent[0]
    assert status == 200
    assert payload["state"] == "error" and payload["items"] == []
    assert payload["metrics"] == []  # nothing is rendered as a zero
    assert payload["limitations"][0]["code"] == "vpn_source_unreadable"
    assert "accounting_source_unreadable" in logged


def test_v2_other_database_errors_are_not_hidden(monkeypatch: pytest.MonkeyPatch) -> None:
    from psycopg import errors

    from server.sli.reporting.v2.reports import vpn_connections

    def broken(*_args, **_kwargs):
        raise errors.DeadlockDetected("deadlock")

    monkeypatch.setattr(vpn_connections, "get_vpn_session_sources", broken)
    with pytest.raises(errors.DeadlockDetected):
        vpn_connections._domain_options({})


@pytest.mark.parametrize("state,value,quality,expected", [
    ("partial", 0, "unknown", None), ("partial", 2, "observed", 2),
    ("processing", 0, "unknown", None), ("stale", 3, "observed", 3),
    ("available", 0, "unknown", None),
])
def test_v2_vpn_metrics_qualify_incomplete_period(monkeypatch, state, value, quality, expected):
    from server.sli.reporting.v2.definition import QueryContext
    from server.sli.reporting.v2.reports import vpn_connections

    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", lambda *args, **kwargs: {
        "state": state, "employees": [], "employee_page": {},
        "analytics": {"employee_count": value, "closed_session_count": 0},
        "coverage": {"completeness": "not_proven"},
    })
    monkeypatch.setattr(vpn_connections, "_domain_options", lambda access: [])
    payload = vpn_connections._query(QueryContext({}, {"domain": "7", "period": {
        "from_utc": "2026-10-01T00:00:00Z", "to_utc": "2026-10-02T00:00:00Z",
    }}))
    metric = payload["metrics"][0]
    assert metric["value"] == expected
    assert metric["quality"] == quality
    assert payload["metrics"][1]["value"] is None
    assert payload["state_details"]["source"] == "accounting"


def test_v2_vpn_zero_is_valid_only_with_confirmed_period_coverage(monkeypatch):
    from server.sli.reporting.v2.definition import QueryContext
    from server.sli.reporting.v2.reports import vpn_connections

    monkeypatch.setattr(vpn_connections, "get_vpn_connections_report", lambda *args, **kwargs: {
        "state": "available", "employees": [], "employee_page": {},
        "analytics": {"employee_count": 0}, "coverage": {"completeness": "proven"},
    })
    monkeypatch.setattr(vpn_connections, "_domain_options", lambda access: [])
    payload = vpn_connections._query(QueryContext({}, {"domain": "7", "period": {
        "from_utc": "2026-10-01T00:00:00Z", "to_utc": "2026-10-02T00:00:00Z",
    }}))
    assert payload["metrics"][0]["value"] == 0
    assert payload["metrics"][0]["quality"] == "complete"
