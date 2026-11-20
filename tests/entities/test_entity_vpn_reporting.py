from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

import pytest


UTC = timezone.utc


def _decision(*, sessions: bool, evidence: bool):
    from server.sli.reports.vpn_report_composition import (
        COMPOSITION_CONTRACT_ID,
        REPORT_KEY,
        VpnReportBranchDecision,
        VpnReportCompositionDecision,
    )

    return VpnReportCompositionDecision(
        contract_id=COMPOSITION_CONTRACT_ID,
        report_key=REPORT_KEY,
        report_allowed=True,
        directory=VpnReportBranchDecision(
            branch="directory_membership", state="available", reason="test",
            dataset_or_resource_group="ad.accounts.vpn", required_capability=None,
        ),
        sessions=VpnReportBranchDecision(
            branch="sessions", state="available" if sessions else "not_authorized",
            reason="test", dataset_or_resource_group="vpn.sessions",
            required_capability="vpn.sessions.view",
        ),
        session_evidence=VpnReportBranchDecision(
            branch="session_evidence", state="available" if evidence else "not_authorized",
            reason="test", dataset_or_resource_group="vpn.sessions",
            required_capability="vpn.session.evidence.read",
        ),
    )


class _Cursor:
    def __init__(self, rows: list[dict]):
        self.rows = rows
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql: str, params=()):
        self.calls.append((" ".join(sql.split()), tuple(params)))

    def fetchall(self):
        return self.rows


class _Connection:
    def __init__(self, cursor: _Cursor):
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return self._cursor


def _row(*, lifecycle_state: str = "closed", completeness: str = "complete") -> dict:
    return {
        "session_row_id": "radius-session-row:" + "a" * 64,
        "entity_id": 41,
        "domain_id": 7,
        "generation": 3,
        "lifecycle_state": lifecycle_state,
        "completeness": completeness,
        "started_at_utc": datetime(2026, 9, 10, 10, 0, 0, 123456, tzinfo=UTC),
        "last_observed_at_utc": datetime(2026, 9, 10, 10, 5, 0, 654321, tzinfo=UTC),
        "stopped_at_utc": (
            datetime(2026, 9, 10, 10, 5, 0, 654321, tzinfo=UTC)
            if lifecycle_state == "closed" else None
        ),
        "duration_seconds": 300 if lifecycle_state == "closed" else None,
        "observation_count": 2 if lifecycle_state == "closed" else 1,
        "anomalies": ("missing_stop",) if completeness == "partial" else (),
        "updated_at": datetime(2026, 9, 10, 10, 5, 1, tzinfo=UTC),
    }


def test_denied_sessions_returns_explicit_branch_before_opening_database(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.entities import entity_vpn_reporting

    monkeypatch.setattr(
        entity_vpn_reporting,
        "vpn_report_composition_decision",
        lambda *_args, **_kwargs: _decision(sessions=False, evidence=False),
    )
    monkeypatch.setattr(
        entity_vpn_reporting,
        "_connect",
        lambda: pytest.fail("denied entity VPN branch must not open database"),
    )

    payload = entity_vpn_reporting.get_entity_vpn_sessions(
        {}, entity_id=41, trusted_domain_id=7,
        time_from_utc="2026-09-10T10:00:00.123456Z",
        time_to_utc_exclusive="2026-09-10T11:00:00.654321Z",
    )

    assert payload["state"] == "not_authorized"
    assert payload["items"] == []
    assert payload["branches"]["sessions"]["state"] == "not_authorized"
    assert payload["branches"]["session_evidence"]["state"] == "not_authorized"


def test_entity_vpn_read_uses_exact_entity_and_trusted_domain_half_open_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.entities import entity_vpn_reporting

    cursor = _Cursor([_row()])
    monkeypatch.setattr(
        entity_vpn_reporting,
        "vpn_report_composition_decision",
        lambda *_args, **_kwargs: _decision(sessions=True, evidence=True),
    )
    monkeypatch.setattr(entity_vpn_reporting, "_connect", lambda: _Connection(cursor))

    payload = entity_vpn_reporting.get_entity_vpn_sessions(
        {}, entity_id=41, trusted_domain_id=7,
        time_from_utc="2026-09-10T10:00:00.123456Z",
        time_to_utc_exclusive="2026-09-10T11:00:00.654321Z",
        limit=3,
    )

    assert cursor.calls[0] == ("set transaction isolation level repeatable read, read only", ())
    sql, params = cursor.calls[1]
    assert "from radius_vpn_session_rows_v1" in sql
    assert "where entity_id=%s and domain_id=%s" in sql
    assert "last_observed_at_utc>=%s" in sql
    assert "last_observed_at_utc<%s" in sql
    assert params == (
        41,
        7,
        datetime(2026, 9, 10, 10, 0, 0, 123456, tzinfo=UTC),
        datetime(2026, 9, 10, 11, 0, 0, 654321, tzinfo=UTC),
        4,
    )
    assert payload["time_range"] == {
        "from_utc": "2026-09-10T10:00:00.123456Z",
        "to_utc_exclusive": "2026-09-10T11:00:00.654321Z",
    }
    assert payload["items"][0]["entity_id"] == 41
    assert "display_name" not in payload["items"][0]
    assert "event_id" not in payload["items"][0]


def test_open_partial_session_retains_factual_lifecycle_and_exact_evidence_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.entities import entity_vpn_reporting

    row = _row(lifecycle_state="open_observed", completeness="partial")
    cursor = _Cursor([row])
    monkeypatch.setattr(
        entity_vpn_reporting,
        "vpn_report_composition_decision",
        lambda *_args, **_kwargs: _decision(sessions=True, evidence=True),
    )
    monkeypatch.setattr(entity_vpn_reporting, "_connect", lambda: _Connection(cursor))

    payload = entity_vpn_reporting.get_entity_vpn_sessions(
        {}, entity_id=41, trusted_domain_id=7,
        time_from_utc="2026-09-10T10:00:00Z",
        time_to_utc_exclusive="2026-09-10T11:00:00Z",
    )

    item = payload["items"][0]
    assert item["lifecycle_state"] == "open_observed"
    assert item["completeness"] == "partial"
    assert item["stopped_at_utc"] is None
    assert item["evidence_ref"] == {
        "kind": "vpn_accounting_session",
        "source_domain_id": 7,
        "session_row_id": row["session_row_id"],
    }
    assert "event_db_id" not in item


def test_session_rows_remain_visible_when_evidence_capability_is_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.entities import entity_vpn_reporting

    cursor = _Cursor([_row()])
    monkeypatch.setattr(
        entity_vpn_reporting,
        "vpn_report_composition_decision",
        lambda *_args, **_kwargs: _decision(sessions=True, evidence=False),
    )
    monkeypatch.setattr(entity_vpn_reporting, "_connect", lambda: _Connection(cursor))

    payload = entity_vpn_reporting.get_entity_vpn_sessions(
        {}, entity_id=41, trusted_domain_id=7,
        time_from_utc="2026-09-10T10:00:00Z",
        time_to_utc_exclusive="2026-09-10T11:00:00Z",
    )

    assert payload["state"] == "available"
    assert payload["branches"]["sessions"]["state"] == "available"
    assert payload["branches"]["session_evidence"]["state"] == "not_authorized"
    assert payload["items"][0]["evidence_ref"] == {"state": "not_authorized"}


@pytest.mark.parametrize(
    ("time_from_utc", "time_to_utc_exclusive", "error"),
    [
        ("2026-09-10T10:00:00Z", "2026-09-10T10:00:00Z", "entity_vpn_time_range_invalid"),
        ("2026-08-01T00:00:00Z", "2026-09-02T00:00:01Z", "entity_vpn_period_too_wide"),
    ],
)
def test_invalid_entity_vpn_bounds_fail_before_access_or_database(
    monkeypatch: pytest.MonkeyPatch,
    time_from_utc: str,
    time_to_utc_exclusive: str,
    error: str,
) -> None:
    from server.sli.entities import entity_vpn_reporting

    monkeypatch.setattr(
        entity_vpn_reporting,
        "vpn_report_composition_decision",
        lambda *_args, **_kwargs: pytest.fail("invalid bounds must fail before access decision"),
    )
    with pytest.raises(ValueError, match=error):
        entity_vpn_reporting.get_entity_vpn_sessions(
            {}, entity_id=41, trusted_domain_id=7,
            time_from_utc=time_from_utc,
            time_to_utc_exclusive=time_to_utc_exclusive,
        )


def test_entity_vpn_http_route_uses_trusted_entity_domain_and_server_access(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.api.routes import entities as routes_entities

    captured: dict[str, object] = {}

    class Handler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            captured["payload"] = payload
            captured["status"] = status

    monkeypatch.setattr(
        routes_entities, "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 41, "entity_type": "ad_user", "domain_id": 7, "server_id": None},
        raising=False,
    )
    monkeypatch.setattr(
        routes_entities, "capability_decision_for_resource_groups",
        lambda *_args, **_kwargs: {"allowed": True},
        raising=False,
    )
    monkeypatch.setattr(
        routes_entities, "get_entity_vpn_sessions",
        lambda access, **kwargs: captured.update(access=access, kwargs=kwargs) or {
            "contract_id": "sli.entity-vpn-sessions.v1", "state": "available", "items": [],
        },
        raising=False,
    )

    assert routes_entities.try_handle_get(
        Handler(), "/api/v1/entities/41/vpn-sessions", {
            "time_from": ["2026-09-10T10:00:00.123456Z"],
            "time_to": ["2026-09-10T11:00:00.654321Z"],
            "timezone": ["Asia/Bangkok"],
            "limit": ["25"],
        },
    )
    assert captured["access"] == {"server_built": True}
    assert captured["kwargs"] == {
        "entity_id": 41,
        "trusted_domain_id": 7,
        "time_from_utc": "2026-09-10T10:00:00.123456Z",
        "time_to_utc_exclusive": "2026-09-10T11:00:00.654321Z",
        "limit": 25,
    }
    assert captured["status"] is None


def test_entity_vpn_http_route_hides_scoped_object_and_never_reads_sessions(monkeypatch: pytest.MonkeyPatch) -> None:
    from http import HTTPStatus
    from server.api.routes import entities as routes_entities

    sent: list[tuple[dict, object]] = []

    class Handler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            sent.append((payload, status))

    monkeypatch.setattr(
        routes_entities, "get_entity_workspace_resource_preflight",
        lambda **_kwargs: {"id": 41, "entity_type": "ad_user", "domain_id": 7, "server_id": None},
        raising=False,
    )
    monkeypatch.setattr(
        routes_entities, "capability_decision_for_resource_groups",
        lambda *_args, **_kwargs: {"allowed": False},
        raising=False,
    )
    monkeypatch.setattr(
        routes_entities, "get_entity_vpn_sessions",
        lambda *_args, **_kwargs: pytest.fail("hidden object must not read VPN projection"),
        raising=False,
    )

    routes_entities.try_handle_get(
        Handler(), "/api/v1/entities/41/vpn-sessions", {
            "time_from": ["2026-09-10T10:00:00Z"],
            "time_to": ["2026-09-10T11:00:00Z"],
        },
    )
    assert sent == [({"error": "entity_not_found", "entity_id": 41}, HTTPStatus.NOT_FOUND)]
