from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from server.api.routes import reports as routes
from server.api.routes import reports_v2 as routes_v2
from server.sli.access import access_control_v4
from server.sli.reporting.v2.reports import computer_logons


def test_migration_126_registers_exact_catalog_access_and_revokes_public() -> None:
    forward = Path("config/postgres_migrations/126_what_where_when_report.sql").read_text(encoding="utf-8")
    rollback = Path("config/postgres_migrations/126_what_where_when_report.rollback.sql").read_text(encoding="utf-8")
    folded = forward.casefold()
    assert "ad.authentication.computer-logons" in forward
    assert "ad.computer-logons" in forward
    assert "'что где когда'" in forward
    assert "'/what-where-when-report'" in forward
    assert "field.computer_logon_observation" in forward
    assert "computer_logon_observation" in forward
    assert "security_analyst" in forward and "project_operations" in forward
    assert "revoke all on what_where_when_observations from public" in folded
    assert "revoke all on what_where_when_projection_state from public" in folded
    assert "delete from access_report_assignments where report_key='ad.computer-logons'" in rollback
    assert "delete from report_registry_v4 where report_key='ad.computer-logons'" in rollback


def test_custom_field_category_is_bounded_by_dedicated_capability() -> None:
    grant = access_control_v4._bounded_report_grant(
        {"field_categories": ["computer_logon_observation"], "allowed_actions": ["view"]},
        {"field.computer_logon_observation"},
    )
    assert grant["field_categories"] == ["computer_logon_observation"]
    denied = access_control_v4._bounded_report_grant(
        {"field_categories": ["computer_logon_observation"], "allowed_actions": ["view"]},
        {"field.security"},
    )
    assert denied["field_categories"] == []


def test_scope_is_bounded_to_report_domain_and_fails_closed() -> None:
    access = {"reports": [{
        "report_key": "ad.computer-logons", "allowed": True, "allowed_actions": ["view"],
        "grants": [{
            "allowed_actions": ["view"],
            "field_categories": ["computer_logon_observation"],
            "scope": {"kind": "all"},
        }],
    }]}
    assert computer_logons.logon_domain_scope(access, domain_id=7) == [7]
    access["reports"][0]["grants"][0]["scope"] = {"kind": "domain", "ids": [8]}
    with pytest.raises(PermissionError, match="report_scope_not_executable"):
        computer_logons.logon_domain_scope(access, domain_id=7)
    access["reports"][0]["allowed"] = False
    with pytest.raises(PermissionError, match="report_access_denied"):
        computer_logons.logon_domain_scope(access, domain_id=7)


def test_time_range_is_utc_bounded_and_boundary_is_inclusive() -> None:
    from server.sli.reports.what_where_when_reporting import parse_time_range

    start, end = parse_time_range("2025-09-01T00:00:00Z", "2026-09-01T00:00:00Z")
    assert start == datetime(2025, 9, 1, tzinfo=timezone.utc)
    assert end == datetime(2026, 9, 1, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="time_range_exceeds_365_days"):
        parse_time_range("2025-08-31T23:59:59Z", "2026-09-01T00:00:00Z")
    with pytest.raises(ValueError, match="time_must_be_utc"):
        parse_time_range("2026-08-01T00:00:00+03:00", "2026-09-01T00:00:00Z")


def _inventory() -> dict:
    return {
        "state": "available",
        "partial": False,
        "items": [
            {"entity_id": 2, "object_guid": "22222222-2222-4222-8222-222222222222", "display_name": "WS-B", "dns_host_name": "ws-b.example.test"},
            {"entity_id": 1, "object_guid": "11111111-1111-4111-8111-111111111111", "display_name": "WS-A", "dns_host_name": "ws-a.example.test"},
        ],
    }


def test_computer_list_preserves_empty_population_and_public_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reports import what_where_when_reporting as reporting

    monkeypatch.setattr(reporting, "_load_workstation_population", lambda _ids: _inventory())
    monkeypatch.setattr(reporting, "_load_projection_status", lambda: {"state": "available", "backfill_completed": True})
    monkeypatch.setattr(reporting, "_load_observation_summaries", lambda *_args, **_kwargs: {
        "11111111-1111-4111-8111-111111111111": {"login_count": 1, "last_observed_logon_at_utc": datetime(2026, 8, 1, tzinfo=timezone.utc)}
    })
    payload = reporting.get_computer_logon_computers(
        domain_ids=[7], from_utc="2026-08-01T00:00:00Z", to_utc_exclusive="2026-09-01T00:00:00Z", limit=50,
    )
    assert [item["display_name"] for item in payload["items"]] == ["WS-A", "WS-B"]
    assert payload["items"][0]["observation_state"] == "observed"
    assert payload["items"][1] == {
        "entity_id": 2, "display_name": "WS-B", "last_observed_logon_at_utc": None,
        "login_count": 0, "observation_state": "empty_unverified",
    }
    forbidden = {"ip", "sid", "event", "provenance", "object_guid", "dns_host_name"}
    assert not forbidden.intersection(payload["items"][0])


def test_cursors_are_filter_and_entity_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reports import what_where_when_reporting as reporting

    monkeypatch.setattr(reporting, "_load_workstation_population", lambda _ids: _inventory())
    monkeypatch.setattr(reporting, "_load_projection_status", lambda: {"state": "available", "backfill_completed": True})
    monkeypatch.setattr(reporting, "_load_current_user_directory", lambda _ids: {})
    monkeypatch.setattr(reporting, "_load_observation_summaries", lambda *_args, **_kwargs: {})
    first = reporting.get_computer_logon_computers(
        domain_ids=[7], from_utc="2026-08-01T00:00:00Z", to_utc_exclusive="2026-09-01T00:00:00Z", limit=1,
    )
    assert first["has_more"] is True and first["next_cursor"]
    with pytest.raises(ValueError, match="invalid_cursor"):
        reporting.get_computer_logon_computers(
            domain_ids=[7], q="WS", from_utc="2026-08-01T00:00:00Z", to_utc_exclusive="2026-09-01T00:00:00Z", limit=1, cursor=first["next_cursor"],
        )

    monkeypatch.setattr(reporting, "_load_observations", lambda *_args, **_kwargs: [
        {"projection_id": 2, "user_name": "EXAMPLE\\ivanov", "observed_at_utc": datetime(2026, 8, 2, tzinfo=timezone.utc)},
        {"projection_id": 1, "user_name": "EXAMPLE\\petrov", "observed_at_utc": datetime(2026, 8, 1, tzinfo=timezone.utc)},
    ])
    detail = reporting.get_computer_logon_observations(
        domain_ids=[7], entity_id=1, from_utc="2026-08-01T00:00:00Z", to_utc_exclusive="2026-09-01T00:00:00Z", limit=1,
    )
    assert set(detail["items"][0]) == {"user_name", "user_display_name", "user_identity_state", "observed_at_utc", "source_event_id", "source_event_state"}
    with pytest.raises(ValueError, match="invalid_cursor"):
        reporting.get_computer_logon_observations(
            domain_ids=[7], entity_id=1, user_q="ivanov", from_utc="2026-08-01T00:00:00Z",
            to_utc_exclusive="2026-09-01T00:00:00Z", limit=1, cursor=detail["next_cursor"],
        )
    with pytest.raises(ValueError, match="invalid_cursor"):
        reporting.get_computer_logon_observations(
            domain_ids=[7], entity_id=2, from_utc="2026-08-01T00:00:00Z", to_utc_exclusive="2026-09-01T00:00:00Z", limit=1, cursor=detail["next_cursor"],
        )


def test_observation_response_is_minimal_and_empty_is_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reports import what_where_when_reporting as reporting

    monkeypatch.setattr(reporting, "_load_workstation_population", lambda _ids: _inventory())
    monkeypatch.setattr(reporting, "_load_projection_status", lambda: {"state": "available", "backfill_completed": True})
    monkeypatch.setattr(reporting, "_load_current_user_directory", lambda _ids: {})
    monkeypatch.setattr(reporting, "_load_observations", lambda *_args: [])
    payload = reporting.get_computer_logon_observations(
        domain_ids=[7], entity_id=1, from_utc="2026-08-01T00:00:00Z",
        to_utc_exclusive="2026-09-01T00:00:00Z",
    )
    assert payload["state"] == "empty_unverified"
    assert payload["items"] == []
    encoded = repr(payload).casefold()
    for forbidden in ("object_guid", "ip_address", "sid", "event_id", "source_event", "provenance"):
        assert forbidden not in encoded
    assert any("не подтверждает" in item for item in payload["limitations"])


def test_v1_routes_are_gone_and_v2_rejects_unknown_filters_before_the_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    assert not routes.is_resource_aware("/api/v1/reports/ad.computer-logons/computers")
    assert routes.try_handle_get(object(), "/api/v1/reports/ad.computer-logons/computers", {}) is False
    assert routes_v2.is_resource_aware("/api/v2/reports/ad.computer-logons/rows/42/detail")
    sent: list[tuple[dict, object]] = []
    monkeypatch.setattr(computer_logons, "get_computer_logon_computers", lambda **_: pytest.fail("engine must not run"))

    class Handler:
        def _access_decision(self):
            return {"reports": [{"report_key": "ad.computer-logons", "allowed": True}]}

        def _send_json(self, payload, status=None):
            sent.append((payload, int(status or 200)))

    assert routes_v2.try_handle_get(Handler(), "/api/v2/reports/ad.computer-logons/data", {"ip": ["10.0.0.1"]}) is True
    assert sent == [({"error": "report_parameter_unknown:ip"}, 400)]

def test_user_filter_is_shared_by_population_summary_and_history(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reports import what_where_when_reporting as reporting

    monkeypatch.setattr(reporting, "_load_workstation_population", lambda _ids: _inventory())
    monkeypatch.setattr(reporting, "_load_projection_status", lambda: {"state": "available", "backfill_completed": True})
    monkeypatch.setattr(reporting, "_load_current_user_directory", lambda _ids: {"ivanov": "Иван Иванов"})
    calls: list[tuple[str, tuple[str, ...]]] = []

    def summaries(_guids, _start, _end, user_q="", matching_sams=()):
        calls.append((user_q, tuple(matching_sams)))
        return {"11111111-1111-4111-8111-111111111111": {"login_count": 2, "last_observed_logon_at_utc": datetime(2026, 8, 2, tzinfo=timezone.utc)}}

    monkeypatch.setattr(reporting, "_load_observation_summaries", summaries)
    payload = reporting.get_computer_logon_computers(
        domain_ids=[7], user_q="Иван", with_logons=True,
        from_utc="2026-08-01T00:00:00Z", to_utc_exclusive="2026-09-01T00:00:00Z",
    )
    assert [(item["display_name"], item["login_count"]) for item in payload["items"]] == [("WS-A", 2)]
    assert calls == [("иван", ("ivanov",))]

    monkeypatch.setattr(reporting, "_load_observations", lambda *_args, **kwargs: (
        calls.append((kwargs["user_q"], tuple(kwargs["matching_sams"]))) or
        [{"projection_id": 2, "user_name": "EXAMPLE\\ivanov", "observed_at_utc": datetime(2026, 8, 2, tzinfo=timezone.utc)}]
    ))
    detail = reporting.get_computer_logon_observations(
        domain_ids=[7], entity_id=1, user_q="Иван",
        from_utc="2026-08-01T00:00:00Z", to_utc_exclusive="2026-09-01T00:00:00Z",
    )
    assert detail["items"] == [{"user_name": "EXAMPLE\\ivanov", "user_display_name": "Иван Иванов", "user_identity_state": "resolved", "observed_at_utc": "2026-08-02T00:00:00+00:00", "source_event_id": None, "source_event_state": "unavailable"}]
    assert calls[-1] == ("иван", ("ivanov",))


def test_user_login_fallback_and_filter_bound_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reports import what_where_when_reporting as reporting

    monkeypatch.setattr(reporting, "_load_workstation_population", lambda _ids: _inventory())
    monkeypatch.setattr(reporting, "_load_projection_status", lambda: {"state": "available", "backfill_completed": True})
    monkeypatch.setattr(reporting, "_load_current_user_directory", lambda _ids: {})
    monkeypatch.setattr(reporting, "_load_observations", lambda *_args, **_kwargs: [
        {"projection_id": 1, "user_name": "EXAMPLE\\missing.user", "observed_at_utc": datetime(2026, 8, 1, tzinfo=timezone.utc)},
    ])
    detail = reporting.get_computer_logon_observations(
        domain_ids=[7], entity_id=1, user_q="missing",
        from_utc="2026-08-01T00:00:00Z", to_utc_exclusive="2026-09-01T00:00:00Z",
    )
    assert detail["items"][0]["user_display_name"] is None

    monkeypatch.setattr(reporting, "_load_observation_summaries", lambda *_args, **_kwargs: {
        item["object_guid"]: {"login_count": 1, "last_observed_logon_at_utc": datetime(2026, 8, 1, tzinfo=timezone.utc)} for item in _inventory()["items"]
    })
    first = reporting.get_computer_logon_computers(
        domain_ids=[7], user_q="ivanov", with_logons=True, limit=1,
        from_utc="2026-08-01T00:00:00Z", to_utc_exclusive="2026-09-01T00:00:00Z",
    )
    with pytest.raises(ValueError, match="invalid_cursor"):
        reporting.get_computer_logon_computers(
            domain_ids=[7], user_q="petrov", with_logons=True, limit=1, cursor=first["next_cursor"],
            from_utc="2026-08-01T00:00:00Z", to_utc_exclusive="2026-09-01T00:00:00Z",
        )


def test_observations_declare_user_identity_resolution_state(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reports import what_where_when_reporting as reporting

    monkeypatch.setattr(reporting, "_load_workstation_population", lambda _ids: _inventory())
    monkeypatch.setattr(reporting, "_load_projection_status", lambda: {"state": "available", "backfill_completed": True})
    monkeypatch.setattr(reporting, "_load_current_user_directory", lambda _ids: {"ivanov": "Иван Иванов"})
    monkeypatch.setattr(reporting, "_load_observations", lambda *_args: [
        {"projection_id": 2, "user_name": "EXAMPLE\\ivanov", "observed_at_utc": datetime(2026, 8, 2, tzinfo=timezone.utc)},
        {"projection_id": 1, "user_name": "EXAMPLE\\missing", "observed_at_utc": datetime(2026, 8, 1, tzinfo=timezone.utc)},
    ])

    payload = reporting.get_computer_logon_observations(
        domain_ids=[7], entity_id=1, from_utc="2026-08-01T00:00:00Z",
        to_utc_exclusive="2026-09-01T00:00:00Z",
    )

    assert [item["user_identity_state"] for item in payload["items"]] == ["resolved", "not_found"]


def test_observation_names_are_current_context_and_preserve_only_durable_exact_event_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Latest AD names enrich history but cannot replace the event proof identity."""
    from server.sli.reports import what_where_when_reporting as reporting

    monkeypatch.setattr(reporting, "_load_workstation_population", lambda _ids: _inventory())
    monkeypatch.setattr(reporting, "_load_projection_status", lambda: {"state": "available", "backfill_completed": True})
    monkeypatch.setattr(reporting, "_load_current_user_directory", lambda _ids: {"ivanov": "Иван Иванов"})
    monkeypatch.setattr(reporting, "_load_observations", lambda *_args: [{
        "projection_id": 2,
        "source_event_id": 42,
        "user_name": "EXAMPLE\\ivanov",
        "observed_at_utc": datetime(2026, 8, 2, tzinfo=timezone.utc),
    }])

    payload = reporting.get_computer_logon_observations(
        domain_ids=[7], entity_id=1, from_utc="2026-08-01T00:00:00Z",
        to_utc_exclusive="2026-09-01T00:00:00Z",
    )

    assert payload["identity_context"] == {
        "display_name": "current_ad_context",
        "historical_display_name": "not_retained",
    }
    assert payload["population_context"] == {
        "computers": "current_computers_v6_workstations",
        "historical_membership": "not_retained",
    }
    assert payload["items"] == [{
        "user_name": "EXAMPLE\\ivanov",
        "user_display_name": "Иван Иванов",
        "user_identity_state": "resolved",
        "observed_at_utc": "2026-08-02T00:00:00+00:00",
        "source_event_id": 42,
        "source_event_state": "available",
    }]
    assert any("текущий AD-контекст" in item for item in payload["limitations"])


def test_default_computer_list_loads_summaries_only_for_paginated_page(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reports import what_where_when_reporting as reporting

    monkeypatch.setattr(reporting, "_load_workstation_population", lambda _ids: _inventory())
    monkeypatch.setattr(reporting, "_load_projection_status", lambda: {"state": "available", "backfill_completed": True})
    summary_guids: list[list[str]] = []
    monkeypatch.setattr(reporting, "_load_observation_summaries", lambda guids, *_args: summary_guids.append(guids) or {})

    reporting.get_computer_logon_computers(
        domain_ids=[7], limit=1, from_utc="2026-08-01T00:00:00Z",
        to_utc_exclusive="2026-09-01T00:00:00Z",
    )

    assert summary_guids == [["11111111-1111-4111-8111-111111111111"]]


def test_current_user_names_are_not_trusted_when_snapshot_hash_mismatches(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reports import what_where_when_reporting as reporting

    payload = {"users": [{"samAccountName": "ivanov", "displayName": "Иван Иванов"}]}
    rows = [{
        "domain_id": 7,
        "payload_json": payload,
        "payload_sha256": b"x" * 32,
    }]
    monkeypatch.setattr(reporting, "query_rows_bounded", lambda *_args, **_kwargs: rows)

    assert reporting._load_current_user_directory([7]) == {}
    rows[0]["payload_sha256"] = reporting._canonical_payload_hash(payload)
    assert reporting._load_current_user_directory([7]) == {"ivanov": "Иван Иванов"}


def test_v2_forwards_user_filters_to_list_and_detail(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict]] = []
    sent: list[tuple[dict, int]] = []
    monkeypatch.setattr(computer_logons, "logon_domain_scope", lambda _access: [7])
    monkeypatch.setattr(computer_logons, "get_computer_logon_computers", lambda **kwargs: calls.append(("computers", kwargs)) or {"state": "available", "items": [], "coverage": {}})
    monkeypatch.setattr(computer_logons, "get_computer_logon_observations", lambda **kwargs: calls.append(("observations", kwargs)) or {"state": "available", "items": []})

    class Handler:
        def _access_decision(self):
            return {"reports": [{"report_key": "ad.computer-logons", "allowed": True}]}

        def _send_json(self, payload, status=None):
            sent.append((payload, int(status or 200)))

    handler = Handler()
    routes_v2.try_handle_get(handler, "/api/v2/reports/ad.computer-logons/data", {"user": ["Иванов"], "with_logons": ["yes"], "period": ["7d"]})
    routes_v2.try_handle_get(handler, "/api/v2/reports/ad.computer-logons/rows/42/detail", {"user": ["Петров"]})
    routes_v2.try_handle_get(handler, "/api/v2/reports/ad.computer-logons/data", {"with_logons": ["true"]})

    assert calls[0][1]["user_q"] == "Иванов" and calls[0][1]["with_logons"] is True
    assert calls[1][1]["entity_id"] == 42 and calls[1][1]["user_q"] == "Петров"
    assert sent[0][0]["state"] == "empty" and sent[1][0]["state"] == "empty"
    assert sent[-1] == ({"error": "report_parameter_invalid:with_logons"}, 400)