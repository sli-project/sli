from __future__ import annotations

from datetime import datetime, timezone
import io
from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

import pytest

from server.sli.reports import security_event_reporting as reporting
from server.sli.events import event_details
from server.api.routes import reports as routes_reports
from server.source_packs.windows_ad_dc import (
    SECURITY_EVENTS_CONTEXT_EVENT_IDS,
    SECURITY_EVENTS_REPORT_DEFAULT_EVENT_IDS,
    SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS,
    SECURITY_EVENTS_REPORT_EVENT_IDS,
    security_event_family,
    security_event_ids_for_family,
    semantic_projection_for_event,
)


UTC = timezone.utc


def _archive_unavailable(_ids: object) -> dict[int, dict[str, object]]:
    """Hydration stand-in: these tests cover cursor/filter binding, not the archive."""
    raise RuntimeError("archive is not part of this test")


def _event(event_db_id: int, event_id: int, minute: int, **overrides: object) -> dict[str, object]:
    return {
        "event_db_id": event_db_id,
        "event_record_id": 9000 + event_db_id,
        "event_id": event_id,
        "time_created_utc": datetime(2026, 9, 1, 10, minute, tzinfo=UTC),
        "source_host": "dc01.example.test",
        "subject_user_sid": "S-1-5-21-actor",
        "subject_user_name": "operator",
        "target_user_sid": "S-1-5-21-affected",
        "target_user_name": "affected",
        "source_core_sha256": b"a" * 32,
        "source_facts_sha256": b"b" * 32,
        **overrides,
    }


def test_required_event_ids_have_one_source_owned_family() -> None:
    expected = {
        4740, 4767, 4723, 4724, 4720, 4722, 4725, 4726, 4738, 4781,
        4728, 4729, 4732, 4733, 4756, 4757,
        4727, 4730, 4737, 4731, 4734, 4735, 4754, 4755, 4758, 4764,
        4719, 1102,
    }

    assert SECURITY_EVENTS_REPORT_DEFAULT_EVENT_IDS == frozenset(expected)
    assert SECURITY_EVENTS_REPORT_EVENT_IDS == SECURITY_EVENTS_REPORT_DEFAULT_EVENT_IDS
    assert SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS == frozenset(
        expected | {4624, 4625, 4771, 4776}
    )
    assert SECURITY_EVENTS_CONTEXT_EVENT_IDS == frozenset({4624, 4625, 4771, 4776})
    assert {security_event_family(event_id) for event_id in expected} == {
        "account_lock", "password_operation", "account_lifecycle",
        "account_change", "group_membership", "group_lifecycle",
        "audit_configuration",
    }


def test_compose_distinguishes_observed_roles_source_outcome_and_exact_evidence() -> None:
    payload = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[
            _event(
                8, 4728, 8,
                membership_member_sid="S-1-5-21-member",
                membership_member_name="CN=Alice,DC=example,DC=test",
                member_entity_id=101,
                target_user_sid="S-1-5-21-group",
                target_user_name="Domain Admins",
                target_entity_id=202,
            ),
            _event(
                9, 4724, 9, result_code="0xC000006D",
                audit_keywords="0x8010000000000000", source_facts_sha256=None,
            ),
            _event(10, 4740, 10),
        ],
        collection_coverage={"history_event_present": True},
        display_limit=3,
        has_more=True,
    )

    assert [item["event_db_id"] for item in payload["items"]] == [10, 9, 8]
    assert payload["items"][0]["event_family"] == "account_lock"
    assert payload["items"][0]["outcome"]["state"] == "unknown"
    assert payload["items"][1]["outcome"] == {
        "state": "observed", "value": "failure",
        "result_code": "0xC000006D", "basis": "audit_keywords",
    }
    assert payload["items"][1]["evidence"] == {
        "state": "partial",
        "missing_fields": ["source_facts_sha256"],
        "event_db_id": 9,
        "event_record_id": 9009,
        "source_core_sha256": "61" * 32,
        "source_facts_sha256": None,
    }
    assert payload["items"][0]["actor"] == {
        "state": "observed", "sid": "S-1-5-21-actor", "name": "operator"
    }
    assert payload["items"][0]["affected_account"] == {
        "state": "observed", "sid": "S-1-5-21-affected", "name": "affected"
    }
    assert payload["items"][0]["member"] == {"state": "unknown"}
    assert payload["items"][0]["group"] == {"state": "unknown"}
    assert payload["items"][0]["source_host"] == {
        "state": "observed", "hostname": "dc01.example.test"
    }
    assert payload["has_more"] is True
    assert payload["next_cursor"]
    assert payload["items"][2]["member"] == {
        "state": "observed", "sid": "S-1-5-21-member", "name": "CN=Alice,DC=example,DC=test",
        "entity_id": 101,
    }
    assert payload["items"][2]["group"] == {
        "state": "observed", "sid": "S-1-5-21-group", "name": "Domain Admins",
        "entity_id": 202,
    }
    assert payload["items"][2]["affected_account"] == {"state": "unknown"}


def test_default_filters_are_unrestricted_and_explicit_category_and_event_id_are_preserved() -> None:
    assert reporting._normalize_filters() == {}
    assert security_event_ids_for_family("authentication") == frozenset({4624, 4625, 4771, 4776})
    assert reporting._normalize_filters(category="authentication") == {"category": "authentication"}
    assert reporting._normalize_filters(event_id=4771) == {"event_id": 4771}


def test_all_domain_daily_counts_apply_the_same_authorized_scope(monkeypatch) -> None:
    access = _report_access()
    access["reports"][0]["grants"][0]["scope"]["ids"] = [7, 8]
    monkeypatch.setattr(reporting, "_read_security_event_domain_batch", lambda **kwargs: [1, 7, 8])
    cursor = _SecurityEventReadCursor(page_rows=[
        {"day": "2026-09-01", "event_id": 4624, "event_count": 3},
        {"day": "2026-09-01", "event_id": 4776, "event_count": 2},
        {"day": "2026-09-01", "event_id": 4720, "event_count": 1},
    ], alias_rows=[])
    monkeypatch.setattr(reporting, "_connect", lambda: _SecurityEventReadConnection(cursor))
    arguments = {"source_domain_id": None, "time_from": "2026-09-01T10:00:00Z", "time_to": "2026-09-01T11:00:00Z"}
    payload = reporting.get_security_events_daily(access, **arguments)
    assert payload["days"] == [{"date": "2026-09-01", "total": 6, "families": {"authentication": 5, "account_lifecycle": 1}}]
    sql, params = cursor.statements[-1]
    assert "event.domain_id=any(%s)" in sql
    assert params[1] == [7, 8]
    assert {4624, 4625, 4776} <= set(params[2])
    monkeypatch.setattr(reporting, "_connect", lambda: pytest.fail("unauthorized daily query read events"))
    assert reporting.get_security_events_daily({}, **arguments)["state"] == "not_authorized"


def test_all_domain_entity_resolution_keeps_identical_sids_in_their_domains(monkeypatch) -> None:
    class DomainCursor(_SecurityEventReadCursor):
        def fetchall(self):
            if "alias.normalized_value=any(%s)" in self._last_sql:
                domain_id = self.statements[-1][1][0]
                return [{"normalized_value": "s-1-5-21-actor", "entity_id": 100 + domain_id}]
            return super().fetchall()

    cursor = DomainCursor(page_rows=[_event(20, 4624, 20, domain_id=8), _event(10, 4625, 10, domain_id=7)], alias_rows=[])
    monkeypatch.setattr(reporting, "_connect", lambda: _SecurityEventReadConnection(cursor))
    events, _coverage, _more = reporting._read_security_events_page(
        domain_id=[7, 8], period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC), limit=2, before=None, filters={},
    )
    assert [(event["domain_id"], event["actor_entity_id"]) for event in events] == [(8, 108), (7, 107)]


def test_all_domain_page_is_globally_ordered_and_cursor_is_bound_to_authorized_domains(monkeypatch) -> None:
    access = _report_access()
    access["reports"][0]["grants"][0]["scope"]["ids"] = [7, 8]
    monkeypatch.setattr(reporting, "_read_security_event_domain_batch", lambda **kwargs: [1, 7, 8] if kwargs["after_domain_id"] == 0 else [])
    cursor = _SecurityEventReadCursor(page_rows=[
        _event(30, 4624, 30, domain_id=8),
        _event(20, 4625, 20, domain_id=7),
        _event(10, 4776, 10, domain_id=8),
    ], alias_rows=[])
    monkeypatch.setattr(reporting, "_connect", lambda: _SecurityEventReadConnection(cursor))
    monkeypatch.setattr(reporting, "_merge_hydrated_fields", lambda _events: None)
    arguments = {"source_domain_id": None, "time_from": "2026-09-01T10:00:00Z", "time_to": "2026-09-01T11:00:00Z", "limit": 2}
    page = reporting.get_security_events_report(access, **arguments)
    assert [item["event_db_id"] for item in page["items"]] == [30, 20]
    assert page["has_more"] and page["next_cursor"]
    sql, params = next((sql, params) for sql, params in cursor.statements if "order by event.time_created_utc desc" in sql)
    assert "event.domain_id=any(%s)" in sql
    assert params[0] == [7, 8]
    assert {4624, 4625, 4776} <= set(params[1])
    reporting.get_security_events_report(access, **arguments, cursor=page["next_cursor"])
    sql, params = next((sql, params) for sql, params in reversed(cursor.statements) if "order by event.time_created_utc desc" in sql)
    assert "(event.time_created_utc,event.id)<(%s,%s)" in sql
    assert params[-2] == 20
    access["reports"][0]["grants"][0]["scope"]["ids"] = [7]
    with pytest.raises(ValueError, match="invalid_cursor"):
        reporting.get_security_events_report(access, **arguments, cursor=page["next_cursor"])


def test_all_domain_export_checks_export_grants_and_no_grants_never_read_events(monkeypatch) -> None:
    monkeypatch.setattr(reporting, "_read_security_event_domain_batch", lambda **kwargs: [1, 7] if kwargs["after_domain_id"] == 0 else [])
    monkeypatch.setattr(reporting, "_merge_hydrated_fields", lambda _events: None)
    read_scopes = []
    monkeypatch.setattr(reporting, "_read_security_events_page", lambda **kwargs: read_scopes.append(kwargs["domain_id"]) or ([], {"history_event_present": True}, False))
    access = _report_access()
    arguments = {"source_domain_id": None, "time_from": "2026-09-01T10:00:00Z", "time_to": "2026-09-01T11:00:00Z"}
    assert reporting.get_security_events_report(access, **arguments)["state"] == "empty_unverified"
    assert read_scopes == [[7]]
    access["reports"][0]["grants"][0]["allowed_actions"] = ["view"]
    assert reporting.get_security_events_report(access, **arguments, action="export")["state"] == "not_authorized"
    assert read_scopes == [[7]]
    assert reporting.get_security_events_report({}, **arguments)["state"] == "not_authorized"
    assert read_scopes == [[7]]


def test_atomic_report_includes_authentication_by_default_and_preserves_explicit_selectors() -> None:
    payload = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[_event(index, event_id, index) for index, event_id in enumerate((4624, 4625, 4776, 4720), start=1)],
        collection_coverage={"history_event_present": True},
    )
    assert {item["event_id"] for item in payload["items"]} == {4624, 4625, 4776, 4720}

    category_payload = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[_event(index, event_id, index) for index, event_id in enumerate((4624, 4625, 4771, 4776), start=1)],
        collection_coverage={"history_event_present": True},
        filters={"category": "authentication"},
    )
    assert {item["event_id"] for item in category_payload["items"]} == {4624, 4625, 4771, 4776}

    exact_payload = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[_event(10, 4771, 10)],
        collection_coverage={"history_event_present": True},
        filters={"event_id": 4771},
    )
    assert [item["event_id"] for item in exact_payload["items"]] == [4771]


def test_account_actions_reuse_account_history_transition_semantics() -> None:
    payload = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[_event(1, 4720, 1), _event(2, 4722, 2)],
        collection_coverage={"history_event_present": True},
    )

    newest = payload["items"][0]
    assert newest["event_db_id"] == 2
    assert newest["account_change"]["change"] == {"kind": "enabled"}
    assert newest["account_change"]["observed_transition"] == {
        "before": {
            "state": "partial",
            "last_observed": {
                "value": "present",
                "event_db_id": 1,
                "time_created_utc": "2026-09-01T10:01:00Z",
            },
            "reason": "intervening_account_state_not_proven",
        },
        "after": {"state": "observed", "value": "enabled"},
    }


def test_password_outcome_requires_source_native_audit_keyword() -> None:
    payload = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[
            _event(
                1, 4724, 1, subject_user_sid=None, subject_user_name=None,
                target_user_sid=None, target_user_name=None, result_code="0x0",
            ),
            _event(2, 4724, 2, audit_keywords="AuditSuccess", result_code="0xC000006D"),
            _event(3, 4724, 3, audit_keywords="AuditFailure", result_code="0x0"),
        ],
        collection_coverage={"history_event_present": True},
    )

    items = {item["event_db_id"]: item for item in payload["items"]}
    item = items[1]
    assert item["actor"] == {"state": "unknown"}
    assert item["affected_account"] == {"state": "unknown"}
    assert item["outcome"] == {
        "state": "unknown", "reason": "event_outcome_not_proven_by_scoped_contract",
        "result_code": "0x0",
    }
    assert items[2]["outcome"]["value"] == "success"
    assert items[2]["outcome"]["basis"] == "audit_keywords"
    assert items[3]["outcome"]["value"] == "failure"


def test_service_validates_bounds_binds_reverse_cursor_and_denies_before_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="security_events_period_too_wide"):
        reporting.get_security_events_report(
            _report_access(),
            source_domain_id=7,
            time_from="2026-08-01T00:00:00Z",
            time_to="2026-09-02T00:00:00Z",
        )
    with pytest.raises(ValueError, match="security_events_limit_invalid"):
        reporting.get_security_events_report(
            _report_access(),
            source_domain_id=7,
            time_from="2026-09-01T10:00:00Z",
            time_to="2026-09-01T11:00:00Z",
            limit=501,
        )

    monkeypatch.setattr(
        reporting, "_read_security_events_page",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )
    denied = reporting.get_security_events_report(
        {"platform_owner": False, "capabilities": [], "capability_policies": [], "reports": []},
        source_domain_id=7,
        time_from="2026-09-01T10:00:00Z",
        time_to="2026-09-01T11:00:00Z",
    )
    assert denied["state"] == "not_authorized"

    cursor = reporting._encode_cursor(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        event_time=datetime(2026, 9, 1, 10, 5, tzinfo=UTC),
        event_db_id=5,
    )
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        reporting,
        "_read_security_events_page",
        lambda **kwargs: captured.update(kwargs) or ([], {"history_event_present": True}, False),
    )
    report = reporting.get_security_events_report(
        _report_access(),
        source_domain_id=7,
        time_from="2026-09-01T10:00:00Z",
        time_to="2026-09-01T11:00:00Z",
        limit=200,
        cursor=cursor,
    )
    assert captured["before"] == (datetime(2026, 9, 1, 10, 5, tzinfo=UTC), 5)
    assert report["state"] == "empty_unverified"
    with pytest.raises(ValueError, match="invalid_cursor"):
        reporting.get_security_events_report(
            _report_access(),
            source_domain_id=8,
            time_from="2026-09-01T10:00:00Z",
            time_to="2026-09-01T11:00:00Z",
            cursor=cursor,
        )


def test_entity_candidate_service_returns_ids_only_after_report_access(monkeypatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        reporting,
        "_read_security_event_candidate_ids",
        lambda **kwargs: captured.update(kwargs) or ([30, 20], True),
        raising=False,
    )

    result = reporting.get_security_event_candidate_ids(
        _report_access(),
        source_domain_id=7,
        time_from="2026-09-01T10:00:00.123001Z",
        time_to="2026-09-01T11:00:00.123999Z",
        timezone_name="UTC",
        limit=101,
        entity_id=55,
    )

    assert result == {
        "state": "available",
        "items": [{"event_db_id": 30}, {"event_db_id": 20}],
        "has_more": True,
    }
    assert captured == {
        "domain_id": 7,
        "period_start": datetime(2026, 9, 1, 10, 0, 0, 123001, tzinfo=UTC),
        "period_end": datetime(2026, 9, 1, 11, 0, 0, 123999, tzinfo=UTC),
        "limit": 101,
        "filters": {"entity_id": 55},
    }


def test_entity_candidate_service_denies_before_candidate_storage_read(monkeypatch) -> None:
    monkeypatch.setattr(
        reporting,
        "_read_security_event_candidate_ids",
        lambda **_kwargs: pytest.fail("denied report reached candidate storage"),
        raising=False,
    )

    result = reporting.get_security_event_candidate_ids(
        {"platform_owner": False, "capabilities": [], "reports": []},
        source_domain_id=7,
        time_from="2026-09-01T10:00:00Z",
        time_to="2026-09-01T11:00:00Z",
        limit=101,
        entity_id=55,
    )

    assert result == {"state": "not_authorized", "items": [], "has_more": False}


def _report_access(*, domain_id: int = 7) -> dict[str, object]:
    return {
        "platform_owner": False,
        "capabilities": ["events.view"],
        "capability_policies": [],
        "reports": [{
            "report_key": "security.events.chains",
            "allowed": True,
            "allowed_actions": ["view", "export"],
            "grants": [{
                "allowed_actions": ["view", "export"],
                "field_categories": ["identity_basic", "security", "technical", "raw_evidence"],
                "scope": {"kind": "domain", "ids": [domain_id]},
            }],
        }],
    }


def test_service_requires_existing_report_and_events_view_before_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting, "_read_security_events_page",
        lambda **_kwargs: pytest.fail("database must not be read"),
    )

    for access in (
        {"platform_owner": False, "capabilities": [], "capability_policies": [], "reports": []},
        {**_report_access(), "capabilities": []},
        {**_report_access(domain_id=8)},
        {
            **_report_access(),
            "reports": [{
                "report_key": "security.events.chains",
                "allowed": True,
                "allowed_actions": ["view"],
                "grants": [{
                    "allowed_actions": ["view"],
                    "field_categories": ["identity_basic", "security"],
                    "scope": {"kind": "domain", "ids": [7]},
                }],
            }],
        },
    ):
        assert reporting.get_security_events_report(
            access,
            source_domain_id=7,
            time_from="2026-09-01T10:00:00Z",
            time_to="2026-09-01T11:00:00Z",
        )["state"] == "not_authorized"


def test_service_accepts_effective_security_event_grant_without_identity_basic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dataset-bounded grants carry only the report's real field categories."""

    monkeypatch.setattr(
        reporting,
        "_read_security_events_page",
        lambda **_kwargs: ([], {"history_event_present": True}, False),
    )
    access = {
        "platform_owner": False,
        "capabilities": [
            "events.view", "semantic.review", "evidence.exact", "field.security",
        ],
        "capability_policies": [],
        "reports": [{
            "report_key": "security.events.chains",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": [{
                "allowed_actions": ["view"],
                "field_categories": ["raw_evidence", "security", "technical"],
                "scope": {"kind": "domain", "ids": [7]},
            }],
        }],
    }

    report = reporting.get_security_events_report(
        access,
        source_domain_id=7,
        time_from="2026-09-01T10:00:00Z",
        time_to="2026-09-01T11:00:00Z",
    )

    assert report["state"] == "empty_unverified"


def test_authorized_source_discovery_checks_access_before_event_presence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting, "_read_security_event_domain_batch", lambda **_kwargs: [7, 8]
    )
    inspected: list[int] = []
    monkeypatch.setattr(
        reporting,
        "_has_security_event_source",
        lambda domain_id: inspected.append(domain_id) or domain_id == 7,
    )

    assert reporting.get_security_event_sources(_report_access())["items"] == [{"source_domain_id": 7}]
    assert inspected == [7]


def test_filters_are_server_bound_to_cursor_and_csv_uses_the_returned_page_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    event = _event(5, 4728, 5, source_facts_sha256=None)
    monkeypatch.setattr(
        reporting,
        "_read_security_events_page",
        lambda **kwargs: captured.update(kwargs) or ([event], {"history_event_present": True}, True),
    )
    monkeypatch.setattr(reporting, "get_v2_event_details_by_ids", _archive_unavailable)
    report = reporting.get_security_events_report(
        _report_access(),
        source_domain_id=7,
        time_from="2026-09-01T10:00:00Z",
        time_to="2026-09-01T11:00:00Z",
        category="group_membership",
        event_id=4728,
        outcome="unknown",
        actor="operator",
        target_account="affected",
        group="Domain Admins",
        source_host="dc01.example.test",
        q="affected",
    )
    filters = captured["filters"]
    assert filters == {
        "category": "group_membership", "event_id": 4728, "outcome": "unknown",
        "actor": "operator", "target_account": "affected", "group": "Domain Admins",
        "source_host": "dc01.example.test", "q": "affected",
    }
    cursor = report["next_cursor"]
    assert cursor
    with pytest.raises(ValueError, match="invalid_cursor"):
        reporting.get_security_events_report(
            _report_access(), source_domain_id=7,
            time_from="2026-09-01T10:00:00Z", time_to="2026-09-01T11:00:00Z",
            category="account_lock", cursor=cursor,
        )

    monkeypatch.setattr(
        reporting, "_read_security_events_page",
        lambda **_kwargs: pytest.fail("CSV must not read database"),
    )
    csv_text = reporting.render_security_events_csv(report)
    assert "event_db_id,event_id,event_family" in csv_text
    assert "5,4728,group_membership" in csv_text
    assert "has_more=true" in csv_text
    assert "incomplete=true" in csv_text


def test_csv_neutralizes_source_native_spreadsheet_formulas() -> None:
    report = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[_event(5, 4728, 5, subject_user_name="=cmd", target_user_name="+group")],
        collection_coverage={"history_event_present": True},
    )

    csv_text = reporting.render_security_events_csv(report)

    assert "'=cmd" in csv_text
    assert "'+group" in csv_text


def test_http_route_forwards_server_access_precise_window_filters_and_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_service(access, **kwargs):
        captured["access"] = access
        captured.update(kwargs)
        return {"state": "available", "items": []}

    monkeypatch.setattr(routes_reports, "get_security_events_report", fake_service, raising=False)

    class Handler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            assert status is None
            captured["payload"] = payload

    assert routes_reports.is_resource_aware("/api/v1/reports/ad.state/security-events")
    assert routes_reports.try_handle_get(
        Handler(),
        "/api/v1/reports/ad.state/security-events",
        {
            "domain_id": ["7"],
            "time_from": ["2026-09-11T10:20:30.123456Z"],
            "time_to": ["2026-09-11T11:20:30.987654Z"],
            "timezone": ["Asia/Bangkok"],
            "limit": ["200"],
            "category": ["group_membership"],
            "event_id": ["4728"],
            "event_db_id": ["77"],
            "entity_id": ["55"],
            "outcome": ["unknown"],
            "actor": ["operator"],
            "target": ["evidence-reader"],
            "group": ["VPNl2tp"],
            "source": ["DC1"],
            "q": ["VPN"],
            "cursor": ["next-page"],
        },
    )
    assert captured == {
        "access": {"server_built": True},
        "source_domain_id": 7,
        "time_from": "2026-09-11T10:20:30.123456Z",
        "time_to": "2026-09-11T11:20:30.987654Z",
        "timezone_name": "Asia/Bangkok",
        "limit": 200,
        "category": "group_membership",
        "event_id": 4728,
        "event_db_id": "77",
        "entity_id": "55",
        "outcome": "unknown",
        "actor": "operator",
        "target_account": "evidence-reader",
        "group": "VPNl2tp",
        "source_host": "DC1",
        "q": "VPN",
        "cursor": "next-page",
        "payload": {"state": "available", "items": []},
    }


@pytest.mark.parametrize(
    ("has_more", "content_disposition", "truncated"),
    [
        (False, 'attachment; filename="sli-security-events-complete-1-rows.csv"', "false"),
        (True, 'attachment; filename="sli-security-events-INCOMPLETE-first-1-rows.csv"', "true"),
    ],
)
def test_security_events_export_url_forwards_exact_filters_and_marks_hidden_evidence_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    has_more: bool,
    content_disposition: str,
    truncated: str,
) -> None:
    captured: dict[str, object] = {}
    url = (
        "/api/v1/reports/ad.state/security-events.csv?domain_id=7"
        "&time_from=2026-09-11T10%3A20%3A30.123456Z"
        "&time_to=2026-09-11T11%3A20%3A30.987654Z"
        "&timezone=Asia%2FBangkok&event_db_id=77&entity_id=55"
        "&actor=operator&target=evidence-reader&source=DC1&q=VPN"
    )

    def fake_service(access, **kwargs):
        captured["access"] = access
        captured.update(kwargs)
        return {
            "state": "available",
            "items": [{
                "event_db_id": 77,
                "event_id": 4728,
                "evidence": {"state": "hidden"},
            }],
            "has_more": has_more,
        }

    monkeypatch.setattr(routes_reports, "get_security_events_report", fake_service)

    class Handler:
        def _access_decision(self):
            return {"server_built": True}

        def send_response(self, status):
            captured["status"] = status

        def send_header(self, name, value):
            captured.setdefault("headers", {})[name] = value

        def end_headers(self):
            return None

        wfile = io.BytesIO()

    parsed = urlparse(url)
    assert routes_reports.is_resource_aware(parsed.path)
    assert routes_reports.try_handle_get(Handler(), parsed.path, parse_qs(parsed.query))
    assert captured["access"] == {"server_built": True}
    assert captured["action"] == "export"
    assert captured["limit"] == 500
    assert captured["cursor"] is None
    assert {key: captured[key] for key in (
        "source_domain_id", "time_from", "time_to", "timezone_name", "event_db_id",
        "entity_id", "actor", "target_account", "source_host", "q",
    )} == {
        "source_domain_id": 7,
        "time_from": "2026-09-11T10:20:30.123456Z",
        "time_to": "2026-09-11T11:20:30.987654Z",
        "timezone_name": "Asia/Bangkok",
        "event_db_id": "77",
        "entity_id": "55",
        "actor": "operator",
        "target_account": "evidence-reader",
        "source_host": "DC1",
        "q": "VPN",
    }
    assert captured["status"] == HTTPStatus.OK
    assert captured["headers"]["Content-Type"] == "text/csv; charset=utf-8"
    assert captured["headers"]["Content-Disposition"] == content_disposition
    assert captured["headers"]["X-Sli-Export-Rows"] == "1"
    assert captured["headers"]["X-Sli-Export-Truncated"] == truncated
    body = Handler.wfile.getvalue()
    assert b"evidence_state" in body
    assert b"hidden" in body
    assert b"incomplete=true" in body


def test_security_events_export_url_denies_before_csv_rendering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = (
        "/api/v1/reports/ad.state/security-events.csv?domain_id=7"
        "&time_from=2026-09-11T10%3A20%3A30Z&time_to=2026-09-11T11%3A20%3A30Z"
    )
    monkeypatch.setattr(
        routes_reports,
        "get_security_events_report",
        lambda *_args, **_kwargs: {"state": "not_authorized", "items": [], "has_more": False},
    )
    monkeypatch.setattr(
        routes_reports,
        "render_security_events_csv",
        lambda *_args: pytest.fail("denied export rendered CSV"),
    )
    captured: dict[str, object] = {}

    class Handler:
        def _access_decision(self):
            return {"server_built": False}

        def _send_json(self, payload, status):
            captured["payload"] = payload
            captured["status"] = status

    parsed = urlparse(url)
    assert routes_reports.try_handle_get(Handler(), parsed.path, parse_qs(parsed.query))
    assert captured == {
        "payload": {"error": "security_events_export_not_authorized"},
        "status": HTTPStatus.FORBIDDEN,
    }


def test_http_source_discovery_uses_server_built_access(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        routes_reports,
        "get_security_event_sources",
        lambda access: captured.setdefault("access", access) or {"state": "available"},
        raising=False,
    )

    class Handler:
        def _access_decision(self):
            return {"server_built": True}

        def _send_json(self, payload, status=None):
            captured["payload"] = payload

    assert routes_reports.try_handle_get(
        Handler(), "/api/v1/reports/ad.state/security-event-sources", {}
    )
    assert captured["access"] == {"server_built": True}


class _SecurityEventReadCursor:
    def __init__(self, *, page_rows: list[dict[str, object]], alias_rows: list[dict[str, object]]) -> None:
        self.page_rows = page_rows
        self.alias_rows = alias_rows
        self.statements: list[tuple[str, object]] = []
        self._last_sql = ""

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, sql: str, params: object = None) -> None:
        self._last_sql = sql
        self.statements.append((sql, params))

    def fetchall(self) -> list[dict[str, object]]:
        if "alias.normalized_value=any(%s)" in self._last_sql:
            return self.alias_rows
        return self.page_rows

    def fetchone(self) -> dict[str, object]:
        return {"history_event_present": True}


class _SecurityEventReadConnection:
    def __init__(self, cursor: _SecurityEventReadCursor) -> None:
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> _SecurityEventReadCursor:
        return self._cursor


def test_page_resolution_batches_only_returned_exact_sids_without_active_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A page must not expand the active-entity view once for every principal."""

    rows = [
        _event(30, 4728, 30, membership_member_sid="S-1-member"),
        _event(20, 4728, 20),
        _event(10, 4728, 10, subject_user_sid="S-1-next"),
    ]
    cursor = _SecurityEventReadCursor(
        page_rows=rows,
        alias_rows=[
            {"normalized_value": "s-1-5-21-actor", "entity_id": 101},
            {"normalized_value": "s-1-5-21-affected", "entity_id": 102},
            {"normalized_value": "s-1-member", "entity_id": 103},
        ],
    )
    monkeypatch.setattr(
        reporting, "_connect", lambda: _SecurityEventReadConnection(cursor)
    )

    events, coverage, has_more = reporting._read_security_events_page(
        domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        limit=2,
        before=None,
        filters={},
    )

    page_sql = next(
        sql for sql, _params in cursor.statements
        if "from events_v2_core event" in sql and "order by event.time_created_utc desc,event.id desc" in sql
    )
    alias_statements = [
        (sql, params) for sql, params in cursor.statements
        if "from ad_context_entity_aliases alias" in sql
    ]
    assert "entities_v2_active" not in page_sql
    assert "left join lateral" not in page_sql
    assert len(alias_statements) == 1
    alias_sql, alias_params = alias_statements[0]
    assert "alias.normalized_value=any(%s)" in alias_sql
    assert "entity_v2_is_active(alias.entity_id)" in alias_sql
    assert alias_params == [7, ["s-1-5-21-actor", "s-1-5-21-affected", "s-1-member"]]
    assert [event["event_db_id"] for event in events] == [30, 20]
    assert events[0]["actor_entity_id"] == 101
    assert events[0]["target_entity_id"] == 102
    assert events[0]["member_entity_id"] == 103
    assert has_more is True
    assert coverage["history_event_present"] is True
    assert coverage["category_coverage"]["group_membership"] == {
        "state": "retained_match_present"
    }
    public_page = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=events,
        collection_coverage=coverage,
        display_limit=2,
        has_more=has_more,
    )
    assert public_page["items"][0]["actor"]["entity_id"] == 101
    assert public_page["items"][0]["group"]["entity_id"] == 102
    assert public_page["items"][0]["member"]["entity_id"] == 103
    assert public_page["next_cursor"]


def test_page_query_binds_all_categories_by_default_and_preserves_explicit_selectors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def bound_event_ids(filters: dict[str, object]) -> list[int]:
        cursor = _SecurityEventReadCursor(page_rows=[], alias_rows=[])
        monkeypatch.setattr(
            reporting, "_connect", lambda: _SecurityEventReadConnection(cursor)
        )
        reporting._read_security_events_page(
            domain_id=7,
            period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
            period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
            limit=2,
            before=None,
            filters=filters,
        )
        _sql, params = next(
            (sql, params) for sql, params in cursor.statements
            if "from events_v2_core event" in sql
            and "order by event.time_created_utc desc,event.id desc" in sql
        )
        return list(params[1])

    default_ids = bound_event_ids({})
    assert set(default_ids) == SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS
    assert {4624, 4625, 4771, 4776} <= set(default_ids)
    assert bound_event_ids({"category": "authentication"}) == [4624, 4625, 4771, 4776]
    assert bound_event_ids({"event_id": 4625}) == [4625]


def test_page_resolution_keeps_merged_and_ambiguous_sids_unresolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only one active canonical entity may be attached to an exact SID."""

    rows = [
        _event(
            30,
            4728,
            30,
            subject_user_sid="S-1-active",
            target_user_sid="S-1-merged",
            membership_member_sid="S-1-ambiguous",
        ),
    ]
    cursor = _SecurityEventReadCursor(
        page_rows=rows,
        alias_rows=[
            {"normalized_value": "s-1-active", "entity_id": 101},
            {"normalized_value": "s-1-ambiguous", "entity_id": 102},
            {"normalized_value": "s-1-ambiguous", "entity_id": 103},
        ],
    )
    monkeypatch.setattr(
        reporting, "_connect", lambda: _SecurityEventReadConnection(cursor)
    )

    events, _coverage, _has_more = reporting._read_security_events_page(
        domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        limit=1,
        before=None,
        filters={},
    )

    assert events[0]["actor_entity_id"] == 101
    assert events[0].get("target_entity_id") is None
    assert events[0].get("member_entity_id") is None


def test_entity_filter_uses_bounded_active_alias_checks_before_page_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = _SecurityEventReadCursor(page_rows=[], alias_rows=[])
    monkeypatch.setattr(
        reporting, "_connect", lambda: _SecurityEventReadConnection(cursor)
    )

    reporting._read_security_events_page(
        domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        limit=2,
        before=None,
        filters={"entity_id": 101},
    )

    page_sql = next(
        sql for sql, _params in cursor.statements
        if "from events_v2_core event" in sql and "order by event.time_created_utc desc,event.id desc" in sql
    )
    assert "entities_v2_active" not in page_sql
    assert page_sql.count("entity_v2_is_active(alias_entity.id)") == 3
    assert page_sql.count("exists(select 1 from ad_context_entity_aliases alias") == 3


def test_entity_filter_includes_exact_canonical_link_block_before_page_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A card's shared history is selected by its durable V2 link, not a name."""

    cursor = _SecurityEventReadCursor(
        page_rows=[_event(1_906_133, 4724, 10)], alias_rows=[]
    )
    monkeypatch.setattr(
        reporting, "_connect", lambda: _SecurityEventReadConnection(cursor)
    )

    events, _coverage, _has_more = reporting._read_security_events_page(
        domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        limit=2,
        before=None,
        filters={"entity_id": 1_088_183},
    )

    page_sql, page_params = next(
        (sql, params) for sql, params in cursor.statements
        if "from events_v2_core event" in sql
        and "order by event.time_created_utc desc,event.id desc" in sql
    )
    assert [event["event_db_id"] for event in events] == [1_906_133]
    assert "entities_v2_active" not in page_sql
    assert "from event_entity_link_blocks_v2 block" in page_sql
    assert "block.entity_id=resolve_entity_identity_v2(%s)" in page_sql
    assert "entity_v2_is_active(block.entity_id)" in page_sql
    assert "block.first_event_id<=event.id and block.last_event_id>=event.id" in page_sql
    assert "cross join lateral unnest(block.event_ids,block.role_ids) linked(event_id,role_id)" in page_sql
    assert "linked.event_id=event.id" in page_sql
    assert list(page_params)[-2:] == [1_088_183, 3]


def test_entity_candidate_query_returns_only_ids_with_the_same_exact_predicate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = _SecurityEventReadCursor(
        page_rows=[{"event_db_id": 30}, {"event_db_id": 20}, {"event_db_id": 10}],
        alias_rows=[],
    )
    monkeypatch.setattr(
        reporting, "_connect", lambda: _SecurityEventReadConnection(cursor)
    )

    event_ids, has_more = reporting._read_security_event_candidate_ids(
        domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        limit=2,
        filters={"entity_id": 101},
    )

    candidate_sql, params = next(
        (sql, params) for sql, params in cursor.statements
        if "from events_v2_core event" in sql
    )
    normalized = " ".join(candidate_sql.lower().split())
    assert event_ids == [30, 20]
    assert has_more is True
    assert "select event.id as event_db_id" in normalized
    assert "event.time_created_utc as" not in normalized
    assert "event.subject_user_name" not in normalized
    assert "event.source_core_sha256" not in normalized
    assert "facts.source_facts_sha256" not in normalized
    assert normalized.count("exists(select 1 from ad_context_entity_aliases alias") == 3
    assert "from event_entity_link_blocks_v2 block" in normalized
    assert list(params)[-2:] == [101, 3]


def test_exact_event_and_entity_selectors_are_bound_to_cursor_and_storage_predicate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    event = _event(91, 4728, 5)
    monkeypatch.setattr(
        reporting,
        "_read_security_events_page",
        lambda **kwargs: captured.update(kwargs) or ([event], {"history_event_present": True}, True),
    )
    monkeypatch.setattr(reporting, "get_v2_event_details_by_ids", _archive_unavailable)

    report = reporting.get_security_events_report(
        _report_access(), source_domain_id=7,
        time_from="2026-09-01T10:00:00Z", time_to="2026-09-01T11:00:00Z",
        entity_id=55, event_db_id=91,
    )

    assert captured["filters"] == {"entity_id": 55, "event_db_id": 91}
    assert report["filters"] == {"entity_id": 55, "event_db_id": 91}
    with pytest.raises(ValueError, match="invalid_cursor"):
        reporting.get_security_events_report(
            _report_access(), source_domain_id=7,
            time_from="2026-09-01T10:00:00Z", time_to="2026-09-01T11:00:00Z",
            entity_id=55, event_db_id=92, cursor=report["next_cursor"],
        )
    for bad in ("0", "-1", "not-an-id"):
        with pytest.raises(ValueError, match="security_events_filter_invalid"):
            reporting._normalize_filters(event_db_id=bad)


def test_page_exposes_caller_concrete_change_and_safe_archive_partial_state() -> None:
    payload = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[
            _event(1, 4740, 1, caller_computer="CLIENT-42"),
            _event(2, 4728, 2, membership_member_name="Alice", target_user_name="Admins"),
            _event(3, 4727, 3, target_user_name="New Group"),
            _event(4, 4719, 4, audit_category_id="{cat}", audit_subcategory_id="{sub}", audit_policy_changes="Success removed"),
            _event(5, 1102, 5, cleared_log="Security"),
            _event(6, 4722, 6, archive_field_state="partial_archive_unavailable"),
        ],
        collection_coverage={"history_event_present": True},
    )
    items = {item["event_db_id"]: item for item in payload["items"]}

    assert items[1]["source_host"] == {"state": "observed", "hostname": "dc01.example.test"}
    assert items[1]["caller_computer"] == {"state": "observed", "hostname": "CLIENT-42"}
    assert items[2]["change"] == {"state": "observed", "kind": "member_added"}
    assert items[3]["change"] == {"state": "observed", "kind": "group_created"}
    assert items[4]["change"] == {
        "state": "observed", "kind": "audit_policy_changed",
        "category_id": "{cat}", "subcategory_id": "{sub}", "observed_value": "Success removed",
    }
    assert items[5]["change"] == {"state": "observed", "kind": "security_log_cleared", "observed_value": "Security"}
    assert items[6]["archive_fields"] == {"state": "partial", "reason": "archive_unavailable"}
    assert "raw_xml" not in repr(items)
    assert "event_data" not in items[2]


def test_service_hydrates_only_authorized_page_ids_and_survives_archive_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[int]] = []
    event = _event(17, 4728, 1)
    monkeypatch.setattr(
        reporting,
        "_read_security_events_page",
        lambda **_kwargs: ([event], {"history_event_present": True}, False),
    )
    monkeypatch.setattr(
        reporting,
        "_hydrate_security_event_fields",
        lambda events: calls.append([int(row["event_db_id"]) for row in events]) or {
            17: {"membership_member_name": "Alice", "target_user_name": "Admins"}
        },
    )
    report = reporting.get_security_events_report(
        _report_access(), source_domain_id=7,
        time_from="2026-09-01T10:00:00Z", time_to="2026-09-01T11:00:00Z",
    )
    assert calls == [[17]]
    assert report["items"][0]["member"]["name"] == "Alice"

    monkeypatch.setattr(
        reporting, "_hydrate_security_event_fields",
        lambda _events: {17: {"archive_field_state": "partial_archive_unavailable"}},
    )
    partial = reporting.get_security_events_report(
        _report_access(), source_domain_id=7,
        time_from="2026-09-01T10:00:00Z", time_to="2026-09-01T11:00:00Z",
    )
    assert partial["items"][0]["archive_fields"] == {"state": "partial", "reason": "archive_unavailable"}


def test_archive_hydration_chunks_exact_page_ids_to_details_owner_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[int]] = []

    def read_details(event_ids: list[int]) -> dict[int, dict[str, object]]:
        calls.append(event_ids)
        return {
            event_id: {"event_data": {"CallerComputerName": f"client-{event_id}"}}
            for event_id in event_ids
        }

    monkeypatch.setattr(reporting, "get_v2_event_details_by_ids", read_details)

    hydrated = reporting._hydrate_security_event_fields([
        {"event_db_id": event_db_id} for event_db_id in range(1, 102)
    ])

    assert calls == [list(range(1, 101)), [101]]
    assert hydrated[1] == {"caller_computer": "client-1"}
    assert hydrated[101] == {"caller_computer": "client-101"}


def test_security_report_uses_v2_only_detail_owner_when_v2_route_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    colliding_id = 77
    v1_detail = {colliding_id: {"event_data": {"CallerComputerName": "V1-COLLISION"}}}
    v2_detail = {colliding_id: {"event_data": {"CallerComputerName": "V2-CORE"}}}
    calls: list[list[int]] = []
    route_calls: list[object] = []

    monkeypatch.setattr(
        event_details,
        "resolve_storage_route",
        lambda **kwargs: route_calls.append(kwargs) or {"route": "v1", "v2_read_enabled": False},
    )
    monkeypatch.setattr(event_details, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(event_details, "_get_v2_event_details_by_ids", lambda ids, **_kwargs: calls.append(ids) or v2_detail)
    monkeypatch.setattr(event_details, "get_event_details_by_ids", lambda _ids: v1_detail)

    details = event_details.get_v2_event_details_by_ids([colliding_id])

    assert route_calls == []
    assert calls == [[colliding_id]]
    assert details == v2_detail

    monkeypatch.setattr(
        reporting,
        "get_v2_event_details_by_ids",
        lambda ids: calls.append(ids) or v2_detail,
    )
    monkeypatch.setattr(
        reporting,
        "get_event_details_by_ids",
        lambda _ids: pytest.fail("security report must not use V1/V2 routed detail owner"),
        raising=False,
    )
    hydrated = reporting._hydrate_security_event_fields([
        _event(colliding_id, 4740, 1),
    ])

    assert calls == [[colliding_id], [colliding_id]]
    assert hydrated[colliding_id] == {"caller_computer": "V2-CORE"}


def test_archive_allowlist_exposes_concrete_account_and_group_change_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "get_v2_event_details_by_ids",
        lambda _ids: {
            1: {"event_data": {"DisplayName": "Alice Example", "UserPrincipalName": "alice@example.test"}},
            2: {"event_data": {"Description": "Tier zero", "GroupType": "Security-enabled global group"}},
            3: {"event_data": {"OldGroupType": "Global", "NewGroupType": "Universal"}},
        },
    )
    events = [_event(1, 4738, 1), _event(2, 4737, 2), _event(3, 4764, 3)]
    reporting._merge_hydrated_fields(events)

    payload = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=events,
        collection_coverage={"history_event_present": True},
    )
    changes = {item["event_db_id"]: item["change"] for item in payload["items"]}

    assert changes[1] == {
        "state": "observed", "kind": "attributes_changed",
        "attributes": {
            "display_name": "Alice Example",
            "user_principal_name": "alice@example.test",
        },
    }
    assert changes[2] == {
        "state": "observed", "kind": "group_changed",
        "attributes": {"description": "Tier zero", "group_type": "Security-enabled global group"},
    }
    assert changes[3] == {
        "state": "observed", "kind": "group_type_changed",
        "old_group_type": "Global", "new_group_type": "Universal",
    }
    assert "account_name_before" not in changes[1]
    assert "event_data" not in repr(changes)


def test_change_contract_ignores_windows_absence_markers_when_real_fields_are_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "get_v2_event_details_by_ids",
        lambda _ids: {
            1: {"event_data": {"DisplayName": " - ", "UserPrincipalName": "alice@example.test"}},
            2: {"event_data": {"Description": "-", "GroupType": "Security-enabled global group"}},
        },
    )
    events = [_event(1, 4738, 1), _event(2, 4737, 2)]
    reporting._merge_hydrated_fields(events)

    payload = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=events,
        collection_coverage={"history_event_present": True},
    )
    changes = {item["event_db_id"]: item["change"] for item in payload["items"]}

    assert changes[1] == {
        "state": "observed", "kind": "attributes_changed",
        "attributes": {"user_principal_name": "alice@example.test"},
    }
    assert changes[2] == {
        "state": "observed", "kind": "group_changed",
        "attributes": {"group_type": "Security-enabled global group"},
    }


def test_change_contract_with_only_windows_absence_markers_is_partial_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "get_v2_event_details_by_ids",
        lambda _ids: {
            1: {"event_data": {"DisplayName": "-", "UserPrincipalName": " - "}},
            2: {"event_data": {"Description": "-", "GroupType": " - "}},
        },
    )
    events = [_event(1, 4738, 1), _event(2, 4737, 2)]
    reporting._merge_hydrated_fields(events)

    payload = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=events,
        collection_coverage={"history_event_present": True},
    )
    changes = {item["event_db_id"]: item["change"] for item in payload["items"]}

    assert changes[1] == {
        "state": "partial", "kind": "attributes_changed",
        "detail": {"state": "unknown", "reason": "account_attributes_not_present"},
    }
    assert changes[2] == {
        "state": "partial", "kind": "group_changed",
        "detail": {"state": "unknown", "reason": "group_change_attributes_not_present"},
    }


def test_change_kinds_are_partial_without_their_source_native_detail() -> None:
    payload = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[
            _event(1, 4738, 1), _event(2, 4737, 2), _event(3, 4764, 3),
            _event(4, 4719, 4), _event(5, 1102, 5),
        ],
        collection_coverage={"history_event_present": True},
    )
    changes = {item["event_db_id"]: item["change"] for item in payload["items"]}

    assert changes[1] == {
        "state": "partial", "kind": "attributes_changed",
        "detail": {"state": "unknown", "reason": "account_attributes_not_present"},
    }
    assert changes[2] == {
        "state": "partial", "kind": "group_changed",
        "detail": {"state": "unknown", "reason": "group_change_attributes_not_present"},
    }
    assert changes[3] == {
        "state": "partial", "kind": "group_type_changed",
        "detail": {"state": "unknown", "reason": "group_type_values_not_present"},
    }
    assert changes[4] == {
        "state": "partial", "kind": "audit_policy_changed",
        "detail": {"state": "unknown", "reason": "audit_policy_fields_not_present"},
    }
    assert changes[5] == {"state": "observed", "kind": "security_log_cleared"}


def test_category_coverage_marks_unselected_families_not_selected() -> None:
    class Cursor:
        def execute(self, _sql: str, _params: object) -> None:
            return None

        def fetchall(self) -> list[dict[str, object]]:
            return [{"event_id": 4728, "processing_unfinished": False}]

    coverage = reporting._read_security_event_category_coverage(
        Cursor(),
        domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        event_ids=[4728], provider_predicate="true", provider_params=[],
        filter_sql="", filter_params=[],
    )

    assert coverage["group_membership"] == {"state": "retained_match_present"}
    assert coverage["account_lock"] == {"state": "not_selected"}


def test_lockout_semantic_projection_keeps_caller_computer_separate_from_source_host() -> None:
    projection = semantic_projection_for_event(
        event_id=4740, channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        event_data={"CallerComputerName": "CLIENT-42"},
        correlation_id=None, source_host="dc01.example.test",
    )

    assert projection["roles"]["source_host"] == "dc01.example.test"
    assert projection["facts"]["caller_computer"] == "CLIENT-42"


@pytest.mark.parametrize(
    ("event_db_id", "event_id", "event_data"),
    (
        (1, 4738, {"DisplayName": "Alice Example"}),
        (2, 4764, {"OldGroupType": "Global", "NewGroupType": "Universal"}),
        (3, 4719, {"CategoryId": "{cat}", "AuditPolicyChanges": "Success removed"}),
    ),
)
def test_projection_and_report_share_one_source_native_change_contract(
    monkeypatch: pytest.MonkeyPatch,
    event_db_id: int,
    event_id: int,
    event_data: dict[str, str],
) -> None:
    monkeypatch.setattr(
        reporting,
        "get_v2_event_details_by_ids",
        lambda _ids: {event_db_id: {"event_data": event_data}},
    )
    event = _event(event_db_id, event_id, event_db_id)
    reporting._merge_hydrated_fields([event])
    report = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[event], collection_coverage={"history_event_present": True},
    )
    projection = semantic_projection_for_event(
        event_id=event_id, channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        event_data=event_data, correlation_id=None, source_host="dc01.example.test",
    )

    assert projection["facts"]["observed_change"] == report["items"][0]["change"]


def test_missing_source_native_change_detail_is_partial_in_projection_and_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        reporting,
        "get_v2_event_details_by_ids",
        lambda _ids: {1: {"event_data": {}}},
    )
    event = _event(1, 4738, 1)
    reporting._merge_hydrated_fields([event])
    report = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[event], collection_coverage={"history_event_present": True},
    )
    projection = semantic_projection_for_event(
        event_id=4738, channel="Security",
        provider="Microsoft-Windows-Security-Auditing",
        event_data={}, correlation_id=None, source_host="dc01.example.test",
    )

    assert report["items"][0]["change"] == {
        "state": "partial", "kind": "attributes_changed",
        "detail": {"state": "unknown", "reason": "account_attributes_not_present"},
    }
    assert projection["facts"]["observed_change"] == report["items"][0]["change"]


def test_category_coverage_is_server_computed_not_inferred_from_page() -> None:
    payload = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[_event(1, 4728, 1)],
        collection_coverage={
            "history_event_present": True,
            "category_coverage": {
                "account_lock": {"state": "no_retained_match"},
                "group_membership": {"state": "retained_match_present"},
                "audit_configuration": {"state": "processing_unfinished"},
                "account_change": {"state": "coverage_unavailable"},
            },
        },
    )
    assert payload["category_coverage"]["account_lock"] == {"state": "no_retained_match"}
    assert payload["category_coverage"]["group_membership"] == {"state": "retained_match_present"}
    assert payload["category_coverage"]["audit_configuration"] == {"state": "processing_unfinished"}
    assert payload["category_coverage"]["account_change"] == {"state": "coverage_unavailable"}


def test_csv_carries_caller_change_and_category_coverage_without_formula_cells() -> None:
    report = reporting.compose_security_events_page(
        source_domain_id=7,
        period_start=datetime(2026, 9, 1, 10, tzinfo=UTC),
        period_end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        events=[_event(1, 4740, 1, caller_computer="=CLIENT")],
        collection_coverage={
            "history_event_present": True,
            "category_coverage": {"account_lock": {"state": "retained_match_present"}},
        },
    )

    csv_text = reporting.render_security_events_csv(report)

    assert "caller_computer,change_state,change_kind" in csv_text
    assert "'=CLIENT" in csv_text
    assert "# category_coverage=" in csv_text
    assert "account_lock" in csv_text


@pytest.mark.parametrize("event_id", (4722, 4723, 4725, 4726, 4738, 4781, 4727, 4730, 4731, 4734, 4735, 4737, 4754, 4755, 4758, 4764))
def test_supported_security_report_events_have_specific_normalization(event_id: int) -> None:
    projection = semantic_projection_for_event(
        event_id=event_id, channel="Security",
        provider="Microsoft-Windows-Security-Auditing", event_data={},
        correlation_id=None, source_host="dc.example.test",
    )
    assert projection["semantic_type"] != "event.unknown"


class _RecordingCursor:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows, self.statements = rows, []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=()):
        self.statements.append((" ".join(str(sql).split()), list(params)))

    def fetchall(self):
        return self.rows


class _RecordingConnection:
    def __init__(self, cursor: _RecordingCursor) -> None:
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def cursor(self):
        return self._cursor


def test_daily_counts_group_by_local_day_and_family_under_the_same_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    cursor = _RecordingCursor([
        {"day": "2026-09-01", "event_id": 4728, "event_count": 2},
        {"day": "2026-09-01", "event_id": 4729, "event_count": 1},
        {"day": "2026-09-03", "event_id": 4740, "event_count": 5},
    ])
    monkeypatch.setattr(reporting, "_connect", lambda: _RecordingConnection(cursor))

    daily = reporting.get_security_events_daily(
        _report_access(), source_domain_id=7, time_from="2026-09-01T00:00:00Z", time_to="2026-09-04T00:00:00Z",
        timezone_name="Asia/Novosibirsk", category="group_membership",
    )

    membership = reporting.security_event_family(4728)
    assert daily["state"] == "available" and daily["timezone"] == "Asia/Novosibirsk"
    assert daily["days"][0] == {"date": "2026-09-01", "total": 3, "families": {membership: 3}}
    assert daily["days"][1]["date"] == "2026-09-03" and daily["days"][1]["total"] == 5
    sql, params = cursor.statements[-1]
    assert "at time zone %s)::date as day" in sql and "group by 1, 2" in sql
    assert "limit" not in sql, "an aggregate over the whole window, not a page"
    assert params[0] == "Asia/Novosibirsk" and params[1] == 7


def test_daily_counts_refuse_unauthorized_domains_and_bad_zones_without_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reporting, "_connect", lambda: pytest.fail("database must not be read"))
    denied = reporting.get_security_events_daily(
        _report_access(domain_id=8), source_domain_id=7, time_from="2026-09-01T00:00:00Z", time_to="2026-09-02T00:00:00Z",
    )
    assert denied == {"state": "not_authorized", "days": []}
    with pytest.raises((ValueError, reporting.TimeRangeError), match="timezone"):
        reporting.get_security_events_daily(
            _report_access(), source_domain_id=7, time_from="2026-09-01T00:00:00Z", time_to="2026-09-02T00:00:00Z",
            timezone_name="Mars/Olympus",
        )


def test_report_daily_tab_fills_every_local_day_and_is_computed_only_for_that_tab(monkeypatch: pytest.MonkeyPatch) -> None:
    from server.sli.reporting.v2.definition import QueryContext
    from server.sli.reporting.v2.reports import security_events as report

    calls: list[dict[str, object]] = []
    monkeypatch.setattr(report, "get_security_events_daily", lambda access, **kwargs: calls.append(kwargs) or {
        "state": "available", "timezone": "UTC",
        "days": [{"date": "2026-09-02", "total": 4, "families": {"authentication": 4}}],
    })
    monkeypatch.setattr(report, "get_security_events_report", lambda *_a, **_k: {"state": "available", "items": []})
    monkeypatch.setattr(report, "_domain_options", lambda _access: [])
    params = {"domain": "7", "period": {"from_utc": "2026-09-01T00:00:00Z", "to_utc": "2026-09-04T00:00:00Z"}}

    def run(tab: str | None) -> dict:
        context = QueryContext(access={}, params=dict(params), domain_ids=[7], action="view", cursor=None, limit=50, timezone="UTC", tab=tab)
        return report._query(context)

    assert "daily" not in (run("events").get("collections") or {})
    assert calls == []
    daily = run("daily")["collections"]["daily"]
    assert [row["date"] for row in daily] == ["2026-09-01", "2026-09-02", "2026-09-03"]
    assert daily[1]["authentication"] == 4 and daily[0]["authentication"] == 0 and daily[1]["group_membership"] == 0
    assert "event_db_id" not in calls[0]
