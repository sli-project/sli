"""Honest v2 report states; readers are replaced with in-memory fakes."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.definition import QueryContext, ResultState, result, source_state
from server.sli.reporting.v2.registry import registered_reports
from server.sli.reporting.v2.reports import computer_logons, events_journal, gpo, security_events, security_problems, users, vpn_connections


STATES = {"ok", "empty", "denied", "not_collected", "partial", "processing", "stale", "error"}


def _view_access(definition):
    return {"reports": [{
        "report_key": definition.access.report_key, "allowed": True, "allowed_actions": ["view"],
        "grants": [{"allowed_actions": ["view"], "field_categories": ["security"], "scope": {"kind": "all"}}],
    }]}


def test_every_registered_report_declares_and_builds_the_same_state_contract():
    assert {state.value for state in ResultState} == STATES
    for report in registered_reports():
        assert set(report.to_json()["result_states"]) == STATES
        for state in STATES:
            assert result(report, state=state)["state"] == state
        with pytest.raises(ValueError, match="report_state_invalid"):
            result(report, state="unavailable")


def test_registered_query_modules_only_emit_allowed_literal_result_states():
    for path in {Path(report.query.__code__.co_filename) for report in registered_reports()}:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "result":
                for keyword in node.keywords:
                    if keyword.arg == "state" and isinstance(keyword.value, ast.Constant):
                        assert keyword.value.value in STATES, path.name


@pytest.mark.parametrize("raw,expected", [
    ("available", "ok"), ("empty", "empty"), ("not_authorized", "denied"),
    ("not_collected", "not_collected"), ("processing", "processing"),
    ("stale", "stale"), ("unavailable", "error"), ("failed", "error"),
    ("empty_unverified", "partial"), ("coverage_unverified", "partial"),
    ("unexpected_state", "error"), (None, "error"),
])
def test_source_vocabulary_is_normalised_without_success_zero(raw, expected):
    assert source_state(raw) == expected


@pytest.mark.parametrize("coverage,expected", [
    ({"completeness": "not_proven"}, "partial"),
    ({"state": "processing"}, "processing"),
    ({"unprocessed_events": 2}, "processing"),
    ({"missing_sources": ["fixture-source"]}, "partial"),
    ({"missing_domains": [7]}, "partial"),
    ({"state": "failed"}, "error"),
    ({"state": "not_collected"}, "not_collected"),
    ({"state": "stale", "observed_at_utc": "2026-10-01T00:00:00Z"}, "stale"),
])
def test_missing_or_pending_coverage_cannot_become_empty(coverage, expected):
    payload = result(events_journal.REPORT, state="empty", coverage=coverage)
    assert payload["state"] == expected
    assert payload["state_details"]["reason"]
    assert result(events_journal.REPORT, state="denied", coverage=coverage)["state"] == "denied"


def test_partial_names_missing_coverage_and_stale_keeps_observation_time():
    coverage = {"missing_sources": ["fixture-source"], "missing_domains": [7]}
    payload = result(events_journal.REPORT, state="ok", items=[{"id": 1}], coverage=coverage)
    assert payload["state"] == "partial"
    assert payload["state_details"]["missing_sources"] == ["fixture-source"]
    assert payload["state_details"]["missing_domains"] == [7]
    stale = result(events_journal.REPORT, state="stale", coverage={"observed_at_utc": "2026-10-01T00:00:00Z"})
    assert stale["state_details"]["observed_at_utc"] == "2026-10-01T00:00:00Z"


def test_partial_details_keep_stage_and_limits_without_inventing_source_outage():
    payload = result(events_journal.REPORT, state="partial", coverage={"stage": "history_read", "truncated": True},
                     has_more=True, limitations=[{"code": "history_limit", "text": "Synthetic read limit reached."}])
    details = payload["state_details"]
    assert details["stage"] == "history_read"
    assert details["limitations"] == [{"code": "history_limit", "text": "Synthetic read limit reached."}]
    assert details["reason"] == "result_truncated"
    assert details["source_issues"] == []
    assert result(events_journal.REPORT, state="partial", has_more=True)["state_details"]["reason"] == "coverage_incomplete"


def test_missing_source_has_a_concrete_issue_without_claiming_event_date_as_outage():
    payload = result(events_journal.REPORT, state="partial", coverage={
        "missing_sources": ["fixture-source"], "event_at_utc": "2020-01-01T00:00:00Z",
    })
    assert payload["state_details"]["source_issues"] == [{
        "source": "fixture-source", "reason": "source_missing", "since_utc": None,
    }]


def test_source_limitations_keep_concrete_sources_reason_and_known_start():
    payload = result(events_journal.REPORT, state="partial", coverage={"domains": [
        {"domain_id": 7, "section_name": "domain_health", "run_status": "failed", "since_utc": "2026-10-01T00:00:00Z"},
        {"domain_id": 8, "section_name": "domain_posture", "run_status": None},
    ], "missing": ["8:domain_posture"]})
    assert payload["state_details"]["source_issues"] == [
        {"source": "7:domain_health", "reason": "source_failed", "since_utc": "2026-10-01T00:00:00Z"},
        {"source": "8:domain_posture", "reason": "source_missing", "since_utc": None},
    ]


def test_event_age_alone_does_not_change_report_state():
    payload = result(events_journal.REPORT, state="ok", items=[{"id": 1}], coverage={
        "event_at_utc": "2020-01-01T00:00:00Z", "freshness_threshold_seconds": 60,
    })
    assert payload["state"] == "ok"
    assert payload["state_details"]["stale_since_utc"] is None


@pytest.mark.parametrize("status,reason", [("unavailable", "source_failed"), ("denied", "access_denied")])
def test_unavailable_source_has_a_concrete_name_and_plain_reason_code(status, reason):
    payload = result(events_journal.REPORT, state="partial", coverage={"domains": [
        {"domain_id": 7, "domain_name": "fixture-source", "section_name": "domain_health",
         "run_status": "completed", "section_status": status},
    ]})
    assert payload["state_details"]["source_issues"] == [{
        "source": "7:domain_health", "source_name": "fixture-source", "reason": reason, "since_utc": None,
    }]


def test_domain_coverage_identifies_missing_domain_and_source():
    coverage = {"domains": [{"domain_id": 7, "run_status": "partial", "section_name": "directory_accounts"}]}
    payload = result(events_journal.REPORT, state="empty", coverage=coverage)
    assert payload["state"] == "partial"
    assert payload["state_details"]["missing_domains"] == [7]
    assert payload["state_details"]["missing_sources"] == ["directory_accounts"]


@pytest.mark.parametrize("module,reader", [
    (events_journal, "execute_report"), (security_problems, "get_security_problems_data"),
])
@pytest.mark.parametrize("raw,expected", [
    ("not_authorized", "denied"), ("not_collected", "not_collected"),
    ("empty", "empty"), ("unavailable", "error"), ("empty_unverified", "partial"),
])
def test_report_queries_distinguish_denied_not_collected_and_empty(monkeypatch, module, reader, raw, expected):
    monkeypatch.setattr(module, reader, lambda *args, **kwargs: {"state": raw, "items": [], "semantic_runtime": {"findings_state": "active"}})
    if module is security_problems and raw == "empty":
        monkeypatch.setattr(module, "password_coverage_catalog_domains", lambda: [7])
        # Active findings do not confirm password coverage omitted by this fake.
        expected = "partial"
    # The caller may view the report; raw "not_authorized" is a reader/source state.
    payload = module.REPORT.query(QueryContext(access=_view_access(module.REPORT), params={"period": {"from_utc": "2026-10-01T00:00:00Z", "to_utc": "2026-10-02T00:00:00Z"}}))
    assert payload["state"] == expected
    if module is security_problems and raw == "empty":
        assert payload["coverage"]["password_detection"]["availability"] == "unavailable"
        assert any(item["code"] == "password_coverage_incomplete" for item in payload["limitations"])


@pytest.mark.parametrize("denial,reason", [
    ("unassigned", "report_access_denied"),
    ("report_denied", "report_access_denied"),
    ("action_denied", "report_access_denied"),
    ("grant_action_denied", "report_field_categories_not_allowed"),
    ("missing_security", "report_field_categories_not_allowed"),
])
def test_security_queue_rejects_unauthorized_callers_before_reading(monkeypatch, denial, reason):
    access = _view_access(security_problems.REPORT)
    report = access["reports"][0]
    if denial == "unassigned":
        access = {}
    elif denial == "report_denied":
        report["allowed"] = False
    elif denial == "action_denied":
        report["allowed_actions"] = ["export"]
    elif denial == "grant_action_denied":
        report["grants"][0]["allowed_actions"] = ["export"]
    elif denial == "missing_security":
        report["grants"][0]["field_categories"] = ["identity_basic", "technical", "raw_evidence"]
    monkeypatch.setattr(security_problems, "get_security_problems_data", lambda **kwargs: pytest.fail("unauthorized read"))
    with pytest.raises(PermissionError, match=f"^{reason}$"):
        security_problems.REPORT.query(QueryContext(access=access, params={}))


def test_logon_unverified_empty_is_partial():
    assert computer_logons._state("empty_unverified", []) == "partial"


@pytest.mark.parametrize("raw_state,items,coverage,expected", [
    ("available", [], {}, "empty"),
    ("available", [{"entity_id": 1}], {}, "ok"),
    ("empty", [], {"observation_state": "available", "completeness": "unverified"}, "empty"),
    ("available", [{"entity_id": 1}], {"observation_state": "available", "completeness": "unverified"}, "ok"),
    ("available", [{"entity_id": 1}], {"observation_state": "partial"}, "partial"),
    ("available", [], {"observation_state": "not_collected"}, "not_collected"),
    ("available", [], {"observation_state": "unavailable"}, "error"),
    ("available", [], {"completeness": "not_proven"}, "partial"),
    ("empty_unverified", [], {}, "partial"),
])
def test_logon_adapter_preserves_reader_coverage_without_inventing_partial(monkeypatch, raw_state, items, coverage, expected):
    monkeypatch.setattr(computer_logons, "logon_domain_scope", lambda _access: [7])
    monkeypatch.setattr(computer_logons, "get_computer_logon_computers", lambda **kwargs: {
        "state": raw_state, "items": items, "coverage": coverage,
    })
    payload = computer_logons.REPORT.query(QueryContext({}, {"period": {"from_utc": "2026-10-01T00:00:00Z", "to_utc": "2026-10-02T00:00:00Z"}}))
    assert payload["state"] == expected
    assert payload["items"] == items
    assert payload["coverage"].get("completeness") == coverage.get("completeness")


@pytest.mark.parametrize("coverage,expected", [
    ({"state": "available", "source_completeness": "not_proven"}, "ok"),
    ({"state": "empty_unverified", "source_completeness": "not_proven"}, "ok"),
    ({"state": "available", "source_completeness": "not_proven", "missing_sources": ["fixture-source"]}, "partial"),
    ({"state": "available", "completeness": "not_proven"}, "partial"),
    ({"state": "partial"}, "partial"),
    ({"state": "processing"}, "processing"),
    ({"state": "unavailable"}, "error"),
])
def test_security_events_query_completion_is_distinct_from_source_audit_completeness(monkeypatch, coverage, expected):
    monkeypatch.setattr(security_events, "_domain_options", lambda _access: [])
    monkeypatch.setattr(security_events, "get_security_events_report", lambda *args, **kwargs: {
        "state": "available", "items": [{"event_db_id": 7}], "collection_coverage": coverage,
    })
    payload = security_events.REPORT.query(QueryContext({}, {"domain": "7", "period": {"from_utc": "2026-10-01T00:00:00Z", "to_utc": "2026-10-02T00:00:00Z"}}))
    assert payload["state"] == expected
    assert payload["coverage"].get("source_completeness") == coverage.get("source_completeness")
    assert payload["coverage"].get("missing_sources") == coverage.get("missing_sources")
    assert payload["items"][0]["event_db_id"] == 7


def test_inactive_findings_cannot_claim_an_empty_queue(monkeypatch):
    monkeypatch.setattr(security_problems, "get_security_problems_data", lambda **kwargs: {"state": "empty", "items": []})
    assert security_problems.REPORT.query(QueryContext(access=_view_access(security_problems.REPORT), params={}))['state'] == "partial"


def test_api_boundary_rejects_unknown_states_and_redacts_denied_metadata():
    definition = events_journal.REPORT
    access = {"reports": [{"report_key": definition.access.report_key, "allowed": True, "allowed_actions": ["view"],
                           "grants": [{"allowed_actions": ["view"], "field_categories": [], "scope": {"kind": "all"}}]}]}
    projection = ReportAccess(definition, access)
    unknown = projection.result({"state": "unexpected", "items": [{"id": 1}]})
    assert unknown["state"] == "error" and unknown["items"] == []
    denied = projection.result(result(definition, state="denied", coverage={"missing_sources": ["private-fixture-marker"]}))
    assert denied["state"] == "denied"
    assert "private-fixture-marker" not in str(denied)


def test_freshness_threshold_reports_when_data_became_stale():
    coverage = {"observed_at_utc": "2020-01-01T00:00:00Z", "freshness_threshold_seconds": 86400}
    payload = result(events_journal.REPORT, state="ok", coverage=coverage)
    assert payload["state"] == "stale"
    assert payload["state_details"]["stale_since_utc"] == "2020-01-02T00:00:00+00:00"
    assert result(events_journal.REPORT, state="ok", coverage={**coverage, "state": "failed"})["state"] == "error"


@pytest.mark.parametrize("raw,expected", [("processing", "processing"), ("not_collected", "not_collected"), ("unavailable", "error")])
def test_vpn_branch_preserves_processing_and_collection_states(raw, expected):
    assert vpn_connections._branch({"state": raw}, [], empty=True)["state"] == expected


@pytest.mark.parametrize("raw,expected", [("not_collected", "not_collected"), ("unavailable", "error"), ("processing", "processing")])
def test_missing_snapshots_do_not_confuse_collection_with_storage_failure(monkeypatch, raw, expected):
    monkeypatch.setattr(users, "_snapshots", lambda *args, **kwargs: {"state": raw, "current": None})
    monkeypatch.setattr(gpo, "load_authorized_snapshot_pair", lambda **kwargs: {"state": raw, "current": None})
    for report in (users.REPORT, gpo.REPORT):
        # Users now defaults to checks, which has a separate saved-source reader.
        context = QueryContext({}, {}, tab="all" if report is users.REPORT else None)
        assert report.query(context)["state"] == expected


@pytest.mark.parametrize("status,expected", [("completed", "empty"), ("partial", "partial"), ("failed", "error"),
                                           ("not_collected", "not_collected"), ("processing", "processing")])
def test_zero_user_rows_respect_snapshot_collection_status(monkeypatch, status, expected):
    monkeypatch.setattr(users.ad_hygiene_policy, "thresholds", lambda: {"password_age": 90, "inactivity": 60})
    snapshot = {"users": [], "groups": [], "metadata": {"collection_status": status}}
    monkeypatch.setattr(users, "_snapshots", lambda *args, **kwargs: {"state": "empty", "current": snapshot, "previous_state": "not_requested"})
    assert users.REPORT.query(QueryContext({}, {}, tab="all"))["state"] == expected
