from __future__ import annotations

import io
import json
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from server.api import http_server
from server.api.routes import findings, investigations, reports_v2
from server.sli.core.messages import localize_presentation, message
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.definition import QueryContext, csv_from_columns
from server.sli.reporting.v2.reports import security_problems as report


def _access(fields=("security",), *, allowed=True, assigned=True, actions=("view", "export"), cases=False):
    reports = [{
        "report_key": "security.queue", "allowed": allowed, "allowed_actions": list(actions),
        "grants": [{"scope": {"kind": "all"}, "allowed_actions": list(actions), "field_categories": list(fields)}],
    }] if assigned else []
    if cases:
        reports.append({
            "report_key": "investigations.workspace", "allowed": True, "allowed_actions": ["view"],
            "grants": [{"scope": {"kind": "domain", "ids": [1]}, "allowed_actions": ["view"], "field_categories": ["security"]}],
        })
    return {"reports": reports, "capabilities": ["investigations.view"]}


def _raw():
    return {
        "state": "available", "status": "ok", "source": "semantic_production_findings",
        "items": [{
            "id": 7, "title": "Synthetic summary", "summary": "Synthetic observation", "status": "new",
            "severity": "high", "evidence_count": 2, "actor": "identity-marker", "target": "identity-marker",
            "source": "technical-marker", "assigned_to": "identity-marker", "status_reason": "exact-marker",
            "unknown_future_field": "future-marker",
            "risk_acceptance": {"id": 31, "finding_id": 7, "state": "active",
                                "expires_at": "2026-10-08T00:00:00Z", "created_at": "2026-10-07T00:00:00Z",
                                "reason": "exact-marker", "responsible_user_id": 900004,
                                "responsible_username": "identity-marker", "created_by": "identity-marker",
                                "changed_by": "identity-marker", "unknown_field": "future-marker"},
            "risk_audit": [{"id": 31, "action": "create", "actor": "identity-marker",
                            "occurred_at": "2026-10-07T00:00:00Z", "unknown_field": "future-marker",
                            "details": {"unknown_field": "future-marker", "rule": {
                                "id": 31, "finding_id": 7, "reason": "exact-marker",
                                "responsible_user_id": 900004, "unknown_field": "future-marker"}}}],
            "review_hint": {"bucket": "unknown", "event_db_id": "exact-marker"},
            "evidence": [{"event_db_id": 900001, "event_record_id": 900002, "event_id": 4719,
                          "hostname": "exact-marker", "channel": "exact-marker", "note": "exact-marker",
                          "unknown_field": "future-marker"}],
            "entities": [{"display_name": "identity-marker", "entity_role": "actor", "unknown_field": "future-marker"}],
            "status_history": [{"id": 900003, "new_status": "new", "changed_by": "identity-marker", "note": "exact-marker",
                                "unknown_field": "future-marker"}],
        }],
        "summary": [{"status": "new", "severity": "high", "count": 1}], "lifecycle": {},
        "semantic_runtime": {"findings_state": "active"}, "limitations": [],
    }


@pytest.fixture
def readers(monkeypatch):
    calls = []
    raw = _raw()

    def read(**kwargs):
        calls.append(kwargs)
        return deepcopy(raw)

    monkeypatch.setattr(report, "get_security_problems_data", read)
    monkeypatch.setattr(findings, "get_security_problems_data", read)
    monkeypatch.setattr(report, "linked_cases_for_findings", lambda ids: {7: {"id": 44, "public_id": "case-marker", "status": "active"}})
    monkeypatch.setattr(report, "case_resource_groups_batch", lambda ids, **_: {44: [[{"kind": "domain", "id": 2}]]})
    monkeypatch.setattr(reports_v2, "get_report", lambda key: report.REPORT if key == report.REPORT_KEY else None)
    monkeypatch.setattr(reports_v2, "report_plugin_state", lambda _: None)
    monkeypatch.setattr(http_server, "principal_from_headers", lambda _: {"role": "viewer"})
    return calls


def _dispatch(decision, path):
    handler = object.__new__(http_server.RequestHandler)
    handler.server = SimpleNamespace(adlog_trusted_proxies=(), storage_route_authorization=None)
    handler.path = path
    handler.headers = {}
    handler.wfile = io.BytesIO()
    handler.sent = []
    handler.response_headers = {}
    handler._access_decision = lambda: decision
    handler._send_json = lambda payload, status=200, **_: handler.sent.append((payload, int(status)))
    handler.send_response = lambda status: setattr(handler, "status", int(status))
    handler.send_header = lambda key, value: handler.response_headers.update({key: value})
    handler.end_headers = lambda: None
    handler._do_GET()
    return handler


@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data", "/api/findings?source=semantic-production"])
def test_security_only_queue_preserves_summary_and_count_but_redacts_details(readers, path):
    handler = _dispatch(_access(), path)
    payload, status = handler.sent[-1]
    assert status == 200
    row = payload["items"][0]
    assert row["title"] == "Synthetic summary" and row["evidence_total"] == 2
    assert row["linked_case"] is None
    assert row["risk_acceptance"] == {"id": 31, "finding_id": 7, "state": "active",
                                      "expires_at": "2026-10-08T00:00:00Z", "created_at": "2026-10-07T00:00:00Z"}
    assert "risk_audit" not in row
    serialized = json.dumps(payload)
    for marker in ("exact-marker", "identity-marker", "technical-marker", "future-marker", "case-marker", "900001", "900002", "900003", "900004"):
        assert marker not in serialized
    assert "evidence" not in row and "status_history" not in row
    assert len(readers) == 1


@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data", "/api/findings?source=semantic-production"])
@pytest.mark.parametrize("locale", ["ru", "en"])
@pytest.mark.parametrize("identity", [False, True])
def test_catalog_envelopes_follow_identity_policy_after_localization(readers, monkeypatch, path, locale, identity):
    raw = _raw()
    raw["items"][0]["actor"] = "sid:fixture-host:S-1-5-18"
    monkeypatch.setattr(report, "get_security_problems_data", lambda **_: deepcopy(raw))
    monkeypatch.setattr(findings, "get_security_problems_data", lambda **_: deepcopy(raw))
    fields = ("security", "identity_basic") if identity else ("security",)
    payload, status = _dispatch(_access(fields), path).sent[-1]
    assert status == 200
    row = localize_presentation(payload, locale)["items"][0]
    for field in ("actor_text", "entity_text", "entity_messages"):
        assert (field in row) == identity
    assert ("actor_text" in row["presentation_messages"]) == identity
    if identity:
        envelope = message("security.problems.entity.system", {"name": "FIXTURE-HOST"}, locale=locale)
        assert row["presentation_messages"]["actor_text"] == envelope
        assert row["actor_text"] == envelope["text"]
        assert row["entity_messages"] == ["identity-marker"]
    else:
        assert "FIXTURE-HOST" not in json.dumps(row)
        assert "identity-marker" not in json.dumps(row)
    assert row["status_message"] == message("security.problems.status.new", locale=locale)
    assert row["severity_message"] == message("reports.v2.security.problems.columns.severity.labels.high", locale=locale)


@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data", "/api/findings?source=semantic-production"])
@pytest.mark.parametrize("decision", [_access(assigned=False), _access(allowed=False), _access(actions=()), _access(fields=())])
def test_report_absent_denied_or_without_action_or_core_fields_never_reads(readers, path, decision):
    assert _dispatch(decision, path).sent[-1][1] == 403
    assert readers == []


@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data", "/api/findings?source=semantic-production"])
def test_full_field_grant_keeps_exact_evidence_but_drops_unknown_fields_and_foreign_case(readers, path):
    handler = _dispatch(_access(("security", "raw_evidence", "identity_basic", "technical"), cases=True), path)
    payload, status = handler.sent[-1]
    assert status == 200
    row = payload["items"][0]
    assert row["evidence"][0]["event_db_id"] == 900001
    assert row["evidence"][0]["event_record_id"] == 900002
    assert row["status_history"][0]["note"] == "exact-marker"
    assert row["risk_acceptance"]["reason"] == "exact-marker"
    assert row["risk_acceptance"]["responsible_user_id"] == 900004
    assert row["risk_audit"][0]["details"]["rule"]["responsible_user_id"] == 900004
    assert row["linked_case"] is None
    assert "future-marker" not in json.dumps(payload)


@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data", "/api/findings?source=semantic-production"])
def test_raw_evidence_still_requires_technical_grant_for_source_fields(readers, path):
    row = _dispatch(_access(("security", "raw_evidence")), path).sent[-1][0]["items"][0]
    assert row["evidence"][0]["event_db_id"] == 900001
    assert "hostname" not in row["evidence"][0] and "channel" not in row["evidence"][0]
    assert "actor" not in row and "status_history" not in row


@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data", "/api/findings?source=semantic-production"])
@pytest.mark.parametrize("category", ["raw_evidence", "identity_basic"])
def test_risk_decision_fields_require_their_independent_grants(readers, path, category):
    row = _dispatch(_access(("security", category)), path).sent[-1][0]["items"][0]
    risk = row["risk_acceptance"]
    assert risk["state"] == "active"
    assert ("reason" in risk) == (category == "raw_evidence")
    for key in ("responsible_user_id", "responsible_username", "created_by", "changed_by"):
        assert (key in risk) == (category == "identity_basic")
    assert "risk_audit" not in row


def test_linked_case_requires_actual_case_resources_and_respects_explicit_deny(readers, monkeypatch):
    decision = _access(cases=True)
    monkeypatch.setattr(report, "case_resource_groups_batch", lambda ids, **_: {44: [[{"kind": "domain", "id": 1}]]})
    row = _dispatch(decision, "/api/v2/reports/security.problems/data").sent[-1][0]["items"][0]
    assert row["linked_case"] == {"id": 44, "public_id": "case-marker", "status": "active"}
    decision["capability_policies"] = [{"capability_key": "investigations.view", "effect": "deny", "valid": True,
                                        "scope": {"kind": "domain", "ids": [1]}}]
    assert _dispatch(decision, "/api/v2/reports/security.problems/data").sent[-1][0]["items"][0]["linked_case"] is None


def test_field_deny_is_not_restored_by_separate_grants(readers):
    decision = _access()
    decision["reports"][0]["grants"].append({"scope": {"kind": "all"}, "allowed_actions": ["view"],
                                            "field_categories": ["raw_evidence"]})
    payload, status = _dispatch(decision, "/api/v2/reports/security.problems/data").sent[-1]
    assert status == 200
    assert "exact-marker" not in json.dumps(payload)


@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data", "/api/findings?source=semantic-production"])
def test_queue_grant_does_not_require_investigations_capability_but_never_exposes_case(readers, path):
    decision = _access()
    decision["capabilities"] = []
    payload, status = _dispatch(decision, path).sent[-1]
    assert status == 200 and payload["items"][0]["linked_case"] is None


@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data", "/api/findings?source=semantic-production"])
@pytest.mark.parametrize("params", ["", "entity_id=7&risk=accepted"])
def test_domain_queue_scope_is_passed_to_reader(readers, path, params):
    decision = _access(("security", "identity_basic"))
    decision["reports"][0]["grants"][0]["scope"] = {"kind": "domain", "ids": [1]}
    if params:
        path += ("?" if "?" not in path else "&") + params
    payload, status = _dispatch(decision, path).sent[-1]
    assert status == 200 and payload["items"][0]["id"] == 7
    assert readers[0]["domain_ids"] == [1]


@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data?", "/api/findings?source=semantic-production&"])
@pytest.mark.parametrize("domain,expected", [(1, [1]), (2, [2]), (3, None)])
def test_queue_requested_domain_intersects_grant_before_reading(readers, path, domain, expected):
    decision = _access()
    decision["reports"][0]["grants"][0]["scope"] = {"kind": "domain", "ids": [1, 2]}
    payload, status = _dispatch(decision, f"{path}domain={domain}").sent[-1]
    if expected is None:
        assert status == 403 and payload["error"] == "report_scope_not_executable"
        assert readers == []
    else:
        assert status == 200
        assert readers[0]["domain_ids"] == expected


@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data", "/api/findings?source=semantic-production"])
@pytest.mark.parametrize("scope", [
    {"kind": "domain", "ids": []}, {"kind": "server", "ids": [1]},
    {"mode": "restricted", "clauses": [{"collection_scope_ids": ["ad-domain:1"], "device_ids": ["fixture-device"]}]},
])
def test_unsupported_queue_scope_never_becomes_global(readers, path, scope):
    decision = _access()
    decision["reports"][0]["grants"][0]["scope"] = scope
    assert _dispatch(decision, path).sent[-1][1] == 403
    assert readers == []


def test_legacy_queue_invalid_domain_never_reads(readers):
    payload, status = _dispatch(_access(), "/api/findings?source=semantic-production&domain=invalid").sent[-1]
    assert status == 400 and payload["error"] == "report_request_invalid"
    assert readers == []


def test_queue_declaration_denies_detail_without_raw_evidence(readers):
    payload, status = _dispatch(_access(), "/api/v2/reports/security.problems").sent[-1]
    assert status == 200
    assert payload["detail"]["access"]["allowed"] is False
    assert payload["detail"]["columns"] == []
    projection = ReportAccess(report.REPORT, _access())
    with pytest.raises(PermissionError):
        projection.validate_request({}, {}, detail=True)
    assert readers == []


@pytest.mark.parametrize("params", ["", "?entity_id=7&risk=accepted"])
def test_evidence_page_without_raw_grant_never_reads(readers, monkeypatch, params):
    monkeypatch.setattr(report, "get_problem_evidence_page", lambda *args, **kwargs: pytest.fail("evidence must not be read"))
    assert _dispatch(_access(("security", "identity_basic")),
                     f"/api/v2/reports/security.problems/rows/7/detail{params}").sent[-1][1] == 403
    assert readers == []


def test_evidence_entity_filter_without_identity_grant_never_reads(readers, monkeypatch):
    monkeypatch.setattr(report, "get_problem_evidence_page", lambda *args, **kwargs: pytest.fail("evidence must not be read"))
    path = "/api/v2/reports/security.problems/rows/7/detail?entity_id=7&risk=accepted"
    assert _dispatch(_access(("security", "raw_evidence")), path).sent[-1][1] == 403
    assert readers == []


def test_evidence_page_outside_domain_queue_scope_never_reads(readers, monkeypatch):
    decision = _access(("security", "raw_evidence"))
    decision["reports"][0]["grants"][0]["scope"] = {"kind": "domain", "ids": [1]}
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: readers.append(kwargs) or {"items": []})
    monkeypatch.setattr(report, "get_problem_evidence_page", lambda *args, **kwargs: pytest.fail("evidence must not be read"))
    assert _dispatch(decision, "/api/v2/reports/security.problems/rows/7/detail").sent[-1][1] == 404
    assert readers[0]["domain_ids"] == [1]


def test_evidence_page_in_domain_queue_scope_reads_after_membership_check(readers, monkeypatch):
    decision = _access(("security", "raw_evidence"))
    decision["reports"][0]["grants"][0]["scope"] = {"kind": "domain", "ids": [1]}
    monkeypatch.setattr(report, "get_problem_evidence_page", lambda *args, **kwargs: {
        "items": [{"evidence_id": 1, "event_db_id": 1}], "total": 1, "has_more": False,
    })
    payload, status = _dispatch(decision, "/api/v2/reports/security.problems/rows/7/detail").sent[-1]
    assert status == 200 and payload["items"][0]["event_db_id"] == 1
    assert readers[0]["domain_ids"] == [1]


@pytest.mark.parametrize("limit,expected", [(1, 1), (20, 20), (200, 20), (0, None), (201, None)])
def test_evidence_endpoint_bounds_page_size_before_reading(readers, monkeypatch, limit, expected):
    calls = []

    def evidence(finding_id, **kwargs):
        calls.append(kwargs["limit"])
        return {"items": [], "total": 0, "has_more": False}

    monkeypatch.setattr(report, "get_problem_evidence_page", evidence)
    payload, status = _dispatch(_access(("security", "raw_evidence")),
                                f"/api/v2/reports/security.problems/rows/7/detail?limit={limit}").sent[-1]
    assert status == (400 if expected is None else 200)
    assert calls == ([] if expected is None else [expected])
    if expected is None:
        assert readers == []


def test_evidence_time_population_membership_is_rechecked_on_continuation(readers, monkeypatch):
    calls = []

    def population(**kwargs):
        calls.append(kwargs)
        return _raw() if len(calls) == 1 else {"items": []}

    monkeypatch.setattr(report, "get_security_problems_data", population)
    evidence_calls = []
    monkeypatch.setattr(report, "get_problem_evidence_page", lambda *args, **kwargs: evidence_calls.append(kwargs) or {
        "items": [{"evidence_id": 1, "event_db_id": 1}], "total": 2, "has_more": True,
    })
    decision = _access(("security", "raw_evidence"))
    decision["reports"][0]["grants"][0]["scope"] = {"kind": "domain", "ids": [1]}
    path = ("/api/v2/reports/security.problems/rows/7/detail?population=attention"
            "&time_from=2026-10-01T00:00:00Z&time_to=2026-10-02T00:00:00Z")
    payload, status = _dispatch(decision, path).sent[-1]
    assert status == 200
    assert _dispatch(decision, f"{path}&cursor={payload['next_cursor']}").sent[-1][1] == 404
    assert len(evidence_calls) == 1
    assert len(calls) == 2 and all(call["domain_ids"] == [1] for call in calls)
    assert all(call["attention_only"] and call["time_from"] == "2026-10-01T00:00:00Z"
               and call["time_to"] == "2026-10-02T00:00:00Z" for call in calls)


@pytest.mark.parametrize("technical", [False, True])
def test_evidence_pages_keep_field_policy_and_risk_entity_membership(readers, monkeypatch, technical):
    calls = []

    def evidence(finding_id, **kwargs):
        calls.append((finding_id, kwargs))
        after_id = kwargs["after_id"]
        return {"items": [{"evidence_id": after_id + 1, "event_db_id": 900001 + after_id,
                           "event_id": 4719, "hostname": "technical-marker", "channel": "technical-marker",
                           "time_created_utc": "2026-10-07T00:00:00Z"}],
                "total": 2, "has_more": after_id == 0}

    monkeypatch.setattr(report, "get_problem_evidence_page", evidence)
    fields = ("security", "raw_evidence", "identity_basic") + (("technical",) if technical else ())
    decision = _access(fields)
    path = "/api/v2/reports/security.problems/rows/7/detail?entity_id=7&risk=accepted"
    payload, status = _dispatch(decision, path).sent[-1]
    assert status == 200 and payload["has_more"] and payload["filtered_count"] == 2
    row = payload["items"][0]
    assert row["event_db_id"] == 900001 and row["event_id"] == 4719
    assert ("hostname" in row) == technical and ("channel" in row) == technical
    payload, status = _dispatch(decision, f"{path}&cursor={payload['next_cursor']}").sent[-1]
    assert status == 200 and not payload["has_more"]
    assert payload["items"][0]["event_db_id"] == 900002
    assert ("technical-marker" in json.dumps(payload)) == technical
    assert len(readers) == 2
    assert all(call["finding_id"] == 7 and call["entity_id"] == 7 and call["risk"] == "accepted" for call in readers)
    assert [call[1]["after_id"] for call in calls] == [0, 1]


def test_hidden_identity_search_rejected_for_both_aliases(readers):
    for path in ("/api/v2/reports/security.problems/data?q=identity-marker", "/api/findings?source=semantic-production&q=identity-marker"):
        assert _dispatch(_access(), path).sent[-1][1] == 403
    assert readers == []


@pytest.mark.parametrize("params", ["entity_id=7&risk=accepted", "q=identity-marker&risk=accepted"])
@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data?",
                                  "/api/findings?source=semantic-production&"])
def test_risk_filter_cannot_bypass_identity_filter_denial(readers, params, path):
    assert _dispatch(_access(), f"{path}{params}").sent[-1][1] == 403
    assert readers == []


@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data?",
                                  "/api/findings?source=semantic-production&"])
def test_risk_and_entity_filters_work_together_with_identity_grant(readers, path):
    payload, status = _dispatch(_access(("security", "identity_basic")),
                                f"{path}entity_id=7&risk=accepted").sent[-1]
    assert status == 200
    assert readers[0]["entity_id"] == 7 and readers[0]["risk"] == "accepted"
    assert payload["items"][0]["risk_acceptance"]["responsible_user_id"] == 900004
    assert "exact-marker" not in json.dumps(payload)


def test_evidence_cursor_rechecks_risk_entity_membership_before_reading_next_page(readers, monkeypatch):
    populations = iter([_raw(), {"items": []}])
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: next(populations))
    evidence_calls = []

    def evidence(finding_id, **kwargs):
        evidence_calls.append(finding_id)
        return {"items": [{"evidence_id": 1, "event_db_id": 900001, "event_id": 4719}],
                "total": 2, "has_more": True}

    monkeypatch.setattr(report, "get_problem_evidence_page", evidence)
    decision = _access(("security", "identity_basic", "raw_evidence"))
    path = "/api/v2/reports/security.problems/rows/7/detail?entity_id=7&risk=accepted"
    payload, status = _dispatch(decision, path).sent[-1]
    assert status == 200
    assert _dispatch(decision, f"{path}&cursor={payload['next_cursor']}").sent[-1][1] == 404
    assert evidence_calls == [7]


def test_home_summary_keeps_field_policy_and_main_filters_without_reading_cases(readers, monkeypatch):
    monkeypatch.setattr(report, "_linked_cases", lambda *args: pytest.fail("compact reader must not fetch cases"))
    context = QueryContext(
        access=_access(), params={"id": 7, "domain": 1,
                                 "time_from": "2026-10-01T00:00:00Z", "time_to": "2026-10-02T00:00:00Z"},
        domain_ids=[1], runtime={"home_summary": True},
    )
    payload = report._query(context)
    assert payload["items"][0]["title"] == "Synthetic summary"
    assert "linked_case" not in payload["items"][0]
    for marker in ("identity-marker", "exact-marker", "technical-marker", "future-marker"):
        assert marker not in json.dumps(payload)
    assert readers[0]["domain_ids"] == [1] and readers[0]["finding_id"] == 7
    assert readers[0]["attention_only"] and readers[0]["home_order"] and readers[0]["compact"]
    assert readers[0]["time_from"] == "2026-10-01T00:00:00Z"
    assert readers[0]["time_to"] == "2026-10-02T00:00:00Z"


def test_queue_passport_lists_all_enforced_field_classes():
    fields = set(report.REPORT.access.required_fields)
    for categories in report.REPORT.row_categories.values():
        fields.update(categories)
    assert fields <= set(report.REPORT.intent.field_classes)


@pytest.mark.parametrize("path", ["/api/v2/reports/security.problems/data?risk=accepted",
                                  "/api/findings?source=semantic-production&risk=accepted"])
def test_risk_filter_preserves_queue_projection_for_both_aliases(readers, path):
    payload, status = _dispatch(_access(), path).sent[-1]
    assert status == 200 and readers[0]["risk"] == "accepted"
    assert payload["items"][0]["risk_acceptance"]["state"] == "active"
    assert "identity-marker" not in json.dumps(payload)


def test_queue_export_remains_unavailable_and_future_export_uses_projected_rows(readers, monkeypatch):
    assert _dispatch(_access(), "/api/v2/reports/security.problems/export.csv").sent[-1][1] == 404
    assert readers == []
    # Exercise the CSV sink with an adapter over the actual queue query.
    definition = replace(report.REPORT, export_csv=lambda context: (
        csv_from_columns(report.REPORT.columns, report._query(context)["items"]), {"rows": 1},
    ))
    monkeypatch.setattr(reports_v2, "get_report", lambda _: definition)
    handler = _dispatch(_access(), "/api/v2/reports/security.problems/export.csv")
    assert handler.status == 200
    body = handler.wfile.getvalue().decode("utf-8-sig")
    assert "Synthetic summary" in body
    for marker in ("exact-marker", "identity-marker", "technical-marker", "case-marker", "future-marker"):
        assert marker not in body


@pytest.mark.parametrize("path", ["/api/findings", "/api/findings?source=legacy", "/api/findings?source=semantic-production&source=legacy"])
def test_unused_non_production_aliases_are_retired_without_readers(readers, path):
    assert _dispatch(_access(), path).sent[-1][1] == 410
    assert readers == []


def test_investigations_assignment_still_allows_case_list_when_queue_is_denied(readers, monkeypatch):
    decision = _access(allowed=False, cases=True)
    decision["reports"][1]["grants"][0]["scope"] = {"kind": "all"}
    calls = []
    monkeypatch.setattr(investigations, "list_cases", lambda **_: calls.append(True) or [])
    monkeypatch.setattr(investigations, "case_resource_groups_batch", lambda *_args, **_kwargs: {})
    payload, status = _dispatch(decision, "/api/v1/investigation-cases").sent[-1]
    assert status == 200 and payload["items"] == []
    assert calls == [True] and readers == []


@pytest.mark.parametrize("technical", [False, True])
def test_decoy_reference_follows_technical_field_policy(monkeypatch, technical):
    raw = _raw()
    raw["items"][0].update(decoy_id="00000000-0000-4000-8000-000000000003", decoy_revision=7)
    monkeypatch.setattr(report, "get_security_problems_data", lambda **_: deepcopy(raw))
    monkeypatch.setattr(report, "linked_cases_for_findings", lambda _: {})
    context = QueryContext(access=_access(fields=("security", "technical") if technical else ("security",)), params={}, limit=50)
    row = report._query(context)["items"][0]
    assert ("decoy_id" in row) is technical
    assert ("decoy_revision" in row) is technical
