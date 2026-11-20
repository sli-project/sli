"""«Очередь проблем» on the v2 framework: presentation, lifecycle options, metrics."""

from __future__ import annotations

from dataclasses import replace

import pytest

from server.sli.core.messages import FINDING_SEVERITIES, FINDING_STATUSES, catalog, message, response_messages
from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import security_problems as report


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_watch_queue_wording_is_localized_without_private_reason(locale):
    raw = {"id": 42, "rule_code": "semantic.qw.account-watch", "severity": "medium",
           "title": "Activity of an account under watch", "summary": "synthetic-private-reason"}
    localized = response_messages({"report_key": "security.problems", "items": [report.presentation(raw)]}, locale)["items"][0]
    assert localized["presentation_code"] == "account_watch_activity"
    for field, suffix in (("title_text", "title"), ("what_happened", "what"),
                          ("why_text", "why"), ("wording_limitation", "limitation")):
        assert localized[field] == catalog(locale)[f"security.problems.presentation.watch_{suffix}"]
    assert "synthetic-private-reason" not in str(localized)


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_decoy_queue_wording_is_localized_and_does_not_claim_complete_coverage(locale):
    raw = {"id": 42, "rule_code": "semantic.qw.account-decoy", "severity": "high",
           "title": "Registered decoy account used", "summary": "synthetic-private-source"}
    view = report.presentation(raw)
    localized = response_messages({"report_key": "security.problems", "items": [view]}, locale)["items"][0]
    assert localized["presentation_code"] == "account_decoy_used"
    assert localized["title_text"] == catalog(locale)["security.problems.presentation.decoy_title"]
    assert localized["what_happened"] == catalog(locale)["security.problems.presentation.decoy_what"]
    assert localized["wording_limitation"] == catalog(locale)["security.problems.presentation.decoy_limitation"]
    assert "synthetic-private-source" not in str(localized)
    assert raw["summary"] == "synthetic-private-source"


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_file_decoy_queue_has_exact_wording_without_private_path(locale):
    raw = {"id": 42, "rule_code": "semantic.qw.file-decoy", "severity": "high",
           "title": "Registered decoy file touched", "summary": "synthetic-private-path"}
    view = report.presentation(raw)
    localized = response_messages({"report_key": "security.problems", "items": [view]}, locale)["items"][0]
    assert localized["presentation_code"] == "file_decoy_touched"
    for field, suffix in (("title_text", "title"), ("what_happened", "what"), ("wording_limitation", "limitation")):
        assert localized[field] == catalog(locale)[f"security.problems.presentation.file_decoy_{suffix}"]
    assert "synthetic-private-path" not in str(localized)


@pytest.fixture(autouse=True)
def no_link_database(monkeypatch):
    monkeypatch.setattr(report, "linked_cases_for_findings", lambda ids: {})


def _context(params: dict[str, str]) -> QueryContext:
    return QueryContext(
        access=_access(), params=params, domain_ids=None, action="view", cursor=None, limit=50, timezone="UTC",
        runtime={"storage_route_authorization": "sealed"},
    )


def _access():
    return {
        "capabilities": ["investigations.view"],
        "reports": [{
            "report_key": key, "allowed": True, "allowed_actions": ["view"],
            "grants": [{"scope": {"kind": "all"}, "allowed_actions": ["view"],
                        "field_categories": ["security", "raw_evidence", "identity_basic", "technical"]}],
        } for key in ("security.queue", "investigations.workspace")],
    }


@pytest.fixture(autouse=True)
def no_real_case_readers(monkeypatch):
    monkeypatch.setattr(report, 'password_coverage_catalog_domains', lambda: [7])
    monkeypatch.setattr(report, "linked_cases_for_findings", lambda _ids: {})
    monkeypatch.setattr(report, "case_resource_groups_batch", lambda ids, **_: {key: [] for key in ids})


def test_audit_policy_change_has_registered_wording_and_system_actor_is_named():
    view = report.presentation({"id": 3, "title": "Audit policy was changed", "actor": "sid:DC1:S-1-5-18"})
    assert view["title_text"] == "Изменена политика аудита Windows"
    assert view["actor_text"] == "Системная учётная запись DC1"
    assert view["wording_limitation"] is None
    other = report.presentation({"id": 4, "title": None, "actor": ""})
    assert other["title_text"] == "Проблема #4" and other["actor_text"] == "—"
    assert other["wording_limitation"]


def test_queue_link_forwards_exact_entity_filter(monkeypatch):
    calls = []
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: calls.append(kwargs) or {"state": "empty"})
    report._query(_context({"entity_id": "7", "rule_code": "semantic.synthetic",
        "created_from": "2026-10-01T00:00:00Z", "created_to": "2026-10-07T00:00:00Z"}))
    assert calls[0]["entity_id"] == 7
    assert calls[0]["rule_code"] == "semantic.synthetic"
    assert calls[0]["created_from"] == "2026-10-01T00:00:00Z"
    assert calls[0]["created_to"] == "2026-10-07T00:00:00Z"
    assert next(param for param in report.REPORT.params if param.key == "entity_id").hidden


@pytest.mark.parametrize("cohort", [False, True])
@pytest.mark.parametrize("risk", [None, "accepted", "all"])
def test_queue_entity_filter_applies_to_rows_and_summary_before_limit(monkeypatch, cohort, risk):
    from server.sli.semantic import findings
    calls = []
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda *, authorization, consumer: {"route": "v2"})
    monkeypatch.setattr(findings, "_attach_postgres_finding_details", lambda rows, *, authorization, identity_labels, defer_identity_labels: None)
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda *, authorization: {"limitations": []})
    def read(sql, params=()):
        calls.append((sql, params))
        return []
    monkeypatch.setattr(findings, "query_rows", read)
    filters = {"rule_code": "semantic.synthetic", "created_from": "2026-10-01T00:00:00Z",
        "created_to": "2026-10-07T00:00:00Z"} if cohort else {}
    result = findings.get_security_problems_data(entity_id=7, limit=1, risk=risk, **filters)
    queries = [(sql, params) for sql, params in calls if "from findings_active findings" in sql]
    assert len(queries) == 2
    assert all("linked.entity_id=?" in sql and params[0] == 7 for sql, params in queries)
    expected = (7, "semantic.synthetic", "2026-10-01T00:00:00+00:00", "2026-10-07T00:00:00+00:00") if cohort else (7,)
    assert queries[0][1] == (*expected, 2)
    assert queries[1][1] == expected
    assert "limit ?" in queries[0][0] and "limit ?" not in queries[1][0]
    accepted = "coalesce(risk.state='active' and risk.expires_at > statement_timestamp(),false)"
    for sql, _ in queries:
        where = sql.split(" where is_semantic_finding_published_v1(findings.id)", 1)[1]
        where = where.split("order by", 1)[0].split("group by", 1)[0]
        if risk == "accepted":
            assert f"and {accepted}" in where and f"not {accepted}" not in where
        elif risk == "all":
            assert accepted not in where
        else:
            assert f"not {accepted}" in where
    if cohort:
        assert all("findings.rule_code = ?" in sql and "findings.created_at >=" in sql
            and "findings.created_at <" in sql for sql, _ in queries)
    assert result["items"] == []


@pytest.mark.parametrize("domain_ids", [[1], [1, 2]])
def test_queue_domain_membership_filters_rows_and_summary_before_limit(monkeypatch, domain_ids):
    from server.sli.semantic import findings

    calls = []
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **_: {"route": "v2"})
    monkeypatch.setattr(findings, "_attach_postgres_finding_details", lambda rows, **_: None)
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **_: {"limitations": []})
    monkeypatch.setattr(findings, "query_rows", lambda sql, params=(): calls.append((sql, params)) or [])

    findings.get_security_problems_data(domain_ids=domain_ids, limit=1)

    queries = [(sql, params) for sql, params in calls if "from findings_active findings" in sql]
    assert len(queries) == 2
    for sql, params in queries:
        assert "semantic_finding_in_domains_v265(findings.id,?::bigint[])" in sql
        assert params[:1] == (domain_ids,)
    assert queries[0][1] == (domain_ids, 2)
    assert queries[1][1] == (domain_ids,)


def test_query_forwards_filters_and_sealed_authorization_and_counts_the_queue(monkeypatch: pytest.MonkeyPatch):
    calls: list[dict[str, object]] = []
    payload = {
        "state": "available",
        "items": [{"id": 7, "status": "new", "title": "X", "evidence": [{"event_db_id": 1}], "entities": [{"display_name": "42", "entity_role": "source_host"}]}],
        "summary": [{"status": "new", "severity": "high", "count": 2}, {"status": "active", "severity": "low", "count": 1}, {"status": "closed", "severity": "low", "count": 5}],
        "lifecycle": {"allowed_transitions": {"new": ["active", "false_positive"]}},
        "semantic_runtime": {"findings_state": "inactive"},
        "limitations": [],
    }
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: calls.append(kwargs) or payload)

    body = report._query(_context({"status": "new", "q": "audit"}))
    assert calls[0]["status"] == "new" and calls[0]["q"] == "audit" and calls[0]["authorization"] == "sealed"
    row = body["items"][0]
    assert row["allowed_statuses"] == ["new", "active", "false_positive"]
    assert row["evidence_total"] == 1 and row["entity_text"] == "Сервер-источник"
    assert {metric["key"]: metric["value"] for metric in body["metrics"]} == {"open": 3, "attention": 2, "progress": 1, "closed": 5}
    assert any(item["code"] == "zero_is_not_safe" for item in body["limitations"])


def test_declaration_names_the_lifecycle_actions_and_uses_the_queue_grant():
    assert report.REPORT.access.report_key == "security.queue"
    assert report.REPORT.detail.to_json()["actions"] == "problems.lifecycle"
    assert next(column for column in report.REPORT.columns if column.key == "risk_acceptance").component == "problems.risk-badge"
    assert ("Отложенные", {"risk": "accepted"}) in report.REPORT.presets


def test_accepted_risks_filter_reaches_the_read_model_with_quality_cohort(monkeypatch):
    calls = []
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: calls.append(kwargs) or {
        "state": "empty", "items": [], "semantic_runtime": {"findings_state": "active"},
    })
    monkeypatch.setattr(report, "linked_cases_for_findings", lambda ids: {})
    report._query(_context({"risk": "accepted", "rule_code": "semantic.synthetic",
        "created_from": "2026-10-01T00:00:00Z", "created_to": "2026-10-07T00:00:00Z"}))
    assert calls[0]["risk"] == "accepted"
    assert calls[0]["rule_code"] == "semantic.synthetic"
    assert calls[0]["created_from"] == "2026-10-01T00:00:00Z"
    assert calls[0]["created_to"] == "2026-10-07T00:00:00Z"
    assert calls[0]["authorization"] == "sealed"
    params = {param.key: param for param in report.REPORT.params}
    assert {"risk", "rule_code", "created_from", "created_to"} <= params.keys()
    assert all(params[key].hidden for key in ("rule_code", "created_from", "created_to"))


def test_accepted_risks_are_not_counted_as_requiring_a_decision():
    assert report._count([
        {"status": "new", "count": 2},
        {"status": "new", "count": 3, "risk_accepted": True},
        {"status": "repeated", "count": 1, "risk_accepted": False},
    ], report.ATTENTION) == 3


def test_evidence_detail_pages_all_rows_and_uses_sealed_authorization(monkeypatch):
    from dataclasses import replace
    from server.sli.semantic import findings, file_acl_evidence

    evidence = [{"evidence_id": i, "event_db_id": i, "event_id": 4719} for i in range(1, 71)]
    routes = []
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **kwargs: routes.append(kwargs) or {"route": "v2"})
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    membership = []
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: membership.append(kwargs) or {"items": [{"id": 7}]})

    def read(sql, params=()):
        if "clock_timestamp()" in sql:
            return [{"watermark": "2026-01-02T00:00:00+00:00"}]
        if "read_file_acl_finding_resources_v265" in sql:
            return [{"resources": []}]
        if "count(*)" in sql:
            return [{"total": len(evidence)}]
        assert "left join events_v2_core" in sql
        assert params[0] == 7
        return [row.copy() for row in evidence if row["evidence_id"] > params[1]][:params[3]]

    monkeypatch.setattr(findings, "query_rows", read)
    monkeypatch.setattr(file_acl_evidence, "query_rows", read)
    context = replace(_context({"status": "new"}), limit=20)
    pages = []
    while True:
        body = report.REPORT.detail.query(context, "7")
        pages.extend(body["items"])
        assert body["filtered_count"] == 70
        if not body["has_more"]:
            break
        context = replace(context, cursor=body["next_cursor"])
    assert [row["event_db_id"] for row in pages] == list(range(1, 71))
    assert all(call["finding_id"] == 7 and call["authorization"] == "sealed" for call in membership)
    assert len(routes) == 4 and all(call["authorization"] == "sealed" for call in routes)
    assert report.REPORT.detail.to_json()["kind"] == "sub"


def test_evidence_detail_rejects_unpublished_finding_before_reading_evidence(monkeypatch):
    from server.sli.semantic import findings

    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: {"items": []})
    monkeypatch.setattr(findings, "query_rows", lambda *args: pytest.fail("evidence must not be read"))
    with pytest.raises(LookupError):
        report.REPORT.detail.query(_context({}), "7")


@pytest.mark.parametrize("row_id,params", [("8", {"status": "new"}), ("7", {"status": "active"})])
def test_evidence_cursor_cannot_be_reused_for_another_problem_or_filter(monkeypatch, row_id, params):
    from dataclasses import replace

    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: {"items": [{"id": kwargs["finding_id"]}]})
    calls = []
    monkeypatch.setattr(report, "get_problem_evidence_page", lambda *args, **kwargs: calls.append(args) or {
        "items": [{"evidence_id": 1}], "has_more": True, "total": 2,
    })
    first = report.REPORT.detail.query(_context({"status": "new"}), "7")
    with pytest.raises(ValueError, match="invalid_cursor"):
        report.REPORT.detail.query(replace(_context(params), cursor=first["next_cursor"]), row_id)
    assert len(calls) == 1


def test_evidence_reader_keeps_links_with_unavailable_source_events(monkeypatch):
    from server.sli.semantic import findings

    monkeypatch.setattr(findings, "resolve_storage_route", lambda **kwargs: {"route": "v2"})
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    retained = {"evidence_id": 1, "event_db_id": None, "event_id": None}
    monkeypatch.setattr(findings, "query_rows", lambda sql, params: [{"total": 1}] if "count(*)" in sql else [retained])
    page = findings.get_problem_evidence_page(7, authorization="sealed")
    assert page == {"items": [retained], "total": 1, "has_more": False}


@pytest.mark.parametrize("limit,expected", [(0, 1), (1, 1), (20, 20), (200, 200), (1000, 200)])
def test_evidence_reader_bounds_page_and_count_queries(monkeypatch, limit, expected):
    from server.sli.semantic import findings

    monkeypatch.setattr(findings, "resolve_storage_route", lambda **kwargs: {"route": "v2"})
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)

    def read(sql, params):
        if "count(*)" in sql:
            assert "limit ?" in sql
            assert params == (7, findings.PROBLEM_EVIDENCE_COUNT_LIMIT + 1)
            return [{"total": findings.PROBLEM_EVIDENCE_COUNT_LIMIT + 1}]
        assert "order by fe.id" in sql and "fe.id>?" in sql
        assert params == (7, 500, expected + 1)
        return [{"evidence_id": 501 + i} for i in range(expected + 1)]

    monkeypatch.setattr(findings, "query_rows", read)
    page = findings.get_problem_evidence_page(7, after_id=500, limit=limit)
    assert len(page["items"]) == expected and page["has_more"]
    assert page["total"] is None
    assert page["total_lower_bound"] == findings.PROBLEM_EVIDENCE_COUNT_LIMIT + 1


@pytest.mark.parametrize("count", [0, 70, 10_000, None])
def test_evidence_count_is_exact_only_when_known_and_not_capped(monkeypatch, count):
    from server.sli.semantic import findings

    monkeypatch.setattr(findings, "resolve_storage_route", lambda **kwargs: {"route": "v2"})
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "query_rows", lambda sql, params: (
        [{"total": count}] if "count(*)" in sql and count is not None else []
    ))
    page = findings.get_problem_evidence_page(7)
    assert page["total"] == count
    assert ("total_lower_bound" in page) == (count is None)


def test_evidence_detail_preserves_all_population_filters_and_reports_partial_sources(monkeypatch):
    calls = []
    params = {"population": "attention", "time_from": "2026-10-01T00:00:00Z",
              "time_to": "2026-10-02T00:00:00Z"}
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: calls.append(kwargs) or {
        "items": [{"id": 7}],
    })
    monkeypatch.setattr(report, "get_problem_evidence_page", lambda *args, **kwargs: {
        "items": [{"evidence_id": 1, "event_db_id": None}], "has_more": True,
        "total": None, "total_lower_bound": 10_001,
    })
    body = report.REPORT.detail.query(replace(_context(params), domain_ids=[7]), "7")
    assert calls[0]["domain_ids"] == [7] and calls[0]["attention_only"] is True
    assert calls[0]["time_from"] == params["time_from"] and calls[0]["time_to"] == params["time_to"]
    assert body["filtered_count"] is None and body["coverage"]["evidence_total_lower_bound"] == 10_001
    assert body["state"] == "partial" and body["coverage"]["evidence_missing_sources"] == 1
    assert body["has_more"] and body["next_cursor"]


def test_exact_finding_filter_is_applied_before_the_queue_limit(monkeypatch):
    from server.sli.semantic import findings

    monkeypatch.setattr(findings, "resolve_storage_route", lambda **kwargs: {"route": "v2"})
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "_attach_postgres_finding_details", lambda *args, **kwargs: None)
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **kwargs: {"limitations": []})
    calls = []
    monkeypatch.setattr(findings, "query_rows", lambda sql, params=(): calls.append((sql, params)) or [])
    findings.get_security_problems_data(finding_id=7, limit=1, authorization="sealed")
    population = [(sql, params) for sql, params in calls if "from findings_active findings" in sql]
    assert len(population) == 2
    assert all("findings.id = ?" in sql and params[0] == 7 for sql, params in population)


def test_queue_freshness_does_not_label_worker_time_as_event_or_snapshot(monkeypatch):
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: {
        "state": "available", "items": [{"id": 7, "last_seen_utc": "2026-09-01T00:00:00Z", "published_at_utc": "2026-10-07T00:00:00Z", "updated_at": "2026-10-07T11:00:00Z"}],
        "semantic_runtime": {"findings_state": "active", "heartbeat_at": "2026-10-07T12:00:00Z"},
    })
    monkeypatch.setattr(report, "linked_cases_for_findings", lambda ids: {})
    coverage = report._query(_context({}))["coverage"]
    assert coverage["event_at_utc"] == "2026-09-01T00:00:00Z"
    assert coverage["published_at_utc"] == "2026-10-07T00:00:00Z"
    assert coverage.get("snapshot_at_utc") is None
    assert coverage.get("observed_at_utc") is None


def test_quality_link_forwards_exact_rule_and_creation_cohort(monkeypatch):
    calls = []
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: calls.append(kwargs) or {"state": "empty", "items": []})
    report._query(_context({"rule_code": "semantic.synthetic", "created_from": "2026-10-01T00:00:00Z",
        "created_to": "2026-10-07T00:00:00Z", "show_suppressed": "true"}))
    assert calls[0]["rule_code"] == "semantic.synthetic"
    assert calls[0]["created_from"] == "2026-10-01T00:00:00Z"
    assert calls[0]["created_to"] == "2026-10-07T00:00:00Z"
    assert calls[0]["show_suppressed"] is True


def test_rows_expose_the_linked_case_and_survive_an_unavailable_link_table(monkeypatch: pytest.MonkeyPatch):
    payload = {"state": "available", "items": [{"id": 7, "status": "new"}, {"id": 8, "status": "new"}], "summary": [], "lifecycle": {}, "semantic_runtime": {"findings_state": "active"}}
    monkeypatch.setattr(report, "get_security_problems_data", lambda **_kwargs: payload)
    monkeypatch.setattr(report, "linked_cases_for_findings", lambda ids: {7: {"id": 4, "public_id": None, "status": "active"}})

    rows = report._query(_context({}))["items"]
    assert rows[0]["linked_case"] == {"id": 4, "public_id": None, "status": "active"}
    assert rows[1]["linked_case"] is None

    def broken(_ids):
        raise RuntimeError("relation does not exist")

    monkeypatch.setattr(report, "linked_cases_for_findings", broken)
    assert [row["linked_case"] for row in report._query(_context({}))["items"]] == [None, None]


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_coded_finding_presentation_and_source_fields(monkeypatch, locale):
    finding = {"id": 9, "title": "Audit policy was changed", "status": "repeated", "severity": "critical",
               "actor": "sid:fixture-host:S-1-5-18", "review_hint": {"bucket": "machine_account"},
               "entities": [{"display_name": "42", "entity_role": "source_host"}, {"display_name": "source-observation"}]}
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: {
        "state": "available", "items": [finding], "semantic_runtime": {"findings_state": "inactive"},
    })
    monkeypatch.setattr(report, "linked_cases_for_findings", lambda ids: {9: {"id": 7, "status": "review"}})
    original = report._query(_context({}))
    actual = response_messages(original, locale, report=True)
    row = actual["items"][0]
    for key, value in finding.items():
        assert row[key] == value
    for field, envelope in row["presentation_messages"].items():
        assert envelope == message(envelope["code"], envelope["params"], locale=locale)
        assert row[field] == envelope["text"]
    assert row["status_message"] == message("security.problems.status.repeated", locale=locale)
    assert row["severity_message"] == message("reports.v2.security.problems.columns.severity.labels.critical", locale=locale)
    for code_field, text_field in (("title_code", "title_text"), ("what_code", "what_happened"),
                                 ("why_code", "why_text"), ("next_step_code", "next_text")):
        assert row[code_field] == row["presentation_messages"][text_field]["code"]
    assert row["linked_case"]["status_message"] == message("investigations.caseStatus.review", locale=locale)
    assert row["entity_text"] == message("security.problems.entity.source_host", locale=locale)["text"] + ", source-observation"
    assert original["items"][0]["status_message"]["text"] == catalog("ru")["security.problems.status.repeated"]
    assert actual["limitations"][0]["text"] == catalog(locale)["reports.v2.security.problems.limitations.zero_is_not_safe"]
    assert actual["metrics"][0]["presentation_messages"]["label"]["code"] == "reports.v2.security.problems.metrics.open.label"


@pytest.mark.parametrize("bucket", sorted(report._REVIEW_BUCKETS))
def test_review_bucket_codes_and_suppression(bucket):
    row = report._row({"id": 1, "review_hint": {"bucket": bucket}}, {})
    assert row["presentation_messages"]["review_hint_text"]["code"] == f"reports.v2.security.problems.presentation.{bucket}"
    suppressed = report._row({"id": 1, "review_hint": {"bucket": bucket, "has_audit_change": False}}, {})
    assert suppressed["review_hint_text"] is None
    assert "review_hint_text" not in suppressed["presentation_messages"]


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_queue_metadata_uses_catalog_codes_and_preserves_filter_values(locale):
    definition = report.REPORT.to_json()
    actual = response_messages(definition, locale)
    assert actual["title"] == catalog(locale)["reports.v2.security.problems.title"]
    assert actual["presentation_messages"]["title"]["code"] == "reports.v2.security.problems.title"
    assert tuple(value for value, label in report.STATUSES) == FINDING_STATUSES
    assert tuple(value for value, label in report.SEVERITIES) == FINDING_SEVERITIES
    for column in actual["columns"]:
        assert column["label"] == catalog(locale)[f"reports.v2.security.problems.columns.{column['key']}.label"]
        for key, envelope in column.get("labels_messages", {}).items():
            assert column["labels"][key] == catalog(locale)[envelope["code"]]
    for before, after in zip(definition["params"], actual["params"]):
        assert after["label"] == catalog(locale)[f"reports.v2.security.problems.params.{after['key']}.label"]
        for option in after.get("options", []):
            code = f"reports.v2.security.problems.params.{after['key']}.options.{option['value']}"
            assert option["label"] == catalog(locale)[code]
            assert option["presentation_messages"]["label"] == message(code, locale=locale)
        assert [option["value"] for option in before.get("options", [])] == [option["value"] for option in after.get("options", [])]
    params = {param["key"]: param for param in actual["params"]}
    assert all(params[key]["hidden"] for key in ("id", "domain", "time_from", "time_to", "entity_id", "rule_code", "created_from", "created_to"))
    assert params["id"]["kind"] == "int"
    assert [option["value"] for option in params["population"]["options"]] == ["open", "attention", "all"]
    assert params["population"]["default"] == "open"
    assert params["entity_id"]["kind"] == "int"
    assert [option["value"] for option in params["risk"]["options"]] == ["accepted", "all"]
    assert actual["presets"][-1]["params"] == {"risk": "accepted"}
    assert actual["presets"][-1]["label"] == catalog(locale)['reports.v2.security.problems.presets.{"risk":"accepted"}']
    assert [item["params"] for item in actual["presets"]] == [item["params"] for item in definition["presets"]]
    assert actual["presets"][0]["params"] == {"population": "attention"}
    assert actual["presets"][0]["presentation_messages"]["label"] == message(
        'reports.v2.security.problems.presets.{"population":"attention"}', locale=locale,
    )
    assert actual["detail"]["row_links"][0]["presentation_messages"]["label"]["code"].endswith("/app/events/{event_db_id}")
    for field in ("question", "denominator", "freshness_expectation"):
        code = f"reports.v2.security.problems.intent.{field}"
        assert actual["intent"][field] == catalog(locale)[code]
        assert actual["intent"]["presentation_messages"][field] == message(code, locale=locale)
    assert {key: value for key, value in actual["intent"].items()
            if key not in {"question", "denominator", "freshness_expectation", "presentation_messages"}} == {
        key: value for key, value in definition["intent"].items()
        if key not in {"question", "denominator", "freshness_expectation"}
    }
    assert definition == report.REPORT.to_json()


def test_unknown_rule_only_codes_fallbacks_and_retains_observations():
    raw = {"id": 4, "title": "Future rule", "summary": "Raw observation", "why_it_matters": "Source explanation", "recommended_action": "Source action", "actor": "source-actor"}
    row = report.presentation(raw)
    assert set(row["presentation_messages"]) == {"wording_limitation"}
    assert all(row[key] is None for key in ("title_code", "what_code", "why_code", "next_step_code"))
    assert [row[key] for key in ("title_text", "what_happened", "why_text", "next_text", "actor_text")] == [raw[key] for key in ("title", "summary", "why_it_matters", "recommended_action", "actor")]
    fallback = response_messages({"report_key": "security.problems", "items": [report.presentation({"id": 4})]}, "en")["items"][0]
    assert fallback["title_text"] == "Problem #4"
    assert fallback["actor_text"] == catalog("en")["security.problems.actor.undefined"]
    for code_field, text_field in (("title_code", "title_text"), ("what_code", "what_happened"),
                                 ("why_code", "why_text"), ("next_step_code", "next_text")):
        assert fallback[code_field] == fallback["presentation_messages"][text_field]["code"]


def test_home_reader_requests_ranked_compact_population_and_exact_window(monkeypatch):
    calls = []
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: calls.append(kwargs) or {
        "state": "available", "items": [], "summary": [], "semantic_runtime": {"findings_state": "active"},
    })
    monkeypatch.setattr(report, "_linked_cases", lambda rows: pytest.fail("compact reader must not fetch cases"))
    context = _context({"time_from": "2026-10-01T00:00:00Z", "time_to": "2026-10-02T00:00:00Z"})
    context = replace(context, domain_ids=[7])
    context.runtime["home_summary"] = True
    body = report._query(context)
    assert calls[0]["home_order"] and calls[0]["attention_only"] and calls[0]["compact"]
    assert calls[0]["domain_ids"] == [7]
    assert calls[0]["time_from"] == context.params["time_from"]
    assert calls[0]["time_to"] == context.params["time_to"]
    assert next(metric for metric in body["metrics"] if metric["key"] == "attention")["filter"] == {"population": "attention"}


def test_attention_population_and_exact_id_reach_the_reader(monkeypatch):
    calls = []
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: calls.append(kwargs) or {
        "state": "available", "items": [], "summary": [{"status": status, "count": count} for status, count in (
            ("new", 2), ("confirmed", 3), ("repeated", 4), ("active", 5))],
        "semantic_runtime": {"findings_state": "active"},
    })
    body = report._query(_context({"population": "attention", "id": 123}))
    assert calls[0]["attention_only"] is True and calls[0]["finding_id"] == 123
    assert next(metric for metric in body["metrics"] if metric["key"] == "attention")["value"] == 9


@pytest.mark.parametrize("params", [
    {"time_from": "not-an-instant"},
    {"time_from": "2026-10-01T00:00:00Z"},
    {"time_from": "2026-10-02T00:00:00Z", "time_to": "2026-10-01T00:00:00Z"},
])
def test_invalid_window_never_reaches_storage(monkeypatch, params):
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: pytest.fail("invalid window read"))
    with pytest.raises(ValueError):
        report._query(_context(params))


def test_findings_home_top_n_is_selected_in_sql_before_limit_and_suppression_expiry(monkeypatch):
    from server.sli.semantic import findings

    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **kwargs: {"route": "v2"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **kwargs: {})
    monkeypatch.setattr(findings, "_attach_postgres_finding_details", lambda *a, **k: pytest.fail("compact reader fetches no evidence"))
    calls, suppressed = [], {99}
    rows = [{"id": i, "severity": "low", "status": "new", "repeat_count": 0} for i in range(30)]
    rows.append({"id": 99, "severity": "critical", "status": "repeated", "repeat_count": 4})

    def fake_query(sql, params=()):
        calls.append((sql, params))
        if "from findings_active" not in sql:
            return []
        assert "not semantic_finding_suppressed_v160" in sql
        assert "else findings.status end) in ('new','confirmed','repeated')" in sql
        assert "semantic_finding_in_domains_v265(findings.id,?::bigint[])" in sql
        assert params[:1] == ([7],)
        eligible = [row for row in rows if row["id"] not in suppressed]
        if "group by" in sql:
            return [{"severity": "low", "status": "new", "count": 30},
                    *([{"severity": "critical", "status": "repeated", "count": 1}] if not suppressed else [])]
        order = sql[sql.rindex("order by"):sql.index("limit ?")]
        assert "case when findings.severity in ('critical','high') then 0 else 2 end" in order
        assert order.index("case findings.severity") < order.index("coalesce(findings.repeat_count,0) desc") < order.index("last_seen_utc") < order.index("findings.id desc")
        eligible.sort(key=lambda row: (row["severity"] != "critical", -row["repeat_count"], -row["id"]))
        return eligible[:params[-1]]

    monkeypatch.setattr(findings, "query_rows", fake_query)
    before = findings.get_security_problems_data(limit=5, attention_only=True, home_order=True, compact=True, domain_ids=[7])
    assert 99 not in [row["id"] for row in before["items"]]
    # The existing suppression function ceases matching at its expires_at;
    # the finding's status is not changed, so it returns to the same population.
    suppressed.clear()
    after = findings.get_security_problems_data(limit=5, attention_only=True, home_order=True, compact=True, domain_ids=[7])
    assert after["items"][0]["id"] == 99
    assert len(after["items"]) == 5 and after["has_more"]
    assert sum(row["count"] for row in after["summary"]) == 31
    assert calls[0][1][-1] == 6


def test_findings_combines_scope_attention_and_exact_id_with_creation_cohort(monkeypatch):
    from server.sli.semantic import findings

    calls = []
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **kwargs: {"route": "v2"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **kwargs: {})
    monkeypatch.setattr(findings, "query_rows", lambda sql, params=(): calls.append((sql, params)) or [])
    monkeypatch.setattr(findings, "_attach_postgres_finding_details", lambda *a, **k: pytest.fail("compact reader fetches no evidence"))

    findings.get_security_problems_data(
        domain_ids=[7], finding_id=123, attention_only=True, home_order=True, compact=True,
        rule_code="semantic.synthetic", created_from="2026-10-01T07:00:00+07:00",
        created_to="2026-10-07T07:00:00+07:00", limit=5,
    )

    expected = ([7], 123, "semantic.synthetic", "2026-10-01T00:00:00+00:00", "2026-10-07T00:00:00+00:00")
    for sql, params in calls[:2]:
        assert "is_semantic_finding_published_v1(findings.id)" in sql
        assert "not semantic_finding_suppressed_v160" in sql
        assert "semantic_finding_in_domains_v265(findings.id,?::bigint[])" in sql
        assert "findings.id = ?" in sql
        assert "else findings.status end) in ('new','confirmed','repeated')" in sql
        assert "risk.expires_at <= statement_timestamp()" in sql
        assert "findings.rule_code = ?" in sql
        assert "findings.created_at >= ?::timestamptz" in sql
        assert "findings.created_at < ?::timestamptz" in sql
        assert params[:len(expected)] == expected
    assert len(calls) == 3
    assert calls[0][1] == (*expected, 6)
    assert calls[1][1] == expected


@pytest.mark.parametrize("home_order", [False, True])
def test_scoped_attention_keeps_risk_expiry_and_exact_cohort_filters(monkeypatch, home_order):
    from server.sli.semantic import findings

    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **kwargs: {"route": "v2"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **kwargs: {})
    monkeypatch.setattr(findings, "_attach_postgres_finding_details",
                        lambda *a, **k: pytest.fail("compact reader must not fetch evidence"))
    calls = []
    monkeypatch.setattr(findings, "query_rows", lambda sql, params=(): calls.append((sql, params)) or [])
    findings.get_security_problems_data(
        domain_ids=[7], finding_id=123, entity_id=9, rule_code="semantic.synthetic",
        created_from="2026-10-01T00:00:00Z", created_to="2026-10-07T00:00:00Z",
        attention_only=True, home_order=home_order, compact=True, limit=5,
    )
    queries = [(sql, params) for sql, params in calls if "from findings_active findings" in sql]
    assert len(queries) == 2
    expected = ([7], 123, 9, "semantic.synthetic",
                "2026-10-01T00:00:00+00:00", "2026-10-07T00:00:00+00:00")
    assert queries[0][1] == (*expected, 6)
    assert queries[1][1] == expected
    for sql, _ in queries:
        assert "semantic_finding_in_domains_v265(findings.id,?::bigint[])" in sql
        assert "findings.id = ?" in sql and "linked.entity_id=?" in sql
        assert "findings.created_at >=" in sql and "findings.created_at <" in sql
        assert "not coalesce(risk.state='active'" in sql
        assert "risk.expires_at <= statement_timestamp()" in sql
        assert "else findings.status end) in ('new','confirmed','repeated')" in sql
    order = queries[0][0][queries[0][0].rindex("order by"):]
    assert "risk.expires_at <= statement_timestamp()" in order
    if home_order:
        assert "case when findings.severity in ('critical','high') then 0 else 2 end" in order
        assert "coalesce(findings.repeat_count,0) desc" in order


@pytest.mark.parametrize("rule", ["account", "file"])
def test_queue_projects_only_event_time_label_reference(rule):
    raw = {"id": 42, "rule_code": f"semantic.qw.{rule}-decoy", "status": "new", "severity": "high",
           "decoy_id": "00000000-0000-4000-8000-000000000003", "decoy_revision": 1,
           "private_label_payload": "synthetic-private-value"}
    view = report._row(raw, {})
    assert view["decoy_id"] == raw["decoy_id"] and view["decoy_revision"] == 1
    assert "private_label_payload" not in view
    assert report.REPORT.row_categories["decoy_id"] == frozenset({"technical"})
    assert report.REPORT.row_categories["decoy_revision"] == frozenset({"technical"})


def test_queue_reader_maps_canonical_label_reference_without_loading_registry(monkeypatch):
    from server.sli.semantic import findings
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **_: {"route": "v2"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **_: {"limitations": []})
    label = {"decoy_id": "00000000-0000-4000-8000-000000000003", "decoy_revision": 1}
    calls = []
    def read(sql, params=()):
        calls.append(sql)
        if "select findings.*" in sql:
            return [{"id": 42, "decoy_label": label}]
        return []
    monkeypatch.setattr(findings, "query_rows", read)
    row = findings.get_security_problems_data(compact=True)["items"][0]
    assert row["decoy_id"] == label["decoy_id"] and row["decoy_revision"] == 1
    assert "decoy_label" not in row
    assert any("public.finding_decoy_context(findings.id)" in sql for sql in calls)
    assert not any("from decoy_label_versions" in sql for sql in calls)


def test_cohort_pages_are_context_bound_and_keep_exact_total_and_original_ids(monkeypatch):
    import json
    from server.sli.core.keyset_cursor import decode_cursor
    cohort = json.dumps(["membership", "synthetic", 7, 11, "S-1-5-21-1-1101", "S-1-5-21-1-512", "2026-10-01"])
    calls = []
    def read(**kwargs):
        calls.append(kwargs)
        return {"state": "available", "items": [{"id": 9}, {"id": 8}], "has_more": True,
                "summary": [{"count": 188, "status": "new"}]}
    monkeypatch.setattr(report, "get_security_problems_data", read)
    context = _context({"cohort": cohort, "population": "attention", "rule_code": "synthetic"})
    page = report._query(context)
    assert page["filtered_count"] == 188 and [row["id"] for row in page["items"]] == [9, 8]
    assert page["next_cursor"]
    binding = {"report": report.REPORT_KEY, "cohort": context.params, "domains": context.domain_ids,
               "timezone": context.timezone, "action": context.action, "group_queue": False}
    assert decode_cursor(page["next_cursor"], binding) == {"after_id": 8}
    report._query(replace(context, cursor=page["next_cursor"]))
    assert calls[-1]["after_id"] == 8 and calls[-1]["cohort_timezone"] == "UTC"
    with pytest.raises(ValueError, match="invalid_cursor"):
        report._query(replace(context, cursor=page["next_cursor"], timezone="Europe/Berlin"))
    with pytest.raises(ValueError, match="invalid_cursor"):
        report._query(replace(context, cursor=page["next_cursor"], domain_ids=[8]))


def test_cohort_detail_rechecks_same_population_before_original_evidence(monkeypatch):
    import json
    calls = []
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: calls.append(kwargs) or {"items": []})
    cohort = json.dumps(["finding", 7])
    with pytest.raises(LookupError, match="report_row_not_found"):
        report._detail(_context({"cohort": cohort, "population": "attention"}), "7")
    assert calls[0]["finding_id"] == 7 and calls[0]["cohort"] == cohort
    assert calls[0]["attention_only"] and calls[0]["cohort_timezone"] == "UTC"


def test_detail_endpoint_does_not_spend_evidence_deadline_on_optional_names(monkeypatch):
    """The real route/detail/population chain must preserve the separate evidence page."""
    from types import SimpleNamespace
    from unittest.mock import Mock
    from server.api.routes import reports_v2 as route
    from server.sli.reporting import read_timeout
    from server.sli.semantic import findings

    clock, calls = [100.0], []
    monkeypatch.setattr(read_timeout, "monotonic", lambda: clock[0])
    monkeypatch.setattr(read_timeout, "read_timeout_ms", lambda: 1000)
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **_: {"route": "v2"})
    def query(sql, params=()):
        read_timeout.remaining_read_ms()
        calls.append("membership" if "select findings.*" in sql else "required")
        return [{"id": 7, "evidence_count": 1}] if "select findings.*" in sql else []
    def optional_names(rows):
        calls.append("optional_names")
        clock[0] += 2
        read_timeout.remaining_read_ms()
    def evidence_page(finding_id, **kwargs):
        read_timeout.remaining_read_ms()
        calls.append("evidence_page")
        assert finding_id == 7
        return {"items": [{"evidence_id": 77, "event_db_id": 91, "event_id": 4728}],
                "has_more": False, "total": 1}
    monkeypatch.setattr(findings, "query_rows", query)
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **_: {})
    monkeypatch.setattr(findings, "_attach_postgres_finding_details", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(findings, "_attach_problem_identities", optional_names)
    monkeypatch.setattr(report, "get_problem_evidence_page", evidence_page)
    monkeypatch.setattr(route, "get_report", lambda _: report.REPORT)
    monkeypatch.setattr(route, "validate_storage_route_authorization", lambda _: None)
    monkeypatch.setattr(route, "annotate_plugin_report", lambda *_: None)
    handler = SimpleNamespace(_access_decision=_access, _send_json=Mock())
    with read_timeout.report_read_budget():
        assert route.try_handle_get(handler, "/api/v2/reports/security.problems/rows/7/detail",
                                    {"cohort": ['["finding",7]'], "tz": ["UTC"]})
    payload = handler._send_json.call_args.args[0]
    assert "error" not in payload and payload["filtered_count"] == 1
    assert payload["items"][0]["event_db_id"] == 91
    assert payload["items"][0]["evidence_id"] == 77
    assert "optional_names" not in calls and calls[-1] == "evidence_page"
