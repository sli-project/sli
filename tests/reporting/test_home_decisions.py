from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from server.api.routes import workspace
from server.sli.access import domain_scope
from server.sli.core.database import QueryTimeoutError
from server.sli.reporting import home_decisions as home
from server.sli.reporting.home_summary import home_summary
from server.sli.semantic import findings


def access(*, identity=True, domains=(7, 8)):
    return {"subject": {"type": "session", "id": 11}, "capabilities": ["workspace.view"], "reports": [
        {"report_key": "security.queue", "allowed": True, "allowed_actions": ["view"], "grants": [
            {"scope": {"kind": "domain", "ids": list(domains)}, "allowed_actions": ["view"],
             "field_categories": ["security", "identity_basic"] if identity else ["security"]},
        ]},
    ]}


@pytest.fixture(autouse=True)
def fakes(monkeypatch):
    monkeypatch.setattr(domain_scope, "_domain_rows", lambda ids: [
        {"id": value, "display_name": f"domain-{value}.example.test", "snapshot_state": "complete",
         "observed_at_utc": "2026-10-17T08:52:00Z"} for value in (7, 8) if ids is None or value in ids
    ])
    monkeypatch.setattr(home, "previous_login", lambda subject: "2026-10-16T18:05:00Z")
    rows = [
        {"rule_code": f"synthetic-{i}", "title": "Synthetic problem", "importance": i % 4,
         "total": i + 1, "new_count": 1 if i < 2 else 0, "last_seen_utc": "2026-10-17T08:41:00Z",
         "assigned_to": "synthetic-assignee", "objects": [{"name": "synthetic-object", "domain": "example.test"}],
         "object_count": 1, "total_problems": 55, "total_new": 2, "total_groups": 10} for i in range(8)
    ]
    read = Mock(return_value={"state": "available", "decision_groups": rows})
    monkeypatch.setattr(home, "get_security_problems_data", read)
    return read


def summary(decision=None, **query):
    return home_summary(access() if decision is None else decision, version="v3", query=query)


def test_v3_contract_is_one_population_with_exact_remainder_and_domain_links(fakes):
    handler = SimpleNamespace(_access_decision=access, _send_json=Mock())
    assert workspace.try_handle_get(handler, "/api/v1/home/summary", {"contract": ["v3"], "domain_id": ["7"]})
    payload = handler._send_json.call_args.args[0]
    assert payload["contract_id"] == "sli.home-summary.v3"
    assert payload["total"] == sum(group["total"] for group in payload["groups"]) + payload["remaining_problems"] == 55
    assert payload["remaining_groups"] == 2
    assert payload["new_count"] == 2
    assert len(payload["groups"]) == 8
    assert all("domain=7" in group["href"] and f"rule_code={group['key']}" in group["href"] for group in payload["groups"])
    assert payload["warnings"] == []
    kwargs = fakes.call_args.kwargs
    assert kwargs["domain_ids"] == [7]
    assert kwargs["attention_only"] and kwargs["home_groups"] and kwargs["compact"]
    assert kwargs["new_since"] == payload["previous_login_at"]
    assert "kpis" not in payload and "readers" not in payload


def test_all_domains_use_queue_grants_not_the_workspace_union(fakes):
    payload = summary(access(domains=(7,)))
    assert fakes.call_args.kwargs["domain_ids"] == [7]
    assert payload["groups"]
    with pytest.raises(PermissionError):
        summary(access(domains=(7,)), domain_id=["8"])


def test_missing_baseline_and_identity_fields_remain_unknown(monkeypatch, fakes):
    monkeypatch.setattr(home, "previous_login", lambda subject: None)
    raw = deepcopy(fakes.return_value)
    for row in raw["decision_groups"]:
        row.update(new_count=None, total_new=None)
    fakes.return_value = raw
    payload = summary(access(identity=False))
    assert payload["previous_login_at"] is None and payload["new_count"] is None
    for group in payload["groups"]:
        assert group["new_count"] is None
        assert group["assigned_to"] is None and group["objects"] == [] and group["object_count"] is None
    assert "synthetic-object" not in str(payload) and "synthetic-assignee" not in str(payload)


def test_mixed_field_grants_do_not_disclose_identity_in_all_domains(fakes):
    decision = access(domains=(7,))
    decision["reports"][0]["grants"].extend(access(identity=False, domains=(8,))["reports"][0]["grants"])
    assert summary(decision)["groups"][0]["objects"] == []
    assert summary(decision, domain_id=["7"])["groups"][0]["objects"]


def test_denied_never_reads_or_leaks_queue(fakes):
    payload = summary({"capabilities": ["workspace.view"]})
    assert payload["state"] == "denied" and payload["total"] is None and payload["groups"] == []
    fakes.assert_not_called()


def test_unknown_queue_scope_is_not_widened(fakes):
    decision = access()
    decision["reports"][0]["grants"][0]["scope"] = {"mode": "restricted", "clauses": [{"entity_ids": [11]}]}
    assert summary(decision)["state"] == "denied"
    fakes.assert_not_called()


@pytest.mark.parametrize("error", [QueryTimeoutError("test", timeout_ms=1), RuntimeError("private-source-error")])
def test_failed_reads_are_unknown_without_source_errors(fakes, error):
    fakes.side_effect = error
    payload = summary()
    assert payload["state"] == "error" and payload["total"] is None and payload["groups"] == []
    assert "private-source-error" not in str(payload)


def test_only_confirmed_empty_can_be_zero(fakes):
    fakes.return_value = {"state": "empty", "decision_groups": []}
    payload = summary()
    assert payload["state"] == "empty" and payload["total"] == payload["new_count"] == 0
    assert payload["updated_at_utc"] == "2026-10-17T08:52:00Z"
    for state in ("partial", "stale", "error"):
        fakes.return_value = {"state": state, "decision_groups": []}
        assert summary()["total"] is None


def test_missing_aggregate_response_is_unknown(fakes):
    fakes.return_value = {"state": "available"}
    assert summary()["total"] is None and summary()["state"] == "error"


def test_group_mode_keeps_publication_scope_and_suppression_gates(monkeypatch):
    calls = []
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **kwargs: {"route": "v2"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **kwargs: {})
    monkeypatch.setattr(findings, "query_rows", lambda sql, params=(): calls.append((sql, params)) or [])
    monkeypatch.setattr(findings, "_attach_postgres_finding_details", lambda *a, **kw: pytest.fail("no detail read"))
    raw = findings.get_security_problems_data(home_groups=True, attention_only=True, compact=True, domain_ids=[7])
    assert raw["decision_groups"] == []
    sql, params = calls[0]
    assert "is_semantic_finding_published_v1(findings.id)" in sql
    assert "not semantic_finding_suppressed_v160" in sql
    assert "not coalesce(risk.state='active'" in sql
    assert "in ('new','confirmed','repeated')" in sql
    assert "semantic_finding_in_domains_v265(findings.id,?::bigint[])" in sql
    assert params == ([7], None, None)
    assert len(calls) == 2  # grouped population and worker health; no rows/evidence query


def test_domain_warning_retains_counts_and_never_claims_incomplete_empty_is_zero(monkeypatch, fakes):
    monkeypatch.setattr(domain_scope, "_domain_rows", lambda ids: [
        {"id": 7, "display_name": "example.test", "snapshot_state": "partial"},
    ])
    payload = summary(domain_id=["7"])
    assert payload["total"] == 55
    assert payload["warnings"] == [{"domain": "example.test", "reason_code": "home.queue.warning.source_incomplete", "href": "/app/operations?domain=7"}]
    assert payload["updated_at_utc"] is None
    fakes.return_value = {"state": "empty", "decision_groups": []}
    assert summary(domain_id=["7"])["total"] is None


def test_observation_window_is_preserved_in_query_and_drilldown(fakes):
    payload = summary(period=["custom"], **{"from": ["2026-10-16"], "to": ["2026-10-17"], "tz": ["UTC"]})
    assert fakes.call_args.kwargs["time_from"].startswith("2026-10-16")
    assert "time_from=" in payload["groups"][0]["href"]


def test_group_query_aggregates_before_limit_without_evidence_fanout(monkeypatch):
    query = Mock(return_value=[{"rule_code": "synthetic"}])
    monkeypatch.setattr(findings, "query_rows", query)
    assert findings._home_groups("from findings_active findings", " where findings.id > ?", [7], None) == [{"rule_code": "synthetic"}]
    sql, params = query.call_args.args
    assert params == (7, None, None)
    assert "count(*) as total" in sql and "group by rule_code" in sql
    assert "sum(total) over()" in sql and "count(*) over() as total_groups" in sql
    assert sql.index("sum(total) over()") < sql.index("limit 8")
    assert "(coalesce(new_count,0)>0) desc,importance,last_seen_utc desc" in sql
    assert "created_at > ?::timestamptz" in sql and "limit 3" in sql
    assert "select string_agg(distinct d.fqdn" in sql


def test_daily_cohort_link_and_home_names_keep_identity_and_exact_field_gates(fakes):
    import json
    from urllib.parse import parse_qs, urlparse
    cohort = ["membership", "synthetic-0", 7, 11, "S-1-5-21-1-1101", "S-1-5-21-1-512", "2026-10-17"]
    row = fakes.return_value["decision_groups"][0]
    row.update(cohort=cohort, day="2026-10-17", assigned_to=None, unassigned_count=row["total"],
        objects=[{"name": "Synthetic retained name", "identifier": cohort[4], "domain": "example.test",
                  "source": {"source_run_id": "synthetic-private-run", "event_db_id": 91,
                             "observed_at_utc": "2026-08-01T00:00:00Z"}}])
    payload = summary(domain_id=["7"])
    group = payload["groups"][0]
    assert json.loads(parse_qs(urlparse(group["href"]).query)["cohort"][0]) == cohort
    assert group["assignee_state"] == "unassigned" and group["day"] == "2026-10-17"
    assert group["objects"][0]["name"] == "Synthetic retained name"
    assert group["objects"][0]["identifier"] == cohort[4]
    assert group["objects"][0]["snapshot_name"] is True
    assert "synthetic-private-run" not in str(payload) and "event_db_id" not in str(payload)
    assert fakes.call_args.kwargs["home_group_timezone"] == "UTC"
    decision = access()
    decision["reports"][0]["grants"][0]["field_categories"].append("raw_evidence")
    assert summary(decision)["groups"][0]["objects"][0]["source"]["event_db_id"] == 91
    hidden = summary(access(identity=False))
    assert "cohort=" not in hidden["groups"][0]["href"]
    assert hidden["groups"][0]["assignee_state"] == "unknown"
    assert hidden["groups"][0]["day"] is None
    assert fakes.call_args.kwargs["home_group_timezone"] is None
    assert cohort[4] not in str(hidden)


def test_group_assignee_distinguishes_some_unassigned_from_all_assigned(fakes):
    fakes.return_value["decision_groups"][0].update(unassigned_count=2)
    group = summary()["groups"][0]
    assert group["assignee_state"] == "mixed" and group["unassigned_count"] == 2


def test_mixed_grant_home_link_matches_actual_route_gate_without_authority_change(monkeypatch, fakes):
    from urllib.parse import parse_qs, urlparse
    from server.api.routes import reports_v2 as route
    from server.sli.reporting.v2.reports import security_problems as report
    decision = access(domains=(7,))
    decision["reports"][0]["grants"].extend(access(identity=False, domains=(8,))["reports"][0]["grants"])
    # Even if a stale/misbehaving read-model supplies a cohort, the home must not emit it.
    fakes.return_value["decision_groups"][0]["cohort"] = ["finding", 7]
    payload = summary(decision, domain_id=["7"])
    query = parse_qs(urlparse(payload["groups"][0]["href"]).query)
    assert "cohort" not in query and query["domain"] == ["7"]
    assert payload["total"] == 55 and payload["remaining_groups"] == 2
    assert fakes.call_args.kwargs["home_group_timezone"] is None
    calls = []
    monkeypatch.setattr(route, "get_report", lambda _: report.REPORT)
    monkeypatch.setattr(route, "annotate_plugin_report", lambda *_: None)
    monkeypatch.setattr(route, "report_plugin_state", lambda *_: None)
    monkeypatch.setattr(route, "validate_storage_route_authorization", lambda _: None)
    monkeypatch.setattr(report, "password_coverage_catalog_domains", lambda: [])
    monkeypatch.setattr(report, "get_security_problems_data", lambda **kwargs: calls.append(kwargs) or {"state": "empty", "items": []})
    handler = SimpleNamespace(_access_decision=lambda: decision, _send_json=Mock())
    assert route.try_handle_get(handler, "/api/v2/reports/security.problems", {})
    declaration = handler._send_json.call_args.args[0]
    assert "cohort" not in {param["key"] for param in declaration["params"]}
    assert route.try_handle_get(handler, "/api/v2/reports/security.problems/data", query)
    assert "error" not in handler._send_json.call_args.args[0]
    assert calls[0]["domain_ids"] == [7] and "cohort" not in calls[0]
    before = len(calls)
    for forbidden in (7, 8, 9):
        bad = {**query, "domain": [str(forbidden)], "cohort": ['["finding",7]']}
        for path in ("/api/v2/reports/security.problems/data", "/api/v2/reports/security.problems/rows/7/detail"):
            route.try_handle_get(handler, path, bad)
            assert handler._send_json.call_args.args[1] == 403
    assert len(calls) == before



def test_real_home_identity_path_retains_names_states_links_and_field_gates(monkeypatch, fakes):
    import json
    from urllib.parse import parse_qs, urlparse
    sid, group_sid = 'S-1-5-21-1-1101', 'S-1-5-21-1-512'
    cohort = ['membership', 'synthetic-0', 7, 11, sid, group_sid, '2026-10-17']
    group = {**fakes.return_value['decision_groups'][0], 'cohort': cohort,
             'object_names': [sid, group_sid], 'domain_name': 'example.test',
             'representative': {'id': 7, 'evidence_count': 1, 'target': sid}}
    witness = {'finding_id': 7, 'event_db_id': 91, 'event_id': 4728, 'hostname': 'synthetic-dc',
        'channel': 'Security', 'identity_provider': 'Microsoft-Windows-Security-Auditing',
        'time_created_utc': '2026-10-17T08:00:00+00:00', 'domain_id': 7,
        'subject_user_sid': sid, 'subject_user_name': '-', 'target_user_sid': group_sid,
        'membership_member_sid': sid, 'identity_domain_min': 7, 'identity_domain_max': 7, 'identity_event_count': 1}
    def query(sql, params=(), **_):
        if 'with population' in sql:
            return [deepcopy(group)]
        if 'from finding_evidence fe' in sql:
            return [deepcopy(witness)]
        if 'problem_identity_snapshot_labels' in sql:
            return [{'request_index': 0, 'label': 'Retained synthetic name', 'source_run_id': 'synthetic-private-run',
                     'entity_id': 14, 'observed_at_utc': '2026-08-01T00:00:00+00:00'}]
        return []
    monkeypatch.setattr(home, 'get_security_problems_data', findings.get_security_problems_data)
    monkeypatch.setattr(findings, 'is_postgres_runtime_db', lambda: True)
    monkeypatch.setattr(findings, 'resolve_storage_route', lambda **_: {'route': 'v2'})
    monkeypatch.setattr(findings, 'get_findings_refresh_status', lambda **_: {})
    monkeypatch.setattr(findings, 'query_rows', query)
    monkeypatch.setattr(findings, 'query_rows_bounded', query)
    payload = summary(domain_id=['7'])
    result = payload['groups'][0]
    assert result['objects'][0]['name'] == 'Retained synthetic name'
    assert result['objects'][0]['name_state'] == 'named'
    assert result['objects'][0]['snapshot_name'] is True
    assert result['objects'][1]['name'] == '' and result['objects'][1]['name_state'] == 'no_match'
    assert [obj['identifier'] for obj in result['objects']] == [sid, group_sid]
    assert json.loads(parse_qs(urlparse(result['href']).query)['cohort'][0]) == cohort
    assert result['total'] == group['total']
    assert 'synthetic-private-run' not in str(payload)
    exact = access()
    exact['reports'][0]['grants'][0]['field_categories'].append('raw_evidence')
    assert summary(exact, domain_id=['7'])['groups'][0]['objects'][0]['source']['event_db_id'] == 91
    hidden = summary(access(identity=False), domain_id=['7'])
    assert hidden['groups'][0]['objects'] == []
    assert sid not in str(hidden) and 'Retained synthetic name' not in str(hidden)
