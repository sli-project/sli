"""Synthetic rule-quality metrics, read boundary and v2 contract; no database."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from unittest.mock import MagicMock

import pytest

from server.api.routes import reports_v2
from server.sli.access.scope import AccessScope, ScopeClause
from server.sli.reporting.v2 import registry
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.definition import QueryContext, parse_params
from server.sli.reporting.v2.reports import rule_quality as report, security_problems
from server.sli.reports import rule_quality as engine
from server.sli.semantic import findings

START = datetime(2026, 10, 1, tzinfo=timezone.utc)
END = START + timedelta(days=7)


def finding(rule="semantic.synthetic", history=(), **extra):
    return {"id": 1, "rule_code": rule, "created_at": START, "repeat_count": 0,
            "history": list(history), "complete_evidence": True, "suppressed": False, **extra}


def change(number, status, hours, old="new"):
    return {"id": number, "new_status": status, "old_status": old, "changed_at": START + timedelta(hours=hours)}


def access(*, capabilities=("semantic.review",), scope=None, fields=("security",), allowed=True):
    return {"capabilities": list(capabilities), "reports": [{"report_key": "security.queue", "allowed": allowed,
        "allowed_actions": ["view"], "grants": [{"scope": scope or {"kind": "all"},
            "allowed_actions": ["view"], "field_categories": list(fields)}]}]}


def context(**overrides):
    values = {"access": access(), "params": {"period": {"preset": "custom", "from_utc": START.isoformat(), "to_utc": END.isoformat()}},
              "scope": AccessScope("all"), "runtime": {"storage_route_authorization": "sealed"}}
    values.update(overrides)
    return QueryContext(**values)


def test_lifecycle_one_vote_latest_classification_closure_reopen_and_median():
    source = [
        finding(history=[change(1, "false_positive", 2), change(2, "false_positive", 3, "false_positive"), change(3, "closed", 4, "false_positive")], suppressed=True),
        finding(history=[change(1, "confirmed", 6), change(2, "false_positive", 10, "confirmed")], repeat_count=2),
        finding(history=[change(1, "false_positive", 8), change(2, "active", 9, "false_positive"), change(3, "confirmed", 12, "active")]),
        finding(history=[change(1, "accepted_risk", 10)]),
        finding(history=[change(1, "new", 0, None)], complete_evidence=False),
    ]
    original = deepcopy(source)
    row = engine.compute_metrics(source, end=END, accepted_risk=True)[0]
    assert row["findings_produced"] == 5
    assert (row["false_positive"], row["confirmed"], row["closed"], row["accepted_risk"], row["suppressed"]) == (2, 1, 1, 1, 1)
    assert row["false_positive_rate"] == 66.67 and row["classified"] == 3
    assert row["median_decision_seconds"] == 7 * 3600 and row["decided"] == 4
    assert row["repeat_rate"] == 20 and row["complete_evidence_share"] == 80
    assert source == original


def test_window_is_exclusive_and_no_decisions_is_unknown_not_zero():
    rows = engine.compute_metrics([
        finding(history=[change(1, "new", 0, None), change(2, "false_positive", 7 * 24)]),
        finding("semantic.other", history=[change(1, "closed", 4)]),
    ], end=END, accepted_risk=False)
    for row in rows:
        assert row["false_positive_rate"] is None
        assert row["accepted_risk"] is None
    assert rows[1]["median_decision_seconds"] is None
    assert rows[0]["median_decision_seconds"] == 4 * 3600


def test_missing_history_ties_and_repeated_transition():
    row = engine.compute_metrics([
        finding(history=[change(2, "false_positive", 1, "confirmed"), change(1, "confirmed", 1), change(3, "repeated", 2, "false_positive")]),
        finding(history=[]),
    ], end=END, accepted_risk=False)[0]
    assert row["false_positive"] == 1 and row["confirmed"] == 0
    assert row["missing_history"] == 1 and row["repeat_rate"] == 50


def test_reader_is_read_only_scopes_before_limit_and_keeps_suppressed(monkeypatch):
    cursor = MagicMock()
    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.cursor.return_value.__enter__.return_value = cursor
    cursor.fetchall.side_effect = [[finding(history=[change(1, "new", 0, None)], suppressed=True)],
        [{"policy_id": "synthetic-policy", "policy_version": 1, "rule_code": "semantic.synthetic", "enabled": False, "managed": True}]]
    monkeypatch.setattr(engine, "connect", lambda: conn)
    calls = []
    monkeypatch.setattr(engine, "resolve_storage_route", lambda **kwargs: calls.append(kwargs))
    body = engine.load_quality(START, END, domain_ids=[7], authorization="sealed")
    assert calls[0]["authorization"] == "sealed"
    assert cursor.execute.call_args_list[0].args == ("set transaction read only",)
    sql, params = cursor.execute.call_args_list[1].args
    assert "from findings_active" in sql and "is_semantic_finding_published_v1" in sql
    assert "not exists" in sql and "e.domain_id is null" in sql
    assert sql.index("e.domain_id=any") < sql.index("limit %s")
    assert params == (START, END, [7], engine.MAX_FINDINGS + 1, END)
    assert "changed_by" not in sql and "actor" not in sql
    assert body["items"][0]["suppressed"] == 1
    assert body["items"][0]["managed_policies"] == ["synthetic-policy:1"]
    assert body["items"][0]["admitted_policies"] == []


def test_reader_marks_truncation(monkeypatch):
    monkeypatch.setattr(engine, "MAX_FINDINGS", 1)
    conn = MagicMock()
    conn.__enter__.return_value = conn
    cur = conn.cursor.return_value.__enter__.return_value
    cur.fetchall.side_effect = [[finding(), finding()], []]
    monkeypatch.setattr(engine, "connect", lambda: conn)
    monkeypatch.setattr(engine, "resolve_storage_route", lambda **kwargs: {})
    body = engine.load_quality(START, END, domain_ids=None)
    assert body["truncated"] and body["items"][0]["findings_produced"] == 1


@pytest.mark.parametrize("decision", [access(capabilities=()), access(allowed=False), access(fields=()), access(scope={"kind": "domain", "ids": []})])
def test_access_denied(decision):
    with pytest.raises(PermissionError):
        ReportAccess(report.REPORT, decision)


def test_owner_and_analyst_grants_and_unsupported_scope_fail_closed(monkeypatch):
    assert ReportAccess(report.REPORT, access()).scope.mode == "all"
    assert ReportAccess(report.REPORT, access(scope={"kind": "domain", "ids": [7]})).scope.domain_ids() == [7]
    load = MagicMock()
    monkeypatch.setattr(engine, "load_quality", load)
    with pytest.raises(PermissionError):
        report.REPORT.query(context(scope=AccessScope("restricted", (ScopeClause(entity_ids=(7,)),))))
    load.assert_not_called()
    monkeypatch.setattr(registry, "registered_reports", lambda: (report.REPORT,))
    assert registry.catalog(access(capabilities=()))["items"] == []
    assert registry.catalog(access())["items"][0]["executable"]


def test_report_contract_sort_cursor_and_findings_cohort_link(monkeypatch):
    rows = engine.compute_metrics([
        finding("semantic.low", history=[change(1, "confirmed", 2)]),
        finding("semantic.high", history=[change(1, "false_positive", 3)]),
        finding("semantic.unknown", history=[change(1, "new", 0, None)]),
    ], end=END, accepted_risk=False)
    monkeypatch.setattr(engine, "load_quality", lambda *args, **kwargs: {"items": rows, "truncated": False, "accepted_risk_supported": False})
    body = report.REPORT.query(context(limit=1))
    assert body["contract_id"] == "sli.report-result.v2" and body["state"] == "partial"
    assert body["items"][0]["rule_code"] == "semantic.high" and body["has_more"]
    second = report.REPORT.query(context(limit=1, cursor=body["next_cursor"]))
    assert second["items"][0]["rule_code"] == "semantic.low"
    assert "accepted_risk_unavailable" in {item["code"] for item in body["limitations"]}
    link = report.REPORT.columns[0].link
    assert "rule_code={rule_code}" in link and "created_from={cohort_from}" in link and "show_suppressed=true" in link
    params, _ = parse_params(security_problems.REPORT, {"rule_code": ["semantic.high"], "created_from": [START.isoformat()], "created_to": [END.isoformat()]})
    assert params["rule_code"] == "semantic.high"
    with pytest.raises(ValueError):
        report.REPORT.query(context(limit=1, cursor=body["next_cursor"], sort="false_positive_rate", direction="asc"))


@pytest.mark.parametrize("truncated,missing,state", [(False, 0, "partial"), (True, 0, "partial"), (False, 1, "partial")])
def test_honest_partial_states(monkeypatch, truncated, missing, state):
    monkeypatch.setattr(engine, "load_quality", lambda *args, **kwargs: {"items": [{"rule_code": "semantic.synthetic", "missing_history": missing, "false_positive_rate": None}], "truncated": truncated, "accepted_risk_supported": True})
    assert report.REPORT.query(context())["state"] == state


def test_unproven_empty_cohort_and_source_error_are_distinct(monkeypatch):
    monkeypatch.setattr(engine, "load_quality", lambda *args, **kwargs: {"items": [], "truncated": False, "accepted_risk_supported": False})
    empty = report.REPORT.query(context())
    assert empty["state"] == "partial" and empty["items"] == []
    assert empty["coverage"]["completeness"] == "not_proven"
    monkeypatch.setattr(engine, "load_quality", MagicMock(side_effect=RuntimeError("synthetic-error")))
    body = report.REPORT.query(context())
    assert body["state"] == "error" and body["filtered_count"] is None
    assert body["state_details"]["reason"] == "source_or_storage_error"
    assert body["limitations"][0]["code"] == "unavailable"
    assert "synthetic-error" not in str(body)


def test_api_declaration_denies_operator_and_accepts_analyst(monkeypatch):
    monkeypatch.setattr(reports_v2, "get_report", lambda key: report.REPORT)
    monkeypatch.setattr(reports_v2, "report_plugin_state", lambda key: None)
    for decision, expected in [(access(capabilities=()), HTTPStatus.FORBIDDEN), (access(), HTTPStatus.OK)]:
        handler = MagicMock()
        handler._access_decision.return_value = decision
        assert reports_v2.try_handle_get(handler, "/api/v2/reports/security.rule-quality", {})
        if expected == HTTPStatus.FORBIDDEN:
            assert handler._send_json.call_args.args[1] == expected
        else:
            assert handler._send_json.call_args.args[0]["key"] == report.REPORT.key


def test_api_pagination_pins_rolling_window_and_rechecks_access(monkeypatch):
    monkeypatch.setattr(reports_v2, "get_report", lambda key: report.REPORT)
    monkeypatch.setattr(reports_v2, "report_plugin_state", lambda key: None)
    monkeypatch.setattr(reports_v2, "validate_storage_route_authorization", lambda value: "sealed")
    clocks = iter([END, END + timedelta(minutes=1)])
    monkeypatch.setattr(reports_v2, "parse_params", lambda definition, query: parse_params(definition, query, now=next(clocks)))
    windows = []
    rows = [{"rule_code": f"semantic.synthetic-{number}", "missing_history": 0, "false_positive_rate": number} for number in (0, 100)]

    def load(start, end, **kwargs):
        windows.append((start, end))
        return {"items": rows, "truncated": False, "accepted_risk_supported": False}

    monkeypatch.setattr(engine, "load_quality", load)
    handler = MagicMock()
    handler._access_decision.return_value = access()
    path = "/api/v2/reports/security.rule-quality/data"
    assert reports_v2.try_handle_get(handler, path, {"period": ["7d"], "limit": ["1"]})
    first = handler._send_json.call_args.args[0]
    assert first["items"][0]["rule_code"] == "semantic.synthetic-100"
    assert reports_v2.try_handle_get(handler, path, {"period": ["7d"], "limit": ["1"], "cursor": [first["next_cursor"]]})
    second = handler._send_json.call_args.args[0]
    assert second["items"][0]["rule_code"] == "semantic.synthetic-0"
    assert windows == [(START, END), (START, END)]
    handler._access_decision.return_value = access(capabilities=())
    assert reports_v2.try_handle_get(handler, path, {"period": ["7d"], "cursor": [first["next_cursor"]]})
    assert handler._send_json.call_args.args[1] == HTTPStatus.FORBIDDEN
    assert len(windows) == 2


def test_queue_filters_exact_rule_and_creation_window_in_both_queries(monkeypatch):
    queries = []
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **kwargs: {"route": "v2"})
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "query_rows", lambda sql, params=(): queries.append((sql, params)) or [])
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **kwargs: {})
    findings.get_security_problems_data(rule_code="semantic.synthetic", created_from=START.isoformat(), created_to=END.isoformat(), show_suppressed=True)
    for sql, params in queries[:2]:
        assert "findings.rule_code = ?" in sql and "findings.created_at >=" in sql and "findings.created_at <" in sql
        assert params[:3] == ("semantic.synthetic", START.isoformat(), END.isoformat())
        assert "not semantic_finding_suppressed" not in sql
    with pytest.raises(ValueError):
        findings.get_security_problems_data(created_from="2026-10-01T00:00:00")



@pytest.mark.parametrize('rule_code,ru,en', [
    ('semantic.qw.file-ransom', 'Признаки шифровальщика: массовые изменения файлов', 'Ransomware indicators: mass file changes'),
    ('semantic.security.audit_controls_changed', 'Изменения контроля аудита', 'Audit control changes'),
    ('semantic.security.privileged_group_member_added', 'Добавление участника в привилегированную группу', 'Member added to a privileged group'),
    ('semantic.security.scheduled_task_created', 'Создание задачи планировщика', 'Scheduled task creation'),
])
def test_rule_names_and_inline_technical_details_preserve_metrics_and_identity(monkeypatch, rule_code, ru, en):
    from server.sli.core.messages import localize_presentation

    rows = engine.compute_metrics([
        finding(rule_code, history=[change(1, 'confirmed', 2)]),
        finding('semantic.synthetic-one'), finding('semantic.synthetic-two'),
    ], end=END, accepted_risk=False)
    for row in rows:
        row.update(policies=['synthetic-policy:7'], admitted_policies=[], managed_policies=['synthetic-policy:7'])
    original = deepcopy(rows)
    monkeypatch.setattr(engine, 'load_quality', lambda *args, **kwargs: {'items': rows, 'truncated': False, 'accepted_risk_supported': False})
    body = report.REPORT.query(context())
    by_code = {row['rule_code']: row for row in body['items']}
    known = by_code[rule_code]
    assert known['rule_name'] == ru
    assert localize_presentation(known, 'en')['rule_name'] == en
    assert known['technical_details'] == [{'rule_code': rule_code, 'policies': ['synthetic-policy:7'], 'admitted_policies': [], 'managed_policies': ['synthetic-policy:7'], **{key: known[key] for key in ('closed', 'accepted_risk', 'suppressed', 'classified', 'median_decision_seconds', 'decided', 'repeat_rate')}}]
    for code in ('semantic.synthetic-one', 'semantic.synthetic-two'):
        row = by_code[code]
        assert row['rule_name'] == 'Название правила недоступно'
        assert localize_presentation(row, 'en')['rule_name'] == 'Rule name unavailable'
        assert row['false_positive_rate'] is None
        assert row['technical_details'] == [{'rule_code': code, 'policies': ['synthetic-policy:7'], 'admitted_policies': [], 'managed_policies': ['synthetic-policy:7'], **{key: row[key] for key in ('closed', 'accepted_risk', 'suppressed', 'classified', 'median_decision_seconds', 'decided', 'repeat_rate')}}]
    for source in original:
        row = by_code[source['rule_code']]
        assert all(row[key] == value for key, value in source.items())
        assert row['cohort_from'] == START.isoformat() and row['cohort_to'] == END.isoformat()
    assert rows == original
    assert report.REPORT.row_key == 'rule_code'
    assert report.REPORT.columns[0].key == 'rule_name'
    assert not {'rule_code', 'policies', 'admitted_policies', 'managed_policies'} & {c.key for c in report.REPORT.columns}
    assert report.REPORT.detail.inline == 'technical_details'
    assert report.REPORT.detail.query is None
    assert {c.key for c in report.REPORT.detail.columns} == {'rule_code', 'policies', 'admitted_policies', 'managed_policies', 'closed', 'accepted_risk', 'suppressed', 'classified', 'median_decision_seconds', 'decided', 'repeat_rate'}
    assert 'rule_code={rule_code}&created_from={cohort_from}&created_to={cohort_to}&show_suppressed=true' in report.REPORT.columns[0].link


@pytest.mark.parametrize('kind,label', [
    ('security_incident', 'Name unavailable · incident detection'),
    ('security_exposure', 'Name unavailable · security exposure'),
    ('control_gap', 'Name unavailable · control gap'),
])
def test_rule_metadata_fallback_is_localized_without_inventing_a_title(kind, label):
    from server.sli.core.messages import localize_presentation
    row = report._presentation({'rule_code': 'semantic.synthetic', 'rule_result_class': kind})
    assert localize_presentation(row, 'en')['rule_name'] == label
    assert row['technical_details'][0]['rule_code'] == 'semantic.synthetic'


def test_rule_metadata_uses_only_unambiguous_allowlisted_policy_class(monkeypatch):
    conn = MagicMock()
    conn.__enter__.return_value = conn
    cur = conn.cursor.return_value.__enter__.return_value
    policies = [dict(policy_id=str(i), policy_version=1, rule_code=code, result_class=kind,
                     enabled=False, managed=False, title='must not escape')
                for i, (code, kind) in enumerate([
                    ('semantic.single', 'security_incident'), ('semantic.single', 'security_incident'),
                    ('semantic.conflict', 'control_gap'), ('semantic.conflict', 'security_incident'),
                    ('semantic.invalid', 'private value'),
                ])]
    cur.fetchall.side_effect = [[finding(code) for code in ('semantic.single', 'semantic.conflict', 'semantic.invalid')], policies]
    monkeypatch.setattr(engine, 'connect', lambda: conn)
    monkeypatch.setattr(engine, 'resolve_storage_route', lambda **kwargs: {})
    rows = {row['rule_code']: row for row in engine.load_quality(START, END, domain_ids=[7])['items']}
    assert rows['semantic.single']['rule_result_class'] == 'security_incident'
    assert rows['semantic.conflict']['rule_result_class'] is None
    assert rows['semantic.invalid']['rule_result_class'] is None
    assert 'must not escape' not in str(rows)
    assert "definition_json->>'result_class'" in cur.execute.call_args_list[-1].args[0]
