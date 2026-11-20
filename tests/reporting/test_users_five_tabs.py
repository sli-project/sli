"""U04: independent slices, exact privilege basis and truthful access/states."""
from copy import deepcopy
import csv
import io
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor

import pytest

from server.sli.entities import users_v2_directory_projection as projection
from server.sli.reporting.v2.definition import QueryContext, parse_params
from server.sli.reporting.v2.reports import users
from server.sli.reports import users_tabs
from tests.reporting.test_reporting_v2_field_access import access, call, grant


def account(entity_id, enabled=True, **fields):
    return {"id": f"user:{entity_id}", "entityId": entity_id, "displayName": f"Synthetic account {entity_id}",
            "samAccountName": f"fixture-{entity_id}", "enabled": enabled,
            "privilegedMemberships": [], "memberships": {"status": "observed", "direct": [], "effective": []},
            "sourceStates": {"directory": {"status": "observed"}}, **fields}


def decision():
    fields = {"identity_basic", "security", "privilege", "technical", "hr", "contact"}
    result = access(grant(fields), key=users.REPORT_KEY)
    result["reports"] += access(grant(fields), key="security.queue")["reports"]
    return result


def context(tab=None, **params):
    return QueryContext(access=decision(), params=params, domain_ids=[1], tab=tab)


@pytest.fixture
def snapshot(monkeypatch):
    monkeypatch.setattr(users.ad_service_exceptions, "configured", lambda: {})
    current = {"metadata": {"observed_at": "2026-10-07T00:00:00Z", "collection_status": "partial",
                            "coverage": {"state": "complete", "privilege_state": "complete"}},
               "users": [account(1), account(2, False), account(3, None)], "groups": []}
    monkeypatch.setattr(users, "_snapshots", lambda *_args, **_kwargs: {"state": "ok", "current": current})
    monkeypatch.setattr(users.ad_hygiene_policy, "get_setting", lambda key: {"ad.password_max_age_days": "90", "ad.inactivity_days": "60"}[key])
    monkeypatch.setattr(users_tabs, "_semantic", lambda ids: ({1: 2}, "active"))
    monkeypatch.setattr(users.users_activity, "load", lambda *_args, **_kwargs: pytest.fail("inventory tab read activity"))
    return current


def test_contract_exposes_owner_tabs_with_legacy_slices_internal_only():
    assert [view.key for view in users.REPORT.views] == ["checks", "privileged", "changes", "all"]
    params, paging = parse_params(users.REPORT, {})
    assert paging["tab"] is None
    assert "view" not in params and "threshold" not in params
    keys = [column.key for column in users.REPORT.columns]
    assert len(keys) == len(set(keys))


def test_default_users_reads_all_granted_domains_without_picking_the_oldest(snapshot, monkeypatch):
    fields = {"identity_basic", "security", "privilege", "technical", "hr", "contact"}
    seen = []
    monkeypatch.setattr(users, "_snapshots", lambda domain_ids, **kwargs: seen.append(domain_ids) or {"state": "ok", "current": snapshot})
    handler = call(monkeypatch, users.REPORT, access(grant(fields, ids=(7, 8)), key=users.REPORT_KEY), "/data", {"tab": ["all"]})
    assert handler.sent[-1][1] == 200
    assert seen == [[7, 8]]
    assert {param.key for param in users.REPORT.params if param.kind == "domain"} == {"domain_id", "domain"}


@pytest.mark.parametrize("tab,expected", [("all", [1, 2, 3]), ("active", [1]), ("disabled", [2]), ("privileged", []), ("risk", []), ("semantic", [1])])
def test_each_tab_queries_its_own_population(snapshot, tab, expected):
    result = users._query(context(tab))
    assert [row["entity_id"] for row in result["items"]] == expected
    assert result["filtered_count"] == len(expected)
    assert result["coverage"]["tab"] == (tab or "active")
    assert result["state"] == ("partial" if tab in {None, "active", "disabled", "risk"} else "ok" if expected else "empty")


def test_privileged_uses_direct_and_nested_evidence_and_keeps_disabled_separate(snapshot):
    direct = [{"group_id": 10, "group": "Synthetic privileged group", "relation": "direct", "basis": "privileged_membership"}]
    snapshot["users"] = [account(1, privilegedMemberships=direct, memberships={"effective": [{"watchGroup": True, "relation": "nested", "name": "Synthetic nested group"}]}), account(2, False, privilegedMemberships=direct),
                         account(3, adminCount=1, memberships={"effective": [{"watchGroup": True, "relation": "nested", "name": "Synthetic nested group"}]})]
    original = deepcopy(snapshot)
    result = users._query(context("privileged"))
    assert [row["entity_id"] for row in result["items"]] == [1, 2, 3]
    assert result["items"][0]["privilege_basis"] == ["Synthetic privileged group"]
    assert result["items"][0]["nested_privilege_groups"] == ["Synthetic nested group"]
    assert result["coverage"]["disabled_privileged"] == 1
    assert result["state"] == "ok"
    assert snapshot == original
    filtered = users._query(context("privileged", group="group:10", relation="effective"))
    assert [row["entity_id"] for row in filtered["items"]] == [1, 2]
    assert {"value": "group:10", "label": "Synthetic privileged group"} in filtered["filter_options"]["group"]


def test_risk_uses_policy_settings_strict_boundaries_and_unknown_facts(snapshot, monkeypatch):
    monkeypatch.setattr(users.ad_hygiene_policy, "get_setting", lambda key: "10")
    snapshot["users"] = [account(1, passwordLastSet="2026-09-26T00:00:00Z", lastLogonTimestamp="2026-10-07T00:00:00Z"),
                         account(2, False, passwordLastSet="2026-09-27T00:00:00Z", lastLogonTimestamp="2026-09-27T00:00:00Z"),
                         account(3, passwordLastSet="invalid", lastLogonTimestamp="2026-10-08T00:00:00Z")]
    result = users._query(context("risk", threshold="1"))
    assert [row["entity_id"] for row in result["items"]] == [1]
    assert result["items"][0]["password_age_policy"] == "exceeded"
    assert result["items"][0]["inactivity_policy"] == "within_policy"
    assert result["coverage"]["unknown_accounts"] == 1
    assert result["coverage"]["hygiene_policy"] == {"password_age": 10, "inactivity": 10}


def test_risk_reuses_the_prepared_policy(snapshot, monkeypatch):
    calls = []
    def setting(key):
        calls.append(key)
        return "120" if key == "ad.password_max_age_days" else "30"
    monkeypatch.setattr(users.ad_hygiene_policy, "get_setting", setting)
    result = users._query(context("risk"))
    assert result["coverage"]["hygiene_policy"] == {"password_age": 120, "inactivity": 30}
    assert calls == ["ad.password_max_age_days", "ad.inactivity_days"]


def test_zero_risks_exposes_unassessed_accounts_in_contract(snapshot, monkeypatch):
    snapshot["users"] = [account(1), account(2, False)]
    response = users._query(context("risk"))
    assert response["state"] == "partial"
    assert response["items"] == []
    assert response["coverage"]["risk_accounts"] == response["filtered_count"] == 0
    assert response["coverage"]["unknown_accounts"] == 2
    assert next(metric["value"] for metric in response["metrics"] if metric["key"] == "unknown") == 2


def test_unassessed_risk_count_uses_the_same_search_scope_as_risk_rows(snapshot):
    snapshot["users"] = [account(1), account(2)]
    response = users._query(context("risk", q="fixture-1"))
    assert response["filtered_count"] == response["coverage"]["risk_accounts"] == 0
    assert response["coverage"]["unknown_accounts"] == 1


def test_privileged_includes_nested_and_primary_standard_group_members(snapshot):
    snapshot["users"] = [account(1, memberships={"effective": [
        {"id": "group:10", "name": "Synthetic admin group", "watchGroup": True, "relation": "nested"}]}),
        account(2, False, memberships={"effective": [
            {"id": "group:10", "name": "Synthetic admin group", "watchGroup": True, "relation": "primary"}]})]
    response = users._query(context("privileged"))
    assert [row["entity_id"] for row in response["items"]] == [1, 2]
    assert response["items"][0]["nested_privilege_groups"] == ["Synthetic admin group"]
    assert response["coverage"]["disabled_privileged"] == 1
    assert users._query(context("privileged", group="group:10"))["filtered_count"] == 2


@pytest.mark.parametrize("enabled,password_last_set,expected_reasons", [
    (True, "2026-10-06T00:00:00Z", ["inactive_threshold"]),
    (False, "2026-10-06T00:00:00Z", []),
    (None, "2026-10-06T00:00:00Z", []),
    (True, "2026-01-01T00:00:00Z", ["password_age", "inactive_threshold"]),
    (False, "2026-01-01T00:00:00Z", ["password_age"]),
    (None, "2026-01-01T00:00:00Z", ["password_age"]),
])
def test_risk_requires_a_confirmed_policy_reason(snapshot, enabled, password_last_set, expected_reasons):
    snapshot["users"] = [account(1, enabled, userPrincipalName="synthetic-1",
                                 passwordLastSet=password_last_set, lastLogonTimestamp="2026-01-01T00:00:00Z")]
    result = users._query(context("risk"))
    count = 1 if expected_reasons else 0
    assert result["filtered_count"] == count
    assert len(result["items"]) == count
    assert next(metric["value"] for metric in result["metrics"] if metric["key"] == "attention") == count
    assert {option["value"] for option in result["filter_options"]["reason"]} == set(expected_reasons)
    if expected_reasons:
        row = result["items"][0]
        assert row["reason_keys"] == expected_reasons
        assert [reason["key"] for reason in row["reasons"]] == expected_reasons
        assert row["reason_text"]
        assert {item["key"] for item in row["review_details"] if item["category"] == "confirmed"} == set(expected_reasons)


def test_risk_reasons_and_counts_agree_across_filters_paging_and_export(snapshot):
    snapshot["users"] = [
        account(1, False, userPrincipalName="synthetic-1", passwordLastSet="2026-10-06T00:00:00Z",
                lastLogonTimestamp="2026-01-01T00:00:00Z", lockedOut=True),
        account(2, userPrincipalName="synthetic-2", passwordLastSet="2026-10-06T00:00:00Z",
                lastLogonTimestamp="2026-01-01T00:00:00Z"),
        account(3, False, userPrincipalName="synthetic-3", passwordLastSet="2026-01-01T00:00:00Z",
                lastLogonTimestamp="2026-01-01T00:00:00Z"),
        account(4, None, userPrincipalName="synthetic-4", passwordLastSet="2026-10-06T00:00:00Z",
                lastLogonTimestamp="2026-01-01T00:00:00Z"),
        account(5, userPrincipalName="synthetic-5"),
    ]
    first = users._query(replace(context("risk"), limit=1))
    second = users._query(replace(context("risk"), limit=1, cursor=first["next_cursor"]))
    assert first["items"][0]["entity_id"] == 2 and first["has_more"]
    assert second["items"][0]["entity_id"] == 3 and not second["has_more"]
    for page in (first, second):
        assert page["filtered_count"] == 2
        assert {metric["key"]: metric["value"] for metric in page["metrics"]} == {"attention": 2, "information": 0, "unknown": 1}
    for reason, entity_id in (("inactive_threshold", 2), ("password_age", 3)):
        filtered = users._query(context("risk", reason=reason))
        assert [row["entity_id"] for row in filtered["items"]] == [entity_id]
        assert filtered["filtered_count"] == 1
        assert next(metric["value"] for metric in filtered["metrics"] if metric["key"] == "attention") == 1
    body, metadata = users._export(context("risk"))
    exported = list(csv.DictReader(io.StringIO(body)))
    assert metadata["rows"] == len(exported) == 2
    assert all(row["Требует внимания"] for row in exported)
    assert "fixture-1" not in body and "fixture-4" not in body


def test_review_reasons_and_information_are_separate_in_rows_filters_kpis_and_csv(snapshot):
    snapshot["users"] = [
        account(1, userPrincipalName="synthetic-1"),
        account(2, userPrincipalName="synthetic-2", lockedOut=True, passwordLastSet="2026-01-01T00:00:00Z"),
        account(3, userPrincipalName="synthetic-3", passwordLastSet="2026-10-06T00:00:00Z", lastLogonTimestamp="2026-10-06T00:00:00Z"),
    ]
    result = users._query(context("active"))
    rows = {row["entity_id"]: row for row in result["items"]}
    assert rows[1]["reason_text"] is None and rows[1]["reasons"] == []
    assert rows[1]["information_keys"] == ["password_age_unknown", "enabled_activity_unknown"]
    assert rows[1]["password_age_policy"] == rows[1]["inactivity_policy"] == "unknown"
    assert rows[2]["reason_keys"] == ["locked_out", "password_age"]
    assert rows[2]["information_keys"] == ["enabled_activity_unknown"]
    assert {item["category"] for item in rows[2]["review_details"]} == {"confirmed", "information"}
    assert rows[3]["reason_text"] is None and rows[3]["information_text"] is None
    assert {metric["key"]: metric["value"] for metric in result["metrics"]} == {"attention": 1, "information": 2}
    assert {option["value"] for option in result["filter_options"]["reason"]} == {"locked_out", "password_age"}
    assert [row["entity_id"] for row in users._query(context("active", information="password_age_unknown"))["items"]] == [1]
    assert users._query(context("active", reason="password_age_unknown"))["items"] == []
    assert [row["entity_id"] for row in users._query(context("active", reason="locked_out"))["items"]] == [2]
    text, meta = users._export(context("active"))
    exported = list(csv.DictReader(io.StringIO(text)))
    assert meta["rows"] == 3
    assert exported[0]["Требует внимания"] == ""
    assert "неизвестно" in exported[0]["Ограничения сведений"]
    assert "неизвестно" not in exported[1]["Требует внимания"]
    risk = users._query(context("risk"))
    assert [row["entity_id"] for row in risk["items"]] == [2]
    assert next(metric["value"] for metric in risk["metrics"] if metric["key"] == "unknown") == 2


@pytest.mark.parametrize("tab", users_tabs.TABS)
@pytest.mark.parametrize("source_state,expected", [("complete", "empty"), ("partial", "partial"), ("stale", "stale"),
                                                  ("failed", "error"), ("not_collected", "not_collected"), ("processing", "processing")])
def test_empty_does_not_hide_partial_stale_or_failed_sources(snapshot, tab, source_state, expected, monkeypatch):
    snapshot["users"] = []
    snapshot["metadata"]["coverage"]["state"] = source_state
    monkeypatch.setattr(users_tabs, "_semantic", lambda ids: ({}, "active"))
    assert users._query(context(tab))["state"] == expected


@pytest.mark.parametrize("tab", users_tabs.TABS)
@pytest.mark.parametrize("raw,expected", [("not_collected", "not_collected"), ("unavailable", "error"),
                                         ("processing", "processing"), ("denied", "denied")])
def test_missing_snapshots_preserve_the_state_contract(monkeypatch, tab, raw, expected):
    monkeypatch.setattr(users, "_snapshots", lambda *_args, **_kwargs: {"state": raw, "current": None})
    result = users._query(context(tab))
    assert result["state"] == expected
    assert result["items"] == [] and result["filtered_count"] is None


def test_tabs_keep_missing_source_and_domain_details(snapshot):
    snapshot["users"] = []
    snapshot["metadata"]["coverage"].update(missing_sources=["fixture-source"], missing_domains=[1])
    result = users._query(context("active"))
    assert result["state"] == "partial"
    assert result["state_details"]["missing_sources"] == ["fixture-source"]
    assert result["state_details"]["missing_domains"] == [1]


@pytest.mark.parametrize("tab,fields", [("active", {"security"}), ("disabled", {"security"}), ("risk", {"security"}), ("privileged", {"security", "privilege"})])
def test_tab_access_is_checked_before_source_reads(monkeypatch, tab, fields):
    monkeypatch.setattr(users, "_snapshots", lambda *_args, **_kwargs: pytest.fail("denied source read"))
    for missing in fields:
        denied = access(grant({"identity_basic", *fields} - {missing}), key=users.REPORT_KEY)
        result, status = call(monkeypatch, users.REPORT, denied, "/data", {"tab": [tab]}).sent[-1]
        if tab == "privileged":
            assert status == 403 and result["state"] == "denied"
        else:
            assert status == 400  # Deprecated API tabs are rejected before reading.


def test_removed_semantic_api_tab_is_rejected_before_source_reads(monkeypatch):
    monkeypatch.setattr(users, "_snapshots", lambda *_args, **_kwargs: pytest.fail("denied source read"))
    denied = decision()
    denied["reports"][1]["grants"][0]["scope"]["ids"] = [2]
    result, status = call(monkeypatch, users.REPORT, denied, "/data", {"tab": ["semantic"]}).sent[-1]
    assert status == 400


def test_semantic_links_exact_account_and_reports_reader_failure(snapshot, monkeypatch):
    result = users._query(context("semantic"))
    assert result["items"][0]["queue_entity_id"] == 1
    assert result["items"][0]["finding_count"] == 2
    monkeypatch.setattr(users_tabs, "_semantic", lambda ids: (_ for _ in ()).throw(RuntimeError("synthetic failure")))
    result = users._query(context("semantic"))
    assert result["state"] == "error" and result["filtered_count"] is None
    assert result["state_details"]["reason"] == "semantic_unavailable"


def test_filters_paging_export_and_counts_are_tab_local(snapshot):
    snapshot["users"] = [account(1), account(2), account(3, False)]
    first = users._query(replace(context("active"), limit=1))
    second = users._query(replace(context("active"), limit=1, cursor=first["next_cursor"]))
    assert first["filtered_count"] == 2 and first["has_more"]
    assert second["items"][0]["entity_id"] == 2 and not second["has_more"]
    filtered = users._query(context("disabled", q="fixture-3"))
    assert filtered["filtered_count"] == 1
    body, metadata = users._export(context("disabled"))
    assert "fixture-3" in body and "fixture-1" not in body and metadata["rows"] == 1


def test_bounded_population_is_partial_even_with_complete_source_coverage(snapshot, monkeypatch):
    snapshot["users"] = [account(1), account(2)]
    monkeypatch.setattr(users_tabs, "USERS_INPUT_LIMIT", 2)
    result = users._query(context("active"))
    assert result["state"] == "partial" and result["coverage"]["truncated"]
    assert "users_bounded" in {item["code"] for item in result["limitations"]}
    assert users._export(context("active"))[1]["truncated"]


def test_semantic_query_is_exact_open_published_unsuppressed_and_bounded(monkeypatch):
    calls = []
    def read(sql, params=(), **kwargs):
        calls.append((sql, params, kwargs))
        return [{"entity_id": 7, "finding_count": 2}] if "finding_entities" in sql else []
    monkeypatch.setattr(users_tabs, "query_rows_bounded", read)
    monkeypatch.setattr(users_tabs, "_semantic_runtime_projection", lambda *args, **kwargs: {"findings_state": "active"})
    assert users_tabs._semantic([7]) == ({7: 2}, "active")
    sql, params, options = calls[0]
    assert params == ([7],) and options["statement_timeout_ms"] == 5000
    assert "linked.entity_id=any(?)" in sql and "count(distinct finding.id)" in sql
    assert "('new','repeated','confirmed','active','review')" in sql
    assert "is_semantic_finding_published_v1" in sql and "not semantic_finding_suppressed_v160" in sql


def test_snapshot_worker_projection_retains_direct_privilege_basis(monkeypatch):
    monkeypatch.setattr(projection, "_entity_versions", lambda ids: ({}, {7: 1}))
    monkeypatch.setattr(projection, "_aliases", lambda ids: {})
    monkeypatch.setattr(projection, "_latest_sections", lambda ids: {})
    monkeypatch.setattr(projection, "_load_graph", lambda **kwargs: {"references": {}, "groups": [], "user_edges": {}, "parent_edges": {}})
    result = projection.build_directory_projection(items=[{"entity_id": 7, "domain_id": 1, "display_name": "Synthetic account",
                    "direct_privileges": [{"group_entity_id": 10, "group_name": "Synthetic group"}]}], coverage={}, requested_domain_ids=[1])
    assert result["users"][0]["privilegedMemberships"] == [{"group_id": 10, "group": "Synthetic group", "relation": "direct", "basis": "privileged_membership"}]


def test_concurrent_tab_queries_share_one_snapshot_build(monkeypatch):
    from threading import Event
    entered, release, second_started, duplicate = Event(), Event(), Event(), Event()
    calls = []
    payload = {"state": "ok", "current": {"users": []}}
    def load(**kwargs):
        calls.append(kwargs)
        if len(calls) > 1:
            duplicate.set()
        entered.set()
        assert release.wait(5)
        return payload
    monkeypatch.setattr(users, "_cache", {})
    monkeypatch.setattr(users, "load_users_v2_snapshots", load)
    def read_again():
        second_started.set()
        return users._snapshots([1])
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(users._snapshots, [1])
        assert entered.wait(5)
        second = pool.submit(read_again)
        try:
            assert second_started.wait(5)
            assert not duplicate.wait(0.1)
        finally:
            release.set()
        assert first.result(timeout=5) is second.result(timeout=5)
    assert len(calls) == 1
