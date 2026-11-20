"""«VPN-доступ» on the v2 framework: unavailable fields are not «нет»."""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from server.api.routes import reports_v2 as routes
from server.sli.reporting import reporting_v4
from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import vpn_audit as report
from tests.reporting.test_report_studio_lifecycle import FakeDb


def _context(params: dict[str, str]) -> QueryContext:
    return QueryContext(access={"reports": []}, params=params, domain_ids=None, action="view", cursor=None, limit=200, timezone="UTC")


def _payload(items, collection):
    return {"state": "available", "items": items, "has_more": False, "filtered_count": len(items),
            "summary": {"total_users": 2, "enabled_users": 1, "active_users": 1, "disabled_users": 1, "collection": collection, "limitations": ["Только группы AD."]}}


def test_missing_field_categories_are_shown_as_unavailable_not_as_no(monkeypatch: pytest.MonkeyPatch):
    calls = []
    items = [{"object_id": 1, "display_name": "A", "activity_state": "active"},
             {"object_id": 2, "display_name": "B", "activity_state": "DISABLED", "privileged_overlap": False, "department": None, "password_never_expires": True}]
    monkeypatch.setattr(report, "execute_report", lambda *args, **kwargs: calls.append((args, kwargs)) or _payload(items, {"privileged_membership": {"state": "partial"}}))
    body = report._query(_context({}))
    assert calls[0][0][0] == "vpn.audit" and calls[0][1]["access"] == {"reports": []}
    first, second = body["items"]
    assert first["privilege_text"] == first["department_text"] == first["password_text"] == "Поле недоступно"
    assert first["privilege_text_code"] == first["department_text_code"] == first["password_text_code"] == "unavailable"
    assert second["activity"] == "disabled"
    assert second["privilege_text"] == "Не обнаружено в неполном срезе"
    assert second["department_text"] == "Не указано" and second["password_text"] == "Без ограничения срока"
    assert second["department_text_code"] == "unspecified"
    assert second["password_text_code"] == "never_expires"
    assert second["privilege_text_code"] == "not_detected_partial"
    assert body["state"] == "partial"
    assert body["limitations"] == [{"code": "vpn_accounts_0", "text": "Только группы AD."}]


def test_activity_filter_and_complete_coverage(monkeypatch: pytest.MonkeyPatch):
    items = [{"object_id": 1, "display_name": "A", "activity_state": "active", "privileged_overlap": False},
             {"object_id": 2, "display_name": "B", "activity_state": "inactive", "privileged_overlap": True}]
    def execute(*args, query_filters, **kwargs):
        assert query_filters["sort"] == "object_id" and query_filters["direction"] == "asc"
        return _payload([item for item in items if item["activity_state"] == query_filters["activity_state"]], {"privileged_membership": {"state": "complete"}})

    monkeypatch.setattr(report, "execute_report", execute)
    body = report._query(_context({"activity": "inactive"}))
    assert [row["object_id"] for row in body["items"]] == [2]
    assert body["items"][0]["privilege_text"] == "Есть пересечение"
    assert body["items"][0]["privilege_text_code"] == "overlap"
    assert body["state"] == "ok"
    assert report._query(_context({"activity": "active"}))["items"][0]["privilege_text"] == "Не обнаружено"
    assert report._query(_context({"activity": "active"}))["items"][0]["privilege_text_code"] == "not_detected"


def test_presentation_codes_keep_real_department_and_unknown_coverage():
    row = report._row({"department": "Подразделение из источника", "password_never_expires": False,
                       "privileged_overlap": False}, "not_collected")
    assert row["department_text"] == "Подразделение из источника"
    assert row["department_text_code"] is None
    assert row["password_text"] == "С ограничением срока"
    assert row["password_text_code"] == "expires"
    assert row["privilege_text"] == "Срез не собран"
    assert row["privilege_text_code"] == "not_collected"


def test_export_uses_the_published_report_document(monkeypatch: pytest.MonkeyPatch):
    seen = {}
    def export(key, principal, query_filters, access):
        seen.update(query_filters)
        return {"csv": "a\r\n", "row_count": 1, "truncated": True}

    monkeypatch.setattr(report, "export_report_csv_document", export)
    context = replace(_context({"q": "account", "activity": "active"}), cursor="ignored")
    assert report._export(context) == ("a\r\n", {"rows": 1, "truncated": True})
    assert seen == {"sort": "object_id", "direction": "asc", "q": "account", "activity_state": "active"}


def _inventory():
    return [{"object_id": str(index), "display_name": "Account", "natural_key": f"account-{index:04}",
             "domain_id": 7, "enabled": index <= 418, "is_inactive": 391 < index <= 418}
            for index in range(1, 439)]


def _activity(user):
    if user.get("enabled") is None:
        return "unknown"
    if user["enabled"] is False:
        return "disabled"
    return "inactive" if user.get("is_inactive") is True else "active"


def _install_inventory(monkeypatch, users=None):
    users = _inventory() if users is None else users
    calls = []
    fields = [{"key": key, "category": category} for key, category in (
        ("object_id", "identity_basic"), ("display_name", "identity_basic"), ("natural_key", "technical"),
        ("enabled", "security"), ("activity_state", "security"),
    )]
    definition = {"dataset_key": "ad.accounts.vpn", "fields_json": fields,
                  "definition_json": {"columns": [field["key"] for field in fields], "actions": ["view"],
                                      "default_sort": [{"field": "privileged_overlap", "direction": "desc"},
                                                       {"field": "activity_state", "direction": "asc"}]}}
    access = {"capabilities": [], "reports": [{"report_key": "vpn.audit", "version": 1, "allowed": True,
              "allowed_actions": ["view"], "grants": [{"scope": {"kind": "domain", "ids": [7]},
              "field_categories": ["identity_basic", "technical", "security"], "allowed_actions": ["view"]}]}]}
    db = FakeDb(lambda sql, params: [definition])
    monkeypatch.setattr(reporting_v4, "_connect", lambda: db)
    monkeypatch.setattr(reporting_v4, "_context_section_coverage", lambda *args: {"vpn_membership": {"state": "complete"}})

    def query(sql, params, **kwargs):
        calls.append((sql, params))
        assert kwargs["statement_timeout_ms"] == 5000
        assert "source_entity.domain_id=any(?)" in sql
        assert "relation.source_section='vpn_membership'" in sql
        assert "entity_type.value='ad_user'" in sql
        assert "entity_v2_is_active(source_entity.id)" in sql
        assert reporting_v4.VPN_ACCOUNT_ATTRIBUTES_LATERAL in sql
        # Multiple VPN memberships must still produce one row per account.
        population = list({user["object_id"]: user for user in users if user["domain_id"] in params[0]}.values())
        state_sql = reporting_v4.runtime_filter_expression("ad.accounts.vpn", "activity_state")
        if "with vpn_users as (" in sql:
            assert f"{state_sql} as activity_state" in sql
            assert "count(*) filter(where activity_state='active') as active_users" in sql
            return [{"total_users": len(population),
                     "enabled_users": sum(user.get("enabled") is True for user in population),
                     "active_users": sum(_activity(user) == "active" for user in population),
                     "inactive_users": sum(_activity(user) == "inactive" for user in population),
                     "disabled_users": sum(_activity(user) == "disabled" for user in population)}]
        values = iter(params[1:])
        if "strpos(" in sql:
            needle = next(values).lower()
            population = [user for user in population if needle in f"{user['display_name']} {user['natural_key']}".lower()]
        if f"{state_sql}=?" in sql:
            state = next(values)
            population = [user for user in population if _activity(user) == state]
        if "as filtered_count" in sql:
            assert "select count(distinct source_entity.id)" in sql
            assert "source_entity.id>?" not in sql and "limit ?" not in sql.split(") account on true", 1)[1]
            assert list(values) == []
            return [{"filtered_count": len(population)}]
        assert "select distinct source_entity.id as _cursor_id" in sql
        assert f"{state_sql} as activity_state" in sql
        assert "order by source_entity.id asc" in sql
        if "source_entity.id>?" in sql:
            cursor_id = next(values)
            population = [user for user in population if int(user["object_id"]) > cursor_id]
        limit = next(values)
        assert list(values) == [] and limit <= reporting_v4.REPORT_LIMIT_MAX + 1
        population.sort(key=lambda user: int(user["object_id"]))
        return [{**user, "activity_state": _activity(user)} for user in population[:limit]]

    monkeypatch.setattr(reporting_v4, "query_rows_bounded", query)
    return replace(_context({}), access=access), calls


def test_inventory_count_and_keyset_pages_include_all_438_users(monkeypatch):
    users = _inventory()
    # Duplicate memberships and a matching account outside the granted domain.
    context, calls = _install_inventory(monkeypatch, [*users, users[0], {**users[0], "object_id": "999", "domain_id": 8}])
    pages = []
    for expected_size in (200, 200, 38):
        page = report._query(context)
        pages.append(page)
        assert page["filtered_count"] == 438
        assert len(page["items"]) == expected_size
        context = replace(context, cursor=page["next_cursor"])
    assert pages[0]["has_more"] and pages[0]["next_cursor"]
    assert pages[1]["has_more"] and pages[1]["next_cursor"]
    assert not pages[2]["has_more"] and pages[2]["next_cursor"] is None
    assert [row["object_id"] for page in pages for row in page["items"]] == [str(index) for index in range(1, 439)]
    assert all(set(row) >= {"object_id", "activity"} and "_cursor_id" not in row for page in pages for row in page["items"])
    assert [params for sql, params in calls if "as filtered_count" in sql] == [([7],)] * 3


@pytest.mark.parametrize("params, expected", [
    ({"q": "ACCOUNT-0438"}, ["438"]),
    ({"q": "account-04", "activity": "inactive"}, [str(index) for index in range(400, 419)]),
    ({"activity": "disabled"}, [str(index) for index in range(419, 439)]),
    ({"q": "%_"}, []),
])
def test_filters_and_literal_search_cover_users_beyond_the_first_page(monkeypatch, params, expected):
    context, calls = _install_inventory(monkeypatch)
    body = report._query(replace(context, params=params))
    assert [row["object_id"] for row in body["items"]] == expected
    assert body["filtered_count"] == len(expected)
    assert body["state"] == ("ok" if expected else "empty")
    count_sql, count_params = next(call for call in calls if "as filtered_count" in call[0])
    row_sql, row_params = calls[-1]
    assert row_params[:-1] == count_params
    assert row_params[-1] == 201
    assert count_sql.split(" from ad_context_relation_versions", 1)[1] in row_sql


def test_activity_cards_count_the_same_population_as_their_filters(monkeypatch):
    context, _ = _install_inventory(monkeypatch)
    initial = report._query(context)
    assert {metric["key"]: metric["value"] for metric in initial["metrics"]}["active_users"] == 391
    for metric in initial["metrics"]:
        if metric.get("filter"):
            filtered = report._query(replace(context, params=metric["filter"]))
            assert metric["value"] == filtered["filtered_count"]
            assert {row["activity"] for row in filtered["items"]} == {metric["filter"]["activity"]}
    filtered = report._query(replace(context, params={"activity": "active"}))
    assert len(filtered["items"]) == 200 and filtered["next_cursor"]
    last = report._query(replace(context, params={"activity": "active"}, cursor=filtered["next_cursor"]))
    assert last["filtered_count"] == 391 and len(last["items"]) == 191
    assert not last["has_more"]


def test_unknown_and_disabled_accounts_are_never_counted_as_active(monkeypatch):
    users = [{**_inventory()[0], "object_id": str(index), "enabled": enabled, "is_inactive": inactive}
             for index, (enabled, inactive) in enumerate(((True, None), (True, False), (True, True),
                                                        (False, True), (None, True)), 1)]
    context, _ = _install_inventory(monkeypatch, users)
    body = report._query(context)
    active = next(metric for metric in body["metrics"] if metric["key"] == "active_users")
    assert active["value"] == 2
    assert report._query(replace(context, params=active["filter"]))["filtered_count"] == 2
    assert [row["activity"] for row in body["items"]] == ["active", "active", "inactive", "disabled", "unknown"]


@pytest.mark.parametrize("payload", [None, [], {}, {"object_id": True}, {"object_id": "0"},
                                      {"object_id": "-1"}, {"object_id": str(2**63)}, {"object_id": "x"}])
def test_malformed_cursors_are_rejected_before_reading_inventory(monkeypatch, payload):
    context, calls = _install_inventory(monkeypatch)
    cursor = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    with pytest.raises(ValueError, match="invalid_report_cursor"):
        report._query(replace(context, cursor=cursor))
    assert calls == []


def test_v2_route_preserves_count_and_next_cursor_contract(monkeypatch):
    context, _ = _install_inventory(monkeypatch)
    responses = []
    handler = SimpleNamespace(_access_decision=lambda: context.access,
                              _send_json=lambda payload, status=200: responses.append((payload, status)))
    assert routes.try_handle_get(handler, "/api/v2/reports/vpn.accounts/data", {})
    first, status = responses[-1]
    assert status == 200 and first["contract_id"] == "sli.report-result.v2"
    assert first["filtered_count"] == 438 and len(first["items"]) == 200 and first["next_cursor"]
    assert routes.try_handle_get(handler, "/api/v2/reports/vpn.accounts/data", {"cursor": [first["next_cursor"]]})
    second, status = responses[-1]
    assert status == 200 and second["filtered_count"] == 438
    assert second["items"][0]["object_id"] == "201" and second["next_cursor"]


@pytest.fixture(autouse=True)
def _hygiene_settings(monkeypatch):
    from server.sli.core import platform_settings

    monkeypatch.setattr(platform_settings, "_stored_row", lambda _key: None)
