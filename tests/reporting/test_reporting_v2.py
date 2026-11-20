from __future__ import annotations

import json
from datetime import datetime, timezone
from http import HTTPStatus

import pytest

from server.api.routes import reports_v2 as routes
from server.sli.reporting.v2 import registry
from server.sli.reporting.v2.access import resolve_domain_scope
from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Detail,
    Param,
    ReportDefinition,
    View,
    parse_params,
    result,
)
from server.sli.reporting.v2.reports import security_events

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


def _definition(**overrides) -> ReportDefinition:
    values = {
        "key": "demo.report", "section": "reports/computers", "title": "Демо", "description": "", "archetype": "inventory-status",
        "access": AccessRule("demo.report", frozenset({"technical"})),
        "params": (Param.period(default="7d", max_days=31), Param.text("q", "Поиск"), Param.choice("os", "ОС", (("win", "Windows"),)), Param.integer("event_id", "Код")),
        "columns": (Column("name", "Имя", sortable=True), Column("seen", "Время", "datetime")),
        "query": lambda context: result(DEMO, state="empty"), "row_key": "id",
    }
    values.update(overrides)
    return ReportDefinition(**values)


DEMO = _definition()


def _access(*, allowed=True, actions=("view", "export"), fields=("technical",), scope=None):
    return {"reports": [{
        "report_key": "demo.report", "allowed": allowed, "allowed_actions": list(actions),
        "grants": [{"allowed_actions": list(actions), "field_categories": list(fields), "scope": scope or {"kind": "domain", "ids": [3, 1]}}],
    }]}


class TestParseParams:
    def test_default_text_parameter_preserves_legacy_declaration(self):
        assert Param.text("q", "Поиск").to_json() == {
            "key": "q", "label": "Поиск", "kind": "text",
        }

    def test_custom_text_limit_is_declared(self):
        assert Param.text("path", "Объект", max_length=4096).to_json() == {
            "key": "path", "label": "Объект", "kind": "text", "max_length": 4096,
        }

    @pytest.mark.parametrize("max_length", [256, 4096])
    def test_text_limit_is_enforced_at_boundary(self, max_length):
        definition = _definition(params=(Param.text("q", "Поиск", max_length=max_length),))
        value = "x" * max_length
        params, _ = parse_params(definition, {"q": [value]}, now=NOW)
        assert params == {"q": value}
        with pytest.raises(ValueError, match="report_parameter_invalid:q"):
            parse_params(definition, {"q": [value + "x"]}, now=NOW)

    def test_rejects_unknown_parameters(self):
        with pytest.raises(ValueError, match="report_parameter_unknown:typo"):
            parse_params(DEMO, {"typo": ["x"]}, now=NOW)

    def test_resolves_period_preset_and_defaults(self):
        params, paging = parse_params(DEMO, {}, now=NOW)
        assert params["period"] == {"preset": "7d", "from_utc": "2026-09-22T12:00:00Z", "to_utc": "2026-09-29T12:00:00Z"}
        assert paging == {"cursor": None, "limit": 100, "timezone": "UTC", "sort": None, "direction": "asc", "tab": None}

    def test_custom_period_uses_calendar_days_in_user_time_zone(self):
        params, _ = parse_params(DEMO, {"period": ["custom"], "from": ["2026-09-10"], "to": ["2026-09-11"], "tz": ["Asia/Novosibirsk"]}, now=NOW)
        assert params["period"]["from_utc"] == "2026-09-09T17:00:00Z"
        assert params["period"]["to_utc"] == "2026-09-11T17:00:00Z"

    def test_custom_period_keeps_exact_instants_of_evidence_links(self):
        params, _ = parse_params(DEMO, {"period": ["custom"], "from": ["2026-09-10T06:15:00Z"], "to": ["2026-09-10T12:00:00+03:00"]}, now=NOW)
        assert params["period"]["from_utc"] == "2026-09-10T06:15:00Z"
        assert params["period"]["to_utc"] == "2026-09-10T09:00:00Z"

    @pytest.mark.parametrize("value", [("2026-09-10T06:00:00", "2026-09-10T07:00:00Z"), ("2026-09-10T07:00:00Z", "2026-09-10T06:00:00Z")])
    def test_exact_instants_need_an_offset_and_order(self, value):
        with pytest.raises(ValueError, match="report_period_invalid"):
            parse_params(DEMO, {"period": ["custom"], "from": [value[0]], "to": [value[1]]}, now=NOW)

    @pytest.mark.parametrize("query, code", [
        ({"period": ["custom"], "from": ["2026-09-12"], "to": ["2026-09-10"]}, "report_period_invalid"),
        ({"period": ["custom"], "from": ["2026-01-01"], "to": ["2026-09-10"]}, "report_period_too_wide"),
        ({"period": ["1y"]}, "report_period_invalid"),
        ({"os": ["mac"]}, "report_parameter_invalid:os"),
        ({"event_id": ["abc"]}, "report_parameter_invalid:event_id"),
        ({"event_id": ["-1"]}, "report_parameter_invalid:event_id"),
        ({"q": ["x" * 300]}, "report_parameter_invalid:q"),
        ({"limit": ["0"]}, "report_limit_invalid"),
        ({"limit": ["501"]}, "report_limit_invalid"),
        ({"sort": ["seen"]}, "report_sort_invalid"),
        ({"direction": ["up"]}, "report_sort_invalid"),
        ({"tz": ["Mars/Base"]}, "report_timezone_invalid"),
    ])
    def test_rejects_invalid_values(self, query, code):
        with pytest.raises(ValueError, match=code):
            parse_params(DEMO, query, now=NOW)

    def test_required_parameter(self):
        definition = _definition(params=(Param.domain(),))
        with pytest.raises(ValueError, match="report_parameter_required:domain"):
            parse_params(definition, {}, now=NOW)
        params, _ = parse_params(definition, {"domain": ["2"]}, now=NOW)
        assert params == {"domain": 2}


class TestDomainScope:
    def test_returns_sorted_domains_or_none_for_all(self):
        assert resolve_domain_scope(_access(), DEMO.access) == [1, 3]
        assert resolve_domain_scope(_access(scope={"kind": "all"}), DEMO.access) is None

    @pytest.mark.parametrize("access, action, code", [
        (_access(allowed=False), "view", "report_access_denied"),
        (_access(actions=("view",)), "export", "report_access_denied"),
        (_access(fields=("identity_basic",)), "view", "report_field_categories_not_allowed"),
        (_access(scope={"kind": "domain", "ids": []}), "view", "report_scope_not_executable"),
    ])
    def test_denies_with_v1_error_codes(self, access, action, code):
        with pytest.raises(PermissionError, match=code):
            resolve_domain_scope(access, DEMO.access, action)


class TestRegistry:
    @pytest.mark.parametrize("actions, executable", [(("view",), True), (("export",), False), ((), False)])
    def test_delegated_catalog_still_requires_view_action(self, monkeypatch, actions, executable):
        definition = _definition(access=AccessRule("demo.report", scope="delegated"))
        monkeypatch.setattr(registry, "registered_reports", lambda: (definition,))
        assert registry.catalog(_access(actions=actions))["items"][0]["executable"] is executable

    @pytest.mark.parametrize("access, executable", [
        (_access(), True),
        (_access(scope={"kind": "all"}), True),
        (_access(scope={"kind": "domain", "ids": []}), False),
        (_access(fields=("identity_basic",)), False),
        (_access(actions=("export",)), False),
    ])
    def test_catalog_marks_non_executable_domain_grants(self, monkeypatch, access, executable):
        monkeypatch.setattr(registry, "registered_reports", lambda: (DEMO,))
        assert registry.catalog(access)["items"][0]["executable"] is executable

    def test_discovers_security_events_with_a_known_section(self):
        reports = registry.registered_reports()
        assert "security.events.chains" in {definition.key for definition in reports}
        assert all(definition.section in registry.SECTION_TITLES for definition in reports)

    def test_catalog_lists_only_granted_reports(self):
        granted = {"reports": [{"report_key": "security.events.chains", "allowed": True}]}
        assert [item["key"] for item in registry.catalog(granted)["items"]] == ["security.events.chains"]
        assert registry.catalog({"reports": []})["items"] == []

    def test_declaration_serialises_for_the_ui(self):
        payload = security_events.REPORT.to_json()
        assert payload["params"][0] == {"key": "domain", "label": "Домен", "kind": "domain", "options_from": "domain"}
        assert {column["path"] for column in payload["columns"]} >= {"actor.name", "affected_account.name", "outcome_code"}
        assert payload["export"] is True


class FakeHandler:
    def __init__(self, access):
        self.access = access
        self.sent: list[tuple[object, int]] = []

    def _access_decision(self):
        return self.access

    def _send_json(self, payload, status=HTTPStatus.OK):
        self.sent.append((json.loads(json.dumps(payload, default=str)), int(status)))


class TestRoutes:
    @pytest.mark.parametrize("overrides, expected", [
        ({}, ("related", "name", "desc")),
        ({"tab": ["table"], "sort": ["seen"], "direction": ["asc"]}, ("table", "seen", "asc")),
    ])
    def test_detail_inherits_context_and_respects_request_overrides(self, monkeypatch, overrides, expected):
        contexts = []
        rows = []

        def query(context):
            contexts.append(context)
            return {"state": "empty"}

        def detail_query(context, row_id):
            rows.append(row_id)
            return query(context)

        definition = _definition(
            columns=(Column("name", "Name", sortable=True), Column("seen", "Seen", sortable=True)),
            views=(View("table"), View("table", key="related")),
            query=query,
            detail=Detail("Fixture detail", "id", (), query=detail_query, default_limit=25),
        )
        monkeypatch.setattr(routes, "get_report", lambda _key: definition)
        handler = FakeHandler(_access())
        query_params = {
            "tab": ["related"], "sort": ["name"], "direction": ["desc"],
            "q": ["fixture"], "cursor": ["fixture-cursor"], "limit": ["40"], "tz": ["Asia/Bangkok"],
            # Separate requests share an explicit range, not a moving default.
            "period": ["custom"], "from": ["2026-09-22T12:00:00Z"], "to": ["2026-09-29T12:00:00Z"],
        }

        assert routes.try_handle_get(handler, "/api/v2/reports/demo.report/data", query_params)
        assert routes.try_handle_get(handler, "/api/v2/reports/demo.report/rows/7/detail", {**query_params, **overrides})
        assert handler.sent[-1][1] == 200
        main, detail = contexts
        assert rows == ["7"]
        assert (detail.tab, detail.sort, detail.direction) == expected
        assert detail.access == main.access
        assert detail.params == main.params
        assert detail.domain_ids == main.domain_ids == [1, 3]
        assert detail.action == main.action == "view"
        assert detail.cursor == main.cursor == "fixture-cursor"
        assert detail.timezone == main.timezone == "Asia/Bangkok"
        assert detail.runtime == main.runtime
        assert main.limit == 40 and detail.limit == 25

    def test_route_is_resource_aware(self):
        assert routes.is_resource_aware("/api/v2/reports")
        assert routes.is_resource_aware("/api/v2/reports/security.events.chains/data")
        assert not routes.is_resource_aware("/api/v1/reports/catalog")

    def test_unknown_report_and_missing_grant(self):
        handler = FakeHandler({"reports": []})
        assert routes.try_handle_get(handler, "/api/v2/reports/nope.report", {})
        assert handler.sent[-1][1] == 404
        assert routes.try_handle_get(handler, "/api/v2/reports/security.events.chains", {})
        assert handler.sent[-1] == ({"error": "report_access_denied"}, 403)

    @pytest.mark.parametrize("suffix", ["", "/data", "/export.csv", "/rows/7/detail"])
    @pytest.mark.parametrize("access", [{"reports": []}, _access(allowed=False)])
    def test_missing_or_denied_grant_preserves_error_contract(self, monkeypatch, suffix, access):
        def unexpected(*_args):
            pytest.fail("denied report executed")

        definition = _definition(
            query=unexpected, options=unexpected, export_csv=unexpected,
            detail=Detail("Fixture detail", "id", (), query=unexpected),
        )
        monkeypatch.setattr(routes, "get_report", lambda _key: definition)
        handler = FakeHandler(access)

        assert routes.try_handle_get(handler, f"/api/v2/reports/demo.report{suffix}", {})
        assert handler.sent == [({"error": "report_access_denied"}, 403)]

    def test_invalid_parameter_is_400_before_the_engine_runs(self, monkeypatch):
        called = []
        monkeypatch.setattr(security_events, "get_security_events_report", lambda *args, **kwargs: called.append(1))
        handler = FakeHandler({"reports": [{"report_key": "security.events.chains", "allowed": True}]})
        routes.try_handle_get(handler, "/api/v2/reports/security.events.chains/data", {"domain": ["1"], "typo": ["x"]})
        assert handler.sent[-1] == ({"error": "report_parameter_unknown:typo"}, 400)
        assert called == []

    @pytest.mark.parametrize("action", ["data", "export.csv"])
    def test_gpo_source_contract_error_is_unavailable_without_private_details(self, monkeypatch, caplog, action):
        from server.sli.reporting.v2.reports import gpo
        from server.sli.sources.gpo_v2_source import GpoV2SourceContractError

        def invalid_snapshot(*, domain_ids):
            assert domain_ids == [1, 3]
            raise GpoV2SourceContractError("timestamp_invalid:started_at:synthetic-private-marker")

        monkeypatch.setattr(gpo, "load_authorized_snapshot_pair", invalid_snapshot)
        access = _access(fields=("identity_basic", "technical", "security", "privilege"))
        access["reports"][0]["report_key"] = gpo.REPORT_KEY
        handler = FakeHandler(access)

        assert routes.try_handle_get(handler, f"/api/v2/reports/{gpo.REPORT_KEY}/{action}", {})
        payload, status = handler.sent[-1]
        assert status == HTTPStatus.SERVICE_UNAVAILABLE
        assert payload["error"] == "gpo_snapshot_unavailable"
        assert payload["state"] == "error"
        assert payload["reason"] == "source_contract_error"
        assert payload["message"]["code"] == "reports.renderer.error_gpo_snapshot"
        assert "недоступен или повреждён" in payload["message"]["text"]
        assert "source contract violation" in caplog.text
        assert "synthetic-private-marker" not in caplog.text
        assert "synthetic-private-marker" not in str(payload)
        assert all(record.exc_info is None for record in caplog.records)

    def test_invalid_request_date_still_returns_400_before_query(self, monkeypatch):
        monkeypatch.setattr(routes, "get_report", lambda _key: DEMO)
        handler = FakeHandler(_access())

        assert routes.try_handle_get(handler, "/api/v2/reports/demo.report/data", {
            "period": ["custom"], "from": ["invalid-date"], "to": ["2026-10-04"],
        })
        assert handler.sent[-1][1] == HTTPStatus.BAD_REQUEST
        assert handler.sent[-1][0]["error"] == "report_period_invalid"

    def test_data_maps_engine_states_to_truthful_result_states(self, monkeypatch):
        monkeypatch.setattr(security_events, "_domain_options", lambda access: [{"value": "1", "label": "example.test"}])
        engine = {"state": "empty_unverified", "items": [], "has_more": False, "next_cursor": None,
                  "collection_coverage": {"state": "empty_unverified", "source_completeness": "not_proven"},
                  "limitations": ["An empty window does not prove complete source coverage."], "time_bounds": {"from_utc": "a", "to_utc_exclusive": "b"}}
        seen = {}
        def fake(access, **kwargs):
            seen.update(kwargs)
            return engine
        monkeypatch.setattr(security_events, "get_security_events_report", fake)
        handler = FakeHandler({"reports": [{"report_key": "security.events.chains", "allowed": True}]})
        routes.try_handle_get(handler, "/api/v2/reports/security.events.chains/data", {"domain": ["1"], "period": ["24h"], "outcome": ["failure"], "limit": ["50"]})
        payload, status = handler.sent[-1]
        assert status == 200
        assert payload["state"] == "partial"
        assert payload["coverage"]["completeness"] == "not_proven"
        assert payload["limitations"] == [{"code": "empty_not_proof", "text": "Пустой результат не доказывает, что источник собран полностью."}]
        assert payload["filter_options"]["domain"] == [{"value": "1", "label": "example.test"}]
        assert seen["source_domain_id"] == 1 and seen["outcome"] == "failure" and seen["limit"] == 50

        engine.update(state="not_authorized")
        routes.try_handle_get(handler, "/api/v2/reports/security.events.chains/data", {"domain": ["1"]})
        assert handler.sent[-1][0]["state"] == "denied"
        engine.update(state="available", items=[{"event_db_id": 7}])
        routes.try_handle_get(handler, "/api/v2/reports/security.events.chains/data", {"domain": ["1"]})
        assert handler.sent[-1][0]["state"] == "ok"

    @pytest.mark.parametrize("inline", [False, True])
    @pytest.mark.parametrize("default, available, explicit, expected", [
        (7, (3, 7), None, 7),
        (99, (3,), None, 3),
        (99, (3, 7), None, None),
        (99, (3, 7), "  ", None),
        (99, (), None, None),
        (7, (3, 7), "3", 3),
    ])
    def test_domain_defaults_use_available_options(self, monkeypatch, inline, default, available, explicit, expected):
        seen = []

        def query(context):
            seen.append(context.params["domain"])
            return result(DEMO, state="empty")

        options = [{"value": str(value), "label": f"Domain {value}"} for value in available]
        definition = _definition(
            params=(Param("domain", "Domain", "domain", required=True, default=default,
                          options=tuple((item["value"], item["label"]) for item in options) if inline else (),
                          options_from=None if inline else "registered_domains"),),
            options=None if inline else lambda _access: {"registered_domains": options},
            query=query,
        )
        monkeypatch.setattr(routes, "get_report", lambda _key: definition)
        handler = FakeHandler(_access(scope={"kind": "all"}))
        parameters = {} if explicit is None else {"domain": [explicit]}

        assert routes.try_handle_get(handler, "/api/v2/reports/demo.report/data", parameters)
        if expected is None:
            assert handler.sent[-1] == ({"error": "report_parameter_required:domain"}, 400)
            assert seen == []
        else:
            assert handler.sent[-1][1] == 200
            assert seen == [expected]

    def test_missing_security_domain_requests_all_accessible_domains(self, monkeypatch):
        seen: list[int | None] = []
        monkeypatch.setattr(security_events, "get_security_events_report",
                            lambda access, **kwargs: seen.append(kwargs["source_domain_id"]) or {"state": "available", "items": []})
        handler = FakeHandler({"reports": [{"report_key": "security.events.chains", "allowed": True}]})

        monkeypatch.setattr(security_events, "_domain_options", lambda access: [{"value": "7", "label": "one.example.test"}])
        routes.try_handle_get(handler, "/api/v2/reports/security.events.chains/data", {})
        assert handler.sent[-1][1] == 200 and seen == [None]

        monkeypatch.setattr(security_events, "_domain_options", lambda access: [{"value": "7", "label": "a"}, {"value": "8", "label": "b"}])
        routes.try_handle_get(handler, "/api/v2/reports/security.events.chains/data", {})
        assert handler.sent[-1][1] == 200
        assert seen == [None, None]


class TestSecurityEventDerivedFields:
    def test_change_text_reports_only_what_the_event_proves(self):
        locked = {"account_change": {"observed_transition": {
            "before": {"state": "unknown", "reason": "prior_account_state_not_observed"},
            "after": {"state": "observed", "value": "locked"},
        }}}
        assert security_events._change_text(locked) == "не подтверждено → заблокирована"
        assert security_events._change_text({"change": {"state": "observed", "kind": "password_reset"}}) == "сброс пароля"
        assert security_events._change_text({"change": {"state": "unknown"}}) is None

    def test_member_text_only_for_observed_members(self):
        assert security_events._with_derived({"member": {"state": "observed", "name": "ivanov"}})["member_text"] == "ivanov"
        assert security_events._with_derived({"member": {"state": "unknown"}})["member_text"] is None


class TestSortAndCsv:
    def test_sort_rows_keeps_empty_values_last_in_both_directions(self):
        from server.sli.reporting.v2.definition import sort_rows

        definition = _definition(columns=(Column("name", "Имя", sortable=True), Column("seen", "Время")))
        rows = [{"name": "b"}, {"name": None}, {"name": "A"}]
        assert [row["name"] for row in sort_rows(definition, rows, "name")] == ["A", "b", None]
        assert [row["name"] for row in sort_rows(definition, rows, "name", "desc")] == ["b", "A", None]
        assert sort_rows(definition, rows, "seen") == rows  # not sortable: order unchanged

    def test_csv_uses_labels_and_neutralises_formulas(self):
        from server.sli.reporting.v2.definition import csv_from_columns

        columns = (Column("name", "Имя"), Column("state", "Состояние", "state", labels={"on": "Включена"}), Column("tags", "Метки", "list", path="meta.tags"))
        text = csv_from_columns(columns, [{"name": "=SUM(A1)", "state": "on", "meta": {"tags": ["x", "y"]}}, {"name": None, "state": "off"}])
        assert text.splitlines() == ["Имя,Состояние,Метки", "'=SUM(A1),Включена,\"x, y\"", ",off,"]


def _gpo_snapshot() -> dict:
    return {
        "collection_status": "completed", "observed_at": "2026-09-10T00:00:00Z", "completed_at": "2026-09-10T01:00:00Z",
        "source_states": {"links": {"status": "observed"}},
        "gpos": [
            {"id": "gpo-a", "display_name": "Beta", "link_ids": ["l1"], "setting_ids": [], "permission_ids": [], "source_states": {"links": {"status": "observed"}}},
            {"id": "gpo-b", "display_name": "Alpha", "link_ids": [], "setting_ids": ["s1", "s2"], "permission_ids": [], "source_states": {"links": {"status": "observed"}}},
        ],
        "settings": [{"id": "s1", "gpo_name": "Alpha", "setting_name": "=cmd"}], "scopes": [], "permissions": [], "wmi_filters": [],
    }


class TestGpoAdapter:
    def _run(self, monkeypatch, query):
        from server.sli.reporting.v2.reports import gpo

        monkeypatch.setattr(gpo, "load_authorized_snapshot_pair", lambda domain_ids: {"state": "available", "current": _gpo_snapshot(), "previous": None})
        params, paging = parse_params(gpo.REPORT, query, now=NOW)
        from server.sli.reporting.v2.definition import QueryContext

        return gpo._query(QueryContext(access={}, params=params, domain_ids=[1], action="view", cursor=None, limit=500, timezone="UTC", tab=paging["tab"], sort=paging["sort"], direction=paging["direction"]))

    def test_views_are_metric_filters_and_sorting_is_server_side(self, monkeypatch):
        data = self._run(monkeypatch, {"view": ["all"], "sort": ["name"]})
        assert [row["display_name"] for row in data["items"]] == ["Alpha", "Beta"]
        assert {metric["key"]: metric["filter"] for metric in data["metrics"]}["unlinked"] == {"view": "unlinked"}
        assert data["collections"] == {}

    def test_only_the_open_tab_collection_is_built(self, monkeypatch):
        data = self._run(monkeypatch, {"view": ["all"], "tab": ["settings"]})
        assert list(data["collections"]) == ["settings"]
        assert data["collections"]["settings"][0]["setting_name"] == "=cmd"

    def test_boundaries_are_human_limitations(self, monkeypatch):
        texts = [item["text"] for item in self._run(monkeypatch, {"view": ["all"]})["limitations"]]
        assert any("RSoP" in text for text in texts) and any("удаление" in text for text in texts)


def test_catalog_exposes_home_widget_order_of_registered_reports():
    from server.sli.reporting.v2.registry import registered_reports

    orders = {definition.key: definition.home_order for definition in registered_reports()}
    assert orders["security.problems"] == 10 and orders["ad.users.v2"] == 30
    assert orders["ad.computer-logons"] is None
    home = sorted((order, key) for key, order in orders.items() if order is not None)
    assert [key for _, key in home][:3] == ["security.problems", "security.events.chains", "ad.infrastructure"]


def test_home_views_name_a_chart_view_of_the_same_report():
    from server.sli.reporting.v2.registry import registered_reports

    declared = [definition for definition in registered_reports() if definition.home_view]
    assert {definition.key for definition in declared} >= {"security.events.chains", "vpn.connections"}
    for definition in declared:
        assert definition.home_order is not None, definition.key
        views = {view.key: view for view in definition.views}
        assert views[definition.home_view].kind == "chart", definition.key


def test_custom_view_names_its_component():
    from server.sli.reporting.v2.reports import security_events

    views = {view.key: view.to_json() for view in security_events.REPORT.views}
    assert views["events"]["kind"] == "table"
    assert views["chains"] == {**views["chains"], "kind": "custom", "component": "security.chains"}
