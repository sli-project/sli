from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from server.api.routes import workspace
from server.sli.access.access_control_v4 import route_capability
from server.sli.access import domain_scope
from server.sli.core.database import QueryTimeoutError
from server.sli.reporting import home_summary as home
from server.sli.reporting.v2 import registry
from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Param,
    ReportDefinition,
    result,
)


@pytest.fixture(autouse=True)
def fake_domain_registry(monkeypatch):
    monkeypatch.setattr(domain_scope, "_domain_rows", lambda ids: [
        {"id": id, "display_name": f"domain-{id}.example.test", "snapshot_state": "partial",
         "observed_at_utc": f"2026-10-0{id - 6}T00:00:00Z"}
        for id in (7, 8) if ids is None or id in ids
    ])


def report(key, order, *, scope="delegated", **values):
    definition = ReportDefinition(
        key=key, title="Synthetic report", description="", section="investigation", archetype="queue",
        access=AccessRule(key, scope=scope), columns=(Column("title", "Title"),), params=(),
        row_key="id", home_order=order, query=lambda ctx: {}, **values,
    )
    return replace(definition, query=Mock(side_effect=lambda ctx: result(
        definition, state="partial", coverage={"observed_at_utc": "2026-10-01T00:00:00Z"},
        metrics=[{"key": "attention", "label": "Attention", "value": 4, "tone": "warning"}],
        items=[{"id": i, "title": "Synthetic action", "status": "new", "severity": "high"} for i in range(7)],
    )))


def access(*definitions):
    return {"capabilities": ["workspace.view"], "reports": [
        {"report_key": d.key, "name": d.title, "allowed": True, "allowed_actions": ["view"],
         "grants": [{"scope": {"kind": "domain", "ids": [7]}, "allowed_actions": ["view"], "field_categories": []}]}
        for d in definitions
    ]}


def install(monkeypatch, *definitions):
    monkeypatch.setattr(registry, "registered_reports", lambda: definitions)


def test_domain_switcher_contract_counts_and_incomplete_data(monkeypatch):
    definition = report("security.problems", 0, scope="domain")
    install(monkeypatch, definition)
    decision = access(definition)
    decision["reports"][0]["grants"][0]["scope"]["ids"] = [7, 8]

    def read(context):
        ids = context.domain_ids
        return result(definition, state="partial" if 8 in ids else "empty",
                      metrics=[{"key": "attention", "label": "Attention", "value": 12 if 7 in ids else 0}],
                      coverage={"observed_at_utc": "2026-10-17T00:00:00Z"})

    definition.query.side_effect = read
    handler = SimpleNamespace(_access_decision=lambda: decision, _send_json=Mock())
    workspace.try_handle_get(handler, "/api/v1/home/summary", {"contract": ["v2"]})
    payload = handler._send_json.call_args.args[0]
    assert payload["problems_found"]["count"] == 12
    assert [(item["id"], item["summary"]["problems_found"]["count"],
             item["summary"]["observation_health"]["state"]) for item in payload["domains"]] == [
        (7, 12, "ok"), (8, 0, "partial"),
    ]

    definition.query.side_effect = lambda context: result(definition, state="error")
    workspace.try_handle_get(handler, "/api/v1/home/summary", {"contract": ["v2"]})
    payload = handler._send_json.call_args.args[0]
    assert payload["problems_found"]["count"] is None
    assert all(item["summary"]["problems_found"]["count"] is None for item in payload["domains"])


def test_endpoint_returns_bounded_summary_and_preserves_reader_scope(monkeypatch):
    definitions = [report(key, i, scope="domain") for i, key in enumerate(home.SUMMARY_REPORTS)]
    other = report("other.report", 4)
    install(monkeypatch, *definitions, other)
    decision = access(*definitions, other)
    handler = SimpleNamespace(_access_decision=lambda: decision, _send_json=Mock())
    assert workspace.try_handle_get(handler, "/api/v1/home/summary", {})
    payload = handler._send_json.call_args.args[0]
    assert route_capability("/api/v1/home/summary") == "workspace.view"
    assert payload["contract_id"] == "sli.home-summary.v1"
    assert len(payload["freshness"]) == 3
    assert len(payload["deviations"]) == 3
    assert len(payload["action_queue"]["items"]) == 5
    assert payload["action_queue"]["has_more"]
    assert payload["action_queue"]["items"][0]["href"].endswith("?status=new&severity=high")
    assert len(payload["reports"]) == 4
    for d in definitions:
        d.query.assert_called_once()
        ctx = d.query.call_args.args[0]
        assert ctx.domain_ids == [7] and ctx.limit == 20
    other.query.assert_not_called()


def test_denied_report_and_field_categories_never_reach_summary(monkeypatch):
    d = report("ad.infrastructure", 1, scope="domain", metric_categories={"attention": frozenset({"secret_category"})})
    hidden = report("hidden.report", 2)
    install(monkeypatch, d, hidden)
    payload = home.home_summary(access(d))
    assert payload["deviations"] == []
    assert [r["key"] for r in payload["reports"]] == [d.key]
    hidden.query.assert_not_called()
    decision = access(d)
    decision["reports"][0]["allowed_actions"] = []
    d.query.reset_mock()
    payload = home.home_summary(decision)
    assert payload["freshness"][0]["state"] == "denied"
    d.query.assert_not_called()


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_summary_preserves_distinct_clocks_and_source_explanations(monkeypatch, version):
    definition = report("ad.infrastructure", 1)
    details = {"reason": "coverage_incomplete", "source_issues": [
        {"source": "7:domain_health", "reason": "source_failed", "since_utc": None},
    ]}
    definition.query.side_effect = lambda ctx: {
        **result(definition, state="partial", coverage={"event_at_utc": "2026-09-01T00:00:00Z",
            "snapshot_at_utc": "2026-09-02T00:00:00Z", "published_at_utc": "2026-10-07T00:00:00Z",
            "last_successful_collection_utc": "2026-10-06T00:00:00Z"}),
        "state_details": details,
        "limitations": [{"code": "coverage", "text": "Synthetic source is incomplete."}],
    }
    install(monkeypatch, definition)
    payload = home.home_summary(access(definition), version=version)
    item = payload["freshness"][0]
    assert item["event_at_utc"] == "2026-09-01T00:00:00Z"
    assert item["snapshot_at_utc"] == "2026-09-02T00:00:00Z"
    assert item["published_at_utc"] == "2026-10-07T00:00:00Z"
    assert item["observed_at_utc"] is None
    assert item["last_successful_check_utc"] == "2026-10-06T00:00:00Z"
    assert item["reason"] == "coverage_incomplete"
    assert item["state_details"] == details
    assert item["limitation"] == "Synthetic source is incomplete."
    if version == "v2":
        reader = payload["readers"][0]
        assert all(reader[key] == value for key, value in item.items())
        assert reader["period_kind"] == "snapshot"
        assert reader["message_code"] == "home.state.partial"


def test_required_domain_never_silently_selects_an_option(monkeypatch):
    d = replace(report("ad.infrastructure", 1, scope="domain"),
                params=(Param("domain", "Domain", "domain", required=True),),
                options=lambda _: {"domain": [{"value": "7", "label": "Synthetic domain"}]})
    install(monkeypatch, d)
    payload = home.home_summary(access(d))
    assert payload["freshness"][0]["reason"] == "domain_required"
    d.query.assert_not_called()
    d = replace(d, options=lambda _: {})
    install(monkeypatch, d)
    assert home.home_summary(access(d))["freshness"][0]["reason"] == "domain_required"
    d.query.assert_not_called()


def test_timeout_degrades_only_affected_report_and_never_returns_false_zeros(monkeypatch):
    d = report("security.problems", 1)
    d.query.side_effect = QueryTimeoutError("Synthetic timeout", timeout_ms=100)
    install(monkeypatch, d)
    payload = home.home_summary(access(d))
    assert payload["freshness"][0]["reason"] == "read_timeout"
    assert payload["deviations"] == []
    assert payload["action_queue"] == {"state": "error", "items": [], "has_more": False}


def test_permission_failure_and_empty_results_are_truthful(monkeypatch):
    handler = SimpleNamespace(_access_decision=dict, _send_json=Mock())
    assert workspace.try_handle_get(handler, "/api/v1/home/summary", {})
    assert handler._send_json.call_args.args[1] == 403
    install(monkeypatch)
    payload = home.home_summary({"capabilities": ["workspace.view"]})
    assert payload["freshness"] == payload["reports"] == payload["deviations"] == []
    with pytest.raises(PermissionError):
        home.home_summary({})


def test_pinned_alias_uses_public_report_route_and_skips_denied_pins(monkeypatch):
    d = replace(report("security.problems", 1), access=AccessRule("security.queue", scope="delegated"))
    install(monkeypatch, d)
    decision = access(d)
    decision["reports"][0].update(report_key="security.queue", pinned=True, target_path="/reports/old.html")
    decision["reports"].append({"report_key": "hidden.report", "allowed": False, "pinned": True})
    payload = home.home_summary(decision)
    assert payload["pinned"] == [{"key": "security.problems", "title": "Synthetic report", "href": "/app/report/security.problems"}]


def test_v2_context_is_explicit_and_has_no_role_view(monkeypatch):
    d = replace(report("security.problems", 1, scope="domain"), params=(Param("domain", "Domain", "domain"),))
    install(monkeypatch, d)
    payload = home.home_summary(access(d), version="v2")
    assert payload["contract_id"] == "sli.home-summary.v2"
    assert payload["context"]["scope"] == "accessible"
    assert payload["context"]["domain_id"] is None
    assert payload["context"]["period"]["kind"] == "snapshot"
    assert payload["context"]["time_zone"] == "UTC"
    assert "view" not in payload["context"]
    assert payload["generated_at_utc"] != payload["readers"][0]["observed_at_utc"]
    assert payload["readers"][0]["scope"] == {"mode": "restricted", "domain_ids": [7]}
    home.home_summary(access(d), version="v2", query={"scope": ["domain"], "domain": ["7"]})
    assert d.query.call_args.args[0].domain_ids == [7]
    d.query.reset_mock()
    with pytest.raises(PermissionError, match="domain_scope_denied"):
        home.home_summary(access(d), version="v2", query={"scope": ["domain"], "domain": ["8"]})
    d.query.assert_not_called()
    for query in ({"view": ["analyst"]}, {"scope": ["domain"]}, {"domain": ["7"]}, {"tz": ["invalid-zone"]},
                  {"scope": ["domain"], "domain": ["7", "8"]}):
        with pytest.raises(ValueError):
            home.home_summary(access(d), version="v2", query=query)


def test_v2_required_domain_needs_an_explicit_selection_even_with_multiple_options(monkeypatch):
    d = replace(report("ad.infrastructure", 1, scope="domain"),
                params=(Param("domain", "Domain", "domain", required=True),),
                options=lambda _: {"domain": [{"value": "7"}, {"value": "8"}]})
    install(monkeypatch, d)
    payload = home.home_summary(access(d), version="v2")
    assert payload["readers"][0]["reason"] == "domain_required"
    assert payload["action_queue"]["items"] == []
    d.query.assert_not_called()
    home.home_summary(access(d), version="v2", query={"scope": ["domain"], "domain": ["7"]})
    assert d.query.call_args.args[0].params["domain"] == 7


def test_v2_attention_order_explanations_and_exact_population_links(monkeypatch):
    from server.sli.reporting.v2.reports.security_problems import _row

    problems = replace(report("security.problems", 0, scope="domain"),
                       params=(Param.choice("population", "Population", (("attention", "Attention"),)),))
    rows = [_row({"id": i, "title": "Synthetic problem", "status": "confirmed", "severity": severity,
                  "repeat_count": repeat, "last_seen_utc": observed, "target": "synthetic-object"}, {})
            for i, severity, repeat, observed in (
                (1, "low", 0, "2026-10-07T01:00:00Z"),
                (2, "high", 0, "2026-10-07T01:00:00Z"),
                (3, "critical", 0, "2026-10-01T01:00:00Z"),
                (4, "high", 3, "2026-10-01T01:00:00Z"),
                (5, "medium", 0, "2026-10-07T01:00:00Z"),
                (6, "high", 3, "2026-10-01T01:00:00+00:00"),
            )]
    problems.query.side_effect = lambda ctx: result(problems, state="ok", items=rows,
        metrics=[{"key": "attention", "value": 6, "filter": {"population": "attention"}}])
    checks = report("ad.infrastructure", 1, scope="domain")
    checks.query.side_effect = lambda ctx: result(checks, state="stale", coverage={"observed_at_utc": "2026-10-01T00:00:00Z"},
        items=[{"row_id": "7:synthetic-check", "qualification": "failed", "label": "Synthetic check"}])
    install(monkeypatch, problems, checks)
    payload = home.home_summary(access(problems, checks), version="v2", query={"scope": ["domain"], "domain": ["7"]})
    assert [item["id"] for item in payload["action_queue"]["items"]] == ["problem:3", "problem:6", "problem:4", "problem:2", "observation:ad.infrastructure"]
    assert payload["action_queue"]["has_more"]
    item = payload["action_queue"]["items"][0]
    assert item["object"] == "synthetic-object"
    assert item["what"] and item["why"] and item["next_step"]
    assert item["observed_at_utc"] == "2026-10-01T01:00:00Z"
    assert item["href"] == "/app/report/security.problems?tz=UTC&domain=7&id=3"
    assert payload["problems_found"]["count"] == 6
    assert payload["problems_found"]["href"] == "/app/report/security.problems?tz=UTC&domain=7&population=attention"
    assert problems.query.call_args.args[0].runtime["home_summary"] is True
    assert problems.query.call_args.args[0].limit == 5


def test_v2_other_decisions_precede_ad_checks_and_time_precedes_stable_id(monkeypatch):
    problems = report("security.problems", 0, scope="domain")
    problems.query.side_effect = lambda ctx: result(problems, state="ok", items=[
        {"id": 9, "status": "new", "severity": "low", "last_seen_utc": "2026-10-01T00:00:00Z"},
        {"id": 1, "status": "new", "severity": "low", "last_seen_utc": "2026-10-02T00:00:00Z"},
        {"id": 10, "status": "active", "severity": "critical"},
    ])
    checks = report("ad.infrastructure", 1, scope="domain")
    checks.query.side_effect = lambda ctx: result(checks, state="ok", items=[
        {"row_id": "7:check", "qualification": "failed", "label": "Synthetic check"},
        {"row_id": "7:passed", "qualification": "passed"},
    ])
    install(monkeypatch, problems, checks)
    payload = home.home_summary(access(problems, checks), version="v2")
    assert [item["id"] for item in payload["action_queue"]["items"]] == ["problem:1", "problem:9", "ad-check:7:check"]
    assert payload["action_queue"]["items"][-1]["href"].endswith("row_id=7%3Acheck")


@pytest.mark.parametrize("state", ["empty", "partial", "stale", "processing", "not_collected", "error", "denied"])
def test_v2_states_do_not_invent_safe_zero_counts(monkeypatch, state):
    d = report("security.problems", 1)
    d.query.side_effect = lambda ctx: result(d, state=state)
    install(monkeypatch, d)
    payload = home.home_summary(access(d), version="v2")
    assert payload["problems_found"]["state"] == state
    assert payload["problems_found"]["count"] is None
    assert payload["problems_found"]["message_code"] == "home.problems.unknown"
    assert payload["observation_health"]["state"] != "ok"


def test_v2_period_links_use_the_same_exact_window_and_shared_read_budget(monkeypatch):
    from server.sli.reporting import read_timeout

    d = replace(report("security.problems", 1, scope="domain"), params=(Param.text("time_from", "From"), Param.text("time_to", "To")))
    e = report("ad.infrastructure", 2, scope="domain")
    deadlines = []
    for definition in (d, e):
        definition.query.side_effect = lambda ctx: deadlines.append(read_timeout._deadline.get()) or {"state": "empty"}
    install(monkeypatch, d, e)
    payload = home.home_summary(access(d, e), version="v2", query={"period": ["custom"], "from": ["2026-10-01"], "to": ["2026-10-01"], "tz": ["Asia/Bangkok"]})
    period = payload["context"]["period"]
    assert period["from_utc"] == "2026-09-30T17:00:00Z"
    assert period["to_utc"] == "2026-10-01T17:00:00Z"
    assert d.query.call_args.args[0].params == {"time_from": period["from_utc"], "time_to": period["to_utc"]}
    assert deadlines[0] is not None and deadlines[0] == deadlines[1]
    assert "time_from=2026-09-30T17%3A00%3A00Z" in payload["problems_found"]["href"]
    assert [reader["period_kind"] for reader in payload["readers"]] == ["observations", "snapshot"]


def test_v2_timeout_is_local_and_endpoint_rejects_role_parameters(monkeypatch):
    broken, healthy = report("security.problems", 1), report("ad.infrastructure", 2)
    broken.query.side_effect = QueryTimeoutError("Synthetic timeout", timeout_ms=100)
    install(monkeypatch, broken, healthy)
    decision = access(broken, healthy)
    handler = SimpleNamespace(_access_decision=lambda: decision, _send_json=Mock())
    workspace.try_handle_get(handler, "/api/v1/home/summary", {"contract": ["v2"]})
    payload = handler._send_json.call_args.args[0]
    assert [reader["state"] for reader in payload["readers"]] == ["error", "partial"]
    healthy.query.assert_called_once()
    workspace.try_handle_get(handler, "/api/v1/home/summary", {"contract": ["v2"], "view": ["analyst"]})
    assert handler._send_json.call_args.args[1] == 400


def test_v2_exhausted_budget_does_not_start_another_reader(monkeypatch):
    d, e = report("security.problems", 1), report("ad.infrastructure", 2)
    install(monkeypatch, d, e)
    calls = 0

    def remaining():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise QueryTimeoutError("Synthetic budget exhausted", timeout_ms=100)
        return 100

    monkeypatch.setattr(home, "remaining_read_ms", remaining)
    payload = home.home_summary(access(d, e), version="v2")
    d.query.assert_called_once()
    e.query.assert_not_called()
    assert payload["readers"][1]["state"] == "error"
    assert payload["readers"][1]["reason"] == "read_timeout"


def test_v2_real_ad_reader_filters_the_exact_control_without_a_db(monkeypatch):
    from server.sli.reporting.v2.definition import QueryContext
    from server.sli.reporting.v2.reports import ad_state

    calls = []
    monkeypatch.setattr(ad_state, "get_active_directory_report", lambda **kwargs: calls.append(kwargs) or {
        "state": "available", "coverage": {}, "controls": [
            {"entity_id": 7, "control_id": "synthetic-a", "qualification": "failed"},
            {"entity_id": 7, "control_id": "synthetic-b", "qualification": "passed"},
        ],
    })
    context = QueryContext(access={}, params={"row_id": "7:synthetic-a"}, domain_ids=[7],
                           action="view", cursor=None, limit=20, timezone="UTC")
    payload = ad_state._query(context)
    assert [row["row_id"] for row in payload["items"]] == ["7:synthetic-a"]
    assert calls[0]["domain_ids"] == [7]


def test_v2_multidomain_accessible_scope_keeps_all_authorized_domains(monkeypatch):
    d = report("ad.infrastructure", 1, scope="domain")
    install(monkeypatch, d)
    decision = access(d)
    decision["reports"][0]["grants"][0]["scope"]["ids"] = [7, 8]
    payload = home.home_summary(decision, version="v2")
    assert d.query.call_args_list[0].args[0].domain_ids == [7, 8]
    assert payload["readers"][0]["scope"]["domain_ids"] == [7, 8]
    assert payload["context"]["domain_id"] is None


def test_v2_inactive_analysis_returns_an_observation_break_even_with_zero_problems(monkeypatch):
    d = report("security.problems", 1)
    d.query.side_effect = lambda ctx: result(d, state="partial", coverage={"state": "inactive"},
                                           metrics=[{"key": "attention", "value": 0}])
    install(monkeypatch, d)
    payload = home.home_summary(access(d), version="v2")
    assert payload["problems_found"]["count"] == 0
    assert payload["observation_health"]["state"] == "partial"
    assert payload["action_queue"]["items"][0]["priority_group"] == 1
    assert payload["action_queue"]["items"][0]["message_code"] == "home.attention.analysis_unconfirmed"


def test_registered_home_contribution_is_scoped_and_preserves_zero_baselines(monkeypatch):
    from server.sli.reporting.v2.definition import HomeContribution

    reader = Mock(return_value={"state": "ok", "metrics": [{"key": "events", "value": 4, "previous_value": 0}],
                               "coverage": {"complete": True, "sources": [7]},
                               "previous_coverage": {"complete": True, "sources": [7]}})
    d = report("synthetic.plugin", None, scope="domain", home_contributions=(HomeContribution(
        key="synthetic", metric_key="events", label_code="home.kpi.privileged_changes", unit_code="home.unit.events",
        period_kind="observations", reader=reader),))
    install(monkeypatch, d)
    payload = home.home_summary(access(d), version="v2")
    kpi = payload["kpis"][0]
    assert kpi["value"] == 4 and kpi["comparison"]["absolute_change"] == 4
    assert kpi["comparison"]["percent_change"] is None
    assert reader.call_args.args[0].domain_ids == [7]
    assert reader.call_args.args[0].runtime["home_windows"][0]["to_utc"] in kpi["href"].replace("%3A", ":")
    assert payload["readers"][0]["period_kind"] == "observations"


def test_disabled_plugin_explains_and_absent_definition_contributes_nothing(monkeypatch):
    from server.sli.reporting.v2.definition import HomeContribution

    reader = Mock()
    d = report("synthetic.plugin", None, scope="domain", home_contributions=(HomeContribution(
        key="synthetic", metric_key="events", label_code="home.kpi.privileged_changes", unit_code="home.unit.events",
        reader=reader, availability=lambda: {"state": "disabled"}),))
    install(monkeypatch, d)
    kpi = home.home_summary(access(d), version="v2")["kpis"][0]
    assert kpi["value"] is None and kpi["message_code"] == "home.plugin.disabled"
    reader.assert_not_called()
    install(monkeypatch)
    assert home.home_summary(access(d), version="v2")["kpis"] == []


def test_contribution_dependencies_do_not_cross_field_grants(monkeypatch):
    from server.sli.reporting.v2.definition import HomeContribution

    reader = Mock()
    d = report("synthetic.plugin", None, scope="domain", home_contributions=(HomeContribution(
        key="synthetic", metric_key="events", label_code="home.kpi.privileged_changes", unit_code="home.unit.events",
        reader=reader, required_fields=frozenset({"privilege"})),))
    install(monkeypatch, d)
    assert home.home_summary(access(d), version="v2")["kpis"][0]["state"] == "denied"
    reader.assert_not_called()


def test_contributions_share_and_measure_elapsed_read_budget(monkeypatch):
    from server.sli.reporting import read_timeout
    from server.sli.reporting.v2.definition import HomeContribution

    clock = [10.0]
    monkeypatch.setattr(read_timeout, "monotonic", lambda: clock[0])
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "100")
    called = []

    def read(ctx):
        called.append(read_timeout.remaining_read_ms())
        clock[0] += 0.2
        return {"state": "ok", "metrics": [{"key": "events", "value": 2}]}

    definitions = [report(f"synthetic.{i}", None, scope="domain", home_contributions=(HomeContribution(
        key=f"synthetic_{i}", metric_key="events", label_code="home.kpi.privileged_changes",
        unit_code="home.unit.events", reader=read),)) for i in range(2)]
    install(monkeypatch, *definitions)
    payload = home.home_summary(access(*definitions), version="v2")
    assert len(called) == 1 and 0 < called[0] <= 100
    assert payload["kpis"][1]["state"] == "error"
    assert payload["readers"][1]["reason"] == "read_timeout"
    assert read_timeout.remaining_read_ms() is None


def test_registry_attention_and_health_contributions_are_projected(monkeypatch):
    from server.sli.reporting.v2.definition import HomeContribution

    candidate = {"id": "synthetic:1", "kind": "observation", "priority_group": 1, "severity": None,
                 "needs_decision": False, "repeat_count": 0, "observed_at_utc": None,
                 "message_code": "home.attention.processing", "href": "/app/report/synthetic.plugin"}
    d = report("synthetic.plugin", None, scope="domain", home_contributions=(HomeContribution(
        key="synthetic", metric_key="events", label_code="home.kpi.privileged_changes", unit_code="home.unit.events",
        reader=lambda ctx: {"state": "partial", "metrics": [{"key": "events", "value": 2}]},
        attention=lambda data, href: [candidate]),))
    install(monkeypatch, d)
    payload = home.home_summary(access(d), version="v2")
    assert payload["action_queue"]["items"] == [candidate]
    assert payload["observation_health"]["state"] == "partial"


def test_failed_attention_hook_preserves_other_contributions(monkeypatch):
    from server.sli.reporting.v2.definition import HomeContribution

    d = report("synthetic.plugin", None, scope="domain", home_contributions=(HomeContribution(
        key="synthetic", metric_key="events", label_code="home.kpi.privileged_changes", unit_code="home.unit.events",
        reader=lambda ctx: {"state": "ok", "metrics": [{"key": "events", "value": 2}]},
        attention=Mock(side_effect=RuntimeError("Synthetic failure"))),))
    install(monkeypatch, d)
    payload = home.home_summary(access(d), version="v2")
    assert payload["kpis"][0]["value"] == 2 and payload["action_queue"]["items"] == []


@pytest.mark.parametrize("version", ["v1", "v2"])
@pytest.mark.parametrize("selected", [None, "7", "8"])
def test_home_domain_selection_and_breakdown_use_each_readers_own_rights(monkeypatch, version, selected):
    from server.sli.reporting.v2.definition import HomeContribution

    d = report("ad.infrastructure", 1, scope="domain", home_contributions=(HomeContribution(
        key="synthetic", metric_key="attention", label_code="home.kpi.privileged_changes", unit_code="home.unit.events"),))
    restricted = report("ad.computers.v6", 2, scope="domain")
    install(monkeypatch, d, restricted)
    decision = access(d, restricted)
    decision["reports"][0]["grants"][0]["scope"]["ids"] = [7, 8]

    def read(ctx):
        return result(d, state="partial", metrics=[{"key": "attention", "value": sum(ctx.domain_ids)}],
                      coverage={"observed_at_utc": str(ctx.domain_ids)})

    d.query.side_effect = read
    handler = SimpleNamespace(_access_decision=lambda: decision, _send_json=Mock())
    query = {"contract": [version], **({"domain_id": [selected]} if selected else {})}
    workspace.try_handle_get(handler, "/api/v1/home/summary", query)
    payload = handler._send_json.call_args.args[0]
    ids = [int(selected)] if selected else [7, 8]
    assert payload["domain_scope"]["domain_ids"] == ids
    assert [domain["id"] for domain in payload["domains"]] == ids
    assert payload["metrics"][0]["items"][0]["value"] == sum(ids)
    for domain in payload["domains"]:
        assert domain["summary"]["metrics"][0]["items"][0]["value"] == domain["id"]
        assert domain["summary"]["freshness"][0]["observed_at_utc"] == str([domain["id"]])
        assert domain["freshness"]["observed_at_utc"] == f"2026-10-0{domain['id'] - 6}T00:00:00Z"
        assert domain["summary"]["metrics"][1]["state"] == ("partial" if domain["id"] == 7 else "denied")
        if version == "v2":
            assert domain["summary"]["kpis"][0]["value"] == domain["id"]
    assert all(call.args[0].domain_ids == [7] for call in restricted.query.call_args_list)


@pytest.mark.parametrize("version", ["v1", "v2"])
@pytest.mark.parametrize("selected", ["8", "9"])
def test_home_rejects_foreign_or_unknown_domain_before_any_reader(monkeypatch, version, selected):
    d = report("ad.infrastructure", 1, scope="domain")
    install(monkeypatch, d)
    decision = access(d)
    handler = SimpleNamespace(_access_decision=lambda: decision, _send_json=Mock())
    workspace.try_handle_get(handler, "/api/v1/home/summary", {"contract": [version], "domain_id": [selected]})
    assert handler._send_json.call_args.args == ({"error": "domain_scope_denied"}, 403)
    d.query.assert_not_called()


def test_home_with_no_registered_domains_never_reads_unscoped_counts(monkeypatch):
    d = report("ad.infrastructure", 1, scope="domain")
    install(monkeypatch, d)
    decision = access(d)
    decision["reports"][0]["grants"][0]["scope"] = {"kind": "all"}
    monkeypatch.setattr(domain_scope, "_domain_rows", lambda ids: [])
    payload = home.home_summary(decision, version="v2")
    assert payload["domains"] == []
    assert payload["domain_scope"]["state"] == "no_domains"
    assert payload["metrics"][0]["state"] == "denied"
    d.query.assert_not_called()


@pytest.mark.parametrize("query", [{"domain_id": [""]}, {"domain_id": ["7", "8"]},
    {"domain_id": ["7"], "domain": ["7"]}, {"domain_id": ["7"], "scope": ["domain"]}])
def test_home_rejects_invalid_or_conflicting_domain_parameters(monkeypatch, query):
    d = report("ad.infrastructure", 1, scope="domain")
    install(monkeypatch, d)
    handler = SimpleNamespace(_access_decision=lambda: access(d), _send_json=Mock())
    workspace.try_handle_get(handler, "/api/v1/home/summary", query)
    assert handler._send_json.call_args.args[1] == 400
    d.query.assert_not_called()


def test_home_domain_breakdown_shares_the_request_budget(monkeypatch):
    from server.sli.reporting import read_timeout

    d = report("ad.infrastructure", 1, scope="domain")
    install(monkeypatch, d)
    decision = access(d)
    decision["reports"][0]["grants"][0]["scope"]["ids"] = [7, 8]
    clock = [10.0]
    monkeypatch.setattr(read_timeout, "monotonic", lambda: clock[0])
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "100")

    def read(ctx):
        clock[0] += 0.2
        return result(d, state="ok", metrics=[{"key": "attention", "value": 15}])

    d.query.side_effect = read
    payload = home.home_summary(decision, version="v2")
    assert payload["metrics"][0]["items"][0]["value"] == 15
    assert len(payload["domains"]) == 2
    for domain in payload["domains"]:
        summary = domain["summary"]
        assert summary["metrics"][0]["items"] == []
        assert summary["freshness"][0]["reason"] == "read_timeout"
    d.query.assert_called_once()
    assert read_timeout.remaining_read_ms() is None
