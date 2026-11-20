from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

from server.sli.access.scope import AccessScope
from server.sli.plugins.ad import home as ad
from server.sli.plugins.remote_access import home as vpn
from server.sli.reporting import read_timeout
from server.sli.reporting.v2.definition import QueryContext

WINDOWS = ({"from_utc": "2026-10-02T00:00:00Z", "to_utc": "2026-10-03T00:00:00Z"},
           {"from_utc": "2026-10-01T00:00:00Z", "to_utc": "2026-10-02T00:00:00Z"})


def context():
    return QueryContext(access={}, params={"domain": 7, "period": WINDOWS[0]}, domain_ids=[7],
                        scope=AccessScope("all"), runtime={"home_windows": WINDOWS})


def test_vpn_capability_denial_does_not_read_session_views(monkeypatch):
    sql = Mock()
    monkeypatch.setattr(vpn, "query_rows_bounded", sql)
    monkeypatch.setattr(vpn, "vpn_report_composition_decision", lambda *args, **kwargs: SimpleNamespace(sessions=SimpleNamespace(allowed=False)))
    assert vpn.read(context()) == {"state": "denied"}
    sql.assert_not_called()


def test_vpn_compact_aggregates_keep_zero_base_and_share_measured_budget(monkeypatch):
    monkeypatch.setattr(vpn, "vpn_report_composition_decision", lambda *args, **kwargs: SimpleNamespace(sessions=SimpleNamespace(allowed=True)))
    monkeypatch.setattr(vpn, "_coverage_state", lambda _: "available")
    coverage = {"history_available_from_utc": "2026-09-01T00:00:00Z", "history_available_to_utc": "2026-10-04T00:00:00Z"}
    clock, budgets, calls = [10.0], [], []
    monkeypatch.setattr(read_timeout, "monotonic", lambda: clock[0])
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "1000")

    def query(sql, params, **kwargs):
        calls.append((sql, params))
        budgets.append(read_timeout.remaining_read_ms())
        clock[0] += 0.025
        return [coverage] if "coverage_v1" in sql else [{"current_count": 4, "previous_count": 0}]

    monkeypatch.setattr(vpn, "query_rows_bounded", query)
    with read_timeout.report_read_budget():
        data = vpn.read(context())
    assert data["metrics"] == [{"key": "closed", "value": 4, "previous_value": 0}]
    assert data["comparison_coverage"] == data["previous_coverage"] == {"domains": [7], "state": "available", "complete": True}
    assert len(calls) == 2 and 0 < budgets[1] < budgets[0] <= 1000
    assert calls[0][1] == (7,)
    assert calls[1][1] == ("2026-10-03T00:00:00Z", "2026-10-02T00:00:00Z", "2026-10-02T00:00:00Z",
                           "2026-10-01T00:00:00Z", 7, "2026-10-03T00:00:00Z", "2026-10-01T00:00:00Z")
    coverage["history_available_from_utc"] = "2026-10-02T00:00:00Z"
    assert vpn.read(context())["metrics"][0]["previous_value"] is None


def test_ad_history_and_drilldown_use_the_same_authorized_window_without_claiming_stream_coverage(monkeypatch):
    observed = datetime(2026, 10, 2, tzinfo=timezone.utc)
    calls = []

    def query(sql, params, **kwargs):
        calls.append((sql, params))
        if "group by run.domain_id" in sql:
            return [{"domain_id": 7, "history_from": datetime(2026, 9, 1, tzinfo=timezone.utc), "observed_at_utc": observed}]
        if "select relation.id" in sql:
            return [{"id": 1, "entity_id": 2, "group_id": 3, "kind": "removed", "observed_at_utc": observed}]
        return [{"current_count": 4, "previous_count": 2}]

    monkeypatch.setattr(ad, "query_rows_bounded", query)
    data = ad.read(context(), details=True)
    assert data["metrics"][0]["value"] == 4 and data["metrics"][0]["previous_value"] == 2
    assert data["comparison_coverage"]["complete"] is False
    assert data["items"][0]["row_id"] == "1:removed"
    assert len(calls) == 3
    # Query contract: the initial population is not an addition; its later
    # removal is a change, while adjacent content versions are not changes.
    assert "change.kind='removed' or exists" in calls[0][0]
    assert "adjacent.valid_to_utc=change.at" in calls[0][0]
    assert "adjacent.valid_from_utc=change.at" in calls[0][0]
    assert "relation.domain_id=any(?)" in calls[0][0] and "relation.domain_id=any(?)" in calls[2][0]
    assert calls[0][1][2:] == ([7], "2026-10-01T00:00:00Z", "2026-10-03T00:00:00Z")
    assert calls[2][1] == ([7], "2026-10-02T00:00:00Z", "2026-10-03T00:00:00Z", 101, 0)
    missing = replace(context(), domain_ids=[8])
    assert ad.read(missing)["metrics"][0]["previous_value"] is None


def test_vpn_report_contribution_is_discovered_only_with_the_installed_package(monkeypatch):
    from server.sli.plugins import registry as plugins
    from server.sli.reporting.v2 import registry

    registry.registered_reports.cache_clear()
    try:
        definition = registry.get_report("vpn.connections")
        assert definition is not None and definition.home_contributions[0].key == "vpn_closed"
        from server.sli.plugins.remote_access import home as active_home
        from server.sli.plugins.remote_access.reports import vpn_connections
        from server.sli.reporting.v2.reports import vpn_connections as legacy

        # The registry wraps executors for generation admission; compatibility
        # imports still expose the active package's original declaration.
        assert vpn_connections.REPORT is legacy.REPORT
        assert definition.to_json() == vpn_connections.REPORT.to_json()
        assert definition.home_contributions == (active_home.CLOSED_SESSIONS,)
        assert vpn_connections.REPORT.query.__module__ == "server.sli.plugins.remote_access.reports.vpn_connections"
        monkeypatch.setattr(plugins, "discover_plugins", tuple)
        plugins.registered_plugins.cache_clear()
        assert not plugins.plugin_installed("sli.remote-access")
        # Installation state changes the report cache key without a manual reset.
        assert registry.get_report("vpn.connections") is None
        assert not any(contribution.key == "vpn_closed"
                       for report in registry.registered_reports()
                       for contribution in report.home_contributions)
    finally:
        plugins.registered_plugins.cache_clear()
        registry.registered_reports.cache_clear()


def test_ad_history_and_privileged_drilldown_remain_independent(monkeypatch):
    from server.sli.reporting.v2.reports import ad_state

    definition = ad_state.REPORT
    periods = [param for param in definition.params if param.key == "period"]
    assert len(periods) == 1 and periods[0].max_days == 3650
    assert ad.PRIVILEGED_CHANGES in definition.home_contributions
    assert {view.key for view in definition.views} >= {"changes", "privileged_changes"}
    history = Mock(return_value={"state": "partial"})
    membership = Mock(return_value={"state": "ok", "items": [{"entity_id": 2, "group_id": 3, "kind": "removed"}],
                                    "coverage": {}, "limitations": [], "has_more": False})
    monkeypatch.setattr(ad_state, "query_history", history)
    monkeypatch.setattr(ad_state, "read_membership_changes", membership)

    history_context = replace(context(), tab="changes")
    assert definition.query(history_context) == {"state": "partial"}
    history.assert_called_once_with(definition, history_context, ("users_v2", "computers_v6"))
    membership.assert_not_called()

    member_context = replace(context(), tab="privileged_changes")
    payload = definition.query(member_context)
    assert payload["items"] == payload["collections"]["privileged_changes"] == membership.return_value["items"]
    membership.assert_called_once_with(member_context, details=True)
    history.assert_called_once()
    csv, metadata = definition.export_csv(member_context)
    assert "Удаление" in csv
    assert metadata == {"rows": 1, "truncated": False}
