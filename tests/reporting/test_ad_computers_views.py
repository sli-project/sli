"""Computer report tabs use scoped synthetic readers, never a database."""
from copy import deepcopy

import pytest

from server.sli.plugins.ad.reports.definitions import computers
from server.sli.plugins.ad.reports import computer_changes
from server.sli.reporting.v2.definition import QueryContext
from tests.reporting.test_reporting_v2_field_access import access, call, grant


@pytest.fixture
def reader(monkeypatch):
    calls = []
    raw = {
        "state": "available", "items": [{"entity_id": 1, "display_name": "synthetic-host",
                                             "computer_type": "domain_controller"}],
        "coverage": {"state": "complete"}, "summary": {"total_computers": 1},
        "filtered_count": 1, "snapshot_comparison": {"state": "available", "current": {
            "captured_at_utc": "2026-10-17T03:00:00Z"}},
    }

    def read(**kwargs):
        calls.append(kwargs)
        return deepcopy(raw)

    monkeypatch.setattr(computers, "get_computers_v6_report", read)
    monkeypatch.setattr("server.sli.core.database.query_rows", lambda *args, **kwargs: pytest.fail("real database read"))
    return raw, calls


@pytest.fixture
def agent_reader(monkeypatch):
    calls = []
    obj = {"object_guid": "synthetic-guid", "display_name": "synthetic-host", "computer_type": "server",
           "operating_system": "Windows Server 2022", "enabled": True, "ou_path": "OU=synthetic"}
    bundles = [{"domain_id": 2, "domain_name": "synthetic.invalid",
                "current": {"state": "complete", "observed_at": "2026-10-17T03:00:00Z", "objects": [obj]},
                "previous": {"state": "complete", "observed_at": "2026-10-16T03:00:00Z", "objects": []}}]

    def load(kind, ids, since):
        calls.append((kind, ids, since))
        return deepcopy(bundles)

    monkeypatch.setattr(computer_changes.review_checks, "load_snapshots", load)
    monkeypatch.setattr(computers, "get_computers_v6_report", lambda **kwargs: pytest.fail("legacy snapshot read"))
    return bundles, calls


def test_exact_three_tabs_and_inventory_name_opens_overlay():
    assert [view.key for view in computers.REPORT.views] == ["checks", "changes", "computers"]
    assert computers.REPORT.columns[0].link is None
    view = next(param for param in computers.REPORT.params if param.key == "view")
    assert view.default == "all" and view.hidden


def test_inventory_tab_defaults_to_all_and_keeps_scope_filters_paging(reader):
    _, calls = reader
    result = computers._query(QueryContext({}, {"q": "synthetic", "type": "domain_controller"},
                                          domain_ids=[2], tab="computers", limit=1, cursor="opaque"))
    assert result["items"][0]["computer_type"] == "domain_controller"
    assert calls[0]["view"] == "all"
    assert calls[0]["domain_ids"] == [2] and calls[0]["cursor"] == "opaque"
    assert calls[0]["computer_type"] == "domain_controller" and calls[0]["q"] == "synthetic"


def test_inventory_selection_limit_remains_an_explicit_coverage_gap(reader):
    raw, _ = reader
    raw["limits"] = {"input_truncated": True}
    assert computers._query(QueryContext({}, {}, tab="computers"))["coverage"]["truncated"] is True


def test_changes_tab_uses_agent_pair_and_preserves_actual_object(agent_reader):
    _, calls = agent_reader
    data = computers._query(QueryContext({}, {"view": "attention"}, domain_ids=[2], tab="changes"))
    assert calls == [("computers", [2], None)]
    change = data["collections"]["changes"][0]
    assert change["computer_type"] == "server"
    assert change["operating_system"] == "Windows Server 2022"
    assert change["observed_at_utc"] == "2026-10-17T03:00:00+00:00"
    assert change["actor"] is None


def test_missing_comparison_is_not_a_confirmed_empty_history(agent_reader):
    bundles, _ = agent_reader
    bundles[0].pop("previous")
    data = computers._query(QueryContext({}, {}, tab="changes"))
    assert data["state"] == "not_collected" and data["filtered_count"] is None


def test_changes_csv_exports_selected_tab_not_inventory(agent_reader):
    bundles, calls = agent_reader
    bundles[0]["current"]["objects"][0]["display_name"] = "=synthetic"
    body, metadata = computers._export(QueryContext({}, {}, domain_ids=[2], tab="changes", action="export"))
    assert calls == [("computers", [2], None)]
    assert "Было" in body and "Стало" in body and "'=synthetic" in body
    assert metadata == {"rows": 1, "truncated": False}


def test_http_changes_contract_uses_authorized_domain_and_its_columns(monkeypatch, agent_reader):
    _, calls = agent_reader
    decision = access(grant({"identity_basic", "technical", "security"}, ids=(2,)), key=computers.REPORT_KEY)
    handler = call(monkeypatch, computers.REPORT, decision, "/data", {"tab": ["changes"], "domain_id": ["2"]})
    payload, status = handler.sent[-1]
    assert status == 200
    assert payload["collections"]["changes"][0]["change_type"] == "new_object"
    assert calls == [("computers", [2], None)]
    denied = call(monkeypatch, computers.REPORT, decision, "/data", {"tab": ["changes"], "domain_id": ["3"]})
    assert denied.sent[-1][1] == 403 and len(calls) == 1


def test_changes_include_only_observed_differences_and_never_invent_actor(agent_reader):
    bundles, _ = agent_reader
    current = bundles[0]["current"]["objects"][0]
    current.update(enabled=False, delegation={"unconstrained": True})
    bundles[0]["previous"]["objects"] = [{**current, "enabled": True, "ou_path": "OU=previous",
                                          "delegation": {"unconstrained": False}, "laps_password_expiration_utc": None}]
    rows = computer_changes.compare(bundles[0])
    assert {row["change_type"] for row in rows} == {"enabled_changed", "ou_changed", "delegation_changed"}
    assert all(row["actor"] is None for row in rows)
    assert next(row for row in rows if row["field"] == "enabled")["after"] is False


def test_changes_sort_domains_by_time_and_page_without_duplication(agent_reader):
    bundles, _ = agent_reader
    later = deepcopy(bundles[0])
    later.update(domain_id=3, domain_name="later.invalid")
    later["current"]["observed_at"] = "2026-10-17T04:00:00Z"
    bundles.append(later)
    context = QueryContext({}, {}, tab="changes", domain_ids=[2, 3], limit=1)
    first = computers._query(context)
    assert first["items"][0]["domain_id"] == 3 and first["has_more"]
    from dataclasses import replace
    second = computers._query(replace(context, cursor=first["next_cursor"]))
    assert second["items"][0]["domain_id"] == 2 and not second["has_more"]
    filtered = computers._query(replace(context, params={"q": "later.invalid"}))
    assert filtered["filtered_count"] == 1
    with pytest.raises(ValueError, match="cursor_invalid"):
        computers._query(replace(context, cursor="not-in-scope"))


def test_missing_object_is_not_called_deleted_and_field_denial_prevents_read(agent_reader):
    bundles, calls = agent_reader
    bundles[0]["previous"]["objects"] = bundles[0]["current"]["objects"]
    bundles[0]["current"]["objects"] = []
    assert computer_changes.compare(bundles[0])[0]["change_type"] == "missing_current"
    assert computers._query(QueryContext({}, {}, tab="changes", field_access=lambda fields: False))["state"] == "denied"
    assert not calls


def test_unknown_fields_do_not_become_false_changes_and_safe_source_facts_reach_preview(agent_reader):
    bundles, _ = agent_reader
    obj = bundles[0]["current"]["objects"][0]
    bundles[0]["previous"]["objects"] = [{**obj, "enabled": None, "delegation": {"unconstrained": None}}]
    obj["delegation"] = {"unconstrained": True}
    assert computer_changes.compare(bundles[0]) == []
    source = computer_changes.review_checks._computer({
        "objectGuid": "synthetic-guid", "name": "synthetic-host", "ou": "OU=synthetic",
        "deviceType": "server", "osName": "Windows Server 2022", "userAccountControl": 524288,
    }, "2026-10-17T03:00:00Z")
    assert source["ou_path"] == "OU=synthetic"
    bundles[0]["current"]["objects"] = [source]
    data = computer_changes.review_checks.summarize("computers", bundles)
    preview = next(check for check in data["items"] if check["key"] == "unconstrained_delegation")["objects"][0]
    assert preview["operating_system"] == "Windows Server 2022" and preview["ou_path"] == "OU=synthetic"


def test_invalid_snapshot_clock_is_not_a_confirmed_empty_comparison(agent_reader):
    bundles, _ = agent_reader
    bundles[0]["current"]["observed_at"] = None
    assert computers._query(QueryContext({}, {}, tab="changes"))["state"] == "not_collected"


def test_database_timestamp_values_are_serializable_on_the_wire(agent_reader):
    import json
    from datetime import datetime, timezone
    bundles, _ = agent_reader
    bundles[0]["current"]["observed_at"] = datetime(2026, 10, 17, 3, tzinfo=timezone.utc)
    data = computers._query(QueryContext({}, {}, tab="changes"))
    assert json.loads(json.dumps(data))["items"][0]["observed_at_utc"] == "2026-10-17T03:00:00+00:00"
