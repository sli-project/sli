from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from server.api.routes import workspace
from server.sli.access import domain_scope
from server.sli.access.access_control_v4 import route_capability
from server.sli.reporting.v2 import registry
from server.sli.reporting.v2.definition import AccessRule


def decision(ids):
    return {"capabilities": ["workspace.view"], "reports": [{
        "report_key": "synthetic", "allowed": True, "allowed_actions": ["view"],
        "grants": [{"allowed_actions": ["view"], "field_categories": ["technical"],
                    "scope": {"kind": "all"} if ids is None else {"kind": "domain", "ids": ids}}],
    }] if ids != [] else []}


@pytest.fixture
def domain_query(monkeypatch):
    definition = SimpleNamespace(access=AccessRule("synthetic", frozenset({"technical"})))
    monkeypatch.setattr(registry, "registered_reports", lambda: (definition,))
    observed = datetime(2026, 10, 1, tzinfo=timezone.utc)

    def query(sql, params):
        assert "where (?::bigint[] is null or d.id=any(?::bigint[]))" in sql
        assert "s.domain_id=d.id" in sql
        assert "other.id<>s.id" in sql
        assert "from events_v2_core" not in sql
        ids, same_ids = params
        assert ids == same_ids
        return [{"id": id, "display_name": f"domain-{id}.example.test",
                 "observed_at_utc": observed, "snapshot_at_utc": observed,
                 "published_at_utc": None, "event_at_utc": None, "snapshot_state": "partial"}
                for id in (7, 8) if ids is None or id in ids]

    fake = Mock(side_effect=query)
    monkeypatch.setattr(domain_scope, "query_rows_bounded", fake)
    return fake


@pytest.mark.parametrize("ids", [[], [7], [7, 8], None])
def test_list_only_accessible_registered_domains(domain_query, ids):
    access = decision(ids)
    handler = SimpleNamespace(_access_decision=lambda: access, _send_json=Mock())
    assert workspace.try_handle_get(handler, "/api/v1/domains", {})
    items = handler._send_json.call_args.args[0]["items"]
    assert [item["id"] for item in items] == ([7, 8] if ids is None else ids)
    for item in items:
        assert item["display_name"].endswith(".example.test")
        assert item["freshness"]["observed_at_utc"] == "2026-10-01T00:00:00+00:00"
        assert item["freshness"]["event_at_utc"] is None
    if ids == []:
        domain_query.assert_not_called()
    assert route_capability("/api/v1/domains") == "workspace.view"


@pytest.mark.parametrize("ids, selected", [([7], "8"), ([], "7"), (None, "9"), ([7, 9], "9")])
def test_foreign_and_unknown_domain_fail_closed(domain_query, ids, selected):
    with pytest.raises(PermissionError, match="^domain_scope_denied$"):
        domain_scope.resolve_domain_selection(decision(ids), {"domain_id": [selected]})
    if ids is not None and int(selected) not in ids:
        domain_query.assert_not_called()


@pytest.mark.parametrize("value", [[], [""], ["0"], ["-1"], ["7", "8"], [7], "7", ["all"], [" 7"], ["7.0"], ["9" * 20]])
def test_explicit_invalid_domain_is_never_all(domain_query, value):
    with pytest.raises(ValueError, match="domain_scope_invalid"):
        domain_scope.resolve_domain_selection(decision(None), {"domain_id": value})
    domain_query.assert_not_called()


def test_selection_requires_workspace_and_atomic_report_fields(domain_query):
    with pytest.raises(PermissionError, match="workspace_view_required"):
        domain_scope.resolve_domain_selection({}, {})
    access = decision([7])
    access["reports"][0]["grants"][0]["field_categories"] = []
    assert domain_scope.resolve_domain_selection(access, {}).domains == ()
    access["reports"][0]["grants"][0]["field_categories"] = ["technical"]
    access["reports"][0]["grants"][0]["scope"] = {
        "mode": "restricted", "clauses": [{"device_ids": ["server:1"], "collection_scope_ids": ["ad-domain:7"]}],
    }
    assert domain_scope.resolve_domain_selection(access, {}).domain_ids == []
    domain_query.assert_not_called()


def test_revocation_is_checked_again_without_a_shared_cache(domain_query):
    access = decision([7, 8])
    assert domain_scope.resolve_domain_selection(access, {"domain_id": ["8"]}).domain_ids == [8]
    access["reports"][0]["grants"][0]["scope"]["ids"] = [7]
    with pytest.raises(PermissionError, match="domain_scope_denied"):
        domain_scope.resolve_domain_selection(access, {"domain_id": ["8"]})
    assert domain_query.call_count == 1


def test_registry_failure_is_not_an_empty_domain_list(domain_query):
    domain_query.side_effect = RuntimeError("synthetic read failure")
    with pytest.raises(RuntimeError, match="synthetic read failure"):
        domain_scope.resolve_domain_selection(decision([7]), {})


@pytest.mark.parametrize("denial", ["report", "action", "grant_action", "capability"])
def test_domain_registry_does_not_bypass_report_permissions(monkeypatch, domain_query, denial):
    access = decision([7])
    report = access["reports"][0]
    if denial == "report":
        report["allowed"] = False
    elif denial == "action":
        report["allowed_actions"] = ["export"]
    elif denial == "grant_action":
        report["grants"][0]["allowed_actions"] = ["export"]
    else:
        rule = AccessRule("synthetic", required_capabilities=frozenset({"synthetic.view"}))
        monkeypatch.setattr(registry, "registered_reports", lambda: (SimpleNamespace(access=rule),))
    assert domain_scope.resolve_domain_selection(access, {}).domain_ids == []
    domain_query.assert_not_called()


def test_domain_registry_unions_only_the_current_users_executable_grants(monkeypatch, domain_query):
    access = decision([7])
    other = decision([8])["reports"][0]
    other["report_key"] = "synthetic.other"
    access["reports"].append(other)
    monkeypatch.setattr(registry, "registered_reports", lambda: tuple(
        SimpleNamespace(access=AccessRule(key)) for key in ("synthetic", "synthetic.other")
    ))
    assert domain_scope.resolve_domain_selection(access, {}).domain_ids == [7, 8]


def test_domain_endpoint_requires_workspace_access_and_rejects_filters(domain_query):
    handler = SimpleNamespace(_access_decision=dict, _send_json=Mock())
    workspace.try_handle_get(handler, "/api/v1/domains", {})
    assert handler._send_json.call_args.args[1] == 403
    workspace.try_handle_get(handler, "/api/v1/domains", {"domain_id": ["7"]})
    assert handler._send_json.call_args.args[1] == 400
    domain_query.assert_not_called()
