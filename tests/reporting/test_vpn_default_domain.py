"""VPN defaults share T049 selection without widening delegated source grants."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from server.api.routes import reports_v2 as routes
from server.sli.access import domain_scope
from server.sli.core import platform_settings
from server.sli.plugins.remote_access.reports.vpn_connections import REPORT


@pytest.fixture
def setup(monkeypatch):
    rows = [
        {"id": 1, "display_name": "archive.example.test", "is_archived": True,
         "default_observed_at_utc": datetime.now(timezone.utc) - timedelta(hours=1)},
        {"id": 2, "display_name": "live.example.test", "is_archived": False,
         "default_observed_at_utc": datetime.now(timezone.utc) - timedelta(days=1)},
    ]
    options = [{"value": str(row["id"]), "label": row["display_name"]} for row in rows]
    definition = replace(REPORT, options=lambda _: {"domain": options})
    access = {"reports": [{"report_key": "vpn.audit", "allowed": True, "allowed_actions": ["view"],
              "grants": [{"allowed_actions": ["view"], "field_categories": [], "scope": {"kind": "all"}}]}]}
    monkeypatch.setattr(routes, "get_report", lambda _: definition)
    monkeypatch.setattr(routes, "report_plugin_state", lambda _: None)
    monkeypatch.setattr(domain_scope, "_domain_rows", lambda _: rows)
    monkeypatch.setattr(platform_settings, "get_setting", lambda _: "archive.example.test")
    return definition, access, rows, options


def declaration(access):
    results = []
    handler = SimpleNamespace(_access_decision=lambda: access, _send_json=lambda payload, *args: results.append(payload))
    assert routes.try_handle_get(handler, "/api/v2/reports/vpn.connections", {})
    return results[0]


def test_vpn_declaration_prefers_live_observed_domain(setup):
    _, access, _, _ = setup
    payload = declaration(access)
    assert payload["default_domain_id"] == 2
    assert payload["default_domain_state"] == "available"
    assert [row["value"] for row in payload["filter_options"]["domain"]] == ["1", "2"]


def test_default_does_not_escape_source_options(setup):
    _, access, _, options = setup
    options.pop()
    payload = declaration(access)
    assert payload["default_domain_id"] is None
    assert payload["default_domain_state"] == "unknown"


@pytest.mark.parametrize("kind", ["archive_only", "unknown", "future"])
def test_no_fallback_to_archive_or_unobserved_domain(setup, kind):
    definition, access, rows, _ = setup
    if kind == "archive_only":
        rows.pop()
    else:
        rows[1]["default_observed_at_utc"] = None if kind == "unknown" else datetime.now(timezone.utc) + timedelta(days=1)
    assert declaration(access)["default_domain_id"] is None
    assert "domain" not in routes._with_only_domain(definition, access, {})


def test_direct_missing_domain_uses_same_default_and_preserves_period(setup):
    definition, access, _, _ = setup
    assert routes._with_only_domain(definition, access, {"period": ["7d"]}) == {"period": ["7d"], "domain": ["2"]}


def test_explicit_archive_does_not_need_default_lookup(setup, monkeypatch):
    definition, access, _, _ = setup
    monkeypatch.setattr(domain_scope, "_domain_rows", lambda _: pytest.fail("explicit selection needs no default"))
    query = {"domain": ["1"], "period": ["custom"], "from": ["2026-01-01"], "to": ["2026-01-07"]}
    assert routes._with_only_domain(definition, access, query) == query


def test_metadata_failure_has_no_invented_default(setup, monkeypatch):
    _, access, _, _ = setup
    def unavailable(_):
        raise RuntimeError("synthetic metadata unavailable")
    monkeypatch.setattr(domain_scope, "_domain_rows", unavailable)
    payload = declaration(access)
    assert payload["default_domain_id"] is None
    assert payload["default_domain_state"] == "unavailable"


def test_recommendation_is_limited_to_report_authorized_domains(setup, monkeypatch):
    _, access, rows, _ = setup
    access["reports"][0]["grants"][0]["scope"] = {"kind": "domain", "ids": [1]}
    reads = []
    def scoped(ids):
        reads.append(ids)
        return [row for row in rows if row["id"] in ids]
    monkeypatch.setattr(domain_scope, "_domain_rows", scoped)
    payload = declaration(access)
    assert reads == [[1]]
    assert payload["default_domain_id"] is None


def test_saved_live_preference_does_not_require_new_observation(setup, monkeypatch):
    _, access, rows, _ = setup
    rows[1]["default_observed_at_utc"] = None
    monkeypatch.setattr(platform_settings, "get_setting", lambda _: "live.example.test")
    assert declaration(access)["default_domain_id"] == 2


@pytest.mark.parametrize("query,expected", [
    ({"domain_id": ["1"], "period": ["7d"]}, 1),
    ({"domain": ["1"], "domain_id": ["1"], "period": ["7d"]}, 1),
    ({"domain": ["1"], "domain_id": ["2"]}, None),
    ({"scope": ["all"], "period": ["7d"]}, None),
])
def test_direct_route_preserves_alias_or_rejects_conflicting_or_all_scope(setup, monkeypatch, query, expected):
    from server.sli.reporting.v2.definition import result

    definition, access, _, _ = setup
    reads, responses = [], []
    def read(context):
        reads.append(context.params["domain"])
        return result(definition, state="empty")
    monkeypatch.setattr(routes, "get_report", lambda _: replace(definition, query=read))
    monkeypatch.setattr(routes, "annotate_plugin_report", lambda *_: None)
    handler = SimpleNamespace(_access_decision=lambda: access,
                              _send_json=lambda payload, status=200: responses.append((status, payload)))
    routes.try_handle_get(handler, "/api/v2/reports/vpn.connections/data", query)
    assert responses[0][0] == (200 if expected else 400), responses
    assert reads == ([] if expected is None else [expected])
