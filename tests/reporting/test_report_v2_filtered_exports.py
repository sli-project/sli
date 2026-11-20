from __future__ import annotations

import csv
import io

import pytest

from server.api.routes import reports_v2 as routes
from server.sli.reporting.v2.definition import QueryContext, parse_params
from server.sli.reporting.v2.reports import ad_state, gpo
from server.sli.reports import ad_snapshot_change_reporting
from server.sli.reports.active_directory_reporting import (
    render_active_directory_report_csv,
)


def _context(report, **query):
    params, paging = parse_params(report, {key: [value] for key, value in query.items()})
    return QueryContext(
        access={}, params=params, domain_ids=[1], action="export", **paging,
    )


def _csv(text, delimiter=","):
    return list(csv.DictReader(io.StringIO(text), delimiter=delimiter))


@pytest.fixture
def ad_engine(monkeypatch):
    controls = [
        {"entity_id": 1, "entity_name": "Synthetic link", "entity_type": "replication_link", "qualification": "failed", "label": "Synthetic replication", "control_id": "replication", "actual_value": "=synthetic"},
        {"entity_id": 2, "entity_name": "Synthetic passed", "entity_type": "replication_link", "qualification": "passed", "label": "Synthetic replication", "control_id": "replication"},
        {"entity_id": 3, "entity_name": "Synthetic controller", "entity_type": "domain_controller", "qualification": "failed", "label": "Synthetic controller", "control_id": "controller"},
        {"entity_id": 4, "entity_name": "Other link", "entity_type": "replication_link", "qualification": "failed", "label": "Other replication", "control_id": "replication"},
    ]
    calls = []

    def fake(**kwargs):
        calls.append(kwargs)
        assert kwargs["domain_ids"] == [1]
        selected = [row for row in controls if kwargs["view"] != "replication" or row["entity_type"] == "replication_link"]
        return {
            "state": "available", "controls": selected, "has_more": False,
            "items": [{"entity_id": row["entity_id"], "entity_type": row["entity_type"], "display_name": row["entity_name"], "semantic_findings": [{"title": f"Finding {row['entity_id']}", "summary": row["entity_name"]}]} for row in controls] if kwargs["view"] == "semantic" else [],
        }

    monkeypatch.setattr(ad_state, "get_active_directory_report", fake)
    return calls


def test_ad_control_export_matches_all_screen_filters(ad_engine):
    context = _context(ad_state.REPORT, tab="controls", view="replication", qualification="failed", entity_type="replication_link", q="synthetic")
    displayed = ad_state._query(context)["items"]
    text, meta = ad_state._export(context)
    rows = _csv(text, delimiter=";")
    assert [row["Объект"] for row in rows] == [row["entity_name"] for row in displayed] == ["Synthetic link"]
    assert rows[0]["Фактическое значение"] == "'=synthetic"
    assert meta == {"rows": 1, "truncated": False}
    assert ad_engine[-1]["view"] == "replication"


def test_ad_empty_filtered_export_never_falls_back_to_entities(ad_engine):
    text, meta = ad_state._export(_context(ad_state.REPORT, q="no-match"))
    assert _csv(text, delimiter=";") == []
    assert text.startswith("Параметр;Объект;")
    assert meta["rows"] == 0


def test_ad_csv_empty_control_ledger_keeps_control_headers():
    text = render_active_directory_report_csv({
        "controls": [],
        "items": [{"entity_type": "domain_controller", "display_name": "Synthetic controller"}],
    }).decode("utf-8-sig")
    assert text.startswith("Параметр;Объект;")
    assert _csv(text, delimiter=";") == []


@pytest.mark.parametrize("query,expected", [
    ({"qualification": "passed"}, ["Synthetic passed"]),
    ({"entity_type": "domain_controller"}, ["Synthetic controller"]),
    ({"q": "OTHER"}, ["Other link"]),
])
def test_ad_export_applies_each_filter_independently(ad_engine, query, expected):
    text, _ = ad_state._export(_context(ad_state.REPORT, **query))
    assert [row["Объект"] for row in _csv(text, delimiter=";")] == expected


def test_ad_semantic_export_uses_selected_collection_and_filters(ad_engine):
    context = _context(ad_state.REPORT, tab="semantic", view="replication", qualification="failed", entity_type="replication_link", q="synthetic")
    displayed = ad_state._query(context)["collections"]["semantic"]
    text, meta = ad_state._export(context)
    assert [row["Находка"] for row in _csv(text)] == [row["title"] for row in displayed] == ["Finding 1"]
    assert meta == {"rows": 1, "truncated": False}


def test_ad_semantic_search_matches_findings_without_matching_control_labels(ad_engine):
    context = _context(ad_state.REPORT, tab="semantic", q="FINDING 1")
    assert ad_state._query(context)["items"] == []
    text, _ = ad_state._export(context)
    assert [row["Находка"] for row in _csv(text)] == ["Finding 1"]


def test_ad_export_keeps_unavailable_evidence_error(monkeypatch):
    monkeypatch.setattr(ad_state, "get_active_directory_report", lambda **kwargs: {"state": "unavailable"})
    with pytest.raises(ValueError, match="active_directory_evidence_not_exportable"):
        ad_state._export(_context(ad_state.REPORT))


@pytest.mark.parametrize("tab", ["gpos", "changes", "scopes", "settings", "permissions", "wmi", "quality"])
def test_gpo_export_uses_selected_tab_columns_and_rows(monkeypatch, tab):
    snapshot = {
        "collection_status": "completed", "source_states": {"links": {"status": "observed"}},
        "gpos": [{"id": "gpo-a", "display_name": "Synthetic policy", "link_ids": [], "source_states": {"links": {"status": "observed"}}}, {"id": "gpo-b", "display_name": "Other policy", "link_ids": ["link"]}],
        "settings": [{"id": "s1", "gpo_name": "Synthetic policy", "setting_name": "=synthetic"}, {"id": "s2", "gpo_name": "Other policy", "setting_name": "other"}],
        "scopes": [{"id": "scope1", "name": "Synthetic scope", "direct_link_ids": ["link"]}, {"id": "scope2", "name": "Other scope"}],
        "permissions": [{"id": "p1", "gpo_name": "Synthetic policy", "trustee_name": "Synthetic trustee"}, {"id": "p2", "gpo_name": "Other policy"}],
        "wmi_filters": [{"id": "w1", "name": "Synthetic filter", "used_by_gpo_ids": ["gpo-a"]}, {"id": "w2", "name": "Other filter"}],
    }
    monkeypatch.setattr(gpo, "load_authorized_snapshot_pair", lambda **kwargs: {"state": "available", "current": snapshot})
    monkeypatch.setattr(gpo, "build_gpo_v2_payload", lambda pair: {"current": snapshot, "comparison": {"items": [{"display_name": "Synthetic change"}, {"display_name": "Other change"}]}})
    monkeypatch.setattr(gpo, "quality_rows", lambda snapshot: [{"entity_name": "Synthetic quality", "status": "observed"}, {"entity_name": "Other quality", "status": "observed"}])
    def read_changes(**kwargs):
        assert kwargs["domain_ids"] == [1]
        assert kwargs["families"] == ("gpo_v2",)
        rows = [{"object_id": "Synthetic change"}, {"object_id": "Other change"}]
        needle = kwargs["query"].casefold()
        return {"state": "ok", "items": [row for row in rows if needle in row["object_id"].casefold()],
                "coverage": {"state": "complete"}, "truncated": False}
    monkeypatch.setattr(ad_snapshot_change_reporting, "read_changes", read_changes)
    context = _context(gpo.REPORT, tab=tab, view="unlinked", q="synthetic")
    displayed = gpo._query(context)
    text, meta = gpo._export(context)
    view = next(view for view in gpo.REPORT.views if view.key == tab)
    expected = displayed["items"] if view.source == "items" else displayed["collections"][view.source]
    assert len(_csv(text)) == len(expected) == 1
    assert next(csv.reader(io.StringIO(text))) == [column.label for column in view.columns or gpo.REPORT.columns]
    assert meta == {"rows": 1, "truncated": False}
    assert "Synthetic" in text and "Other" not in text
    if tab == "settings":
        assert "'=synthetic" in text


def test_gpo_collection_export_marks_truncation(monkeypatch):
    monkeypatch.setattr(gpo, "_query", lambda context: {"items": [], "collections": {"settings": [{"gpo_name": "Synthetic"}]}, "limitations": [{"code": "settings_truncated"}]})
    _, meta = gpo._export(_context(gpo.REPORT, tab="settings"))
    assert meta == {"rows": 1, "truncated": True}


@pytest.mark.parametrize("report,tab,query", [
    (ad_state.REPORT, "semantic", {"qualification": "failed", "entity_type": "replication_link", "q": "synthetic"}),
    (gpo.REPORT, "settings", {"view": "unlinked", "q": "synthetic"}),
])
def test_export_route_preserves_tab_and_conditions(monkeypatch, report, tab, query):
    from server.sli.access import domain_scope

    monkeypatch.setattr(domain_scope, "_domain_rows", lambda ids: [
        {"id": key, "display_name": f"domain-{key}.example.test"} for key in ids
    ])
    from dataclasses import replace

    seen = []
    definition = replace(report, export_csv=lambda context: (seen.append(context) or "header\n", {"rows": 0}))
    monkeypatch.setattr(routes, "get_report", lambda key: definition)

    class Handler:
        wfile = io.BytesIO()

        def _access_decision(self):
            return {"reports": [{"report_key": report.access.report_key, "allowed": True, "allowed_actions": ["export"], "grants": [{"allowed_actions": ["export"], "field_categories": list(report.access.required_fields), "scope": {"kind": "domain", "ids": [1]}}]}]}

        def send_response(self, status):
            assert status == 200

        def send_header(self, key, value):
            pass

        def end_headers(self):
            pass

        def _send_json(self, payload, status=200):
            pytest.fail(f"Unexpected JSON response: {status}")

    assert routes.try_handle_get(Handler(), f"/api/v2/reports/{report.key}/export.csv", {key: [value] for key, value in {**query, "tab": tab}.items()})
    assert len(seen) == 1
    assert seen[0].tab == tab
    assert seen[0].domain_ids == [1]
    assert all(seen[0].params[key] == value for key, value in query.items())
