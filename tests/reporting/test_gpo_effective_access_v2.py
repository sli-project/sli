import csv
import io
from datetime import datetime, timezone

import pytest

from server.sli.reporting.v2.access import resolve_domain_scope
from server.sli.reporting.v2.definition import QueryContext, parse_params
from server.sli.reporting.v2.reports import gpo
from server.sli.reports import ad_snapshot_change_reporting
from tests.unit.test_gpo_effective_access import graph, snapshot, topology


@pytest.fixture
def collected(monkeypatch):
    data = snapshot()
    data["observed_at"] = datetime.now(timezone.utc).isoformat()
    source = graph()
    source["source"]["observed_at_utc"] = data["observed_at"]
    seen = []

    def load(snapshot, *, domain_ids):
        seen.append(domain_ids)
        return source

    monkeypatch.setattr(gpo, "load_authorized_snapshot_pair", lambda domain_ids: {"state": "available", "current": data, "previous": None})
    monkeypatch.setattr(gpo, "load_directory_graph", load)
    return data, source, seen


def context(tab, **params):
    return QueryContext(access={}, params=params, domain_ids=[7], tab=tab)


def test_changes_use_confirmed_period_history_and_export_fingerprints(monkeypatch):
    period = {"from_utc": "2026-01-01T00:00:00Z", "to_utc": "2026-10-01T00:00:00Z"}
    row = {"observed_at": "2026-02-01T00:00:00Z", "object_type": "gpo", "object_id": "policy-a",
           "kind": "attribute_changed", "field": "gpo_status", "before_sha256": "a" * 64, "after_sha256": "b" * 64}

    def read(**kwargs):
        assert kwargs == {"domain_ids": [7], "families": ("gpo_v2",), "period": period, "query": "policy-a"}
        return {"state": "partial", "items": [row], "coverage": {"state": "partial"}, "truncated": False}

    def unexpected_snapshot(*args, **kwargs):
        pytest.fail("History must not load inventory or membership snapshots")

    monkeypatch.setattr(ad_snapshot_change_reporting, "read_changes", read)
    monkeypatch.setattr(gpo, "load_authorized_snapshot_pair", unexpected_snapshot)
    monkeypatch.setattr(gpo, "load_directory_graph", unexpected_snapshot)
    query = context("changes", period=period, q="policy-a")
    data = gpo.REPORT.query(query)
    assert data["state"] == "partial"
    assert data["collections"] == {"changes": [row]}
    assert data["limitations"][0]["code"] == "history_partial"
    assert data["window"] == {"from_utc": period["from_utc"], "to_utc_exclusive": period["to_utc"]}
    text, metadata = gpo.REPORT.export_csv(query)
    exported = list(csv.DictReader(io.StringIO(text)))
    assert len(exported) == 1
    assert exported[0]["Объект"] == row["object_id"]
    assert exported[0]["Прежний отпечаток"] == row["before_sha256"]
    assert exported[0]["Новый отпечаток"] == row["after_sha256"]
    assert metadata == {"rows": 1, "truncated": False}


@pytest.mark.parametrize("tab", ["filtering", "delegation"])
def test_report_contract_exposes_only_the_open_collection(collected, tab):
    data = gpo._query(context(tab))
    assert data["contract_id"] == "sli.report-result.v2"
    assert data["report_key"] == "ad.gpo.v2" and data["state"] == "ok"
    assert data["items"] == [] and list(data["collections"]) == [tab]
    assert data["collections"][tab]
    assert collected[2] == [[7]]
    assert data["coverage"]["passport"] == gpo.REPORT.intent_ref
    assert any("RSoP" in item["text"] for item in data["limitations"])


def test_report_search_and_csv_share_membership_paths(collected):
    data = gpo._query(context("filtering", q="user-a"))
    assert len(data["collections"]["filtering"]) == 1
    text, metadata = gpo._export(context("filtering", q="user-a"))
    assert "user-a → group-a → group-b → policy-a [ACE 0]" in text
    assert "computer-a" not in text and metadata == {"rows": 1, "truncated": False}


def test_old_and_missing_sources_remain_partial_and_stale_is_separate(collected):
    snapshot, source, _ = collected
    snapshot["gpos"][0]["source_states"].pop("acl")
    data = gpo._query(context("filtering"))
    assert data["state"] == "partial"
    assert data["collections"]["filtering"][0]["outcome"] == "not_collected"
    snapshot["gpos"][0]["source_states"]["acl"] = {"status": "observed"}
    source["source"]["observed_at_utc"] = "2020-01-01T00:00:00Z"
    assert gpo._query(context("filtering"))["state"] == "stale"


def test_topology_does_not_query_directory_and_honors_missing_link_source(collected):
    snapshot, _, seen = collected
    snapshot.update(topology())
    snapshot["observed_at"] = datetime.now(timezone.utc).isoformat()
    data = gpo._query(context("linked_scopes"))
    assert seen == [] and len(data["collections"]["linked_scopes"]) == 3
    snapshot["source_states"]["links"]["status"] = "partial"
    assert gpo._query(context("linked_scopes"))["state"] == "partial"


def test_effective_tabs_keep_the_existing_atomic_gpo_access_and_export_rules():
    assert gpo.REPORT.access.report_key == "ad.gpo.v2"
    categories = ["identity_basic", "technical", "security", "privilege"]
    grant = {"allowed_actions": ["view", "export"], "field_categories": categories, "scope": {"kind": "domain", "ids": [7]}}
    access = {"reports": [{"report_key": "ad.gpo.v2", "allowed": True, "allowed_actions": ["view", "export"], "grants": [grant]}]}
    assert resolve_domain_scope(access, gpo.REPORT.access, "view") == [7]
    assert resolve_domain_scope(access, gpo.REPORT.access, "export") == [7]
    grant["field_categories"] = categories[:-1]
    with pytest.raises(PermissionError):
        resolve_domain_scope(access, gpo.REPORT.access)
    with pytest.raises(PermissionError):
        resolve_domain_scope({}, gpo.REPORT.access)
    for tab in ("filtering", "delegation", "linked_scopes"):
        _, paging = parse_params(gpo.REPORT, {"tab": [tab]})
        assert paging["tab"] == tab
