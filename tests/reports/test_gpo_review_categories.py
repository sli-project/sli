"""Review categories are derived from observed facts, never from missing data."""
from copy import deepcopy

import pytest

from server.sli.reports import gpo_v2_reporting as engine
from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import gpo as report


@pytest.fixture
def snapshot():
    return {"observed_at": "2026-10-07T00:00:00Z", "completed_at": "2026-10-07T00:05:00Z",
            "collection_status": "complete", "source_states": {"links": {"status": "observed"}},
            "gpos": [{"id": "synthetic-policy", "display_name": "Synthetic policy", "link_ids": [],
                      "source_states": {key: {"status": "observed"} for key in ("report", "sysvol_gpt", "links")},
                      "computer": {"enabled": True, "settings_count": 0, "directory_version": 1, "sysvol_version": 1}}]}


def test_empty_unlinked_policy_is_an_assignment_question(snapshot):
    original = deepcopy(snapshot)
    assert engine.filter_snapshot_view(snapshot, "attention")["items"] == []
    assert engine.filter_snapshot_view(snapshot, "unverified")["items"] == []
    reasons = engine.filter_snapshot_view(snapshot, "assignment")["items"][0]["reasons"]
    assert {item["code"] for item in reasons} == {"unlinked", "empty_enabled_side"}
    assert all(item["category"] == "assignment" and item["priority"] == "low" and item["next"] for item in reasons)
    assert snapshot == original


def test_missing_setting_count_is_not_an_empty_policy(snapshot):
    del snapshot["gpos"][0]["computer"]["settings_count"]
    assert "empty_enabled_side" not in {item["code"] for item in engine.attention_reasons(snapshot["gpos"][0], snapshot=snapshot)}


def test_partial_source_is_unverified_information(snapshot):
    snapshot["gpos"][0]["source_states"]["report"]["status"] = "partial"
    reasons = engine.filter_snapshot_view(snapshot, "unverified")["items"][0]["reasons"]
    assert reasons[0]["code"] == "source_unverified"
    assert reasons[0]["category"] == "unverified"
    assert not engine.filter_snapshot_view(snapshot, "attention")["items"]


@pytest.mark.parametrize("source_status,view", [("observed", "attention"), ("failed", "unverified"), ("partial", "unverified")])
def test_version_deviation_requires_verified_sources(snapshot, source_status, view):
    policy = snapshot["gpos"][0]
    policy["computer"]["sysvol_version"] = 2
    policy["source_states"]["sysvol_gpt"]["status"] = source_status
    rows = engine.filter_snapshot_view(snapshot, view)["items"]
    assert len(rows) == 1
    reason = next(item for item in rows[0]["reasons"] if item["code"] == "version_mismatch")
    assert reason["category"] == ("deviation" if source_status == "observed" else "unverified")
    assert rows[0]["reasons"][0]["priority"] == ("high" if source_status == "observed" else "medium")
    if source_status != "observed":
        assert engine.filter_snapshot_view(snapshot, "attention")["items"] == []


def test_snapshot_contract_kpis_details_and_csv_separate_categories(snapshot, monkeypatch):
    policy = snapshot["gpos"][0]
    policy["source_states"]["sysvol_gpt"]["status"] = "failed"
    monkeypatch.setattr(report, "load_authorized_snapshot_pair", lambda **kwargs: {"state": "available", "current": snapshot})
    monkeypatch.setattr(report, "build_gpo_v2_payload", lambda pair: {"current": pair["current"]})
    context = QueryContext(access={}, params={"view": "all"}, domain_ids=[1], tab="gpos")
    payload = report._query(context)
    assert payload["window"] == {}
    assert payload["coverage"]["observed_at_utc"] == snapshot["observed_at"]
    assert {metric["key"]: metric["value"] for metric in payload["metrics"]} == {
        "attention": 0, "unverified": 1, "assignment": 1, "all": 1, "linked": 0, "unlinked": 1}
    row = payload["items"][0]
    assert row["reason_titles"] is None and row["reason_count"] == 0
    assert row["priority"] == "medium" and row["next_step"]
    assert row["unverified_titles"] and row["assignment_titles"]
    assert "sysvol_gpt" not in row["reasons"][0]["fact"]
    text, meta = report._export(context)
    assert "Непроверенные сведения" in text and "Вопросы назначения" in text
    assert meta["rows"] == 1


def test_changes_keep_the_requested_period(monkeypatch):
    window = {"from_utc": "2026-10-01T00:00:00Z", "to_utc_exclusive": "2026-10-08T00:00:00Z"}
    monkeypatch.setattr(report, "query_history", lambda *_args: {"window": window})
    assert report._query(QueryContext(access={}, params={}, tab="changes"))["window"] == window
