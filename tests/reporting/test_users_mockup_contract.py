"""Owner-approved Users tabs, with synthetic saved snapshots and no database."""
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from server.sli.plugins.ad.reports import review_checks
from server.sli.plugins.ad.reports.definitions import users
from server.sli.reporting.v2.definition import QueryContext
from tests.reporting.test_ad_review_checks import bundle, user
from tests.reporting.test_users_five_tabs import account, snapshot as snapshot


@pytest.fixture(autouse=True)
def snapshot_clock(monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 18, tzinfo=timezone.utc).astimezone(tz)
    monkeypatch.setattr(users, "datetime", Clock)


def test_four_owner_tabs_and_fifty_row_default():
    assert [view.key for view in users.REPORT.views] == ["checks", "privileged", "changes", "all"]
    assert users.REPORT.default_limit == 50


def test_all_accounts_include_enabled_disabled_and_unknown(snapshot):
    data = users._query(QueryContext(access={}, params={}, domain_ids=[1], tab="all", limit=2))
    assert [row["entity_id"] for row in data["items"]] == [1, 2]
    assert data["filtered_count"] == 3 and data["next_cursor"] == "2"
    tail = users._query(QueryContext(access={}, params={}, domain_ids=[1], tab="all", cursor="2", limit=2))
    assert tail["items"][0]["enabled"] is None
    assert not tail["has_more"]


def test_check_objects_page_is_exact_and_not_an_inventory_search(monkeypatch):
    monkeypatch.setattr(review_checks, "previous_login", lambda _: None)
    monkeypatch.setattr(review_checks, "load_snapshots", lambda *_: [bundle([
        *(user(i, userAccountControl=640) for i in range(1, 8)), user(8),
    ])])
    monkeypatch.setattr(review_checks, "load_events", lambda *_: ([], False))
    monkeypatch.setattr(review_checks.ad_service_exceptions, "configured", lambda: {})
    ctx = QueryContext(access={}, params={"check": "reversible_password"}, domain_ids=[1], tab="checks", limit=5)
    first = users._query(ctx)
    assert first["filtered_count"] == 7
    assert len(first["items"]) == 5 and first["next_cursor"] == "5"
    assert first["items"][0]["name"].startswith("synthetic-account-")
    tail = users._query(replace(ctx, cursor="5"))
    assert len(tail["items"]) == 2 and not tail["has_more"]
    assert {row["entity_id"] for row in first["items"]}.isdisjoint(row["entity_id"] for row in tail["items"])
    searched = users._query(replace(ctx, params={"check": "reversible_password", "q": "synthetic-account-7"}))
    assert searched["filtered_count"] == 1 and searched["items"][0]["entity_id"] == 7
    body, meta = users._export(replace(ctx, params={}))
    assert "Synthetic" not in body  # No fixture-only presentation enters the catalog.
    assert "Проверка" in body and meta["rows"] == 12


def test_historical_privileges_use_saved_baseline_and_never_current_workplace(snapshot, monkeypatch):
    saved = account(9, domainId=1, privilegedMemberships=[{"relation": "direct", "group": "Synthetic admin group"}])
    seen = []
    def load(kind, domains, at):
        seen.append((kind, domains, at))
        return [bundle([user(99)], baseline=[saved])]
    monkeypatch.setattr(review_checks, "load_snapshots", load)
    monkeypatch.setattr(users.report_additions, "last_workplaces", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("current workplace")))
    data = users._query(QueryContext(access={}, params={"as_of": "2026-10-17"}, domain_ids=[1], tab="privileged"))
    assert [row["entity_id"] for row in data["items"]] == [9]
    assert data["coverage"]["as_of"] == "2026-10-17"
    assert seen[0][:2] == ("users", [1])
    assert seen[0][2].startswith("2026-10-17T23:59:59")


def test_missing_historical_snapshot_does_not_fall_back_to_current(snapshot, monkeypatch):
    monkeypatch.setattr(review_checks, "load_snapshots", lambda *_: [bundle([user()])])
    data = users._query(QueryContext(access={}, params={"as_of": "2026-10-17"}, domain_ids=[1], tab="privileged"))
    assert data["state"] == "not_collected" and data["items"] == []


def test_historical_snapshot_without_observation_time_stays_partial(snapshot, monkeypatch):
    saved = account(9, privilegedMemberships=[{"relation": "direct", "group": "Synthetic admin group"}])
    source = bundle([], baseline=[saved])
    source["baseline"]["observed_at"] = None
    monkeypatch.setattr(review_checks, "load_snapshots", lambda *_: [source])
    data = users._query(QueryContext(access={}, params={"as_of": "2026-10-17"}, domain_ids=[1], tab="privileged"))
    assert data["state"] == "partial"
    assert data["coverage"]["observed_at_utc"] is None
    assert [row["entity_id"] for row in data["items"]] == [9]


def test_check_search_scopes_previous_and_current_counts():
    old = [user(1, userAccountControl=640), user(2, userAccountControl=640)]
    data = review_checks.summarize("users", [bundle([old[0]], previous=old)], search="synthetic-account-1")
    check = next(row for row in data["items"] if row["key"] == "reversible_password")
    assert check["previous_total"] == check["total"] == 1
    assert check["status"] == "unchanged"


def test_changes_expose_change_count_and_comparison_interval(snapshot, monkeypatch):
    previous = {**snapshot, "metadata": {**snapshot["metadata"], "observed_at": "2026-10-06T00:00:00Z"},
                "users": [{**snapshot["users"][0], "enabled": False}]}
    monkeypatch.setattr(users, "_snapshots", lambda *_a, **_k: {"state": "ok", "current": snapshot, "previous": previous})
    data = users._query(QueryContext(access={}, params={}, domain_ids=[1], tab="changes"))
    assert data["filtered_count"] == len(data["collections"]["changes"])
    assert data["window"]["from_utc"] == "2026-10-06T00:00:00Z"
    assert all(row["observed_at_utc"] == "2026-10-07T00:00:00Z" for row in data["collections"]["changes"])
