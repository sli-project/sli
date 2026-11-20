"""Saved comparison reads preserve the caller's explicit domain boundary."""
from copy import deepcopy

import pytest

from server.sli.plugins.ad.reports import users_v2_reporting as reader


CURRENT = {"metadata": {"observed_at": "2026-10-21T12:00:00Z", "collection_status": "partial"},
           "users": [], "groups": []}
FOREIGN = {"metadata": {"observed_at": "2026-10-20T12:00:00Z"}, "groups": [], "users": [
    {"id": "user:22001", "entityId": 22001, "domainId": 22,
     "displayName": "Foreign account", "samAccountName": "foreign-login"},
]}


@pytest.fixture
def snapshots(monkeypatch):
    calls = []
    monkeypatch.setattr(reader, "build_users_v2_snapshot", lambda **_: deepcopy(CURRENT))

    def query(sql, params, **kwargs):
        calls.append((sql, params, kwargs))
        return [{"snapshot_id": 7, "captured_at_utc": "2026-10-20T12:00:00Z",
                 "payload_json": deepcopy(FOREIGN)}]

    monkeypatch.setattr(reader, "query_rows_bounded", query)
    return calls


@pytest.mark.parametrize("scope", [[], [0], [-1, 0, -1]])
def test_explicit_empty_scope_never_loads_foreign_saved_users(snapshots, scope):
    payload = reader.load_users_v2_snapshots(domain_ids=scope)
    assert payload["current"]["users"] == []
    assert payload["previous"] is None
    assert payload["saved_snapshot_count"] == 0
    assert payload["previous_state"] == "none"
    assert payload["state"] == "empty"
    assert payload["current"]["metadata"]["collection_status"] == "partial"
    assert snapshots == []


def test_unrestricted_none_retains_saved_comparison(snapshots):
    payload = reader.load_users_v2_snapshots(domain_ids=None)
    assert payload["previous"]["users"] == FOREIGN["users"]
    assert payload["previous_state"] == "loaded"
    assert payload["saved_snapshot_count"] == 1
    sql, params, kwargs = snapshots[0]
    assert "domain_id=any(?)" not in sql
    assert params == (reader.CONTRACT_ID,)
    assert kwargs == {"statement_timeout_ms": 5_000}


def test_nonempty_scope_keeps_normalized_sql_predicate(snapshots):
    reader.load_users_v2_snapshots(domain_ids=[22, 0, 22, -1])
    sql, params, _ = snapshots[0]
    assert "domain_id=any(?)" in sql
    assert params == (reader.CONTRACT_ID, [22])


@pytest.mark.parametrize("scope", [None, [], [22]])
def test_comparison_not_requested_never_reads_saved_snapshots(snapshots, scope):
    payload = reader.load_users_v2_snapshots(domain_ids=scope, include_previous=False)
    assert payload["previous"] is None
    assert payload["previous_state"] == "not_requested"
    assert payload["saved_snapshot_count"] is None
    assert snapshots == []


@pytest.mark.parametrize("scope", [None, [22]])
def test_saved_storage_failure_remains_unavailable(monkeypatch, snapshots, scope):
    def unavailable(*args, **kwargs):
        raise RuntimeError("synthetic storage unavailable")

    monkeypatch.setattr(reader, "query_rows_bounded", unavailable)
    payload = reader.load_users_v2_snapshots(domain_ids=scope)
    assert payload["current"]["metadata"]["collection_status"] == "partial"
    assert payload["previous"] is None
    assert payload["previous_state"] == "unavailable"
    assert payload["saved_snapshot_count"] is None
