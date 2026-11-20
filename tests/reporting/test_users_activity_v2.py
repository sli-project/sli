"""Users activity slices use bounded reads and synthetic observations only."""

from datetime import datetime, timedelta, timezone

import pytest
from psycopg import errors

from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import users
from server.sli.reports import users_activity as activity
from server.sli.reports.users_v2_views import user_row

AT = datetime(2026, 10, 1, tzinfo=timezone.utc)
SID = "S-1-5-21-100-200-300-1001"
GROUP_SID = "S-1-5-21-100-200-300-2001"
USER = {"id": "user:1", "entityId": 1, "displayName": "Synthetic account", "samAccountName": "fixture", "enabled": False}
GROUP = {"id": "group:2", "name": "Synthetic control group", "watchGroup": True}
CURRENT = {"users": [USER], "groups": [GROUP], "metadata": {"observed_at": AT.isoformat(), "watch_groups": [GROUP], "collection_status": "completed"}}
PARAMS = {"period": {"from_utc": AT.isoformat(), "to_utc": (AT + timedelta(days=1)).isoformat()}}


def event(row_id, code, minutes, **overrides):
    semantic = {4624: "authentication.session.created", 6272: "remote_access.authentication.allowed",
                4725: "directory.account.disabled", 4722: "directory.account.enabled"}
    semantic.update({key: "group.member.added" for key in activity.MEMBERSHIP_PAIRS})
    semantic.update({key: "group.member.removed" for key in activity.MEMBERSHIP_PAIRS.values()})
    value = {"id": row_id, "event_id": code, "domain_id": 1, "server_id": 7,
             "time_created_utc": AT + timedelta(minutes=minutes), "target_user_sid": SID,
             "subject_user_sid": SID if code == 6272 else "S-1-5-21-100-200-300-3001",
             "normalized_event_id": f"00000000-0000-0000-0000-{row_id:012d}",
             "processing_status": "normalized", "semantic_type": semantic[code], "facts_json": {}}
    if code in activity.MEMBERSHIP_IDS:
        value.update(target_user_sid=GROUP_SID, membership_member_sid=SID,
                     facts_json={"relation_member_sid": SID, "relation_group_sid": GROUP_SID})
    value.update(overrides)
    return value


def shaped(events, *, user=USER, candidates=None, **kwargs):
    return activity.shape(CURRENT, events, {(1, SID): user}, {(1, GROUP_SID): GROUP}, candidates or {},
                          max_minutes=kwargs.get("max_minutes", 60), min_repeats=kwargs.get("min_repeats", 1))


@pytest.mark.parametrize("scope", [None, [], [1, 2]])
def test_source_sql_bounds_indexed_scan_and_selects_one_current_interpretation(scope):
    sql, params = activity.event_sql(scope, [4624, 6272], AT, AT + timedelta(days=1))
    assert "e.event_id=any(?)" in sql and "e.time_created_utc>=?" in sql and "e.time_created_utc<?" in sql
    assert ("e.domain_id=any(?)" in sql) == (scope is not None)
    assert params[-1] == activity.SCAN_LIMIT + 1
    assert "where n.source_event_id=e.id" in sql
    assert "nullif(btrim(f.account_target_sid),'')" in sql
    assert "semantic_contract_version desc,n.normalized_at desc,n.normalized_event_id desc limit 1" in sql
    assert "processing_status='normalized'" not in sql  # status checked AFTER newest selection


@pytest.mark.parametrize("values", [
    {"max_minutes": 1441}, {"min_repeats": 101}, {"max_minutes": -1},
    {"period": {"from_utc": AT.isoformat(), "to_utc": (AT + timedelta(days=32)).isoformat()}},
    {"period": {"from_utc": AT.isoformat(), "to_utc": AT.isoformat()}},
])
def test_activity_windows_and_thresholds_are_bounded(values):
    with pytest.raises(ValueError):
        activity.window({**PARAMS, **values})


def test_disabled_requires_observed_disable_exact_domain_and_success_after_it():
    events = [event(1, 4725, 10), event(2, 4624, 9), event(3, 4624, 10), event(4, 4624, 11),
              event(5, 6272, 12), event(6, 6272, 13, subject_user_sid=None), event(7, 4624, 14, domain_id=2),
              event(8, 4624, 15, processing_status="ignored"), event(9, 4624, 16, semantic_type="event.unknown")]
    data = shaped([*events, events[3]])
    assert [row["evidence"] for row in data["disabled_active"]] == [[1, 4], [1, 5]]
    assert data["unknown_identity_events"] == 2 and data["unprocessed_events"] == 1
    assert data["disabled_active"][0]["delay_minutes"] == 1
    assert shaped(events, user={**USER, "enabled": True})["disabled_active"] == []
    assert shaped([event(1, 4624, 11)], user={**USER, "whenChanged": AT.isoformat()})["disabled_active"] == []


def test_reenable_and_latest_disable_prevent_old_activity_from_counting():
    events = [event(1, 4725, 1), event(2, 4624, 2), event(3, 4722, 3)]
    assert shaped(events)["disabled_active"] == []
    data = shaped([*events, event(4, 4725, 4), event(5, 6272, 5)])
    assert [row["evidence"] for row in data["disabled_active"]] == [[4, 5]]


@pytest.mark.parametrize("add,remove", activity.MEMBERSHIP_PAIRS.items())
def test_membership_pairs_repeat_without_current_membership_or_replay_counting(add, remove):
    events = [event(1, add, 1), event(2, 4624, 2), event(3, remove, 3),
              event(4, add, 4), event(5, remove, 5)]
    data = shaped([*events, events[0]], min_repeats=2)
    rows = data["temporary_memberships"]
    assert len(rows) == 2 and [row["repeats"] for row in rows] == [2, 2]
    assert rows[0]["activity_evidence"] == [2] and rows[0]["interval_minutes"] == 2
    enriched = {**USER, "temporaryMemberships": rows}
    row = user_row(enriched, AT.isoformat())
    assert "temporary_membership" in row["reason_keys"]
    reason = next(reason for reason in row["reasons"] if reason["key"] == "temporary_membership")
    assert "не доказывают" in reason["limitation"]
    assert reason["evidence"] == [[1, 3], [4, 5]]


def test_pairs_do_not_mix_group_domain_event_family_or_unknown_member():
    assert shaped([event(1, 4728, 1), event(2, 4733, 2)])["temporary_memberships"] == []
    assert shaped([event(1, 4728, 1), event(2, 4729, 2, domain_id=2)])["temporary_memberships"] == []
    assert shaped([event(1, 4728, 1), event(2, 4729, 62)])["temporary_memberships"] == []
    assert shaped([event(1, 4728, 1), event(2, 4729, 1)])["temporary_memberships"] == []
    unknown = event(3, 4728, 2, membership_member_sid=None, facts_json={})
    assert shaped([unknown])["unknown_identity_events"] == 1
    unmonitored = event(3, 4729, 2, target_user_sid="S-1-5-32-555", facts_json={"relation_member_sid": SID})
    assert shaped([event(1, 4728, 1), unmonitored])["temporary_memberships"] == []


def test_alternative_removals_and_existing_candidate_remain_ambiguous():
    candidate = {1: {"candidate_id": "00000000-0000-0000-0000-000000000001", "evidence_count": 3, "confidence": "medium"}}
    for events, candidates in [([event(1, 4728, 1), event(2, 4729, 2), event(3, 4729, 3)], {}),
                               ([event(1, 4728, 1), event(2, 4729, 2)], candidate)]:
        row = shaped(events, candidates=candidates)["temporary_memberships"][0]
        assert row["quality"] == "ambiguous"
        assert row["interval_minutes"] is None and row["removed_at"] is None and row["activity_count"] is None
        assert row["candidate_id"] == (candidate[1]["candidate_id"] if candidates else None)


def fake_reads(monkeypatch, events, *, candidates=()):
    calls = []
    def read(sql, params, **kwargs):
        assert kwargs["statement_timeout_ms"] == 10_000
        calls.append((sql, params))
        if "ad_context_entity_aliases" in sql:
            return [{"entity_id": 1, "domain_id": 1, "sid": SID}, {"entity_id": 2, "domain_id": 1, "sid": GROUP_SID}]
        if "semantic_correlation_candidates" in sql:
            return list(candidates)
        return [value for value in events if value["event_id"] in params[0]]
    monkeypatch.setattr(activity, "query_rows_bounded", read)
    return calls


def test_loader_reuses_current_chain_candidates_with_indexed_anchor_predicate(monkeypatch):
    calls = fake_reads(monkeypatch, [event(1, 4728, 1), event(2, 4729, 2)],
                       candidates=[{"add_id": 1, "candidate_id": "00000000-0000-0000-0000-000000000001", "evidence_count": 2}])
    data = activity.load(CURRENT, [1], PARAMS)
    assert data["temporary_memberships"][0]["candidate_id"] is not None
    sql, params = calls[-1]
    assert "ae.normalized_event_id=any(?::uuid[])" in sql
    assert "latest.source_event_id=old.source_event_id" in sql and "r.rule_version>c.rule_version" in sql
    assert activity.CHAIN in params and AT in params and params[-1] == activity.SCAN_LIMIT
    assert data["state"] == "partial" and not data["truncated"]


def test_truncated_scans_are_explicit_and_empty_scope_never_reads(monkeypatch):
    monkeypatch.setattr(activity, "SCAN_LIMIT", 2)
    fake_reads(monkeypatch, [event(1, 4728, 1), event(2, 4729, 2), event(3, 4728, 3)])
    assert activity.load(CURRENT, [1], PARAMS)["truncated"] is True
    monkeypatch.setattr(activity, "_read", lambda *_: pytest.fail("empty domain scope read"))
    assert activity.load(CURRENT, [], PARAMS)["disabled_active"] == []


def context(tab, **params):
    return QueryContext({}, {**PARAMS, **params}, [1], "view", None, 100, "UTC", tab=tab)


def test_tab_filters_metrics_and_unreadable_source_are_honest(monkeypatch):
    monkeypatch.setattr(users, "_snapshots", lambda *_args, **_kwargs: {"state": "ok", "current": CURRENT})
    fake_reads(monkeypatch, [event(1, 4725, 1), event(2, 4624, 2), event(3, 6272, 3)])
    data = users._query(context("disabled_active", activity_type="6272"))
    assert data["state"] == "partial" and data["coverage"]["completeness"] == "not_proven"
    assert len(data["collections"]["disabled_active"]) == 1
    assert data["metrics"][0]["value"] == 1 and data["items"] == []
    monkeypatch.setattr(activity, "_read", lambda *_args: (_ for _ in ()).throw(errors.InsufficientPrivilege()))
    data = users._query(context("disabled_active"))
    assert data["state"] == "error" and data["metrics"] == []
    assert "activity_unavailable" in {note["code"] for note in data["limitations"]}


def test_main_list_gets_temporary_reason_and_filters_without_mutating_snapshot(monkeypatch):
    monkeypatch.setattr(users, "_snapshots", lambda *_args, **_kwargs: {"state": "ok", "current": CURRENT})
    fake_reads(monkeypatch, [event(1, 4728, 1), event(2, 4729, 2), event(3, 4728, 3), event(4, 4729, 4)])
    data = users._query(context("users", reason="temporary_membership", min_repeats=2))
    assert len(data["items"]) == 1 and "temporary_membership" in data["items"][0]["reason_keys"]
    assert "temporaryMemberships" not in USER
    assert data["state"] == "partial"


@pytest.fixture(autouse=True)
def _hygiene_settings(monkeypatch):
    from server.sli.core import platform_settings

    monkeypatch.setattr(platform_settings, "_stored_row", lambda _key: None)
