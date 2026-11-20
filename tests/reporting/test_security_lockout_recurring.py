from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from server.sli.reporting.v2.definition import QueryContext, parse_params
from server.sli.reporting.v2.reports import security_events
from server.sli.reports import security_lockout_recurring as reporting

START = datetime(2026, 10, 1, tzinfo=timezone.utc)
SID = "S-1-5-21-100-200-300-1001"


def event(identifier, event_id, minute, **fields):
    return {"event_db_id": identifier, "event_id": event_id,
            "time_created_utc": START + timedelta(minutes=minute),
            "target_user_sid": SID, "target_user_name": "account-a",
            "normalized_event_id": str(identifier), "facts_json": {}, **fields}


def aggregate(events, **filters):
    return reporting.aggregate_lockouts(events, failure_window_minutes=15, minimum_repeats=1, **filters)


def access(domain=7, *, fields=("security", "technical", "raw_evidence"), capabilities=("events.view",)):
    return {"platform_owner": False, "capabilities": list(capabilities), "capability_policies": [],
            "reports": [{"report_key": "security.events.chains", "allowed": True, "allowed_actions": ["view"],
                         "grants": [{"allowed_actions": ["view"], "field_categories": list(fields),
                                     "scope": {"kind": "domain", "ids": [domain]}}]}]}


def arguments(**overrides):
    return {"domain_id": 7, "time_from": START.isoformat(), "time_to": (START + timedelta(hours=1)).isoformat(),
            "limit": 100, **overrides}


def test_episodes_match_sid_once_and_link_observations():
    events = [event(1, 4625, -2, ip_address="192.0.2.1", result_code="0xC000006A"),
              event(2, 4740, 0, facts_json={"caller_computer": "workstation-a"}),
              event(3, 4767, 4), event(4, 4771, 6, facts_json={"result_code": "0x18"}),
              event(5, 4740, 10), event(6, 4776, 15, result_code="0xC000006A", facts_json={"workstation": "workstation-b"}),
              event(7, 4740, 20), event(8, 4767, 21)]
    row = aggregate([*reversed(events), events[0]])[0]
    assert row["lockouts"] == 3 and row["relocks"] == 1 and row["unlocks"] == 2
    assert row["failures"] == row["matched_lockouts"] == 3
    assert row["intervals_seconds"] == [600, 600]
    assert row["last_interval_seconds"] == 600
    assert row["first_lockout"] == "2026-10-01T00:00:00Z"
    assert row["last_lockout"] == "2026-10-01T00:20:00Z"
    assert row["matching"] == "all_with_failures"
    assert row["callers"] == ["workstation-a"] and row["ips"] == ["192.0.2.1"]
    assert row["workstations"] == ["workstation-b"]
    assert row["failure_codes"] == ["0x18", "0xc000006a"]
    assert (row["first_event"], row["last_event"], row["unlock_event"], row["failure_event"]) == (2, 7, 8, 6)
    assert set(row["event_ids"]) == set(range(1, 9))


@pytest.mark.parametrize("sid", [None, "-", "S-1-0-0", "invalid"])
def test_unknown_identities_never_merge_by_name_or_match_failures(sid):
    rows = aggregate([event(1, 4740, 0, target_user_sid=sid), event(2, 4740, 10, target_user_sid=sid),
                      event(3, 4625, -1, target_user_sid=sid), event(4, 4767, 5, target_user_sid=sid)])
    assert len(rows) == 2
    assert {row["account_key"] for row in rows} == {"unknown:1", "unknown:2"}
    assert all(row["lockouts"] == 1 and row["failures"] == row["relocks"] == 0 for row in rows)
    assert all(row["matching"] == "unknown_sid" for row in rows)


def test_same_name_different_sid_is_not_a_match():
    row = aggregate([event(1, 4740, 0), event(2, 4740, 10),
                     event(3, 4625, -1, target_user_sid=SID + "9"),
                     event(4, 4767, 5, target_user_sid=SID + "9")])[0]
    assert row["failures"] == row["relocks"] == 0
    assert row["matching"] == "no_failures"


def test_time_boundaries_and_successful_4776_do_not_imply_failures_or_relock():
    row = aggregate([event(1, 4740, 0), event(2, 4740, 10),
                     event(3, 4625, -16), event(4, 4625, 0), event(5, 4625, 10),
                     event(6, 4767, 0), event(7, 4767, 10),
                     event(8, 4776, 5, result_code="0x00000000"), event(9, 4776, 6),
                     event(10, 4776, 7, result_code="invalid")])[0]
    assert row["failures"] == row["relocks"] == 0
    # The inclusive lower boundary is allowed; upper boundaries are exclusive.
    assert aggregate([event(1, 4740, 0), event(2, 4625, -15)])[0]["failures"] == 1


@pytest.mark.parametrize("filters, expected", [
    ({"account": SID.lower()}, 1), ({"account": "ACCOUNT-A"}, 1), ({"account": "other"}, 0),
    ({"caller": "WORKSTATION-A"}, 1), ({"caller": "192.0.2.1"}, 1), ({"caller": "other"}, 0),
    ({"failure_code": "0xC000006A"}, 1), ({"failure_code": "0x18"}, 0),
])
def test_filters_preserve_complete_account_episode_counts(filters, expected):
    rows = aggregate([event(1, 4740, 0), event(2, 4740, 10, facts_json={"caller_computer": "workstation-a"}),
                      event(3, 4625, 9, ip_address="192.0.2.1", result_code="0xc000006a")], **filters)
    assert len(rows) == expected
    if rows:
        assert rows[0]["lockouts"] == 2


def test_matching_labels_missing_semantics_and_truncated_slice():
    assert aggregate([event(1, 4740, 0, normalized_event_id=None)])[0]["matching"] == "partial"
    assert aggregate([event(1, 4740, 0)], truncated=True)[0]["matching"] == "partial"
    rows = reporting.aggregate_lockouts([event(1, 4740, 0)], failure_window_minutes=15, minimum_repeats=2)
    assert rows == []


class FakeCursor:
    def __init__(self, batches):
        self.batches = iter(batches)
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchall(self):
        return next(self.batches)

    def cursor(self):
        return self


def test_bounded_reader_pins_current_unique_semantic_version():
    cur = FakeCursor([[event(1, 4740, 0), event(2, 4740, 1)]])
    rows, truncated = reporting._read_events(cur, domain_id=7, start=START, end=START + timedelta(days=1), event_ids=[4740], limit=1)
    assert len(rows) == 1 and truncated
    sql, params = cur.calls[0]
    assert "event.domain_id=%s" in sql and "event.event_id=any(%s)" in sql
    assert "event.time_created_utc>=%s and event.time_created_utc<%s" in sql
    assert "normalized.processing_status='normalized'" in sql
    assert "normalized.semantic_contract_version=%s" in sql
    assert "normalized.normalizer_id=%s and normalized.normalizer_version=%s" in sql
    assert "source_event_id=event.id" in sql and "limit %s" in sql
    assert params[:3] == [reporting.SEMANTIC_CONTRACT_VERSION, reporting.NORMALIZER_ID, reporting.NORMALIZER_VERSION]
    assert params[3:5] == [7, [4740]] and params[-1] == 2


@pytest.mark.parametrize("decision", [{}, access(8), access(capabilities=()), access(fields=("security",))])
def test_denies_before_database_read(monkeypatch, decision):
    monkeypatch.setattr(reporting.security, "_connect", lambda: pytest.fail("unauthorized database read"))
    assert reporting.get_recurring_lockouts(decision, **arguments()) == {"state": "denied", "rows": []}


@pytest.mark.parametrize("overrides", [
    {"time_to": (START + timedelta(days=32)).isoformat()}, {"time_to": START.isoformat()},
    {"failure_window_minutes": 1441}, {"failure_window_minutes": 0}, {"minimum_repeats": 0},
    {"limit": 501}, {"domain_id": 0}, {"action": "delete"},
])
def test_invalid_bounds_rejected_before_read(monkeypatch, overrides):
    monkeypatch.setattr(reporting.security, "_connect", lambda: pytest.fail("invalid database read"))
    with pytest.raises(ValueError):
        reporting.get_recurring_lockouts(access(), **arguments(**overrides))


def test_service_caps_sources_separately_and_metrics_cover_filtered_slice(monkeypatch):
    monkeypatch.setattr(reporting, "MAX_SOURCE_ROWS", 2)
    cur = FakeCursor([[event(1, 4740, 0), event(2, 4740, 10), event(3, 4740, 20)],
                      [event(4, 4767, 5)], [event(5, 4625, 9, result_code="0x18")]])
    monkeypatch.setattr(reporting.security, "_connect", lambda: cur)
    raw = reporting.get_recurring_lockouts(access(), **arguments())
    assert raw["state"] == "partial" and raw["coverage"]["source_truncated"]
    assert raw["rows"][0]["matching"] == "partial"
    assert raw["totals"] == {"accounts": 1, "lockouts": 2, "relocked_accounts": 1, "caller_percent": 0, "sources": 0}
    assert cur.calls[:2] == [("set transaction read only", None), ("set local statement_timeout='3000ms'", None)]
    assert [params[4] for _, params in cur.calls[2:]] == [[4740], [4767], [4625, 4771, 4776]]
    assert cur.calls[-1][1][5] == START - timedelta(minutes=15)
    assert raw["window"]["idea_key"] == "security.lockout-recurring"


def test_empty_is_unverified_and_row_cap_is_explicit(monkeypatch):
    monkeypatch.setattr(reporting.security, "_connect", lambda: FakeCursor([[], [], []]))
    raw = reporting.get_recurring_lockouts(access(), **arguments())
    assert raw["state"] == "empty" and raw["coverage"]["completeness"] == "not_proven"
    assert raw["totals"]["caller_percent"] is None
    monkeypatch.setattr(reporting.security, "_connect", lambda: FakeCursor([
        [event(1, 4740, 0), event(2, 4740, 1, target_user_sid=SID + "9")], [], []]))
    raw = reporting.get_recurring_lockouts(access(), **arguments(limit=1, minimum_repeats=1))
    assert raw["state"] == "partial" and raw["coverage"]["accounts_truncated"]
    assert raw["filtered_count"] == 2 and len(raw["rows"]) == 1


def test_existing_report_dispatches_tab_own_query_and_declares_columns(monkeypatch):
    params, paging = parse_params(security_events.REPORT, {"domain": ["7"], "tab": ["lockout-recurring"]}, now=START)
    assert params["min_repeats"] == 2 and params["failure_window"] == "15"
    monkeypatch.setattr(security_events, "get_security_events_report", lambda *_args, **_kwargs: pytest.fail("main event query"))
    monkeypatch.setattr(security_events, "_domain_options", lambda _access: [])
    monkeypatch.setattr(reporting.security, "_connect", lambda: FakeCursor([[event(1, 4740, 0), event(2, 4740, 10)], [], []]))
    context = QueryContext(access=access(), params=params, domain_ids=None, action="view", cursor=None,
                           limit=100, timezone="UTC", tab=paging["tab"])
    raw = security_events._query(context)
    assert raw["report_key"] == "security.events.chains" and raw["items"] == []
    assert raw["collections"]["lockout_recurring"][0]["lockouts"] == 2
    assert len(raw["metrics"]) == 5 and raw["limitations"]
    tab = next(view for view in security_events.REPORT.views if view.key == "lockout-recurring")
    assert tab.source == "lockout_recurring" and tab.kind == "table"
    assert {column.key for column in tab.columns if column.link} == {"first_event", "last_event", "unlock_event", "failure_event"}
    assert next(column for column in tab.columns if column.key == "sid").optional
    assert security_events.REPORT.access.scope == "delegated"
