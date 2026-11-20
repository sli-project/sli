"""T042: real report composition, synthetic readers, and the shared HTTP deadline."""
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from psycopg.errors import QueryCanceled

from server.sli.core.database import QueryTimeoutError
from server.sli.plugins.remote_access import session_overlap
from server.sli.plugins.remote_access.reports import vpn_connections as report
from server.sli.reporting import read_timeout
from server.sli.reporting.v2.definition import QueryContext
from server.sli.reports import windows_authentication_reporting as windows

START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = START + timedelta(days=90)
ACCESS = {"platform_owner": True, "capabilities": ["vpn.sessions.view", "events.view"],
          "capability_policies": [], "reports": [{"report_key": "vpn.audit", "allowed": True,
          "grants": [{"allowed_actions": ["view"], "scope": {"kind": "all"}}]}]}


def context(tab):
    return QueryContext(access=ACCESS, params={"domain": "7", "period": {
        "from_utc": START.isoformat(), "to_utc": END.isoformat(),
    }}, domain_ids=[7], action="view", cursor=None, limit=50, timezone="UTC", tab=tab)


def event(index=1, code=6273):
    return {"event_db_id": index, "event_record_id": index, "event_id": code,
            "time_created_utc": START + timedelta(seconds=index),
            "subject_user_sid": "S-1-5-21-100-2001", "alias_match_count": 0,
            "domain_controller": "dc.example.invalid"}


class Cursor:
    def __init__(self, events=(), *, timeout_coverage=False):
        self.events = list(events)
        self.statements = []
        self.timeout_coverage = timeout_coverage

    def execute(self, sql, params=()):
        self.statements.append((sql, params))
        if self.timeout_coverage and "history_event_present" in sql:
            raise QueryCanceled("synthetic statement timeout")

    def fetchall(self):
        return self.events

    def fetchone(self):
        return {"history_event_present": True, "window_success_6272_count": 0,
                "window_failed_6273_count": len(self.events), "projected_session_count": 1}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def connection(cursor):
    return nullcontext(type("Connection", (), {"cursor": lambda _self: cursor})())


@pytest.mark.parametrize("tab", ["authorizations", "failed"])
def test_http_eight_second_budget_keeps_completed_nps_rows(monkeypatch, tab):
    from server.api.http_server import RequestHandler

    tick = [100.0]
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    monkeypatch.setattr(read_timeout, "monotonic", lambda: tick[0])
    monkeypatch.setattr(report, "get_vpn_authorization_timeline", lambda *_a, **_k: {
        "state": "available", "items": [event()],
    })

    def slow_accounting(*_a, **_k):
        tick[0] += 8.1
        read_timeout.remaining_read_ms()

    monkeypatch.setattr(report, "get_vpn_connections_report", slow_accounting)
    monkeypatch.setattr(report, "_domain_options", lambda _a: read_timeout.remaining_read_ms())
    handler = object.__new__(RequestHandler)
    handler.path = "/api/v2/reports/vpn.connections/data"
    handler._admit_request = lambda: True
    handler.server = Mock()
    handler._send_json = Mock()
    handler._do_GET = lambda: handler._send_json(report._query(context(tab)))
    handler.do_GET()
    args = handler._send_json.call_args.args
    assert len(args) == 1 or int(args[1]) == 200
    payload = args[0]
    assert payload["state"] == "partial"
    assert payload["collections"][tab][0]["event_db_id"] == 1
    assert payload["branches"]["accounting"]["reason"] == "source_read_timeout"
    assert all(metric.get("value") is None for metric in payload["metrics"])
    assert read_timeout.remaining_read_ms() is None


@pytest.mark.parametrize("error", [QueryCanceled("synthetic"), QueryTimeoutError("synthetic", timeout_ms=8000)])
def test_requested_source_timeout_is_partial_not_successful_empty(monkeypatch, error):
    def fail(*_a, **_k):
        raise error

    monkeypatch.setattr(report, "get_overlaps", fail)
    payload = report._query(context("session_overlap"))
    assert payload["state"] == "partial"
    assert payload["branches"]["accounting"]["reason"] == "source_read_timeout"
    assert payload["collections"]["session_overlap"] == []
    assert payload["branches"]["accounting"]["limits"]["max_period_days"] == 90
    assert all(metric["value"] is None for metric in payload["metrics"])


@pytest.mark.parametrize("reader", [windows.get_windows_authentication_report, windows.get_windows_authentication_failure_grid])
def test_windows_ninety_days_reaches_authorized_reader_without_clamping(monkeypatch, reader):
    calls = []

    def read(**kwargs):
        calls.append(kwargs)
        if "zone" in kwargs:
            return []
        return [], {"history_event_present": True}, {"truncated": False, "manual_review_policy": {}}

    monkeypatch.setattr(windows, "_read_windows_authentication_data", read)
    monkeypatch.setattr(windows, "_read_windows_authentication_failure_grid", read)
    reader(ACCESS, source_domain_id=7, time_from=START.isoformat(), time_to=END.isoformat())
    assert calls[0]["period_start"] == START and calls[0]["period_end"] == END


def test_overlap_ninety_days_reaches_authorized_reader(monkeypatch):
    cursor = Cursor()
    monkeypatch.setattr(session_overlap, "get_runtime_connection", lambda: connection(cursor))
    payload = session_overlap.get_overlaps(ACCESS, source_domain_id=7, time_from=START.isoformat(), time_to=END.isoformat())
    assert payload["state"] != "not_authorized"
    assert payload["limits"]["max_period_days"] >= 90
    params = next(params for sql, params in cursor.statements if "session_rows" in sql)
    assert START in params and END in params


def test_nps_busy_window_keeps_bounded_rows_and_exact_counts(monkeypatch):
    from server.sli.plugins.remote_access.reports import vpn_connections_reporting as nps
    cursor = Cursor([event(index) for index in range(1, 2002)])
    monkeypatch.setattr(nps, "_connect", lambda: connection(cursor))
    payload = nps.get_vpn_authorization_timeline(ACCESS, source_domain_id=7,
        time_from=START.isoformat(), time_to=END.isoformat())
    assert payload["state"] == "partial"
    assert len(payload["items"]) == 2000
    assert payload["result_window"]["truncated"] is True
    assert payload["collection_coverage"]["window_failed_6273_count"] == 2001


def test_nps_count_timeout_keeps_observed_rows_but_not_zero_totals(monkeypatch):
    from server.sli.plugins.remote_access.reports import vpn_connections_reporting as nps
    cursor = Cursor([event()], timeout_coverage=True)
    monkeypatch.setattr(nps, "_connect", lambda: connection(cursor))
    payload = nps.get_vpn_authorization_timeline(ACCESS, source_domain_id=7,
        time_from=START.isoformat(), time_to=END.isoformat())
    assert payload["state"] == "partial"
    assert payload["items"][0]["event_db_id"] == 1
    assert payload["unavailable_reason"] == "source_read_timeout"
    assert payload["collection_coverage"]["window_failed_6273_count"] is None


def test_failed_tab_filters_in_sql_before_the_limit(monkeypatch):
    from server.sli.plugins.remote_access.reports import vpn_connections_reporting as nps
    cursor = Cursor([event()])
    monkeypatch.setattr(nps, "_connect", lambda: connection(cursor))
    payload = nps.get_vpn_authorization_timeline(ACCESS, source_domain_id=7,
        time_from=START.isoformat(), time_to=END.isoformat(), failed_only=True)
    assert payload["items"][0]["event_id"] == 6273
    sql, params = next((sql, params) for sql, params in cursor.statements if "alias_resolution" in sql)
    assert params[1] == [6273]
    assert sql.index("limit %s") < sql.index("left join lateral")


def test_windows_optional_policy_timeout_preserves_history(monkeypatch):
    cursor = Cursor([event(code=4625)])
    monkeypatch.setattr(windows, "_connect", lambda: connection(cursor))
    def timeout(*_args):
        raise QueryCanceled("synthetic policy timeout")
    monkeypatch.setattr(windows, "_read_manual_review_policy", timeout)
    payload = windows.get_windows_authentication_report(ACCESS, source_domain_id=7,
        time_from=START.isoformat(), time_to=(START + timedelta(days=30)).isoformat())
    assert payload["state"] == "partial"
    assert payload["items"][0]["event_db_id"] == 1
    assert payload["manual_review_policy"]["state"] == "unavailable"
    assert payload["manual_review_policy"]["coverage_scope"] == "not_evaluated"


def test_windows_review_input_bound_never_claims_no_signal(monkeypatch):
    from server.sli.core.platform_settings import SETTINGS
    monkeypatch.setattr(windows, "get_setting", lambda key: SETTINGS[key].default)
    monkeypatch.setattr(windows, "MAX_REVIEW_INPUT_ROWS", 3, raising=False)
    cursor = Cursor([{"id": i, "at": START + timedelta(seconds=i), "sid": f"S-{i}",
                     "ip": None, "source": None} for i in range(4)])
    policy = windows._read_manual_review_policy(cursor, START, END, 7)
    assert policy["state"] == "unavailable"
    assert policy["coverage_scope"] == "not_evaluated"
    assert policy["reason"] == "review_input_limit"
    assert policy["signals"] == []


def test_windows_python_review_respects_the_existing_request_deadline(monkeypatch):
    tick = [100.0]
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    monkeypatch.setattr(read_timeout, "monotonic", lambda: tick[0])
    with read_timeout.report_read_budget():
        tick[0] += 8.1
        with pytest.raises(QueryTimeoutError):
            windows._first_manual_review_window([{"id": 1, "at": START, "sid": "S-1",
                                                  "ip": None, "source": None}],
                rule="single_ip", source_ip=None, duration=timedelta(minutes=15),
                minimum_failures=5, minimum_targets=3)


def test_heatmap_timeout_is_not_a_grid_of_successful_zeroes(monkeypatch):
    def timed_out(*_args, **_kwargs):
        raise QueryTimeoutError("synthetic", timeout_ms=8000)

    monkeypatch.setattr(report, "get_windows_authentication_failure_grid", timed_out)
    monkeypatch.setattr(report, "get_vpn_connections_report", lambda *_a, **_k: {
        "state": "available", "employees": [], "analytics": {},
    })
    monkeypatch.setattr(report, "_domain_options", lambda _a: [])
    payload = report._query(context("windows_heatmap"))
    assert payload["state"] == "partial"
    assert payload["collections"]["windows_heatmap"] == []
    assert payload["branches"]["windows_heatmap"]["reason"] == "source_read_timeout"


@pytest.mark.parametrize("reader", [windows.get_windows_authentication_report, windows.get_windows_authentication_failure_grid])
def test_windows_over_90_days_is_refused_not_silently_clamped(monkeypatch, reader):
    connect = Mock(side_effect=AssertionError("must reject before opening a connection"))
    monkeypatch.setattr(windows, "_connect", connect)
    with pytest.raises(ValueError, match="windows_authentication_period_too_wide"):
        reader(ACCESS, source_domain_id=7, time_from=START.isoformat(),
               time_to=(END + timedelta(days=1)).isoformat())
    connect.assert_not_called()


def test_overlap_over_90_days_is_refused_not_silently_clamped(monkeypatch):
    connect = Mock(side_effect=AssertionError("must reject before opening a connection"))
    monkeypatch.setattr(session_overlap, "get_runtime_connection", connect)
    with pytest.raises(ValueError, match="vpn_overlap_window_invalid"):
        session_overlap.get_overlaps(ACCESS, source_domain_id=7, time_from=START.isoformat(),
                                     time_to=(END + timedelta(days=1)).isoformat(), params={})
    connect.assert_not_called()


@pytest.mark.parametrize("reader", [windows.get_windows_authentication_report, windows.get_windows_authentication_failure_grid])
def test_90_day_support_does_not_bypass_windows_access(monkeypatch, reader):
    connect = Mock(side_effect=AssertionError("denied source must not read"))
    monkeypatch.setattr(windows, "_connect", connect)
    raw = reader({}, source_domain_id=7, time_from=START.isoformat(), time_to=END.isoformat())
    assert raw["state"] == "not_authorized"
    connect.assert_not_called()


def test_timeout_remains_partial_when_another_source_is_processing(monkeypatch):
    def timed_out(*_args, **_kwargs):
        raise QueryCanceled("synthetic")

    monkeypatch.setattr(report, "get_vpn_authorization_timeline", timed_out)
    monkeypatch.setattr(report, "get_vpn_connections_report", lambda *_a, **_k: {"state": "processing"})
    monkeypatch.setattr(report, "_domain_options", lambda _a: [])
    payload = report._query(context("authorizations"))
    assert payload["state"] == "partial"
    assert payload["branches"]["accounting"]["state"] == "processing"


def test_settings_fallback_after_deadline_does_not_start_policy_sql(monkeypatch):
    from server.sli.core import platform_settings

    tick = [100.0]
    calls = []
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    monkeypatch.setattr(read_timeout, "monotonic", lambda: tick[0])

    def delayed_setting(_sql, params=(), **_kwargs):
        calls.append(params[0])
        tick[0] += 2.1
        read_timeout.remaining_read_ms()  # _stored_row catches the final timeout.
        return []

    platform_settings.clear_cache()
    monkeypatch.setattr(platform_settings.database, "query_rows", delayed_setting)
    cursor = Cursor()
    with read_timeout.report_read_budget(), pytest.raises(QueryTimeoutError):
        windows._read_manual_review_policy(cursor, START, END, 7)
    assert len(calls) == 4
    assert cursor.statements == [], "expired settings fallback must not start another statement"
    platform_settings.clear_cache()


def test_policy_statement_timeout_never_exceeds_remaining_budget(monkeypatch):
    tick = [100.0]
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    monkeypatch.setattr(read_timeout, "monotonic", lambda: tick[0])
    monkeypatch.setattr(windows, "get_setting", lambda _key: 10)
    cursor = Cursor()
    with read_timeout.report_read_budget():
        tick[0] = 107.0
        windows._read_manual_review_policy(cursor, START, END, 7)
    assert cursor.statements[0][0] == "set local statement_timeout = '1000ms'"


def test_policy_deadline_is_rechecked_after_setting_local_timeout(monkeypatch):
    tick = [100.0]
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    monkeypatch.setattr(read_timeout, "monotonic", lambda: tick[0])
    monkeypatch.setattr(windows, "get_setting", lambda _key: 10)

    class ExpireAfterSet(Cursor):
        def execute(self, sql, params=()):
            super().execute(sql, params)
            tick[0] = 108.1

    cursor = ExpireAfterSet()
    with read_timeout.report_read_budget(), pytest.raises(QueryTimeoutError):
        windows._read_manual_review_policy(cursor, START, END, 7)
    assert len(cursor.statements) == 1


def test_nps_expiration_between_statements_keeps_rows_without_new_query(monkeypatch):
    from server.sli.plugins.remote_access.reports import vpn_connections_reporting as nps

    tick = [100.0]
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    monkeypatch.setattr(read_timeout, "monotonic", lambda: tick[0])

    class ExpireAfterFetch(Cursor):
        def fetchall(self):
            tick[0] = 108.1
            return super().fetchall()

    cursor = ExpireAfterFetch([event()])
    monkeypatch.setattr(nps, "_connect", lambda: connection(cursor))
    with read_timeout.report_read_budget():
        events, _identities, coverage = nps._read_vpn_authorization_timeline_data(
            domain_id=7, period_start=START, period_end=END)
    assert events and coverage.get("unavailable_reason") == "source_read_timeout"
    assert not any("history_event_present" in sql for sql, _params in cursor.statements)


def test_windows_settings_expiration_retains_history_and_marks_policy_not_evaluated(monkeypatch):
    from server.sli.core import platform_settings

    tick = [100.0]
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    monkeypatch.setattr(read_timeout, "monotonic", lambda: tick[0])

    def delayed_setting(_sql, _params=(), **_kwargs):
        tick[0] += 2.1
        read_timeout.remaining_read_ms()
        return []

    platform_settings.clear_cache()
    monkeypatch.setattr(platform_settings.database, "query_rows", delayed_setting)
    cursor = Cursor([event(code=4625)])
    monkeypatch.setattr(windows, "_connect", lambda: connection(cursor))
    with read_timeout.report_read_budget():
        payload = windows.get_windows_authentication_report(ACCESS, source_domain_id=7,
            time_from=START.isoformat(), time_to=END.isoformat())
    assert payload["state"] == "partial" and payload["items"][0]["event_db_id"] == 1
    assert payload["manual_review_policy"]["coverage_scope"] == "not_evaluated"
    assert not any("set local statement_timeout" in sql for sql, _params in cursor.statements)
    platform_settings.clear_cache()


def test_windows_expiration_between_history_and_coverage_keeps_rows(monkeypatch):
    tick = [100.0]
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    monkeypatch.setattr(read_timeout, "monotonic", lambda: tick[0])

    class ExpireAfterFetch(Cursor):
        def fetchall(self):
            tick[0] = 108.1
            return super().fetchall()

    cursor = ExpireAfterFetch([event(code=4625)])
    monkeypatch.setattr(windows, "_connect", lambda: connection(cursor))
    with read_timeout.report_read_budget():
        payload = windows.get_windows_authentication_report(ACCESS, source_domain_id=7,
            time_from=START.isoformat(), time_to=END.isoformat())
    assert payload["state"] == "partial" and payload["items"][0]["event_db_id"] == 1
    assert not any("history_event_present" in sql for sql, _params in cursor.statements)


def test_overlap_expiration_after_coverage_does_not_start_session_read(monkeypatch):
    tick = [100.0]
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    monkeypatch.setattr(read_timeout, "monotonic", lambda: tick[0])

    class ExpireAfterCoverage(Cursor):
        def fetchone(self):
            tick[0] = 108.1
            return super().fetchone()

    cursor = ExpireAfterCoverage()
    monkeypatch.setattr(session_overlap, "get_runtime_connection", lambda: connection(cursor))
    with read_timeout.report_read_budget():
        payload = report._query(context("session_overlap"))
    assert payload["state"] == "partial"
    assert payload["branches"]["accounting"]["reason"] == "source_read_timeout"
    assert not any("radius_vpn_session_rows_v1" in sql for sql, _params in cursor.statements)


@pytest.mark.parametrize("threshold", [1, 2])
def test_rejected_overlap_pairs_still_check_cpu_deadline(monkeypatch, threshold):
    tick = [100.0]
    comparisons = []
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    monkeypatch.setattr(read_timeout, "monotonic", lambda: tick[0])

    class ExpireDuringComparisons:
        def __int__(self):
            comparisons.append(True)
            if len(comparisons) == 1024:
                tick[0] = 108.1
            return threshold

    # All pairs overlap for one second: threshold 2 rejects every pair, so
    # the output cap never fires. Threshold 1 verifies accumulated pairs survive.
    rows = [{"session_row_id": f"synthetic-{i}", "entity_id": 1, "domain_id": 7,
             "generation": 1, "completeness": "complete", "started_at_utc": START,
             "stopped_at_utc": START + timedelta(seconds=1), "last_observed_at_utc": START}
            for i in range(128)]
    cursor = Cursor(rows)
    monkeypatch.setattr(session_overlap, "get_runtime_connection", lambda: connection(cursor))
    ctx = context("session_overlap")
    ctx.params["overlap_min_seconds"] = ExpireDuringComparisons()
    with read_timeout.report_read_budget():
        payload = report._query(ctx)
    assert payload["state"] == "partial", (len(comparisons), tick, payload)
    assert payload["branches"]["accounting"]["reason"] == "source_read_timeout"
    assert len(comparisons) < 2048
    assert bool(payload["collections"]["session_overlap"]) is (threshold == 1)
    assert not any(note["code"] == "overlap_truncated" for note in payload["limitations"])
    assert all(metric["value"] is None for metric in payload["metrics"])
