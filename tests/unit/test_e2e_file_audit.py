"""File replay must detect partial losses and explain genuinely empty tabs."""
import pytest

from tools.e2e.file_audit import assess_report


def test_nonempty_page_still_fails_when_a_projected_action_is_missing():
    result = assess_report("file-audit.actions", {"one", "two"}, {"one"}, state="partial")
    assert result == {"report": "file-audit.actions", "projection": 2, "api": 1,
                      "missing": 1, "unexpected": 0, "state": "partial", "status": "failed",
                      "reason": "report_projection_mismatch"}


@pytest.mark.parametrize("report,reason", [
    ("file-audit.mass-operations", "no_mass_rule_results_in_window"),
    ("file-audit.permission-changes", "no_permission_change_actions_in_window"),
    ("file-audit.access-denials", "no_failed_access_actions_in_window"),
    ("file-audit.out-of-hours", "no_out_of_hours_rule_results_in_window"),
    ("file-audit.permissions", "no_acl_rule_results_for_latest_snapshots"),
])
def test_zero_is_explained_only_when_projection_is_also_empty(report, reason):
    result = assess_report(report, set(), set(), state="partial")
    assert result["status"] == "empty_explained" and result["reason"] == reason
    assert assess_report(report, {"missing"}, set(), state="partial")["status"] == "failed"


def test_unavailable_report_is_never_an_explained_empty_result():
    result = assess_report("file-audit.permissions", set(), set(), state="error")
    assert result["status"] == "failed" and result["reason"] == "report_error"


def test_unexpected_report_rows_fail_exact_source_scope_comparison():
    result = assess_report("file-audit.actions", {"one"}, {"one", "foreign"}, state="partial")
    assert result["status"] == "failed" and result["unexpected"] == 1


def test_file_api_counter_keeps_cursor_window_across_wall_clock_seconds(monkeypatch):
    import io
    import json
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    from urllib.parse import parse_qs, urlsplit

    from server.sli.core.keyset_cursor import decode_cursor, encode_cursor
    from server.sli.plugins.file_audit.reports import REPORTS
    from server.sli.reporting.v2.definition import parse_params
    from tools.e2e import scenario

    now = datetime(2026, 10, 11, 5, 0, tzinfo=timezone.utc)
    calls = []

    def execute(sql, *_args):
        if "select now()" in sql:
            return SimpleNamespace(fetchone=lambda: {"at": now})
        return [{"id": "one"}, {"id": "two"}]

    def read(url, **_kwargs):
        query = parse_qs(urlsplit(url).query)
        params, paging = parse_params(REPORTS[1], query, now=now + timedelta(seconds=len(calls)))
        if paging["cursor"]:
            decode_cursor(paging["cursor"], params)
        calls.append(query)
        first = len(calls) == 1
        return io.BytesIO(json.dumps({"items": [{"id": "one" if first else "two"}], "has_more": first,
            "next_cursor": encode_cursor(params, {"cursor": "second"}) if first else None}).encode())

    monkeypatch.setattr(scenario, "read_file_report", lambda url: json.load(read(url)))
    assert scenario.api_count(SimpleNamespace(execute=execute), "file-audit", base_url="http://fixture") == (2, None)
    assert calls[0]["from"] == calls[1]["from"] and calls[0]["to"] == calls[1]["to"]


@pytest.mark.parametrize("age,state", [(30, "recent"), (900, "recent"), (901, "stale")])
def test_replay_distinguishes_event_recency_from_equal_projection_counts(age, state):
    from datetime import datetime, timedelta, timezone

    from tools.e2e.file_audit import event_recency
    from tools.e2e.scenario import replay_status

    end = datetime(2026, 10, 12, tzinfo=timezone.utc)
    latest = end - timedelta(seconds=age)
    recency = event_recency([{"latest_event_utc": latest}], end=end)
    assert recency == {"state": state, "latest_event_utc": latest.isoformat(),
                       "age_seconds": age, "threshold_seconds": 900}
    assert replay_status(failed=False, retained_conflicts=[], file_source={"event_recency": recency}) == (
        "partial" if state == "stale" else "verified")
    assert replay_status(failed=True, retained_conflicts=[], file_source={"event_recency": recency}) == "failed"


def test_recency_uses_latest_event_across_types_and_keeps_absence_unknown():
    from datetime import datetime, timedelta, timezone

    from tools.e2e.file_audit import event_recency

    end = datetime(2026, 10, 12, tzinfo=timezone.utc)
    result = event_recency([{"latest_event_utc": end-timedelta(hours=6)},
                            {"latest_event_utc": end-timedelta(seconds=10)}], end=end)
    assert result["state"] == "recent" and result["age_seconds"] == 10
    assert event_recency([], end=end) == {"state": "unknown", "latest_event_utc": None,
        "age_seconds": None, "threshold_seconds": 900}


def test_recent_shared_context_cannot_hide_stale_file_actions():
    from tools.e2e.scenario import replay_status

    assert replay_status(failed=False, retained_conflicts=[], file_source={
        "event_recency": {"state": "recent"}, "action_recency": {"state": "stale"}}) == "partial"


def test_source_summary_serializes_event_and_action_times_without_private_values():
    import json
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace

    from tools.e2e.file_audit import source_summary

    end = datetime(2026, 10, 12, tzinfo=timezone.utc)
    latest = end - timedelta(hours=6)

    def execute(sql, _params):
        if "from sli_plugin_file_audit.observations" in sql:
            rows = [{"event_id": 4663, "observations": 20, "scoped": 20, "latest_event_utc": latest}]
        elif "from sli_plugin_file_audit.actions" in sql:
            rows = [{"operation": "read", "outcome": "success", "actions": 20,
                     "distinct_objects": 5, "latest_action_utc": latest}]
        elif "mass_operation_files" in sql:
            rows = [{"files": 20, "seconds": 300}]
        else:
            return SimpleNamespace(fetchone=lambda: None)
        return SimpleNamespace(fetchall=lambda: rows)

    result = source_summary(SimpleNamespace(execute=execute), agents=["synthetic"], start=end-timedelta(days=1), end=end)
    assert result["event_recency"]["state"] == "stale"
    assert result["action_recency"]["state"] == "stale"
    assert result["action_recency"]["latest_action_utc"] == latest.isoformat()
    assert result["events"][0]["latest_event_utc"] == latest.isoformat()
    assert result["actions"][0]["latest_action_utc"] == latest.isoformat()
    assert result["working_time"] == "not_configured"
    assert json.loads(json.dumps(result)) == result


def test_file_report_network_is_kill_bounded_and_private_errors_stay_local(monkeypatch):
    import subprocess

    from tools.e2e import file_audit

    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, '{"state":"partial","items":[]}', '')

    monkeypatch.setattr(file_audit.subprocess, "run", run)
    assert file_audit.read_report("http://127.0.0.1:18443/api/v2/reports/file-audit.actions/data") == {
        "state": "partial", "items": []}
    args, options = calls[0]
    assert args[:5] == ["timeout", "-k", "2s", "35s", "curl"]
    assert options["timeout"] == 40 and options["capture_output"] is True
    monkeypatch.setattr(file_audit.subprocess, "run", lambda *_a, **_k:
        subprocess.CompletedProcess([], 22, 'private native evidence', 'private credential'))
    with pytest.raises(ValueError, match="^report_api_failed$"):
        file_audit.read_report("http://127.0.0.1:18443/api/v2/reports/file-audit.actions/data")


@pytest.mark.parametrize("payload", ['["private native evidence"]', '"private credential"', "null", "42"])
def test_file_report_rejects_non_object_json_without_private_values(monkeypatch, payload):
    import subprocess

    from tools.e2e import file_audit

    monkeypatch.setattr(file_audit.subprocess, "run", lambda *_a, **_k:
        subprocess.CompletedProcess([], 0, payload, 'private diagnostic'))
    with pytest.raises(TypeError, match="^report_api_failed$"):
        file_audit.read_report("http://127.0.0.1:18443/api/v2/reports/file-audit.actions/data")
