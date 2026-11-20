"""Independent projection-to-API checks for all eight file-audit products."""
import json
import subprocess
from urllib.parse import urlencode

from server.sli.core.working_time import SETTING_KEY, validate

EVENT_RECENCY_SECONDS = 900

TABS = ("overview", "actions", "mass-operations", "permission-changes", "access-denials",
        "out-of-hours", "permissions", "audit-state")
REPORTS = tuple("file-audit." + tab for tab in TABS)
EMPTY_REASONS = {
    "actions": "no_file_actions_in_window",
    "mass-operations": "no_mass_rule_results_in_window",
    "permission-changes": "no_permission_change_actions_in_window",
    "access-denials": "no_failed_access_actions_in_window",
    "out-of-hours": "no_out_of_hours_rule_results_in_window",
    "permissions": "no_acl_rule_results_for_latest_snapshots",
}

ROOTS_SQL = """with policies as (
    select distinct on(agent_id,source_instance_id) *
    from sli_plugin_file_audit.policy_revisions where agent_id::text=any(%s)
    order by agent_id,source_instance_id,revision desc
), roots as (
    select p.agent_id,p.source_instance_id,r->>'collection_scope_id' as collection_scope_id
    from policies p cross join lateral jsonb_array_elements(p.policy->'roots') r
) """

def assess_report(report, expected, found, *, state):
    missing, unexpected = len(expected - found), len(found - expected)
    reason = None
    status = "verified"
    if state not in ("ok", "partial", "empty"):
        status, reason = "failed", "report_" + str(state)
    elif missing or unexpected:
        status, reason = "failed", "report_projection_mismatch"
    elif not expected:
        reason = EMPTY_REASONS.get(report.removeprefix("file-audit."))
        status = "empty_explained" if reason else "failed"
        reason = reason or "no_admitted_file_roots"
    return {"report": report, "projection": len(expected), "api": len(found),
            "missing": missing, "unexpected": unexpected, "state": state,
            "status": status, "reason": reason}


def projection_ids(conn, tab, *, agents, start, end):
    """Read source tables independently of the report function and HTTP reader."""
    if tab in ("overview", "audit-state"):
        sql = "select agent_id::text||':'||source_instance_id||':'||collection_scope_id as id from roots"
        params = (agents,)
    elif tab in ("actions", "permission-changes", "access-denials"):
        predicates = {"actions": "true", "permission-changes": "operation in ('permissions','share_change','audit_change')",
                      "access-denials": "outcome='failure'"}
        sql = ("select action_id as id from sli_plugin_file_audit.actions join roots "
               "using(agent_id,source_instance_id,collection_scope_id) "
               "where observed_at>=%s and observed_at<%s and " + predicates[tab])
        params = (agents, start, end)
    elif tab in ("mass-operations", "out-of-hours"):
        codes = ["file-audit.mass-read", "file-audit.mass-write", "file-audit.mass-delete"] if tab == "mass-operations" else ["file-audit.out-of-hours"]
        sql = ("select result_id as id from sli_plugin_file_audit.rule_results join roots "
               "using(agent_id,source_instance_id,collection_scope_id) "
               "where observed_at>=%s and observed_at<%s and rule_code=any(%s)")
        params = (agents, start, end, codes)
    elif tab == "permissions":
        sql = """, latest as (
            select distinct on(s.agent_id,s.source_instance_id,s.collection_scope_id) s.*
            from sli_plugin_file_audit.access_snapshots s join roots
            using(agent_id,source_instance_id,collection_scope_id) where s.observed_at<%s
            order by s.agent_id,s.source_instance_id,s.collection_scope_id,s.observed_at desc,s.snapshot_id desc
        ) select distinct f.result_id as id from sli_plugin_file_audit.rule_results f
          join sli_plugin_file_audit.rule_snapshots e using(result_id) join latest s using(snapshot_id)
          where f.agent_id=s.agent_id and f.source_instance_id=s.source_instance_id
            and f.collection_scope_id=s.collection_scope_id and f.rule_code in
            ('file-audit.broad-write','file-audit.direct-user-rights','file-audit.disabled-account-rights','file-audit.acl-review')"""
        params = (agents, end)
    else:
        raise ValueError("file_audit_report_unknown")
    return {str(row["id"]) for row in conn.execute(ROOTS_SQL + sql, params)}


def read_report(url):
    """Bound even a stuck HTTP client and retain private diagnostics locally."""
    try:
        response = subprocess.run([
            "timeout", "-k", "2s", "35s", "curl", "--disable", "--silent", "--fail",
            "--max-time", "30", "--max-filesize", "16777216", "--url", url,
        ], capture_output=True, text=True, encoding="utf-8", timeout=40, check=False)
    except (OSError, subprocess.SubprocessError):
        raise ValueError("report_api_failed") from None
    if response.returncode:
        raise ValueError("report_api_failed")
    try:
        data = json.loads(response.stdout)
    except ValueError:
        raise ValueError("report_api_failed") from None
    if not isinstance(data, dict):
        raise TypeError("report_api_failed")
    return data


def event_recency(events, *, end, time_key="latest_event_utc"):
    """Recency of observed events is separate from projection/API parity."""
    latest = max((row[time_key] for row in events if row.get(time_key)), default=None)
    age = max(0, (end - latest).total_seconds()) if latest else None
    return {"state": "unknown" if age is None else "recent" if age <= EVENT_RECENCY_SECONDS else "stale",
            time_key: latest.isoformat() if latest else None, "age_seconds": age,
            "threshold_seconds": EVENT_RECENCY_SECONDS}


def scan_api(base_url, report, *, start, end):
    found, cursor = set(), None
    collections = {}
    for _ in range(100):
        query = {"period": "custom", "from": start.isoformat(), "to": end.isoformat(),
                 "limit": "100", "tz": "UTC"}
        if cursor:
            query["cursor"] = cursor
        data = read_report(base_url + f"/api/v2/reports/{report}/data?" + urlencode(query))
        found.update(str(row["id"]) for row in data.get("items", []))
        for key, values in data.get("collections", {}).items():
            if isinstance(values, list):
                collections[key] = len(values)
        if not data.get("has_more"):
            return found, data.get("state"), collections
        next_cursor = data.get("next_cursor")
        if not next_cursor or next_cursor == cursor:
            raise ValueError("report_cursor_missing_or_repeated")
        cursor = next_cursor
    raise ValueError("report_scan_limit")


def measure_reports(conn, *, agents, start, end, base_url):
    results = []
    for tab, report in zip(TABS, REPORTS, strict=True):
        expected = projection_ids(conn, tab, agents=agents, start=start, end=end)
        found, state, collections = scan_api(base_url, report, start=start, end=end)
        result = assess_report(report, expected, found, state=state)
        result["collections"] = collections
        results.append(result)
    return results


def source_summary(conn, *, agents, start, end):
    """Only aggregate evidence may leave the disposable database."""
    events = conn.execute("select event_id,count(*) as observations,max(observed_at) as latest_event_utc,"
        "count(*) filter(where jsonb_array_length(normalized->'scopes')>0) as scoped "
        "from sli_plugin_file_audit.observations where agent_id::text=any(%s) "
        "and observed_at>=%s and observed_at<%s group by event_id order by event_id", (agents, start, end)).fetchall()
    actions = conn.execute(ROOTS_SQL + "select operation,outcome,count(*) as actions,max(observed_at) as latest_action_utc,"
        "count(distinct lower(path)) as distinct_objects from sli_plugin_file_audit.actions join roots "
        "using(agent_id,source_instance_id,collection_scope_id) where observed_at>=%s and observed_at<%s "
        "group by operation,outcome order by operation,outcome", (agents, start, end)).fetchall()
    thresholds = conn.execute(
        ROOTS_SQL + "select distinct (policy->>'mass_operation_files')::integer as files,"
        "(policy->>'mass_operation_seconds')::integer as seconds from policies", (agents,)).fetchall()
    stored = conn.execute("select value from platform_settings where key=%s", (SETTING_KEY,)).fetchone()
    calendar = "not_configured"
    if stored:
        try:
            validate(json.loads(stored["value"]))
            calendar = "configured"
        except (ValueError, TypeError):
            calendar = "invalid"
    recency = event_recency(events, end=end)
    action_recency = event_recency(actions, end=end, time_key="latest_action_utc")
    for row in events:
        row["latest_event_utc"] = row["latest_event_utc"].isoformat() if row["latest_event_utc"] else None
    for row in actions:
        row["latest_action_utc"] = row["latest_action_utc"].isoformat() if row["latest_action_utc"] else None
    return {"events": events, "actions": actions, "mass_thresholds": thresholds, "working_time": calendar,
            "event_recency": recency, "action_recency": action_recency}
