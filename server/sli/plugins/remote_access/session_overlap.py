"""Bounded overlap analysis of canonical RADIUS Accounting session rows."""

from collections import defaultdict
from datetime import timedelta
from typing import Any

from server.sli.core.time_contract import normalize_utc_range
from server.sli.core.database import QueryTimeoutError
from server.sli.reporting.read_timeout import remaining_read_ms
from server.sli.reporting.reporting_common import format_iso, get_runtime_connection, parse_utc
from server.sli.plugins.remote_access.reports.vpn_connections_reporting import _coverage_state
from server.sli.plugins.remote_access.reports.vpn_report_composition import vpn_report_composition_decision

OWNER_ID = "sli.remote-access"
MAX_PERIOD_DAYS = 90
MAX_SESSIONS = 5000
MAX_PAIRS = 5000


def _sweep(intervals, *, threshold=2):
    remaining_read_ms()
    edges = sorted((point, delta) for start, end in intervals for point, delta in ((start, 1), (end, -1)))
    current = maximum = seconds = 0
    previous = None
    for point, delta in edges:
        if previous is not None and current >= threshold:
            seconds += int((point - previous).total_seconds())
        current += delta
        maximum = max(maximum, current)
        previous = point
    return maximum, seconds


def analyze(rows, time_from, time_to, *, params=None):
    remaining_read_ms()
    params = params or {}
    start, end = parse_utc(time_from), parse_utc(time_to)
    groups = defaultdict(list)
    seen = set()
    unknown_identity = incomplete = invalid_intervals = 0
    for row_index, row in enumerate(rows):
        if row_index % 256 == 0:
            remaining_read_ms()
        identity = (row.get("domain_id"), row.get("entity_id"))
        row_key = (*identity, row.get("session_row_id"), row.get("generation"))
        if row_key in seen:
            continue
        seen.add(row_key)
        if not all(identity) or not row.get("session_row_id") or not row.get("generation"):
            unknown_identity += 1
            continue
        left = parse_utc(row.get("started_at_utc"))
        stopped = parse_utc(row.get("stopped_at_utc"))
        right = stopped or parse_utc(row.get("last_observed_at_utc"))
        complete = stopped is not None and row.get("completeness") == "complete"
        incomplete += not complete
        if params.get("overlap_complete") == "true" and not complete:
            continue
        if params.get("overlap_account") is not None and row["entity_id"] != params["overlap_account"]:
            continue
        if left is None or right is None or right <= left:
            invalid_intervals += 1
            continue
        left, right = max(left, start), min(right, end)
        if right > left:
            # Generation is local to a session identity key, not an account
            # epoch. Compare distinct canonical rows, retaining both generations
            # rather than combining observations into one account interval.
            groups[identity].append((left, right, complete, row))
    items = []
    accounts = set()
    maximum = seconds = 0
    truncated = False
    comparisons = 0
    timed_out = False
    try:
        for identity, intervals in sorted(groups.items()):
            remaining_read_ms()
            confirmed_intersections = []
            group_pair_count = 0
            active = []
            for left, right, complete, row in sorted(intervals, key=lambda value: (value[0], value[3]["session_row_id"])):
                active = [other for other in active if other[1] > left]
                for other_start, other_end, other_complete, other in active:
                    comparisons += 1
                    if comparisons % 1024 == 0:
                        remaining_read_ms()
                    overlap_start, overlap_end = max(left, other_start), min(right, other_end)
                    duration = int((overlap_end - overlap_start).total_seconds())
                    if duration < max(1, int(params.get("overlap_min_seconds") or 0)):
                        continue
                    if len(items) >= MAX_PAIRS:
                        truncated = True
                        break
                    accounts.add(identity[:2])
                    group_pair_count += 1
                    if complete and other_complete:
                        confirmed_intersections.append((overlap_start, overlap_end))
                    items.append({"row_id": f"{other['session_row_id']}:{row['session_row_id']}",
                                  "domain_id": identity[0], "entity_id": identity[1],
                                  "generation_a": other["generation"], "generation_b": row["generation"],
                                  "session_a": other["session_row_id"], "session_b": row["session_row_id"],
                                  "start_a": format_iso(other.get("started_at_utc")), "end_a": format_iso(other.get("stopped_at_utc")) or None,
                                  "start_b": format_iso(row.get("started_at_utc")), "end_b": format_iso(row.get("stopped_at_utc")) or None,
                                  "completeness_a": other.get("completeness"), "completeness_b": row.get("completeness"),
                                  "last_a": format_iso(other.get("last_observed_at_utc")), "last_b": format_iso(row.get("last_observed_at_utc")),
                                  "overlap_start_utc": format_iso(overlap_start), "overlap_end_utc": format_iso(overlap_end),
                                  "overlap_seconds": duration, "interval_quality": "confirmed" if complete and other_complete else "observed"})
                if truncated:
                    break
                active.append((left, right, complete, row))
            if group_pair_count:
                concurrency, _ = _sweep([(a, b) for a, b, _, _ in intervals])
                maximum = max(maximum, concurrency)
                _, confirmed = _sweep(confirmed_intersections, threshold=1)
                seconds += confirmed
            if truncated:
                break
        remaining_read_ms()
    except QueryTimeoutError:
        # Completed pair observations survive, but aggregate totals are unknown.
        timed_out = truncated = True
    return {"items": items, **({"unavailable_reason": "source_read_timeout"} if timed_out else {}),
            "metrics": {} if truncated else {"accounts": len(accounts), "max_concurrent": maximum,
            "confirmed_seconds": seconds, "incomplete_sessions": incomplete},
            "unknown_identity_count": unknown_identity, "invalid_interval_count": invalid_intervals, "truncated": truncated}


def get_overlaps(access, *, source_domain_id, time_from, time_to, params=None, action="view") -> dict[str, Any]:
    params = params or {}
    start, end = normalize_utc_range(time_from, time_to, timezone_name="UTC")
    start, end = parse_utc(start), parse_utc(end)
    if start is None or end is None or end <= start or end - start > timedelta(days=MAX_PERIOD_DAYS):
        raise ValueError("vpn_overlap_window_invalid")
    domain_id = int(source_domain_id)
    if domain_id <= 0:
        raise ValueError("vpn_overlap_domain_invalid")
    if not vpn_report_composition_decision(access, source_domain_id=domain_id, action=action).sessions.allowed:
        return {"state": "not_authorized", "items": [], "metrics": {}, "coverage": {}}
    with get_runtime_connection() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        remaining = remaining_read_ms()
        timeout_ms = min(10_000, remaining) if remaining is not None else 10_000
        cur.execute(f"set local statement_timeout = '{timeout_ms}ms'")
        remaining_read_ms()
        cur.execute("select * from radius_vpn_session_coverage_v1 where domain_id=%s", (domain_id,))
        coverage = cur.fetchone()
        if coverage is None:
            return {"state": "not_collected", "reason": "no_accounting_data", "items": [], "metrics": {}, "coverage": {}}
        remaining_read_ms()
        cur.execute(
            """select session_row_id,entity_id,domain_id,generation,lifecycle_state,completeness,
                      started_at_utc,stopped_at_utc,last_observed_at_utc
               from radius_vpn_session_rows_v1
               where domain_id=%s
                 and (%s::bigint is null or entity_id=%s)
                 and ((started_at_utc<%s and
                       ((stopped_at_utc is not null and stopped_at_utc>%s)
                        or (stopped_at_utc is null and last_observed_at_utc>%s)))
                      or (started_at_utc is null and last_observed_at_utc>=%s and last_observed_at_utc<%s))
               order by started_at_utc,session_row_id limit %s""", (domain_id, params.get("overlap_account"), params.get("overlap_account"), end, start, start, start, end, MAX_SESSIONS + 1),
        )
        rows = [dict(row) for row in cur.fetchall()]
    if not coverage.get("projected_session_count"):
        return {"state": "not_collected", "reason": "no_accounting_data", "items": [], "metrics": {}, "coverage": dict(coverage)}
    data = analyze(rows[:MAX_SESSIONS], start, end, params=params)
    truncated = len(rows) > MAX_SESSIONS or data["truncated"]
    timed_out = data.get("unavailable_reason") == "source_read_timeout"
    coverage_state = "partial" if timed_out else _coverage_state(coverage)
    partial = truncated or data["unknown_identity_count"] or data["invalid_interval_count"] or coverage_state != "available"
    state = "partial" if partial else "available"
    return {**data, "state": state, "truncated": truncated, "metrics": {} if truncated else data["metrics"],
            "limits": {"max_period_days": MAX_PERIOD_DAYS, "max_session_rows": MAX_SESSIONS, "max_pairs": MAX_PAIRS},
            "coverage": {**dict(coverage), "state": coverage_state,
                         **({"read_incomplete": True, "completeness": "not_proven"} if timed_out else {}),
                         "unknown_identity_count": data["unknown_identity_count"],
                         "invalid_interval_count": data["invalid_interval_count"], "truncated": truncated}}
