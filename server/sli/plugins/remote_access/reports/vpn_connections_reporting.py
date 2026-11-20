# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``vpn_connections_reporting`` at call time.
from __future__ import annotations

"""Human-readable VPN connections report over existing durable projections.

The module is deliberately a read model: RADIUS Accounting remains the sole
session-lifecycle source, AD Context remains the identity/entitlement source,
and durable NPS 6273 events remain a separate authorization-failure list.
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from server.sli.plugins.remote_access.entitlements import MAX_ENTITLEMENT_ROWS, read_entitlements
from server.sli.core.time_contract import TimeRangeError, normalize_utc_range
from server.sli.core.time_format import get_display_timezone, parse_event_time
from server.sli.reporting.reporting_common import get_runtime_connection, parse_utc
from server.sli.plugins.remote_access.reports.vpn_report_composition import vpn_report_composition_decision

CONTRACT_ID = "sli.vpn-connections-report.v1"
REPORT_KEY = "vpn.connections"
FAILED_AUTHORIZATION_SERIES_CONTRACT_ID = "sli.vpn-audit-failed-authorization-series.v1"
FAILED_AUTHORIZATION_SERIES_REPORT_KEY = "vpn.audit"
AUTHORIZATION_TIMELINE_CONTRACT_ID = "sli.vpn-audit-authorization-timeline.v1"
AUTHORIZATION_TIMELINE_REPORT_KEY = "vpn.audit"
MAX_SESSION_ROWS = 20_000
MAX_EMPLOYEE_PAGE = 200
MAX_FAILED_EVENT_ROWS = 2_000
MAX_AUTHORIZATION_TIMELINE_ROWS = 2_000
MAX_FAILED_AUTHORIZATION_SERIES = 500
MAX_FAILED_AUTHORIZATION_EVENT_REFERENCES = 100
MAX_FAILED_AUTHORIZATION_REASON_CODES = 100
MAX_SESSION_DETAILS_PER_EMPLOYEE = 100
MAX_BRANCH_OUTPUT_ROWS = 200
MAX_PERIOD_DAYS = 366


_utc = parse_utc


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _public(value: Any) -> Any:
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, tuple):
        return [_public(item) for item in value]
    if isinstance(value, list):
        return [_public(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _public(item) for key, item in value.items()}
    return value


def _round_minutes(seconds: int) -> int:
    """Round once, after exact seconds have been unioned."""

    return int(seconds / 60 + 0.5)


def _session_observed_end(row: Mapping[str, Any]) -> datetime | None:
    return _utc(row.get("stopped_at_utc")) or _utc(row.get("last_observed_at_utc"))


def session_intersects_period(
    row: Mapping[str, Any],
    period_start: datetime,
    period_end: datetime,
) -> bool:
    start = _utc(row.get("started_at_utc"))
    observed_end = _session_observed_end(row)
    if start is None or observed_end is None or start >= period_end:
        return False
    if _utc(row.get("stopped_at_utc")) is not None:
        return max(start, period_start) < min(observed_end, period_end)
    return observed_end >= start and observed_end >= period_start


def _closed_effective_interval(
    row: Mapping[str, Any],
    period_start: datetime,
    period_end: datetime,
) -> tuple[datetime, datetime] | None:
    start = _utc(row.get("started_at_utc"))
    stop = _utc(row.get("stopped_at_utc"))
    if start is None or stop is None:
        return None
    effective = max(start, period_start), min(stop, period_end)
    return effective if effective[0] < effective[1] else None


def _union_seconds(intervals: Iterable[tuple[datetime, datetime]]) -> int:
    ordered = sorted(intervals)
    if not ordered:
        return 0
    total = 0
    current_start, current_end = ordered[0]
    for start, end in ordered[1:]:
        if start <= current_end:
            current_end = max(current_end, end)
            continue
        total += int((current_end - current_start).total_seconds())
        current_start, current_end = start, end
    return total + int((current_end - current_start).total_seconds())


def _overlapping_row_ids(
    intervals: Sequence[tuple[str, datetime, datetime]],
) -> tuple[set[str], int]:
    overlapping: set[str] = set()
    pair_count = 0
    ordered = sorted(intervals, key=lambda item: (item[1], item[2], item[0]))
    for index, (row_id, start, end) in enumerate(ordered):
        for other_id, other_start, other_end in ordered[index + 1:]:
            if other_start >= end:
                break
            if max(start, other_start) < min(end, other_end):
                overlapping.update((row_id, other_id))
                pair_count += 1
    return overlapping, pair_count


def _identity_for(
    identities: Mapping[int, Mapping[str, Any]],
    entity_id: int | None,
) -> dict[str, Any]:
    source = identities.get(int(entity_id)) if entity_id is not None else None
    source = source or {}
    netbios_name = str(source.get("netbios_name") or "").strip()
    sam_account_name = str(source.get("sam_account_name") or "").strip()
    account_name = (
        f"{netbios_name}\\{sam_account_name}"
        if netbios_name and sam_account_name
        else "Не определено"
    )
    return {
        "entity_id": entity_id,
        "display_name": str(source.get("display_name") or "Не определено"),
        "account_name": account_name,
        "department": str(source.get("department") or "Не определено"),
        "enabled": source.get("enabled"),
        "last_logon_utc": _public(source.get("last_logon_utc")),
        "privileged": bool(source.get("privileged")),
    }


def _coverage_state(coverage: Mapping[str, Any]) -> str:
    total = int(coverage.get("total_delivery_count") or 0)
    projected = int(coverage.get("projected_session_count") or 0)
    pending = sum(int(coverage.get(key) or 0) for key in (
        "queued_delivery_count", "leased_delivery_count", "failed_delivery_count",
    ))
    unresolved = sum(int(coverage.get(key) or 0) for key in (
        "identity_unresolved_count", "timestamp_unresolved_count", "quarantined_delivery_count",
    ))
    if total == 0:
        return "not_collected"
    if pending:
        return "processing"
    if projected == 0 and unresolved:
        return "identity_incomplete"
    if unresolved:
        return "partial"
    return "available"


def _daily_analytics(
    employees: Sequence[Mapping[str, Any]],
    *,
    period_start: datetime,
    period_end: datetime,
    office_timezone: str,
) -> list[dict[str, Any]]:
    zone, _ = get_display_timezone(office_timezone)
    first_day = period_start.astimezone(zone).date()
    last_instant = period_end - timedelta(microseconds=1)
    last_day = last_instant.astimezone(zone).date()
    result: list[dict[str, Any]] = []
    current = first_day
    while current <= last_day:
        local_start = datetime.combine(current, time.min, tzinfo=zone)
        local_end = datetime.combine(current + timedelta(days=1), time.min, tzinfo=zone)
        day_start = max(period_start, local_start.astimezone(timezone.utc))
        day_end = min(period_end, local_end.astimezone(timezone.utc))
        starts: set[int] = set()
        closed_count = 0
        intervals: dict[int, list[tuple[datetime, datetime]]] = defaultdict(list)
        for employee in employees:
            entity_id = int(employee["entity_id"])
            for session in employee["sessions_all"]:
                started = _utc(session.get("started_at_utc"))
                stopped = _utc(session.get("stopped_at_utc"))
                if started and day_start <= started < day_end:
                    starts.add(entity_id)
                if stopped:
                    interval = _closed_effective_interval(session, day_start, day_end)
                    if interval:
                        intervals[entity_id].append(interval)
                    if started and day_start <= started < day_end:
                        closed_count += 1
        exact_seconds = sum(_union_seconds(items) for items in intervals.values())
        result.append({
            "date": current.isoformat(),
            "employees_with_observed_start": len(starts),
            "closed_session_count": closed_count,
            "confirmed_seconds": exact_seconds,
            "confirmed_minutes": _round_minutes(exact_seconds),
        })
        current += timedelta(days=1)
    return result


def _employee_rows(
    session_rows: Sequence[Mapping[str, Any]],
    identities: Mapping[int, Mapping[str, Any]],
    *,
    period_start: datetime,
    period_end: datetime,
    office_timezone: str,
) -> list[dict[str, Any]]:
    zone, _ = get_display_timezone(office_timezone)
    by_entity: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for row in session_rows:
        if session_intersects_period(row, period_start, period_end):
            by_entity[int(row["entity_id"])].append(row)

    employees: list[dict[str, Any]] = []
    for entity_id, rows in by_entity.items():
        intervals: list[tuple[str, datetime, datetime]] = []
        for row in rows:
            effective = _closed_effective_interval(row, period_start, period_end)
            if effective:
                intervals.append((str(row["session_row_id"]), *effective))
        overlapping, overlap_pair_count = _overlapping_row_ids(intervals)
        exact_seconds = _union_seconds((start, end) for _, start, end in intervals)
        has_closed = bool(intervals)
        session_items: list[dict[str, Any]] = []
        start_days: set[date] = set()
        for row in sorted(rows, key=lambda item: _utc(item.get("started_at_utc")) or period_start, reverse=True):
            started = _utc(row.get("started_at_utc"))
            stopped = _utc(row.get("stopped_at_utc"))
            observed_end = _session_observed_end(row)
            if started:
                start_days.add(started.astimezone(zone).date())
            effective = _closed_effective_interval(row, period_start, period_end)
            row_id = str(row["session_row_id"])
            session_items.append({
                "session_row_id": row_id,
                "lifecycle_state": str(row.get("lifecycle_state") or "unknown"),
                "completeness": str(row.get("completeness") or "partial"),
                "started_at_utc": _iso(started),
                "last_observed_at_utc": _iso(_utc(row.get("last_observed_at_utc"))),
                "stopped_at_utc": _iso(stopped),
                "duration_seconds": int(row["duration_seconds"]) if row.get("duration_seconds") is not None else None,
                "confirmed_seconds_in_period": int((effective[1] - effective[0]).total_seconds()) if effective else None,
                "effective_start_utc": _iso(effective[0]) if effective else _iso(max(started, period_start)) if started and observed_end else None,
                "effective_stop_utc": _iso(effective[1]) if effective else _iso(min(observed_end, period_end)) if started and observed_end else None,
                "observation_count": int(row.get("observation_count") or 0),
                "overlap_violation": row_id in overlapping,
                "anomalies": [str(item) for item in (row.get("anomalies") or [])],
                "evidence_links": [],
                "evidence_state": "not_available_in_current_safe_read_path",
            })
        identity = _identity_for(identities, entity_id)
        employees.append({
            **identity,
            "closed_session_count": len(intervals),
            "open_session_count": sum(1 for row in rows if _utc(row.get("stopped_at_utc")) is None),
            "confirmed_seconds": exact_seconds if has_closed else None,
            "confirmed_minutes": _round_minutes(exact_seconds) if has_closed else None,
            "overlap_violation": bool(overlapping),
            "overlap_count": overlap_pair_count,
            "days_with_observed_start": len(start_days),
            "session_count": len(rows),
            "session_details_has_more": len(session_items) > MAX_SESSION_DETAILS_PER_EMPLOYEE,
            "sessions": session_items[:MAX_SESSION_DETAILS_PER_EMPLOYEE],
            "sessions_all": session_items,
        })
    return sorted(employees, key=lambda item: (
        str(item["display_name"]).casefold(), str(item["account_name"]).casefold(), int(item["entity_id"]),
    ))














def _filter_employees(
    employees: Sequence[dict[str, Any]],
    *,
    search: str | None,
    department: str | None,
    status: str,
) -> list[dict[str, Any]]:
    clean_search = str(search or "").strip().casefold()
    clean_department = str(department or "").strip().casefold()
    if status not in {"all", "closed", "open"}:
        raise ValueError("vpn_connections_status_invalid")
    result = []
    for employee in employees:
        haystack = f"{employee['display_name']} {employee['account_name']}".casefold()
        if clean_search and clean_search not in haystack:
            continue
        if clean_department and str(employee["department"]).casefold() != clean_department:
            continue
        if status == "closed" and not employee["closed_session_count"]:
            continue
        if status == "open" and not employee["open_session_count"]:
            continue
        result.append(employee)
    return result


def compose_vpn_connections_report(
    *,
    source_domain_id: int,
    period_start: datetime,
    period_end: datetime,
    office_timezone: str,
    coverage: Mapping[str, Any],
    session_rows: Sequence[Mapping[str, Any]],
    identities: Mapping[int, Mapping[str, Any]],
    entitlement_rows: Sequence[Mapping[str, Any]],
    failed_events: Sequence[Mapping[str, Any]],
    failed_collection_state: str,
    failed_authorization_unavailable_reason: str | None = None,
    search: str | None = None,
    department: str | None = None,
    status: str = "all",
    employee_limit: int = MAX_EMPLOYEE_PAGE,
    employee_offset: int = 0,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    from server.sli.plugins.remote_access.reports.vpn_connections_reporting_failed import _failed_rows

    if not period_start.tzinfo or not period_end.tzinfo or period_start >= period_end:
        raise ValueError("vpn_connections_period_invalid")
    if len(session_rows) > MAX_SESSION_ROWS:
        raise ValueError("vpn_connections_session_bound_exceeded")
    if len(entitlement_rows) > MAX_ENTITLEMENT_ROWS:
        raise ValueError("vpn_connections_entitlement_bound_exceeded")
    if len(failed_events) > MAX_FAILED_EVENT_ROWS:
        raise ValueError("vpn_connections_failed_event_bound_exceeded")
    if not 1 <= int(employee_limit) <= MAX_EMPLOYEE_PAGE or not 0 <= int(employee_offset) <= MAX_SESSION_ROWS:
        raise ValueError("vpn_connections_page_invalid")

    employees = _employee_rows(
        session_rows, identities,
        period_start=period_start,
        period_end=period_end,
        office_timezone=office_timezone,
    )
    employees = _filter_employees(
        employees, search=search, department=department, status=status,
    )
    daily = _daily_analytics(
        employees,
        period_start=period_start,
        period_end=period_end,
        office_timezone=office_timezone,
    )
    confirmed_values = [int(item["confirmed_seconds"]) for item in employees if item["confirmed_seconds"] is not None]
    confirmed_total = sum(confirmed_values)
    department_rows: list[dict[str, Any]] = []
    by_department: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for employee in employees:
        by_department[str(employee["department"])].append(employee)
    for name, items in sorted(by_department.items()):
        values = [int(item["confirmed_seconds"]) for item in items if item["confirmed_seconds"] is not None]
        exact = sum(values)
        department_rows.append({
            "department": name,
            "employee_count": len(items),
            "closed_session_count": sum(int(item["closed_session_count"]) for item in items),
            "confirmed_seconds": exact if values else None,
            "confirmed_minutes": _round_minutes(exact) if values else None,
            "employees_with_open_sessions": sum(bool(item["open_session_count"]) for item in items),
            "employees_with_overlap": sum(bool(item["overlap_violation"]) for item in items),
        })

    clean_search = str(search or "").strip().casefold()
    clean_department = str(department or "").strip().casefold()
    entitlement_items = [
        identity
        for row in entitlement_rows
        for identity in [_identity_for(identities, int(row["entity_id"]))]
        if (not clean_search or clean_search in f"{identity['display_name']} {identity['account_name']}".casefold())
        and (not clean_department or clean_department == str(identity["department"]).casefold())
    ]
    failed_items = [
        item for item in _failed_rows(failed_events, identities)
        if (not clean_search or clean_search in f"{item['display_name']} {item['account_name']}".casefold())
        and (not clean_department or clean_department == str(item["department"]).casefold())
    ]
    public_employees = []
    for employee in employees[int(employee_offset):int(employee_offset) + int(employee_limit)]:
        public_employees.append({key: _public(value) for key, value in employee.items() if key != "sessions_all"})
    analytic_employees = [{key: _public(value) for key, value in item.items() if key not in {"sessions", "sessions_all"}} for item in employees]
    zone, _ = get_display_timezone(office_timezone)
    failed_unavailable = failed_collection_state == "unavailable"
    if failed_unavailable:
        failed_authorizations = {
            "state": "unavailable",
            "unavailable_reason": failed_authorization_unavailable_reason or "input_event_bound_exceeded",
            "count": None,
            "items": [],
        }
    else:
        failed_authorizations = {
            "state": failed_collection_state,
            "count": len(failed_items) if failed_collection_state != "not_collected" else None,
            "items": failed_items[:MAX_BRANCH_OUTPUT_ROWS],
            "has_more": len(failed_items) > MAX_BRANCH_OUTPUT_ROWS,
        }
    limitations = [
        "Подтверждённое время VPN-подключения не является показателем рабочего времени.",
        "NPS 6273 отражает отказ авторизации и не определяет длительность VPN-сессии.",
        "Ссылки на raw Accounting evidence не публикуются текущей безопасной session view.",
    ]
    if failed_unavailable:
        limitations.append(
            "Список NPS 6273 превысил ограничение безопасного чтения; количество и список не показаны. Это не означает отсутствие отказов."
        )
    return {
        "contract_id": CONTRACT_ID,
        "report_key": REPORT_KEY,
        "source_domain_id": int(source_domain_id),
        "state": "partial" if failed_unavailable else _coverage_state(coverage),
        "office_timezone": office_timezone,
        "generated_at_utc": _iso(generated_at or datetime.now(timezone.utc)),
        "period": {
            "from_utc": _iso(period_start),
            "to_utc_exclusive": _iso(period_end),
            "local_from_date": period_start.astimezone(zone).date().isoformat(),
            "local_to_date": (period_end - timedelta(microseconds=1)).astimezone(zone).date().isoformat(),
        },
        "coverage": _public(coverage),
        "employees": public_employees,
        "employee_page": {
            "limit": int(employee_limit), "offset": int(employee_offset),
            "has_more": int(employee_offset) + int(employee_limit) < len(employees),
            "filtered_count": len(employees),
        },
        "analytics": {
            "employee_count": len(employees),
            "closed_session_count": sum(int(item["closed_session_count"]) for item in employees),
            "confirmed_seconds": confirmed_total if confirmed_values else None,
            "confirmed_minutes": _round_minutes(confirmed_total) if confirmed_values else None,
            "open_session_count": sum(int(item["open_session_count"]) for item in employees),
            "employees_with_overlap": sum(bool(item["overlap_violation"]) for item in employees),
            "daily": daily,
            "employees": analytic_employees[:MAX_BRANCH_OUTPUT_ROWS],
            "employees_has_more": len(analytic_employees) > MAX_BRANCH_OUTPUT_ROWS,
            "departments": department_rows[:MAX_BRANCH_OUTPUT_ROWS],
            "departments_has_more": len(department_rows) > MAX_BRANCH_OUTPUT_ROWS,
        },
        "entitlements": {
            "state": "available",
            "items": entitlement_items[:MAX_BRANCH_OUTPUT_ROWS],
            "has_more": len(entitlement_items) > MAX_BRANCH_OUTPUT_ROWS,
        },
        "failed_authorizations": failed_authorizations,
        "limitations": limitations,
        "limits": {
            "session_calculation_limit": MAX_SESSION_ROWS,
            "employee_page_limit": MAX_EMPLOYEE_PAGE,
            "session_details_per_employee": MAX_SESSION_DETAILS_PER_EMPLOYEE,
            "entitlement_limit": MAX_ENTITLEMENT_ROWS,
            "failed_event_limit": MAX_FAILED_EVENT_ROWS,
            "branch_output_limit": MAX_BRANCH_OUTPUT_ROWS,
        },
    }


def _default_period(now: datetime, zone) -> tuple[datetime, datetime]:
    local_now = now.astimezone(zone)
    start = datetime(local_now.year, local_now.month, 1, tzinfo=zone)
    if local_now.month == 12:
        end = datetime(local_now.year + 1, 1, 1, tzinfo=zone)
    else:
        end = datetime(local_now.year, local_now.month + 1, 1, tzinfo=zone)
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def _report_period(
    time_from: str | None,
    time_to: str | None,
    *,
    office_timezone: str,
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    zone, _ = get_display_timezone(office_timezone)
    if not time_from and not time_to:
        return _default_period(now or datetime.now(timezone.utc), zone)
    if not time_from or not time_to:
        raise TimeRangeError("vpn_connections_period_requires_both_bounds")
    start_raw, end_raw = normalize_utc_range(time_from, time_to, timezone_name=office_timezone)
    start, end = _utc(start_raw), _utc(end_raw)
    if start is None or end is None or start >= end:
        raise TimeRangeError("empty_or_reversed_time_range")
    if end - start > timedelta(days=MAX_PERIOD_DAYS):
        raise TimeRangeError("vpn_connections_period_too_wide")
    return start, end


def get_vpn_connections_report(
    access: Mapping[str, Any],
    *,
    source_domain_id: int,
    time_from: str | None = None,
    time_to: str | None = None,
    search: str | None = None,
    department: str | None = None,
    status: str = "all",
    employee_limit: int = MAX_EMPLOYEE_PAGE,
    employee_offset: int = 0,
    include_failed_authorizations: bool = True,
) -> dict[str, Any]:
    domain_id = int(source_domain_id)
    if domain_id <= 0:
        raise ValueError("vpn_connections_domain_invalid")
    composition = vpn_report_composition_decision(access, source_domain_id=domain_id, action="view")
    branches = {
        "directory": asdict(composition.directory),
        "sessions": asdict(composition.sessions),
        "session_evidence": asdict(composition.session_evidence),
    }
    if not (composition.directory.allowed and composition.sessions.allowed):
        return {
            "contract_id": CONTRACT_ID,
            "report_key": REPORT_KEY,
            "source_domain_id": domain_id,
            "state": "not_authorized",
            "branches": branches,
            "employees": [],
        }
    _, timezone_name = get_display_timezone()
    start, end = _report_period(time_from, time_to, office_timezone=timezone_name)
    data = _read_report_data(domain_id=domain_id, period_start=start, period_end=end,
                             include_failed_authorizations=include_failed_authorizations)
    if data["coverage"] is None:
        return {
            "contract_id": CONTRACT_ID,
            "report_key": REPORT_KEY,
            "source_domain_id": domain_id,
            "state": "not_collected",
            "unavailable_reason": "no_accounting_data",
            "branches": branches,
            "employees": [],
        }
    payload = compose_vpn_connections_report(
        source_domain_id=domain_id,
        period_start=start,
        period_end=end,
        office_timezone=timezone_name,
        coverage=data["coverage"],
        session_rows=data["sessions"],
        identities=data["identities"],
        entitlement_rows=data["entitlements"],
        failed_events=data["failed_events"],
        failed_collection_state=data["failed_collection_state"],
        failed_authorization_unavailable_reason=data.get("failed_authorization_unavailable_reason"),
        search=search,
        department=department,
        status=status,
        employee_limit=employee_limit,
        employee_offset=employee_offset,
    )
    payload["branches"] = branches
    return payload










def _read_report_data(
    *,
    domain_id: int,
    period_start: datetime,
    period_end: datetime,
    include_failed_authorizations: bool = True,
) -> dict[str, Any]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            """select domain_id,total_delivery_count,queued_delivery_count,
                      leased_delivery_count,failed_delivery_count,
                      delivered_delivery_count,quarantined_delivery_count,
                      projected_receipt_count,identity_unresolved_count,
                      timestamp_unresolved_count,projected_session_count,
                      history_available_from_utc,history_available_to_utc
               from radius_vpn_session_coverage_v1 where domain_id=%s""",
            (domain_id,),
        )
        coverage_row = cur.fetchone()
        if coverage_row is None:
            return {"coverage": None, "sessions": [], "identities": {}, "entitlements": [], "failed_events": [], "failed_collection_state": "not_collected"}
        cur.execute(
            """select session_row_id,entity_id,domain_id,generation,
                      lifecycle_state,completeness,started_at_utc,
                      last_observed_at_utc,stopped_at_utc,duration_seconds,
                      observation_count,anomalies,updated_at
               from radius_vpn_session_rows_v1
               where domain_id=%s and started_at_utc is not null
                 and started_at_utc<%s
                 and (
                     (stopped_at_utc is not null and stopped_at_utc>%s)
                     or (stopped_at_utc is null and last_observed_at_utc>=%s)
                 )
               order by started_at_utc,session_row_id limit %s""",
            (domain_id, period_end, period_start, period_start, MAX_SESSION_ROWS + 1),
        )
        sessions = [dict(row) for row in cur.fetchall()]
        if len(sessions) > MAX_SESSION_ROWS:
            raise ValueError("vpn_connections_session_bound_exceeded")

        entitlements = read_entitlements(cur, source_domain_id=domain_id).as_rows()

        failed_events = []
        failed_authorization_unavailable_reason = None
        collected = False
        if include_failed_authorizations:
            cur.execute(
                """select event.id as event_db_id,event.event_record_id,event.event_id,
                          event.time_created_utc,event.subject_user_sid,
                          event.subject_user_name,subject_domain.value as subject_domain_name,
                          facts.result_code as reason_code,
                          case when count(distinct alias.entity_id)=1 then min(alias.entity_id) end as entity_id,
                          event.source_core_sha256
                   from events_v2_core event
                   join storage_v2_channel channel on channel.id=event.channel_id
                   join storage_v2_provider provider on provider.id=event.provider_id
                   left join storage_v2_domain_name subject_domain on subject_domain.id=event.subject_domain_id
                   left join event_facts_v2 facts on facts.event_id=event.id
                   left join ad_context_entity_aliases alias
                     on alias.domain_id=event.domain_id and alias.alias_type='object_sid'
                    and alias.normalized_value=lower(event.subject_user_sid)
                   where event.domain_id=%s and event.event_id=6273
                     and channel.value='Security'
                     and provider.value='Microsoft-Windows-Security-Auditing'
                     and event.time_created_utc>=%s and event.time_created_utc<%s
                   group by event.id,event.event_record_id,event.event_id,
                            event.time_created_utc,event.subject_user_sid,
                            event.subject_user_name,subject_domain.value,
                            facts.result_code,event.source_core_sha256
                   order by event.time_created_utc desc,event.id desc limit %s""",
                (domain_id, period_start, period_end, MAX_FAILED_EVENT_ROWS + 1),
            )
            failed_events = [dict(row) for row in cur.fetchall()]
            if len(failed_events) > MAX_FAILED_EVENT_ROWS:
                failed_events = []
                failed_authorization_unavailable_reason = "input_event_bound_exceeded"
            cur.execute(
                """select exists(
                       select 1 from events_v2_core event
                       join storage_v2_channel channel on channel.id=event.channel_id
                       join storage_v2_provider provider on provider.id=event.provider_id
                       where event.domain_id=%s and event.event_id=6273
                         and channel.value='Security'
                         and provider.value='Microsoft-Windows-Security-Auditing'
                   ) as collected""",
                (domain_id,),
            )
            collected = bool((cur.fetchone() or {}).get("collected"))

        entity_ids = sorted({int(row["entity_id"]) for row in sessions + entitlements + failed_events if row.get("entity_id") is not None})
        identities: dict[int, dict[str, Any]] = {}
        if entity_ids:
            cur.execute(
                """select entity.id as entity_id,entity.display_name,
                          domain_row.netbios_name,
                          account.attributes_json->'attributes'->>'sam_account_name' as sam_account_name,
                          account.attributes_json->'attributes'->>'department' as department,
                          case when account.attributes_json->'attributes'->>'enabled' in ('true','false')
                               then (account.attributes_json->'attributes'->>'enabled')::boolean end as enabled,
                          account.attributes_json->'attributes'->>'last_logon_utc' as last_logon_utc,
                          exists(select 1 from ad_context_relation_versions privileged
                                 where privileged.source_entity_id=entity.id
                                   and privileged.valid_to_utc is null
                                   and privileged.relation_kind='member_of'
                                   and privileged.source_section='privileged_membership') as privileged
                   from entities_v2 entity
                   join domains domain_row on domain_row.id=entity.domain_id
                   left join lateral (
                       select current.attributes_json
                       from ad_context_entity_versions current
                       where current.entity_id=entity.id
                         and current.source_section in ('directory_accounts','vpn_membership')
                         and current.valid_to_utc is null
                       order by case current.source_section when 'directory_accounts' then 0 else 1 end,
                                current.last_observed_at_utc desc,current.id desc
                       limit 1
                   ) account on true
                   where entity.id=any(%s) and entity.domain_id=%s
                     and entity_v2_is_active(entity.id)""",
                (entity_ids, domain_id),
            )
            identities = {int(row["entity_id"]): dict(row) for row in cur.fetchall()}
    return {
        "coverage": dict(coverage_row),
        "sessions": sessions,
        "identities": identities,
        "entitlements": entitlements,
        "failed_events": failed_events,
        "failed_collection_state": (
            "unavailable"
            if failed_authorization_unavailable_reason
            else "available" if collected else "not_collected"
        ),
        "failed_authorization_unavailable_reason": failed_authorization_unavailable_reason,
    }


_connect = get_runtime_connection


def __getattr__(name: str) -> Any:
    # Split modules import this hub for shared names. Resolve their re-exports
    # only on access so either split module can be imported first after reload.
    if name in {
        "_failed_authorization_collection_coverage", "_failed_authorization_identity",
        "_failed_rows", "_read_vpn_failed_authorization_series_data",
        "compose_vpn_failed_authorization_series", "get_vpn_failed_authorization_series",
    }:
        from server.sli.plugins.remote_access.reports import vpn_connections_reporting_failed as implementation
    elif name in {
        "_authorization_timeline_collection_coverage", "_read_vpn_authorization_timeline_data",
        "compose_vpn_authorization_timeline", "get_vpn_authorization_timeline",
    }:
        from server.sli.plugins.remote_access.reports import vpn_connections_reporting_timeline as implementation
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(implementation, name)
