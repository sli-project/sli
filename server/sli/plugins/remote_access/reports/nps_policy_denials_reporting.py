"""Remote access plugin's bounded, retained NPS decision read model."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.reports.windows_authentication_reporting import _read_access_allowed
from server.sli.reporting.reporting_common import clean_text, format_iso, parse_utc
from server.sli.semantic.semantic_processing import NORMALIZER_ID, SEMANTIC_CONTRACT_VERSION

REPORT_KEY = "vpn.policy-denials"
ALLOWED = "remote_access.authentication.allowed"
DENIED = "remote_access.authentication.denied"
MAX_PERIOD_DAYS = 31
MAX_FACTS = 10_000
MAX_GROUPS = 500
MAX_EVIDENCE = 500
DIMENSIONS = ("network_policy", "nas_identifier", "reason_code", "authentication_type", "authentication_provider")


def _text(value: Any) -> str | None:
    text = clean_text(value)
    return None if text in {"-", "N/A"} else text


def _account(row: Mapping[str, Any]) -> str | None:
    identity = (row.get("quality_json") or {}).get("identity_roles", {}).get("affected_entity", {})
    if identity.get("state") != "resolved" or identity.get("provisional"):
        return None
    return _text((row.get("roles_json") or {}).get("affected_entity"))


def _coverage(rows: Sequence[Mapping[str, Any]], start: datetime, end: datetime, truncated: bool) -> dict[str, Any]:
    return {
        "state": "truncated" if truncated else "observed_unverified" if rows else "empty_unverified",
        "from_utc": format_iso(start), "to_utc_exclusive": format_iso(end),
        "observed_decisions": len(rows), "source_completeness": "not_proven",
        "truncated": truncated,
    }


def compose_policy_denials(
    current: Sequence[Mapping[str, Any]], previous: Sequence[Mapping[str, Any]], *,
    start: datetime, end: datetime, current_truncated: bool = False,
    previous_truncated: bool = False, min_decisions: int = 0, min_growth: int = 0,
) -> dict[str, Any]:
    """Compare observed counts; unknown identities are decisions, never accounts.

    Readers supply one current semantic interpretation per event. Input caps
    apply independently to equal adjacent windows. Truncation makes growth
    unknown; source completeness is never inferred from a successful read.
    """
    if len(current) > MAX_FACTS or len(previous) > MAX_FACTS:
        raise ValueError("nps_policy_input_limit")
    if start.tzinfo is None or end.tzinfo is None or start >= end or end - start > timedelta(days=MAX_PERIOD_DAYS) or min_decisions < 0 or min_growth < 0:
        raise ValueError("nps_policy_window_or_threshold_invalid")
    groups: dict[tuple, dict[str, Any]] = {}
    policy_counts = defaultdict(lambda: [0, 0])
    nas_counts = defaultdict(lambda: [0, 0])
    accounts: set[str] = set()
    metrics = {key: 0 for key in ("allowed", "denied", "affected_accounts", "unknown_identity_denials", "missing_policy", "missing_reason")}
    for index, rows in enumerate((current, previous)):
        seen = set()
        window_start, window_end = (start, end) if index == 0 else (start - (end - start), start)
        for event in rows:
            if event["source_event_id"] in seen:
                raise ValueError("nps_policy_duplicate_source_event")
            seen.add(event["source_event_id"])
            occurred = parse_utc(event.get("occurred_at_utc"))
            if occurred is None or not window_start <= occurred < window_end or event.get("semantic_type") not in {ALLOWED, DENIED}:
                raise ValueError("nps_policy_fact_invalid")
            facts = event.get("facts_json") or {}
            key = tuple(_text(facts.get(field)) for field in DIMENSIONS)
            group = groups.setdefault(key, {
                **dict(zip(DIMENSIONS, key)), "allowed": 0, "denied": 0, "previous_denied": 0,
                "previous_decisions": 0, "accounts": set(), "unknown_identity_denials": 0,
                "first_denial_utc": None, "last_denial_utc": None,
                "first_event_id": None, "last_event_id": None,
            })
            denied = event["semantic_type"] == DENIED
            if index == 1:
                group["previous_decisions"] += 1
                group["previous_denied"] += int(denied)
            else:
                decision = "denied" if denied else "allowed"
                group[decision] += 1
                metrics[decision] += 1
                metrics["missing_policy"] += int(key[0] is None)
                metrics["missing_reason"] += int(key[2] is None)
                if denied:
                    account = _account(event)
                    if account:
                        group["accounts"].add(account)
                        accounts.add(account)
                    else:
                        group["unknown_identity_denials"] += 1
                        metrics["unknown_identity_denials"] += 1
                    time = format_iso(occurred)
                    if group["first_denial_utc"] is None or time < group["first_denial_utc"]:
                        group["first_denial_utc"], group["first_event_id"] = time, event["source_event_id"]
                    if group["last_denial_utc"] is None or time >= group["last_denial_utc"]:
                        group["last_denial_utc"], group["last_event_id"] = time, event["source_event_id"]
            if denied:
                if key[0] is not None:
                    policy_counts[key[0]][index] += 1
                if key[1] is not None:
                    nas_counts[key[1]][index] += 1
    comparable = not current_truncated and not previous_truncated
    items = []
    for group in groups.values():
        count = group["allowed"] + group["denied"]
        growth = group["denied"] - group["previous_denied"] if comparable else None
        distinct_accounts = group.pop("accounts")
        if count == 0 or count < min_decisions or (min_growth > 0 and (growth is None or growth < min_growth)):
            continue
        items.append({**group, "decisions": count, "affected_accounts": len(distinct_accounts),
                      "denial_share": round(100 * group["denied"] / count, 2), "growth": growth,
                      "coverage_state": "truncated" if not comparable else "observed_unverified"})
    items.sort(key=lambda row: (-row["denied"], tuple(str(row[field] or "") for field in DIMENSIONS)))
    count = metrics["allowed"] + metrics["denied"]
    metrics.update({
        "affected_accounts": len(accounts), "denial_share": round(100 * metrics["denied"] / count, 2) if count else None,
        "growing_policies": sum(now > before for now, before in policy_counts.values()) if comparable else None,
        "growing_nas": sum(now > before for now, before in nas_counts.values()) if comparable else None,
    })
    return {
        "report_key": REPORT_KEY, "state": "partial", "items": items[:MAX_GROUPS], "metrics": metrics,
        "coverage": {"current": _coverage(current, start, end, current_truncated),
                     "previous": _coverage(previous, start - (end - start), start, previous_truncated)},
        "result_truncated": len(items) > MAX_GROUPS,
        "evidence_truncated": len(current) > MAX_EVIDENCE,
        "events": [{"event_db_id": row["source_event_id"], "normalized_event_id": str(row["normalized_event_id"]),
                    "event_id": 6272 if row["semantic_type"] == ALLOWED else 6273,
                    "occurred_at_utc": format_iso(row["occurred_at_utc"]),
                    "decision": "allowed" if row["semantic_type"] == ALLOWED else "denied",
                    "identity_state": "resolved" if _account(row) else "unknown",
                    **{field: _text((row.get("facts_json") or {}).get(field)) for field in DIMENSIONS}}
                   for row in current[:MAX_EVIDENCE]],
        "limits": {"max_period_days": MAX_PERIOD_DAYS, "input_limit_per_window": MAX_FACTS,
                   "group_limit": MAX_GROUPS, "evidence_limit": MAX_EVIDENCE},
    }


def _read_windows(domain_id: int, start: datetime, end: datetime, filters: Mapping[str, str | None]) -> tuple[list[dict], list[dict], bool, bool]:
    # semantic_type/time and source_event_id use existing indexes (025/022).
    # Select the latest interpretation BEFORE testing status/dimensions. A
    # failed or changed replay must not resurrect a prior admissible decision.
    predicates = []
    values = []
    for field, value in filters.items():
        if value is not None:
            predicates.append(f"nullif(nullif(btrim(n.facts_json->>'{field}'),''),'-')=%s")
            values.append(value)
    extra = " and " + " and ".join(predicates) if predicates else ""
    sql = """select n.source_event_id,n.normalized_event_id,n.occurred_at_utc,
                    n.semantic_type,n.facts_json,n.roles_json,n.quality_json
             from normalized_events n
             where n.semantic_type in (%s,%s)
               and n.occurred_at_utc >= %s and n.occurred_at_utc < %s
               and n.source_identity_json->>'domain_id'=%s
               and n.source_identity_json->>'event_id' in ('6272','6273')
               and n.processing_status='normalized'
               and n.normalizer_id=%s and n.semantic_contract_version=%s
               and not exists (
                   select 1 from normalized_events newer
                   where newer.source_event_id=n.source_event_id
                     and newer.normalizer_id=n.normalizer_id
                     and (newer.normalized_at,newer.normalized_event_id) > (n.normalized_at,n.normalized_event_id)
               )""" + extra + " order by n.occurred_at_utc desc,n.normalized_event_id limit %s"
    windows = []
    with connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read, read only")
        cur.execute("set local statement_timeout='10s'")
        for first, last in ((start, end), (start - (end - start), start)):
            cur.execute(sql, (ALLOWED, DENIED, first, last, str(domain_id), NORMALIZER_ID, SEMANTIC_CONTRACT_VERSION, *values, MAX_FACTS + 1))
            rows = [dict(row) for row in cur.fetchall()]
            windows.append((rows[:MAX_FACTS], len(rows) > MAX_FACTS))
    return windows[0][0], windows[1][0], windows[0][1], windows[1][1]


def get_policy_denials(
    access: Mapping[str, Any], *, source_domain_id: int, time_from: str, time_to: str,
    policy: str | None = None, nas: str | None = None, reason: str | None = None,
    method: str | None = None, min_decisions: int = 0, min_growth: int = 0,
) -> dict[str, Any]:
    start, end = parse_utc(time_from), parse_utc(time_to)
    if source_domain_id <= 0 or start is None or end is None or start >= end or end - start > timedelta(days=MAX_PERIOD_DAYS):
        raise ValueError("nps_policy_window_invalid")
    if min_decisions < 0 or min_growth < 0:
        raise ValueError("nps_policy_threshold_invalid")
    if not _read_access_allowed(access, source_domain_id):
        return {"report_key": REPORT_KEY, "state": "not_authorized", "items": []}
    filters = dict(zip(DIMENSIONS[:4], map(_text, (policy, nas, reason, method))))
    if any(value and len(value) > 256 for value in filters.values()):
        raise ValueError("nps_policy_filter_invalid")
    current, previous, current_truncated, previous_truncated = _read_windows(source_domain_id, start, end, filters)
    return compose_policy_denials(current, previous, start=start, end=end, current_truncated=current_truncated,
                                  previous_truncated=previous_truncated, min_decisions=min_decisions, min_growth=min_growth)
