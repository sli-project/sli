"""Compare workstation logon pairs using published permanent ClickHouse facts."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping

from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.core.report_domain import report_domain_fqdn
from server.sli.entities.what_where_when_projection import (
    SUCCESSFUL_LOGON_EVENT_ID,
    _filter_reason,
    _load_domain_controller_membership,
    _load_service_accounts,
    _normalize_source_event,
    load_computer_match_index,
    project_event,
)
from server.sli.plugins.ad.reports.what_where_when_reporting import _load_workstation_population
from server.sli.sources.computers_v6_source import load_latest_computers_v6_source_snapshot
from server.sli.storage import permanent_fact_history as history

MAX_EVENTS = 50_000


def utc(value: Any) -> datetime:
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("logon_timezone_required")
    return parsed.astimezone(timezone.utc)


def load_context(domain_id: int) -> dict[str, Any]:
    """Reuse the projection's verified inventory, classification and DC scope."""
    with connect() as connection:
        with connection.cursor() as cursor:
            membership = _load_domain_controller_membership(cursor, domain_id=domain_id)
        if not membership.server_ids:
            raise RuntimeError("logon_domain_controllers_missing")
        _, accounts = _load_service_accounts(connection, domain_id)
        snapshot = load_latest_computers_v6_source_snapshot(connection, domain_fqdn=report_domain_fqdn())
    if not snapshot:
        raise RuntimeError("logon_computers_snapshot_missing")
    population = _load_workstation_population([domain_id], raise_on_error=True)
    if population["state"] == "unavailable":
        raise RuntimeError("logon_inventory_unavailable")
    return {
        "index": load_computer_match_index(snapshot), "accounts": accounts,
        "server_ids": sorted(membership.server_ids),
        "computers": {item["object_guid"]: item for item in population["items"]},
        "partial": population["state"] != "available" or snapshot["collection_status"] != "complete",
    }


def _source_sql() -> str:
    # Domain and source predicates precede aggregation and limits. No raw payload.
    return f"""FROM {history.DATABASE}.events
        WHERE batch_sha256 IN (SELECT batch_sha256 FROM {history.DATABASE}.published_batches)
          AND event_key={SUCCESSFUL_LOGON_EVENT_ID}
          AND server_id IN {{servers:Array(UInt64)}}
          AND JSONExtractInt(core_json, 'domain_id')={{domain:UInt64}}
          AND lowerUTF8(JSONExtractString(core_json, 'channel'))='security'"""


def load_history(domain_id: int, server_ids: list[int], baseline_start: datetime,
                 start: datetime, end: datetime) -> dict[str, Any]:
    if not history.primary_read_enabled():
        raise RuntimeError("logon_history_unavailable")
    port = history.configured_read_port()
    params = {"domain": str(domain_id), "servers": str(server_ids)}
    bounds = history._rows(port, f"""SELECT server_id,
        min(time_created_utc) AS first_utc, max(time_created_utc) AS last_utc
        {_source_sql()} GROUP BY server_id""", query_params=params)
    first = min((utc(row["first_utc"] + "+00:00") for row in bounds), default=None)
    last = max((utc(row["last_utc"] + "+00:00") for row in bounds), default=None)
    baseline_covered = {int(row["server_id"]) for row in bounds
                        if utc(row["first_utc"] + "+00:00") <= baseline_start
                        and utc(row["last_utc"] + "+00:00") >= start} == set(server_ids)
    period_covered = {int(row["server_id"]) for row in bounds
                      if utc(row["first_utc"] + "+00:00") <= start
                      and utc(row["last_utc"] + "+00:00") >= end} == set(server_ids)

    def window(left: datetime, right: datetime) -> tuple[list[dict[str, Any]], bool, bool]:
        rows = history._rows(port, f"""SELECT event_db_id {_source_sql()}
            AND time_created_utc>={{start:DateTime64(6, 'UTC')}}
            AND time_created_utc<{{end:DateTime64(6, 'UTC')}}
            ORDER BY time_created_utc DESC,event_db_id DESC LIMIT {MAX_EVENTS + 1}""",
            query_params={**params, "start": history._ch_time(left), "end": history._ch_time(right)})
        ids = [int(row["event_db_id"]) for row in rows[:MAX_EVENTS]]
        events = []
        # The shared reader verifies publication, batch identity and fact hashes.
        for offset in range(0, len(ids), history.MAX_BATCH_EVENTS):
            events.extend(history.read_published_events_many(port, ids[offset:offset + history.MAX_BATCH_EVENTS]).values())
        return events, len(rows) > MAX_EVENTS, len(events) != len(ids)

    baseline, baseline_truncated, baseline_incomplete = window(baseline_start, start)
    period, period_truncated, period_incomplete = window(start, end)
    return {"baseline": baseline, "period": period, "history_from_utc": first.isoformat() if first else None,
            "history_to_utc": last.isoformat() if last else None,
            "baseline_bounds_covered": baseline_covered, "period_bounds_covered": period_covered,
            "baseline_truncated": baseline_truncated, "period_truncated": period_truncated,
            "facts_incomplete": baseline_incomplete or period_incomplete,
            "period_covered": period_covered and not period_truncated and not period_incomplete,
            "baseline_covered": baseline_covered and not baseline_truncated and not baseline_incomplete,
            "truncated": baseline_truncated or period_truncated}


def _user(event: Mapping[str, Any]) -> str:
    # Prefer stable identity; missing SID must never prove account novelty.
    sid = str(event.get("target_user_sid") or "").strip()
    if sid and sid != "-":
        return sid.casefold()
    return f"{event.get('target_domain_name') or ''}\\{event['target_user_name']}".strip().casefold()


def compute_pairs(baseline: list[Mapping[str, Any]], period: list[Mapping[str, Any]], *,
                  baseline_start: datetime, start: datetime, end: datetime,
                  index: Mapping[str, Any], accounts: Mapping[str, bool],
                  baseline_covered: bool) -> dict[str, Any]:
    """Pure novelty calculation; a prior user logon need not resolve to a workstation."""
    prior_users: set[str] = set()
    prior_pairs: set[tuple[str, str]] = set()
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    incomplete = False
    seen: set[int] = set()
    for raw in [*baseline, *period]:
        event = _normalize_source_event(raw)
        event_id = event["source_event_id"]
        if event_id in seen:
            continue
        seen.add(event_id)
        observed = utc(event["observed_at_utc"])
        if not baseline_start <= observed < end:
            continue
        reason = _filter_reason(event, accounts)
        if reason:
            incomplete |= reason == "classification_unknown"
            continue
        user = _user(event)
        incomplete |= not event.get("target_user_sid") or event.get("target_user_sid") == "-"
        projected = project_event(event, index, accounts)
        if observed < start:
            prior_users.add(user)
            if projected["status"] == "observation":
                prior_pairs.add((user, projected["observation"]["computer_object_guid"]))
            else:
                # An unresolved prior computer can conceal an existing pair.
                incomplete = True
            continue
        if projected["status"] != "observation":
            incomplete = True
            continue
        observation = projected["observation"]
        key = (user, observation["computer_object_guid"])
        if key in prior_pairs:
            continue
        row = groups.setdefault(key, {
            "id": hashlib.sha256(f"{key[0]}\0{key[1]}".encode()).hexdigest(),
            "user": observation["user_name"], "user_sid": event.get("target_user_sid"),
            "computer": observation["computer_name"], "computer_guid": key[1],
            "first_seen": observed, "source_event_id": event_id, "count": 0,
            "logon_types": set(), "sources": set(),
        })
        row["count"] += 1
        if observed < row["first_seen"]:
            row.update(first_seen=observed, source_event_id=event_id)
        if event.get("logon_type"):
            row["logon_types"].add(str(event["logon_type"]))
        if raw.get("computer"):
            row["sources"].add(str(raw["computer"]))
    covered = baseline_covered and not incomplete
    items = []
    for (user, _), row in groups.items():
        row["novelty"] = "new_pair" if covered and user in prior_users else "new_user" if covered else "no_baseline"
        row["prior_user_logon"] = "yes" if user in prior_users else "no" if covered else "unknown"
        row["first_seen"] = row["first_seen"].isoformat()
        row["logon_types"] = sorted(row["logon_types"])
        row["sources"] = sorted(row["sources"])
        items.append(row)
    return {"items": sorted(items, key=lambda row: (row["first_seen"], row["id"])),
            "baseline_covered": covered, "incomplete": incomplete}


def user_entities(domain_id: int, sids: list[str]) -> dict[str, int]:
    if not sids:
        return {}
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("""select a.normalized_value,min(a.entity_id) as entity_id
            from ad_context_entity_aliases a
            join entities_v2 e on e.id=a.entity_id
            join storage_v2_entity_type t on t.id=e.entity_type_id and t.value='ad_user'
            where a.domain_id=%s and a.alias_type='object_sid'
              and a.normalized_value=any(%s) group by a.normalized_value
            having count(distinct a.entity_id)=1""", (domain_id, [sid.casefold() for sid in sids]))
        return {str(row["normalized_value"]): int(row["entity_id"]) for row in cursor.fetchall()}
