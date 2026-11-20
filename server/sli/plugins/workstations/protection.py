"""C01/C09 and observed Defender transitions, inside the WR05 publication fence.

Snapshots attest Defender flags, not the presence of every antivirus product.
The caller owns the transaction; these handlers never commit or collect data.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sli_agent.workstations import PROTECTION_COMPONENTS, validate_protection_state

from .check_catalog import BY_ID
from .importer import digest
from .overview_contracts import CheckCounts, CheckResult, Count, Quality, Reason

MAX_AGE = timedelta(hours=24)
MAX_BATCH = 100


def timestamp(value):
    value = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("workstation_protection_timestamp_invalid")
    return value.astimezone(timezone.utc)


def snapshot_ref(snapshot):
    return {"kind": "protection_snapshot", "agent_key": snapshot["agent_key"],
            "observed_at": timestamp(snapshot["observed_at"]).isoformat(),
            "sha256": snapshot["state_sha256"]}


def evaluate(snapshot, *, now, station_type="unknown"):
    """Return scoped per-station results; unknown C01 counts are never zero."""
    now = timestamp(now)
    observed_at, disabled, unknown = None, [], list(PROTECTION_COMPONENTS)
    components = dict.fromkeys(PROTECTION_COMPONENTS)
    status = "not_collected"
    if snapshot is not None:
        state = validate_protection_state(snapshot["state"])
        if digest(state) != snapshot["state_sha256"]:
            raise ValueError("workstation_protection_snapshot_conflict")
        observed_at = timestamp(snapshot["observed_at"])
        components = state["components"]
        unknown = [key for key in PROTECTION_COMPONENTS if components[key] is None]
        disabled = [key for key in PROTECTION_COMPONENTS if components[key] is False]
        if observed_at > now or state["state"] == "unavailable":
            status = "unavailable"
        elif now - observed_at > MAX_AGE:
            status = "stale"
        else:
            status = "partial" if unknown else "complete"
    # An old unavailable observation still proves that the last collection is
    # old, but it does not prove anything about the flags at that time.
    stale = observed_at is not None and now - observed_at > MAX_AGE
    known = status in {"complete", "partial"}
    quality_reason = {"partial": "coverage_incomplete", "stale": "data_stale",
                      "unavailable": "source_missing", "not_collected": "not_collected"}
    quality = Quality(status, (Reason(quality_reason[status]),) if status != "complete" else ())
    c01_reason = (Reason("protection_disabled", {"components": ", ".join(disabled)}),) if known and disabled else ()
    c09_reason = (Reason("protection_stale", {"age_hours": int((now - observed_at).total_seconds() // 3600)}),) if stale else ()
    c01 = CheckResult("C01", quality, CheckCounts(
        Count(int(bool(disabled)), "exact" if status == "complete" else "at_least") if known and len(unknown) < len(PROTECTION_COMPONENTS)
        else Count(None, "unknown"), Count(None, "unknown")), c01_reason)
    c09_quality = Quality("complete") if observed_at is not None and observed_at <= now else quality
    c09 = CheckResult("C09", c09_quality, CheckCounts(
        Count(int(stale), "exact") if c09_quality.status == "complete" else Count(None, "unknown"),
        Count(None, "unknown")), c09_reason)
    summary = {"observed_at": observed_at.isoformat() if observed_at else None,
               "quality": quality.to_dict(), "components": components if known else dict.fromkeys(PROTECTION_COMPONENTS),
               "last_known_components": components, "disabled_components": disabled if known else [],
               "unknown_components": unknown if known else list(PROTECTION_COMPONENTS),
               "next_refresh_at": (observed_at if observed_at > now else observed_at + MAX_AGE).isoformat()
                   if observed_at is not None and not stale else None}
    return {"summary": summary, "checks": (c01, c09),
            "severities": {key: BY_ID[key].severity_for(station_type) for key in ("C01", "C09")}}


def transitions(previous, current):
    """One observed change per direction, never an invented first-true event."""
    if previous is None or timestamp(previous["observed_at"]) >= timestamp(current["observed_at"]):
        return []
    for snapshot in (previous, current):
        validate_protection_state(snapshot["state"])
        if digest(snapshot["state"]) != snapshot["state_sha256"]:
            raise ValueError("workstation_protection_snapshot_conflict")
    if any(snapshot["state"]["state"] != "available" for snapshot in (previous, current)):
        return []
    before, after = previous["state"]["components"], current["state"]["components"]
    return [{"change_kind": f"protection_{direction}", "components": components}
            for direction, old, new in (("enabled", False, True), ("disabled", True, False))
            if (components := [key for key in PROTECTION_COMPONENTS if before[key] is old and after[key] is new])]


def due(cur, *, now, limit=MAX_BATCH):
    if type(limit) is not int or not 1 <= limit <= MAX_BATCH:
        raise ValueError("workstation_projection_batch_invalid")
    cur.execute("""select i.station_id from sli_plugin_workstations.station_inventory i
        left join sli_plugin_workstations.station_summary s using(station_id)
        where s.station_id is null or s.protection='{}'::jsonb
            or (s.protection->>'next_refresh_at')::timestamptz<%s
        order by i.station_id limit %s""", (timestamp(now), limit))
    return [row["station_id"] for row in cur.fetchall()]


def _finding(cur, station_id, check, severity, snapshot, now):
    key = check.check_id
    cur.execute("""select * from sli_plugin_workstations.check_findings
        where station_id=%s and check_id=%s and rule_version=%s
        order by first_detected_at desc,id desc limit 1 for update""",
        (station_id, key, BY_ID[key].rule_version))
    previous = cur.fetchone()
    observed_active = bool(check.reasons)
    observed_clear = (check.quality.status == "complete"
                      and check.counts.stations.relation == "exact"
                      and check.counts.stations.value == 0)
    if not observed_active and (previous is None or previous["status"] == "resolved"):
        return
    # Silence and partial coverage cannot close an unresolved episode. Its
    # historical evidence remains historical; evaluate() still reports current
    # flags/counts as unknown rather than inventing a current disabled state.
    active = observed_active or not observed_clear
    observed = observed_active or observed_clear
    reason_params = dict(check.reasons[0].params) if observed_active else previous["reason_params"]
    quality = check.quality.to_dict()
    # Snapshot times/refs and age progression are not material changes. A new
    # disabled component, certainty, severity or episode is a new revision.
    condition = digest([key, reason_params.get("components"), quality, severity, active])
    if active and (previous is None or previous["status"] == "resolved"):
        episode = digest([key, station_id, snapshot_ref(snapshot)])
        finding_id = digest([key, BY_ID[key].rule_version, station_id, episode])
        cur.execute("""insert into sli_plugin_workstations.check_findings
            (id,station_id,check_id,rule_version,episode_id,condition_sha256,status,severity,
             fact_at,first_detected_at,last_observed_at,materially_changed_at,
             reason_code,reason_params,quality,evidence_refs)
            values(%s,%s,%s,%s,%s,%s,'active',%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s::jsonb)
            on conflict(id) do nothing""",
            (finding_id, station_id, key, BY_ID[key].rule_version, episode, condition, severity,
             timestamp(snapshot["observed_at"]), now, timestamp(snapshot["observed_at"]), now,
             BY_ID[key].reason_code, json.dumps(reason_params), json.dumps(quality),
             json.dumps([snapshot_ref(snapshot)])))
        return
    cur.execute("""update sli_plugin_workstations.check_findings set
        revision=revision+case when condition_sha256<>%s then 1 else 0 end,
        materially_changed_at=case when condition_sha256<>%s then %s else materially_changed_at end,
        condition_sha256=%s,status=%s,severity=%s,last_observed_at=%s,resolved_at=%s,
        reason_params=%s::jsonb,quality=%s::jsonb,evidence_refs=%s::jsonb where id=%s""",
        (condition, condition, now, condition, "active" if active else "resolved", severity,
         timestamp(snapshot["observed_at"]) if observed and snapshot else previous["last_observed_at"],
         None if active else now, json.dumps(reason_params), json.dumps(quality),
         json.dumps([snapshot_ref(snapshot)]) if observed and snapshot else json.dumps(previous["evidence_refs"]), previous["id"]))


def refresh(conn, station_id, *, now):
    """Refresh one station from its latest attestation, including age-only C09."""
    now = timestamp(now)
    with conn.cursor() as cur:
        cur.execute("""select i.station_type,p.id,p.agent_key,p.observed_at,p.state,p.state_sha256
            from sli_plugin_workstations.station_inventory i
            left join sli_plugin_workstations.protection_state p on p.agent_key=i.agent_key
            where i.station_id=%s""", (station_id,))
        row = cur.fetchone()
        if row is None:
            raise ValueError("workstation_projection_station_missing")
        snapshot = row if row["observed_at"] is not None else None
        result = evaluate(snapshot, now=now, station_type=row["station_type"])
        for check in result["checks"]:
            _finding(cur, station_id, check, result["severities"][check.check_id], snapshot, now)
        cur.execute("""insert into sli_plugin_workstations.station_summary(station_id,protection,as_of_utc)
            values(%s,%s::jsonb,%s) on conflict(station_id) do update set
                protection=excluded.protection,as_of_utc=excluded.as_of_utc,
                revision=station_summary.revision+case when station_summary.protection<>excluded.protection then 1 else 0 end,
                updated_at=now()""", (station_id, json.dumps(result["summary"]), now))
    return result


def apply(conn, station_id, fact):
    """WR05 callback: exact snapshot history plus current-state projection."""
    if fact["kind"] not in {"protection_state", "station_inventory"}:
        return
    with conn.cursor() as cur:
        cur.execute("select clock_timestamp() as now")
        now = cur.fetchone()["now"]
        if fact["kind"] == "protection_state":
            current = fact["payload"]
            # Read the immutable predecessor, not the already overwritten
            # protection_state row, which may be many imports ahead of this job.
            cur.execute("""select payload from sli_plugin_workstations.projection_work
                where kind='protection_state' and agent_key=%s
                  and work_id<(select work_id from sli_plugin_workstations.projection_work
                      where kind='protection_state' and source_id=%s)
                order by work_id desc limit 1""", (current["agent_key"], fact["source_id"]))
            row = cur.fetchone()
            previous = row["payload"] if row else None
            for change in transitions(previous, current):
                change_id = digest([station_id, fact["source_id"], change["change_kind"]])
                params = {"components": ", ".join(change["components"]),
                          "previous_observed_at": timestamp(previous["observed_at"]).isoformat(),
                          "observed_at": timestamp(current["observed_at"]).isoformat()}
                cur.execute("""insert into sli_plugin_workstations.station_changes
                    (id,station_id,change_kind,event_at,detected_at,reason_code,reason_params,quality,evidence_refs)
                    values(%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s::jsonb) on conflict(id) do nothing""",
                    (change_id, station_id, change["change_kind"], timestamp(current["observed_at"]), now,
                     change["change_kind"], json.dumps(params), json.dumps(Quality("complete").to_dict()),
                     json.dumps([snapshot_ref(previous), snapshot_ref(current)])))
    refresh(conn, station_id, now=now)
