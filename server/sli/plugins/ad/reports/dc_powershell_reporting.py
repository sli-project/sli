from __future__ import annotations

"""Bounded evidence-first PowerShell activity on domain controllers.

This read model deliberately exposes source-native 4103/4104 observations,
not process episodes.  Origin is disclosed only when a PowerShell event's
System.Execution.ProcessID, Security process lifecycle and LogonId lifecycle
form one closed source-native chain on the same domain controller and inside
one Security 4608 boot boundary. Names and timestamps alone never form a
bridge.
"""

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from server.sli.access.access_control_v4 import capability_decision_for_resource_groups
from server.sli.reporting.reporting_common import (
    build_domain_resource_groups,
    format_iso,
    get_runtime_connection,
    parse_utc,
    sanitize_public,
)
from server.sli.core.time_contract import TimeRangeError, normalize_utc_range
from server.sli.core.time_format import parse_event_time
from server.source_packs.windows_ad_dc import DC_POWERSHELL_ORIGIN_EVENT_IDS


CONTRACT_ID = "sli.dc-powershell-activity.v1"
REPORT_KEY = "dc.powershell.activity"
EVENT_VIEW_CAPABILITY = "events.view"
SENSITIVE_FIELD_CAPABILITY = "field.sensitive"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
POWERSHELL_PROVIDER = "Microsoft-Windows-PowerShell"
POWERSHELL_EVENT_IDS = frozenset({4103, 4104})
MAX_PERIOD_DAYS = 31
MAX_ACTIVITY_ROWS = 500
DEFAULT_ACTIVITY_ROWS = 200
SECURITY_CHANNEL = "Security"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
PROCESS_START_EVENT_ID = DC_POWERSHELL_ORIGIN_EVENT_IDS["process_start"]
PROCESS_STOP_EVENT_ID = DC_POWERSHELL_ORIGIN_EVENT_IDS["process_stop"]
LOGON_START_EVENT_ID = DC_POWERSHELL_ORIGIN_EVENT_IDS["session_start"]
LOGON_STOP_EVENT_ID = DC_POWERSHELL_ORIGIN_EVENT_IDS["session_stop"]
BOOT_START_EVENT_ID = DC_POWERSHELL_ORIGIN_EVENT_IDS["boot_start"]
ORIGIN_CONTEXT_CANDIDATE_LIMIT = 2
ORIGIN_CONTEXT_MAX_DAYS = 31

_utc = parse_utc
_iso = format_iso
_public = sanitize_public
_domain_resource_groups = build_domain_resource_groups


def _actor(event: Mapping[str, Any]) -> dict[str, Any]:
    observed_sid = str(event.get("subject_user_sid") or "").strip() or None
    observed_name = (
        str(event.get("subject_user_name") or "").strip()
        or str(event.get("powershell_user_name") or "").strip()
        or None
    )
    if observed_sid is None and observed_name is None:
        return {"state": "unknown"}
    return {
        "state": "observed",
        "subject_user_sid": observed_sid,
        "subject_user_name": observed_name,
    }


def _activity(event: Mapping[str, Any], *, include_script_block_text: bool) -> dict[str, Any]:
    event_id = int(event["event_id"])
    if event_id == 4103:
        command_name = str(event.get("powershell_command_name") or "").strip()
        return (
            {"state": "observed", "kind": "command", "command_name": command_name}
            if command_name
            else {"state": "unknown", "kind": "command"}
        )

    script_block_text = str(event.get("powershell_script_block_text") or "").strip()
    if not include_script_block_text and script_block_text:
        return {"state": "restricted", "kind": "script_block"}
    return (
        {
            "state": "observed",
            "kind": "script_block",
            "script_block_text": script_block_text,
        }
        if script_block_text
        else {"state": "unknown", "kind": "script_block"}
    )


def _origin(event: Mapping[str, Any]) -> dict[str, Any]:
    """Publish a source-native origin only when one boot-scoped chain is complete."""

    kind = str(event.get("origin_kind") or "").strip()
    evidence = {
        "process_start_event_db_id": event.get("origin_process_start_event_db_id"),
        "process_stop_event_db_id": event.get("origin_process_stop_event_db_id"),
        "session_start_event_db_id": event.get("origin_session_start_event_db_id"),
        "session_end_event_db_id": event.get("origin_session_end_event_db_id"),
    }
    boot_boundaries = {
        "process_start": event.get("origin_process_start_boot_event_db_id"),
        "process_stop": event.get("origin_process_stop_boot_event_db_id"),
        "session_start": event.get("origin_session_start_boot_event_db_id"),
        "session_end": event.get("origin_session_end_boot_event_db_id"),
    }
    if kind not in {"powershell_remoting", "rdp", "local"} or any(
        not isinstance(value, int) or value <= 0 for value in evidence.values()
    ):
        return {"state": "unknown", "reason": "no_complete_native_origin_chain"}
    if any(not isinstance(value, int) or value <= 0 for value in boot_boundaries.values()):
        return {"state": "unknown", "reason": "no_complete_native_origin_chain"}
    if len(set(boot_boundaries.values())) != 1:
        return {"state": "unknown", "reason": "origin_crosses_security_boot_boundary"}

    source_ip = str(event.get("origin_source_ip") or "").strip() or None
    workstation_name = str(event.get("origin_workstation_name") or "").strip() or None
    if kind == "rdp" and source_ip is None and workstation_name is None:
        return {"state": "unknown", "reason": "native_rdp_source_missing"}

    item: dict[str, Any] = {
        "state": "observed",
        "kind": kind,
        "evidence": {
            **evidence,
            "boot_start_event_db_id": boot_boundaries["process_start"],
        },
    }
    if source_ip is not None:
        item["source_ip"] = source_ip
    if workstation_name is not None:
        item["workstation_name"] = workstation_name
    return item


def _origin_for_event(candidates: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    observed = [_origin(candidate) for candidate in candidates]
    resolved = [item for item in observed if item["state"] == "observed"]
    if not resolved:
        return observed[0] if observed else {
            "state": "unknown",
            "reason": "no_complete_native_origin_chain",
        }
    unique = {
        (
            item["kind"],
            item.get("source_ip"),
            item.get("workstation_name"),
            tuple(sorted(item["evidence"].items())),
        ): item
        for item in resolved
    }
    if len(unique) != 1:
        return {"state": "unknown", "reason": "ambiguous_complete_native_origin_chain"}
    return next(iter(unique.values()))


def _collection_coverage(
    coverage: Mapping[str, Any],
    *,
    observed_event_count: int,
) -> tuple[str, dict[str, Any]]:
    history_event_present = bool(coverage.get("history_event_present"))
    if observed_event_count < 0:
        raise ValueError("dc_powershell_activity_collection_coverage_invalid")
    if observed_event_count and not history_event_present:
        raise ValueError("dc_powershell_activity_collection_coverage_invalid")
    if observed_event_count:
        state = "available"
    elif not history_event_present:
        state = "not_collected"
    else:
        state = "coverage_unverified"
    return state, {
        "state": state,
        "history_event_present": history_event_present,
        "source_completeness": "not_proven",
    }


def compose_dc_powershell_activity(
    *,
    source_domain_id: int,
    period_start: datetime,
    period_end: datetime,
    events: Sequence[Mapping[str, Any]],
    collection_coverage: Mapping[str, Any],
    include_script_block_text: bool,
) -> dict[str, Any]:
    """Make a bounded public view without synthesizing a process/session link."""

    if not period_start.tzinfo or not period_end.tzinfo or period_start >= period_end:
        raise ValueError("dc_powershell_activity_period_invalid")
    if len(events) > MAX_ACTIVITY_ROWS * ORIGIN_CONTEXT_CANDIDATE_LIMIT:
        raise ValueError("dc_powershell_activity_input_bound_exceeded")

    clean_start = _utc(period_start)
    clean_end = _utc(period_end)
    by_event_id: dict[int, list[Mapping[str, Any]]] = {}
    for event in events:
        event_id = int(event.get("event_id") or 0)
        if event_id not in POWERSHELL_EVENT_IDS:
            raise ValueError("dc_powershell_activity_event_invalid")
        observed_at = _utc(event.get("time_created_utc"))
        if observed_at is None or not clean_start <= observed_at < clean_end:
            raise ValueError("dc_powershell_activity_event_outside_bounds")
        event_db_id = int(event.get("event_db_id") or 0)
        if event_db_id <= 0:
            raise ValueError("dc_powershell_activity_event_identity_invalid")
        domain_controller = str(event.get("domain_controller") or "").strip()
        if not domain_controller:
            raise ValueError("dc_powershell_activity_domain_controller_missing")
        by_event_id.setdefault(event_db_id, []).append(event)
    if len(by_event_id) > MAX_ACTIVITY_ROWS:
        raise ValueError("dc_powershell_activity_input_bound_exceeded")

    items: list[dict[str, Any]] = []
    for event_db_id, event_candidates in by_event_id.items():
        event = event_candidates[0]
        event_id = int(event["event_id"])
        observed_at = _utc(event["time_created_utc"])
        assert observed_at is not None
        domain_controller = str(event["domain_controller"])
        items.append({
            "event_db_id": event_db_id,
            "event_record_id": event.get("event_record_id"),
            "event_id": event_id,
            "time_created_utc": _iso(observed_at),
            "domain_controller": domain_controller,
            "actor": _actor(event),
            "activity": _activity(
                event,
                include_script_block_text=include_script_block_text,
            ),
            "origin": _origin_for_event(event_candidates),
            "evidence": {
                "event_db_id": event_db_id,
                "event_record_id": event.get("event_record_id"),
                "source_core_sha256": _public(event.get("source_core_sha256")),
                "source_facts_sha256": _public(event.get("source_facts_sha256")),
            },
        })
    items.sort(key=lambda item: (item["time_created_utc"], item["event_db_id"]))
    state, public_coverage = _collection_coverage(
        collection_coverage,
        observed_event_count=len(items),
    )
    return {
        "contract_id": CONTRACT_ID,
        "report_key": REPORT_KEY,
        "source_domain_id": int(source_domain_id),
        "state": state,
        "time_bounds": {
            "from_utc": _iso(clean_start),
            "to_utc_exclusive": _iso(clean_end),
        },
        "items": items,
        "collection_coverage": public_coverage,
        "limits": {
            "input_event_limit": MAX_ACTIVITY_ROWS,
            "origin_context_days": ORIGIN_CONTEXT_MAX_DAYS,
            "bounded": True,
        },
        "limitations": [
            "PowerShell 4103/4104 are evidence facts, not process sessions.",
            "Origin remains unknown unless one complete source-native process and LogonId chain is present.",
            "An empty window does not prove complete source coverage.",
        ],
    }


def get_dc_powershell_activity(
    access: Mapping[str, Any],
    *,
    source_domain_id: int,
    time_from: str | None,
    time_to: str | None,
    timezone_name: str = "UTC",
    limit: int = DEFAULT_ACTIVITY_ROWS,
) -> dict[str, Any]:
    """Read domain-controller PowerShell facts after the domain access check."""

    domain_id = int(source_domain_id)
    if domain_id <= 0:
        raise ValueError("dc_powershell_activity_domain_invalid")
    if not time_from or not time_to:
        raise TimeRangeError("dc_powershell_activity_requires_time_bounds")
    start_raw, end_raw = normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
    period_start, period_end = _utc(start_raw), _utc(end_raw)
    if period_start is None or period_end is None or period_start >= period_end:
        raise TimeRangeError("empty_or_reversed_time_range")
    if period_end - period_start > timedelta(days=MAX_PERIOD_DAYS):
        raise TimeRangeError("dc_powershell_activity_period_too_wide")
    if not 1 <= int(limit) <= MAX_ACTIVITY_ROWS:
        raise ValueError("dc_powershell_activity_limit_invalid")

    resource_groups = _domain_resource_groups(domain_id)
    event_access = capability_decision_for_resource_groups(
        access,
        EVENT_VIEW_CAPABILITY,
        resource_groups=resource_groups,
    )
    if not event_access["allowed"]:
        return {
            "contract_id": CONTRACT_ID,
            "report_key": REPORT_KEY,
            "source_domain_id": domain_id,
            "state": "not_authorized",
            "time_bounds": {
                "from_utc": _iso(period_start),
                "to_utc_exclusive": _iso(period_end),
            },
            "items": [],
            "limits": {
                "input_event_limit": int(limit),
                "origin_context_days": ORIGIN_CONTEXT_MAX_DAYS,
                "bounded": True,
            },
        }
    sensitive_access = capability_decision_for_resource_groups(
        access,
        SENSITIVE_FIELD_CAPABILITY,
        resource_groups=resource_groups,
    )
    events, collection_coverage = _read_dc_powershell_activity_data(
        domain_id=domain_id,
        period_start=period_start,
        period_end=period_end,
        limit=int(limit),
        include_script_block_text=bool(sensitive_access["allowed"]),
    )
    return compose_dc_powershell_activity(
        source_domain_id=domain_id,
        period_start=period_start,
        period_end=period_end,
        events=events,
        collection_coverage=collection_coverage,
        include_script_block_text=bool(sensitive_access["allowed"]),
    )


def _read_dc_powershell_activity_data(
    *,
    domain_id: int,
    period_start: datetime,
    period_end: datetime,
    limit: int,
    include_script_block_text: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read selected DC PowerShell facts and at most two exact boot-scoped chains."""

    script_block_sql = (
        "facts.powershell_script_block_text"
        if include_script_block_text
        else "null::text"
    )
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read, read only")
        cur.execute(
            f"""with bounded_powershell as (
                    select event.id as event_db_id,event.event_record_id,event.event_id,
                           event.time_created_utc,event.server_id,event.domain_id,
                           server.hostname as domain_controller,
                           event.subject_user_sid,event.subject_user_name,
                           facts.powershell_user_name,facts.powershell_command_name,
                           {script_block_sql} as powershell_script_block_text,
                           facts.powershell_process_id,
                           event.source_core_sha256,facts.source_facts_sha256
                    from events_v2_core event
                    join servers server on server.id=event.server_id
                    join storage_v2_channel channel on channel.id=event.channel_id
                    join storage_v2_provider provider on provider.id=event.provider_id
                    left join event_facts_v2 facts on facts.event_id=event.id
                    where event.domain_id=%s and server.role='domain_controller'
                      and event.event_id in (4103,4104)
                      and channel.value=%s and provider.value=%s
                      and event.time_created_utc>=%s and event.time_created_utc<%s
                    order by event.time_created_utc,event.id limit %s
                  ), security_boot_boundaries as (
                    select boot.id,boot.domain_id,boot.server_id,
                           boot.event_record_id,boot.time_created_utc
                    from events_v2_core boot
                    join storage_v2_channel boot_channel on boot_channel.id=boot.channel_id
                    join storage_v2_provider boot_provider on boot_provider.id=boot.provider_id
                    where boot.domain_id=%s and boot.event_id=%s
                      and boot_channel.value=%s and boot_provider.value=%s
                      and boot.event_record_id>0
                  )
                  select power.event_db_id,power.event_record_id,power.event_id,
                         power.time_created_utc,power.domain_controller,
                         power.subject_user_sid,power.subject_user_name,
                         power.powershell_user_name,power.powershell_command_name,
                         power.powershell_script_block_text,
                         power.source_core_sha256,power.source_facts_sha256,
                         origin.origin_kind,origin.source_ip as origin_source_ip,
                         origin.workstation_name as origin_workstation_name,
                         origin.process_start_event_db_id as origin_process_start_event_db_id,
                         origin.process_stop_event_db_id as origin_process_stop_event_db_id,
                         origin.session_start_event_db_id as origin_session_start_event_db_id,
                         origin.session_end_event_db_id as origin_session_end_event_db_id,
                         origin.process_start_boot_event_db_id as origin_process_start_boot_event_db_id,
                         origin.process_stop_boot_event_db_id as origin_process_stop_boot_event_db_id,
                         origin.session_start_boot_event_db_id as origin_session_start_boot_event_db_id,
                         origin.session_end_boot_event_db_id as origin_session_end_boot_event_db_id
                  from bounded_powershell power
                  left join lateral (
                      select case
                               when right(lower(coalesce(process_facts.process_name,'')), 15)='wsmprovhost.exe'
                                and session_start.logon_type='3' then 'powershell_remoting'
                               when session_start.logon_type='10' then 'rdp'
                               when session_start.logon_type='2' then 'local'
                               else null
                             end as origin_kind,
                             nullif(nullif(btrim(session_start.ip_address),''),'-') as source_ip,
                             nullif(nullif(btrim(session_start.workstation_name),''),'-') as workstation_name,
                             process_start.id as process_start_event_db_id,
                             process_stop.id as process_stop_event_db_id,
                             session_start.id as session_start_event_db_id,
                             session_start.session_stop_event_db_id as session_end_event_db_id,
                             process_start_boot.id as process_start_boot_event_db_id,
                             process_stop_boot.id as process_stop_boot_event_db_id,
                             session_start.session_start_boot_event_db_id,
                             session_start.session_end_boot_event_db_id
                      from events_v2_core process_start
                      join event_facts_v2 process_facts on process_facts.event_id=process_start.id
                      join storage_v2_channel process_channel on process_channel.id=process_start.channel_id
                      join storage_v2_provider process_provider on process_provider.id=process_start.provider_id
                      join lateral (
                          select process_stop_event.id,process_stop_event.event_record_id,
                                 process_stop_event.time_created_utc
                          from events_v2_core process_stop_event
                          join event_facts_v2 process_stop_facts
                            on process_stop_facts.event_id=process_stop_event.id
                          join storage_v2_channel process_stop_channel
                            on process_stop_channel.id=process_stop_event.channel_id
                          join storage_v2_provider process_stop_provider
                            on process_stop_provider.id=process_stop_event.provider_id
                          where process_stop_event.domain_id=power.domain_id
                            and process_stop_event.server_id=power.server_id
                            and process_stop_event.event_id=%s
                            and process_stop_channel.value=%s and process_stop_provider.value=%s
                            and process_stop_facts.process_id=process_facts.process_id
                            and nullif(btrim(process_stop_event.logon_id),'')=nullif(btrim(process_start.logon_id),'')
                            and process_stop_event.time_created_utc>=power.time_created_utc
                            and process_stop_event.time_created_utc<
                                power.time_created_utc + make_interval(days => %s)
                          order by process_stop_event.time_created_utc,process_stop_event.id
                          limit 1
                      ) process_stop on true
                      join lateral (
                          select boot.id
                          from security_boot_boundaries boot
                          where boot.domain_id=process_start.domain_id
                            and boot.server_id=process_start.server_id
                            and boot.event_record_id<=process_stop.event_record_id
                            and boot.time_created_utc<=process_stop.time_created_utc
                          order by boot.time_created_utc desc,boot.id desc
                          limit 1
                      ) process_stop_boot on true
                      join lateral (
                          select login_event.id,login_event.time_created_utc,
                                 login_event.ip_address,login_event.workstation_name,
                                 login_facts.logon_type,
                                 session_stop.id as session_stop_event_db_id,
                                 session_start_boot.id as session_start_boot_event_db_id,
                                 session_end_boot.id as session_end_boot_event_db_id
                          from events_v2_core login_event
                          join event_facts_v2 login_facts on login_facts.event_id=login_event.id
                          join storage_v2_channel login_channel on login_channel.id=login_event.channel_id
                          join storage_v2_provider login_provider on login_provider.id=login_event.provider_id
                          join lateral (
                              select logoff_event.id,logoff_event.event_record_id,
                                     logoff_event.time_created_utc
                              from events_v2_core logoff_event
                              join storage_v2_channel logoff_channel on logoff_channel.id=logoff_event.channel_id
                              join storage_v2_provider logoff_provider on logoff_provider.id=logoff_event.provider_id
                              where logoff_event.domain_id=power.domain_id
                                and logoff_event.server_id=power.server_id
                                and logoff_event.event_id=%s
                                and logoff_channel.value=%s and logoff_provider.value=%s
                                and nullif(btrim(logoff_event.logon_id),'')=nullif(btrim(process_start.logon_id),'')
                                and logoff_event.time_created_utc>=process_stop.time_created_utc
                                and logoff_event.time_created_utc<
                                    process_stop.time_created_utc + make_interval(days => %s)
                              order by logoff_event.time_created_utc,logoff_event.id
                              limit 1
                          ) session_stop on true
                          join lateral (
                              select boot.id
                              from security_boot_boundaries boot
                              where boot.domain_id=login_event.domain_id
                                and boot.server_id=login_event.server_id
                                and boot.event_record_id<=login_event.event_record_id
                                and boot.time_created_utc<=login_event.time_created_utc
                              order by boot.time_created_utc desc,boot.id desc
                              limit 1
                          ) session_start_boot on true
                          join lateral (
                              select boot.id
                              from security_boot_boundaries boot
                              where boot.domain_id=login_event.domain_id
                                and boot.server_id=login_event.server_id
                                and boot.event_record_id<=session_stop.event_record_id
                                and boot.time_created_utc<=session_stop.time_created_utc
                              order by boot.time_created_utc desc,boot.id desc
                              limit 1
                          ) session_end_boot on true
                          where login_event.domain_id=power.domain_id
                            and login_event.server_id=power.server_id
                            and login_event.event_id=%s
                            and login_channel.value=%s and login_provider.value=%s
                            and nullif(btrim(login_event.logon_id),'')=nullif(btrim(process_start.logon_id),'')
                            and login_event.time_created_utc<=process_start.time_created_utc
                            and login_event.time_created_utc>=
                                process_start.time_created_utc - make_interval(days => %s)
                          order by login_event.time_created_utc desc,login_event.id desc
                          limit 1
                      ) session_start on true
                      join lateral (
                          select boot.id
                          from security_boot_boundaries boot
                          where boot.domain_id=process_start.domain_id
                            and boot.server_id=process_start.server_id
                            and boot.event_record_id<=process_start.event_record_id
                            and boot.time_created_utc<=process_start.time_created_utc
                          order by boot.time_created_utc desc,boot.id desc
                          limit 1
                      ) process_start_boot on true
                      where power.powershell_process_id is not null
                        and process_start.domain_id=power.domain_id
                        and process_start.server_id=power.server_id
                        and process_start.event_id=%s
                        and process_channel.value=%s and process_provider.value=%s
                        and process_facts.process_id=power.powershell_process_id
                        and nullif(btrim(process_start.logon_id),'') is not null
                        and process_start.time_created_utc<=power.time_created_utc
                        and process_start.time_created_utc>=
                            power.time_created_utc - make_interval(days => %s)
                        and process_start_boot.id=process_stop_boot.id
                        and process_start_boot.id=session_start.session_start_boot_event_db_id
                        and process_start_boot.id=session_start.session_end_boot_event_db_id
                      order by process_start.time_created_utc desc,process_start.id desc
                      limit 2
                  ) origin on true
                  order by power.time_created_utc,power.event_db_id,origin.process_start_event_db_id""",
            (
                domain_id,
                POWERSHELL_CHANNEL,
                POWERSHELL_PROVIDER,
                period_start,
                period_end,
                limit + 1,
                domain_id,
                BOOT_START_EVENT_ID,
                SECURITY_CHANNEL,
                SECURITY_PROVIDER,
                PROCESS_STOP_EVENT_ID,
                SECURITY_CHANNEL,
                SECURITY_PROVIDER,
                ORIGIN_CONTEXT_MAX_DAYS,
                LOGON_STOP_EVENT_ID,
                SECURITY_CHANNEL,
                SECURITY_PROVIDER,
                ORIGIN_CONTEXT_MAX_DAYS,
                LOGON_START_EVENT_ID,
                SECURITY_CHANNEL,
                SECURITY_PROVIDER,
                ORIGIN_CONTEXT_MAX_DAYS,
                PROCESS_START_EVENT_ID,
                SECURITY_CHANNEL,
                SECURITY_PROVIDER,
                ORIGIN_CONTEXT_MAX_DAYS,
            ),
        )
        events = [dict(row) for row in cur.fetchall()]
        if len({int(event["event_db_id"]) for event in events}) > limit:
            raise ValueError("dc_powershell_activity_input_bound_exceeded")
        cur.execute(
            """select exists(
                       select 1 from events_v2_core history_event
                       join servers history_server on history_server.id=history_event.server_id
                       join storage_v2_channel history_channel on history_channel.id=history_event.channel_id
                       join storage_v2_provider history_provider on history_provider.id=history_event.provider_id
                       where history_event.domain_id=%s
                         and history_server.role='domain_controller'
                         and history_event.event_id in (4103,4104)
                         and history_channel.value=%s and history_provider.value=%s
                   ) as history_event_present""",
            (domain_id, POWERSHELL_CHANNEL, POWERSHELL_PROVIDER),
        )
        collection_coverage = dict(cur.fetchone() or {})
    return events, collection_coverage


_connect = get_runtime_connection
