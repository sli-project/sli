"""Read-only collection health from agent policies, receipts and import queues."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from psycopg.errors import QueryCanceled

from server.sli.agents.agent_names import human_host_name, reported_hostname
from server.sli.core.database import QueryTimeoutError, query_rows_bounded
from sli_agent.ad_dc import CHANNELS as DC_CHANNELS
from sli_agent.snapshot_stream import MODULE_FAMILIES
from sli_agent.workstations import WorkstationsModule

IMPORT_BUDGET_SECONDS = 900
# Policy metadata must remain readable without the optional VPN collectors.
NPS_FAMILIES = {"sli.vpn-nps": "nps", "sli.radius-accounting": "radius_accounting"}

_AGENTS_SQL = """
select a.id::text, a.host_id::text, a.instance_name, a.status, a.last_seen,
       a.created_at, a.assigned_modules, a.collection_policy, a.registration_host_name,
       a.policy_revision, a.applied_policy_revision, a.applied_collection_state,
       (select coalesce(jsonb_agg(jsonb_build_object('module_id',b.module_id,'source_name',b.source_name)), '[]'::jsonb)
        from sli_agent_module_bindings b where b.agent_id=a.id) as source_bindings,
       ack.occurred_at as policy_applied_at, enrolled.fqdn as domain, enrolled.host_name,
       gap.occurred_at as last_accepted_gap_at,
       (select received_at from sli_agent_receipts where agent_id=a.id
        order by received_at desc limit 1) as last_packet_at
from sli_agents a
left join lateral (
    select occurred_at from sli_agent_audit
    where target=a.id::text and action='sequence_gap_accepted'
    order by id desc limit 1
) gap on true
left join lateral (
    select occurred_at from sli_agent_audit
    where target=a.id::text and action='policy_ack'
      and details->>'revision'=a.policy_revision::text
    order by id desc limit 1
) ack on true
left join lateral (
    select d.fqdn, coalesce(nullif(btrim(v.attributes_json->'attributes'->>'dns_host_name'),''),
                           nullif(btrim(v.attributes_json->'attributes'->>'display_name'),'')) as host_name
    from sli_agent_audit issued
    join sli_agent_group_approval_links c on issued.actor='enrollment:' || c.enrollment_token_id::text
    join sli_agent_group_requests r on r.id=c.request_id
    join ad_context_entity_versions v on v.id=r.computer_version_id
    join sli_agent_group_tokens t on t.id=r.token_id
    join domains d on d.id=t.domain_id
    where issued.target=a.id::text and issued.action='issue'
    order by issued.id desc limit 1
) enrolled on true
order by a.created_at, a.id
"""

# Migration290 maintains exact import maxima in the same transaction as inbox
# progress. A recent-receipt window is unsafe: consume_agent_packets permits
# deferred inputs, cursor wrap and SKIP LOCKED; quarantine replay imports old
# packets too. last_import_at also drives an overdue fallback in the projection.
# Latest receipt/pending lookups keep their existing semantics and indexes.
_STREAMS_SQL = """
with requested as materialized (
    select * from jsonb_to_recordset(?::jsonb) as x(
        agent_id uuid,module_id text,revision text,channel text,snapshot boolean)
)
select wanted.agent_id::text,wanted.module_id,wanted.revision,wanted.channel,
       latest.received_at as last_packet_at,imported.last_import_at,
       pending.pending_since,
       case when wanted.module_id='sli.file-audit' then (
           select case when payload.packet#>'{context,read_error}'='null'::jsonb then false
               when payload.packet#>>'{context,read_error}' in
                   ('file_audit_read_failed','file_audit_journal_gap') then true
               else null end
           from sli_agent_packet_inbox payload where payload.packet_id=latest.packet_id
       ) else latest.collection_read_error end as read_error,
       pending.historical_unimported_packets,pending.historical_error_at
from requested wanted
left join lateral (
    select r.packet_id,r.received_at,i.collection_read_error
    from sli_agent_receipts r join sli_agent_packet_inbox i using(packet_id)
    where r.agent_id=wanted.agent_id and r.module_id=wanted.module_id
      and i.collection_revision=wanted.revision
      and i.collection_channel is not distinct from wanted.channel
    order by r.received_at desc,r.sequence desc limit 1
) latest on true
left join sli_agent_stream_import_health imported
  on imported.agent_id=wanted.agent_id and imported.module_id=wanted.module_id
 and imported.revision=wanted.revision
 and imported.channel is not distinct from wanted.channel
 and latest.packet_id is not null
left join lateral (
    select min(r.received_at) filter(where historical.packet_id is null) as pending_since,
           count(*) filter(where historical.packet_id is not null) as historical_unimported_packets,
           min(historical.quarantined_at) as historical_error_at
    from sli_agent_packet_inbox i join sli_agent_receipts r using(packet_id)
    left join sli_agent_packet_quarantine historical on historical.packet_id=r.packet_id
      and historical.reason_code in ('source_event_allocation_hash_mismatch','published_source_event_hash_mismatch')
      and r.received_at < now() - interval '7 days'
    where i.imported_at is null
      and r.agent_id=wanted.agent_id and r.module_id=wanted.module_id
      and i.collection_revision=wanted.revision
      and i.collection_channel is not distinct from wanted.channel
) pending on true
where not wanted.snapshot
union all
select wanted.agent_id::text,wanted.module_id,wanted.revision,null,
       max(coalesce(c.completed_at,c.created_at)),max(c.published_at),
       min(c.created_at) filter(where c.publication_state='pending'),false,0,null::timestamptz
from requested wanted left join sli_agent_snapshot_cycles c
  on c.agent_id=wanted.agent_id and c.module_id=wanted.module_id
 and c.policy->>'policy_revision'=wanted.revision
where wanted.snapshot
group by wanted.agent_id,wanted.module_id,wanted.revision
"""


def _time(value):
    if value is None:
        return None
    result = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)


def _iso(value):
    parsed = _time(value)
    return parsed.isoformat() if parsed else None


def _age(value, now):
    parsed = _time(value)
    return max(0, int((now - parsed).total_seconds())) if parsed else None


def _channels(module, config, host):
    if module == "sli.workstations":
        return list(WorkstationsModule(host, config).enabled_channels())
    if module == "sli.windows.ad-dc":
        return [channel for channel in DC_CHANNELS if config.get("channels", {}).get(channel, True)]
    if module in NPS_FAMILIES and not config.get("families", {}).get(NPS_FAMILIES[module], True):
        return []
    if module in ("sli.vpn-nps", "sli.file-audit"):
        return ["Security"]
    if module == "sli.radius-accounting":
        return ["radius-accounting"]
    if module == "sli.windows-eventlog" and config.get("channel"):
        return [config["channel"]]
    return []


def _budget(module, config, interval, channel_count):
    if module in MODULE_FAMILIES:
        hours = config.get("schedule", {}).get("hours", [6, 18])
        gaps = [b - a for a, b in zip(hours, hours[1:] + [hours[0] + 24])]
        return max(gaps) * 3600 + config.get("capture_seconds", 300) + IMPORT_BUDGET_SECONDS
    return max(IMPORT_BUDGET_SECONDS, interval * max(1, channel_count) * 3)


def _requested_streams(agents):
    streams = []
    for agent in agents:
        for assignment in agent.get("assigned_modules", []):
            if not isinstance(assignment, dict) or assignment.get("enabled") is not True:
                continue
            module, config = assignment["module_id"], assignment.get("config") or {}
            for channel in _channels(module, config, agent["host_id"]) or ([None] if module in MODULE_FAMILIES else []):
                streams.append({"agent_id": agent["id"], "module_id": module,
                                "revision": str(config.get("policy_revision", "1")), "channel": channel,
                                "snapshot": module in MODULE_FAMILIES})
    return streams


def collection_health_view(agents, streams, *, now=None, diagnostics_available=True):
    """Pure projection; only confirmed failures of enabled collection turn red."""
    now = now or datetime.now(timezone.utc)
    by_stream = {(row["agent_id"], row["module_id"], row["revision"], row["channel"]): row for row in streams}
    items = []
    for agent in agents:
        policy = agent.get("collection_policy") or {}
        enabled = agent["status"] == "active" and policy.get("state", "active") == "active"
        applied = (agent["policy_revision"] == agent["applied_policy_revision"]
                   and agent.get("applied_collection_state") == "active")
        interval = policy.get("interval_seconds", 60)
        connection_age = _age(agent.get("last_seen"), now)
        # last_seen is server-observed authenticated contact from the successful
        # registry read. A failed stream read cannot invalidate that evidence.
        connection = "never_seen" if connection_age is None else "online" if connection_age <= max(300, interval * 3) else "offline"
        module_views = []
        domains = {agent["domain"]} if agent.get("domain") else set()
        for assignment in agent.get("assigned_modules", []):
            if not isinstance(assignment, dict) or assignment.get("enabled") is not True:
                continue
            module = assignment["module_id"]
            config = assignment.get("config") or {}
            if config.get("domain_dns"):
                domains.add(config["domain_dns"])
            channels = _channels(module, config, agent["host_id"])
            module_enabled = enabled and not config.get("paused", False)
            budget = _budget(module, config, interval, len(channels))
            checks = []
            for channel in channels or ([None] if module in MODULE_FAMILIES else []):
                stream = by_stream.get((agent["id"], module, str(config.get("policy_revision", "1")), channel), {})
                age = _age(stream.get("last_packet_at"), now)
                pending = _age(stream.get("pending_since"), now)
                grace_start = _time(agent.get("policy_applied_at") or agent.get("created_at"))
                grace = _age(grace_start, now)
                grace_deadline = grace_start + timedelta(seconds=budget) if grace_start else None
                import_budget = IMPORT_BUDGET_SECONDS + (config.get("capture_seconds", 300) if module in MODULE_FAMILIES else 0)
                state = "paused" if agent["status"] == "active" and not module_enabled else "disabled" if not enabled else "waiting"
                failure_reason = None
                issue_since = issue_observed_at = None
                if module_enabled and not diagnostics_available:
                    state = "unknown"
                elif module_enabled and (applied or connection != "online" and grace is not None and grace > budget):
                    if stream.get("read_error"):
                        state = "error"
                        failure_reason = "read_error"
                        received_at = _time(stream.get("last_packet_at"))
                        issue_observed_at = received_at if received_at and received_at <= now else None
                    elif pending is not None and pending > import_budget:
                        state = "error"
                        failure_reason = "import_overdue"
                        issue_since = _time(stream["pending_since"]) + timedelta(seconds=import_budget)
                    elif age is None:
                        state = "error" if grace is not None and grace > budget else "waiting"
                        failure_reason = "packet_missing" if state == "error" else None
                        issue_since = grace_deadline if state == "error" else None
                    elif age > budget:
                        state = "waiting" if grace is not None and grace <= budget else "error"
                        failure_reason = "packet_stale" if state == "error" else None
                        if state == "error":
                            issue_since = _time(stream["last_packet_at"]) + timedelta(seconds=budget)
                            if grace_deadline:
                                issue_since = max(issue_since, grace_deadline)
                    elif _age(stream.get("last_import_at"), now) is not None and _age(stream["last_import_at"], now) > budget:
                        state = "error"
                        failure_reason = "import_overdue"
                        issue_since = _time(stream["last_import_at"]) + timedelta(seconds=budget)
                    elif pending is not None:
                        state = "lagging"
                    elif module == "sli.file-audit" and stream.get("read_error") is None:
                        # Missing/unsupported retained error metadata is not a
                        # successful empty check, even when import completed.
                        state = "unknown"
                    elif stream.get("last_import_at"):
                        state = "current"
                    else:
                        state = "unknown"
                # Dates describe only the selected current channel condition:
                # "since" is its evidenced overdue threshold, NOT an outage
                # onset or proof of uninterrupted failure/active collection.
                # Read errors have receipt evidence only, never a known onset.
                # No history scan, last_seen substitution or persisted incident
                # is needed; unavailable/non-failing states keep both dates null.
                if issue_since is not None:
                    if not applied and grace_deadline:
                        issue_since = max(issue_since, grace_deadline)
                    issue_observed_at = now
                import_lag = pending
                if import_lag is None and stream.get("last_packet_at") and stream.get("last_import_at"):
                    import_lag = max(0, int((_time(stream["last_import_at"]) - _time(stream["last_packet_at"])).total_seconds()))
                checks.append({"channel": channel, "state": state,
                               "failure_reason": failure_reason,
                               "issue_since_utc": _iso(issue_since),
                               "issue_observed_at_utc": _iso(issue_observed_at),
                               "last_packet_at": _iso(stream.get("last_packet_at")),
                               "last_import_at": _iso(stream.get("last_import_at")),
                               **({"historical_unimported_packets": int(stream.get("historical_unimported_packets") or 0),
                                   "historical_error_at": _iso(stream.get("historical_error_at"))}
                                  if diagnostics_available else {}),
                               "import_lag_seconds": import_lag, "budget_seconds": budget})
            module_views.append({"module_id": module, "channels": checks})
        checks = [check for module in module_views for check in module["channels"]
                  if check["state"] not in ("paused", "disabled")]
        state = ("disabled" if agent["status"] != "active" else "paused" if not enabled
                 else "unknown" if not diagnostics_available
                 else "error" if any(check["state"] == "error" for check in checks)
                 else "waiting" if not applied or not checks
                 else "current" if all(check["state"] == "current" for check in checks)
                 else "lagging" if any(check["state"] == "lagging" for check in checks)
                 else "waiting" if any(check["state"] == "waiting" for check in checks) else "unknown")
        packets = [check["last_packet_at"] for check in checks if check["last_packet_at"]]
        # Display metadata comes from the approved AD version or a DC policy;
        # registry UUIDs remain technical identifiers, never hostname fallbacks.
        host_name = human_host_name(agent.get("host_name")) or reported_hostname(agent.get("registration_host_name")) or ""
        if not host_name:
            host_name = next((((assignment.get("config") or {}).get("source_name") or "").strip()
                              for assignment in agent.get("assigned_modules", [])
                              if isinstance(assignment, dict) and assignment.get("module_id") == "sli.windows.ad-dc"), "")
        if host_name in (agent["host_id"], agent["id"]):
            host_name = ""
        name = " · ".join(part for part in (host_name, agent.get("instance_name")) if part)
        items.append({"id": agent["id"], "host_id": agent["host_id"], "name": name,
                      "domains": sorted(domains), "state": state, "connection": connection,
                      # Delivery health is not a completeness assertion. This is
                      # historical evidence, independent of current connectivity.
                      "completeness": {"state": "known_gaps" if agent.get("last_accepted_gap_at") else "not_assessed",
                                       "last_accepted_gap_at": _iso(agent.get("last_accepted_gap_at"))},
                      "last_seen": _iso(agent.get("last_seen")),
                      "last_packet_at": _iso(agent.get("last_packet_at")) or max(packets, default=None),
                      "modules": module_views, "policy_revision": agent["policy_revision"],
                      "applied_policy_revision": agent["applied_policy_revision"],
                      "href": "/app/agents?agent_id=" + agent["id"] + "#agent-" + agent["id"]})
    items.sort(key=lambda item: (item["domains"], item["name"], item["id"]))
    active = [item for item in items if item["state"] not in ("paused", "disabled")]
    state = ("error" if any(item["state"] == "error" for item in active)
             else "current" if active and all(item["state"] == "current" for item in active)
             else "partial" if active else "unknown")
    return {"state": state, "items": items, "checked_at_utc": now.isoformat(),
            "completeness": {"state": "known_gaps" if any(item["completeness"]["state"] == "known_gaps" for item in items) else "not_assessed"},
            "active_agents": len(active), "current_agents": sum(item["state"] == "current" for item in active)}


def _setup_source_bindings(agents):
    """Private setup projection, never included in the default health response."""
    bindings = []
    for agent in agents:
        policy = agent.get("collection_policy") or {}
        enabled = agent["status"] == "active" and policy.get("state", "active") == "active"
        for assignment in agent.get("assigned_modules", []):
            if not isinstance(assignment, dict):
                continue
            module = assignment.get("module_id")
            if module not in {"sli.windows.ad-dc", "sli.ad-snapshot", "sli.gpo-snapshot"}:
                continue
            config = assignment.get("config") or {}
            source = config.get("source_name")
            if not source:
                source = next((binding.get("source_name") for binding in agent.get("source_bindings", [])
                               if binding.get("module_id") == module), None)
            if not isinstance(source, str) or source.strip().casefold() in {
                str(agent["id"]).casefold(), str(agent["host_id"]).casefold(),
            }:
                source = None
            bindings.append({
                "agent_id": agent["id"], "module_id": module,
                "source_name": source if module == "sli.windows.ad-dc" else None,
                "domain_dns": config.get("domain_dns") if module in MODULE_FAMILIES else None,
                "enabled": enabled and assignment.get("enabled") is True and not config.get("paused", False),
                "paused": agent["status"] == "active" and assignment.get("enabled") is True
                          and (policy.get("state", "active") != "active" or bool(config.get("paused", False))),
            })
    return bindings


def get_agent_collection_health(*, include_setup_bindings=False):
    try:
        agents = query_rows_bounded(_AGENTS_SQL, statement_timeout_ms=3000)
        try:
            requested = _requested_streams(agents)
            streams = query_rows_bounded(_STREAMS_SQL, (json.dumps(requested),), statement_timeout_ms=3000, jit=False) if requested else []
        except PermissionError:
            # An application authorization denial is never a degraded-data path.
            raise
        except Exception as exc:  # noqa: BLE001 -- unavailable diagnostics must not expose source details
            # Registry timestamps remain evidence, not proof of current collection.
            # Unknown stream state must not become packet_missing or current.
            result = collection_health_view(agents, [], diagnostics_available=False)
            result["diagnostics"] = {"state": "unavailable", "reason":
                                     "timeout" if isinstance(exc, (TimeoutError, QueryTimeoutError, QueryCanceled)) else "read_failed"}
            if include_setup_bindings:
                result["_setup_bindings"] = _setup_source_bindings(agents)
            return result
        result = collection_health_view(agents, streams)
        if include_setup_bindings:
            result["_setup_bindings"] = _setup_source_bindings(agents)
        return result
    except Exception:  # noqa: BLE001 -- malformed or unauthorized reads must fail closed
        # Do not turn a failed read into a collection failure or expose data.
        return {"state": "unavailable", "items": [], "active_agents": 0, "current_agents": 0,
                "completeness": {"state": "not_assessed"},
                "checked_at_utc": datetime.now(timezone.utc).isoformat()}


