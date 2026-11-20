"""Read-only AD report supplements from saved DNS, registry and logon evidence."""
from __future__ import annotations

from datetime import datetime, timezone

from server.sli.core.database import query_rows_bounded

SILENT_SECONDS = 86400


def _time(value):
    try:
        stamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def dns_observation(raw):
    """Never relabel an undated or non-DNS address as an agent DNS observation."""
    state = ((raw.get("evidence") or {}).get("network_sources") or {}).get("dns_addresses") or {}
    at = state.get("observed_at")
    addresses = raw.get("ip_addresses") or []
    return {"state": state.get("status") or state.get("state") or "not_collected",
            "addresses": addresses if state.get("status") == "observed" and _time(at) else [],
            "observed_at_utc": at if _time(at) else None}


def load_agents(domain_ids):
    """Only explicit enrollment/identity links establish a directory match.

    Unbound registry entries prevent an absence claim. No registry identifiers,
    enrollment tokens or policy payloads are returned to the report client.
    """
    if domain_ids == []:
        return []
    try:
        return query_rows_bounded("""/* ad_report_agent_registry */
            with bindings as (
                select issued.target::uuid as agent_id,r.computer_entity_id,issued.occurred_at as bound_at
                from sli_agent_audit issued
                join sli_agent_group_approval_links c on issued.actor='enrollment:' || c.enrollment_token_id::text
                join sli_agent_group_requests r on r.id=c.request_id
                where issued.action='issue'
                union
                select agent.id,a.target_entity_id,greatest(a.created_at_utc,r.observed_at_utc)
                from sli_agents agent join core_entity_scope_resources r
                  on r.natural_key='core:' || encode(sha256(convert_to(
                      '["device","sli.agent.key","agent-registry","' || agent.id::text || '"]', 'UTF8')), 'hex')
                 and r.plugin_id='sli.workstations' and r.source_instance_id=agent.host_id::text
                 and r.entity_type='device' and r.resolution='resolved'
                join core_entity_associations a on a.source_entity_id=r.entity_id
                where a.relation='directory_computer'
            ), unique_bindings as (
                select agent_id,min(computer_entity_id) as entity_id,min(bound_at) as bound_at from bindings
                group by agent_id having count(distinct computer_entity_id)=1
            )
            select a.id as agent_id,a.created_at,a.last_seen,a.status,e.id as entity_id,e.domain_id,b.bound_at,
                   removal.state as removal_state,removal.reported_at as removed_at,
                   guid.alias_value as object_guid,version.version
            from sli_agents a left join unique_bindings b on b.agent_id=a.id
            left join sli_agent_removals removal on removal.agent_id=a.id
            left join entities_v2 e on e.id=b.entity_id
              and e.entity_type_id=(select id from storage_v2_entity_type where value='ad_computer')
            left join ad_context_entity_aliases guid on guid.entity_id=e.id and guid.alias_type='object_guid'
            left join lateral (
                select version from sli_agent_update_results u where u.agent_id=a.id
                order by observed_at desc,package_sha256,status limit 1
            ) version on true
            where e.id is null or (?::bigint[] is null or e.domain_id=any(?::bigint[]))
            order by a.id,guid.alias_value limit 10001""", (domain_ids, domain_ids), statement_timeout_ms=5000)
    except Exception:  # Optional data must fail closed without source identities in errors.
        return None


def agent_index(agents):
    """Build once per request; checking every AD object must not scan the registry."""
    if agents is None or len(agents) > 10000:
        return {"unavailable": True}
    index = {"by_guid": {}, "by_entity": {}, "unbound": False}
    for row in agents:
        domain = row.get("domain_id")
        guid = str(row.get("object_guid") or "").strip("{}").casefold()
        entity = row.get("entity_id")
        index["unbound"] |= not entity or not guid
        if guid:
            index["by_guid"].setdefault((domain, guid), []).append(row)
        if entity:
            index["by_entity"].setdefault((domain, entity), []).append(row)
    return index


def agent_status(obj, domain_id, agents, *, at=None):
    now = _time(at) or datetime.now(timezone.utc)
    unknown = {"state": "unknown", "version": None, "last_seen_utc": None, "age_seconds": None}
    if at is not None and _time(at) is None:
        return {**unknown, "reason": "historical_registry_unknown"}
    indexed = agents if isinstance(agents, dict) else agent_index(agents)
    if indexed.get("unavailable"):
        return {**unknown, "reason": "registry_unavailable"}
    guid = str(obj.get("object_guid") or "").strip("{}").casefold()
    candidates = [*indexed["by_guid"].get((domain_id, guid), []),
                  *indexed["by_entity"].get((domain_id, obj.get("entity_id")), [])]
    matches = list({id(row): row for row in candidates}.values())
    if len({row.get("entity_id") for row in matches}) > 1:
        return {**unknown, "reason": "ambiguous_binding"}
    if not matches:
        unbound = indexed["unbound"]
        return {**unknown, "state": "unknown" if unbound or not guid else "absent",
                "reason": "unbound_registry" if unbound else "no_registry_match"}
    eligible = [row for row in matches if at is None or (
        _time(row.get("created_at")) and _time(row["created_at"]) <= now and
        _time(row.get("bound_at")) and _time(row["bound_at"]) <= now)]
    if not eligible:
        return {**unknown, "reason": "historical_registry_unknown"}
    present = [row for row in eligible if not (row.get("removal_state") == "state_cleaned"
               and _time(row.get("removed_at")) and _time(row["removed_at"]) <= now)]
    if not present:
        return {**unknown, "state": "absent", "reason": "removal_confirmed"}
    row = max(present, key=lambda row: _time(row.get("last_seen")) or datetime.min.replace(tzinfo=timezone.utc))
    seen = _time(row.get("last_seen"))
    age = int((now - seen).total_seconds()) if seen and seen <= now else None
    return {"state": "silent" if age is not None and age >= SILENT_SECONDS else "installed",
            "version": row.get("version") if at is None else None,
            "last_seen_utc": seen.isoformat() if age is not None else None, "age_seconds": age}


def enrich_computers(items, domain_ids):
    agents = agent_index(load_agents(domain_ids))
    for item in items:
        item["dns_ip"] = dns_observation(item)
        item["sli_agent"] = agent_status(item, item.get("domain_id"), agents)


def _native_workplaces(context, domain_ids, sids):
    """Reuse the workstation report's atomic grants and identity scope adapter."""
    if context is None:
        return []
    from server.sli.plugins.workstations.reports import FIELDS
    from server.sli.plugins.workstations.scope import WorkstationScopeAdapter

    try:
        keys = WorkstationScopeAdapter().agent_keys(context.access, "workstations.logons", context.action, FIELDS)
        if not keys or len(keys) > 500:
            return []
        return query_rows_bounded("""/* ad_report_native_workplaces */
            select distinct on (e.domain_id,lower(o.observation->'facts'->>'relation_account_sid'))
                   e.domain_id,o.observation->'facts'->>'relation_account_sid' as sid,
                   e.display_name as computer_name,e.id as computer_id,
                   null::text as computer_object_guid,o.observed_at as observed_at_utc,
                   o.observation->'facts'->>'logon_type' as logon_type
            from sli_plugin_workstations.observations o
            join entities_v2 e on e.id=o.ad_computer_id
            where o.agent_key=any(?) and o.family='logons' and o.event_id=4624
              and (?::bigint[] is null or e.domain_id=any(?::bigint[]))
              and lower(o.observation->'facts'->>'relation_account_sid')=any(?)
              and o.observation->'facts'->>'logon_type' in ('2','10','11') and o.observed_at<=now()
            order by e.domain_id,lower(o.observation->'facts'->>'relation_account_sid'),o.observed_at desc,o.id desc
            limit 10001""", (list(keys), domain_ids, domain_ids, sids), statement_timeout_ms=5000)
    except Exception:
        return []


def last_workplaces(users, domain_ids, *, context=None):
    """Latest retained interactive observation per exact snapshot account/domain.

    The existing AD logon projection owns the computer match. Its user snapshot
    owns domain scope; duplicate accounts and noninteractive/DC network logons
    cannot become a user's workplace. Missing event facts remain unknown.
    """
    if not users or domain_ids == []:
        return {}
    sids = sorted({str(user.get("sid") or "").casefold() for user in users} - {""})
    if not sids:
        return {}
    try:
        rows = query_rows_bounded("""/* ad_report_last_workplaces */
            select distinct on (s.domain_id,lower(e.target_user_sid))
                   s.domain_id,e.target_user_sid as sid,o.computer_name,o.computer_object_guid,
                   o.observed_at_utc,f.logon_type,o.source_event_id,computer.computer_id
            from what_where_when_observations o
            join users_report_v2_snapshots s on s.snapshot_id=o.user_snapshot_id
            join events_v2_core e on e.id=o.source_event_id and e.domain_id=s.domain_id
            join event_facts_v2 f on f.event_id=o.source_event_id
            left join lateral (
                select min(a.entity_id) as computer_id from ad_context_entity_aliases a
                join entities_v2 c on c.id=a.entity_id and c.domain_id=s.domain_id
                where a.alias_type='object_guid' and lower(a.alias_value)=o.computer_object_guid::text
                having count(distinct a.entity_id)=1
            ) computer on true
            where (?::bigint[] is null or s.domain_id=any(?::bigint[]))
              and lower(e.target_user_sid)=any(?) and f.logon_type in ('2','10','11')
              and o.observed_at_utc<=now()
            order by s.domain_id,lower(e.target_user_sid),o.observed_at_utc desc,o.projection_id desc
            limit 10001""", (domain_ids, domain_ids, sids),
            statement_timeout_ms=5000)
    except Exception:
        rows = []
    if len(rows) > 10000:
        rows = []
    native = _native_workplaces(context, domain_ids, sids)
    if len(native) <= 10000:
        rows.extend(native)
    accounts = {}
    for user in users:
        key = (user.get("domainId"), str(user.get("sid") or "").casefold())
        accounts.setdefault(key, []).append(user.get("entityId"))
    result = {}
    for row in rows:
        key = (row["domain_id"], str(row["sid"]).casefold())
        if len(accounts.get(key, [])) == 1:
            entity_id = accounts[key][0]
            at = _time(row.get("observed_at_utc"))
            previous = _time(result.get(entity_id, {}).get("at_utc"))
            if not at or previous and previous >= at:
                continue
            result[entity_id] = {"computer": row["computer_name"], "computer_id": row.get("computer_id"),
                                       "computer_guid": str(row["computer_object_guid"]) if row.get("computer_object_guid") else None,
                                       "at_utc": at.isoformat(),
                                       "kind": "rdp" if str(row["logon_type"]) == "10" else "local"}
    return result
