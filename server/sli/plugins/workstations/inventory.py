"""WR04 identity union for the internal WS projector, never an access endpoint.

The caller owns the transaction and publication fence (WR05). Returned inventory
is not an access grant: every user-facing read must apply WR03 admission before
rows, pagination or counts. No event payload, name or IP establishes identity.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from ipaddress import ip_address

from server.sli.plugins.workstations.scope import REGISTERED

MAX_INPUT_ROWS = 10_000

DIRECTORY = """
    select e.id as ad_computer_id,e.domain_id,e.display_name,
           v.last_observed_at_utc as metadata_observed_at,
           case when v.id is not null then jsonb_build_object(
               'organizational_unit',v.attributes_json->'attributes'->'organizational_unit',
               'distinguished_name',v.attributes_json->'attributes'->'distinguished_name',
               'operating_system',v.attributes_json->'attributes'->'operating_system',
               'operating_system_version',v.attributes_json->'attributes'->'operating_system_version',
               'ip_addresses',v.attributes_json->'attributes'->'ip_addresses') end as attributes
    from entities_v2_active e
    join storage_v2_entity_type t on t.id=e.entity_type_id and t.value='ad_computer'
    left join ad_context_entity_versions v on v.entity_id=e.id
      and v.valid_to_utc is null and v.source_section='directory_accounts'
    order by e.id limit %s
"""

DEVICES = """
    with registered as (""" + REGISTERED + """), devices as (
        select distinct a.agent_key,a.source_instance_id,r.entity_id,r.display_name
        from registered a join core_entity_scope_resources r
          on r.natural_key=a.identity_key and r.plugin_id='sli.workstations'
         and r.source_instance_id=a.source_instance_id
         and r.entity_type='device' and r.resolution='resolved'
    )
"""


def inventory_source(cur):
    """Read bounded projector inputs in the caller's consistent DB snapshot.

    This internal plugin hook performs no writes, scheduling or source collection.
    Overflow aborts the projection instead of publishing an incomplete population.
    """
    cur.execute("set local statement_timeout = '5000ms'")
    queries = (
        DIRECTORY,
        REGISTERED + " order by agent_key limit %s",
        DEVICES + " select * from devices order by agent_key,entity_id limit %s",
        DEVICES + """ select distinct c.source_entity_id,c.target_entity_id
            from core_entity_associations c
            where c.relation='directory_computer'
              and exists(select 1 from devices d where d.entity_id=c.source_entity_id)
            order by c.source_entity_id,c.target_entity_id limit %s""",
        """select station_id,entity_id,ad_computer_id,agent_key
            from sli_plugin_workstations.station_inventory order by station_id limit %s""",
    )
    inputs = []
    for sql in queries:
        cur.execute(sql, (MAX_INPUT_ROWS + 1,))
        rows = cur.fetchall()
        if len(rows) > MAX_INPUT_ROWS:
            raise ValueError("workstation_inventory_too_large")
        inputs.append(rows)
    return build_inventory(*inputs)


def _index(rows, key):
    result = {}
    for row in rows:
        value = row.get(key)
        if value is None:
            continue
        if value in result and result[value] != row:
            raise ValueError("workstation_inventory_identity_conflict")
        result[value] = row
    return result


def _text(value):
    return (value.strip() or None) if isinstance(value, str) else None


def _station_type(operating_system):
    # These metadata helpers must also work when the optional AD plugin is absent.
    value = str(operating_system or "").strip().casefold()
    if not value or value in {"unknown", "неизвестно"}:
        return "unknown"
    return "server" if "server" in value else "workstation"


def _split_dn(value):
    parts, current = [], []
    escaped = False
    for char in value:
        if char == "," and not escaped:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
        escaped = char == "\\" and not escaped
    if current:
        parts.append("".join(current).strip())
    return parts


def _metadata(computer, display_name):
    raw = computer.get("attributes") if computer else None
    attrs = raw if isinstance(raw, Mapping) else {}
    # Keep a directory reference, including its domain and escaped RDNs. Display
    # captions such as "unknown location" do not belong in identity metadata.
    parent_dn = ",".join(_split_dn(_text(attrs.get("distinguished_name")) or "")[1:]) or None
    addresses = set()
    for value in attrs.get("ip_addresses", []) if isinstance(attrs.get("ip_addresses"), list) else []:
        if isinstance(value, str):
            try:
                addresses.add(str(ip_address(value)))
            except ValueError:
                pass
    return {
        "display_name": _text(display_name),
        "ou_path": _text(attrs.get("organizational_unit")) or parent_dn,
        "operating_system": _text(attrs.get("operating_system")),
        "operating_system_version": _text(attrs.get("operating_system_version")),
        "ip_addresses": sorted(addresses),
    }


def build_inventory(directory, agents, devices, associations, existing=()):
    """Union trusted source rows, resolving only one-to-one explicit links.

    AD-only and agent-only rows remain first-class stations. Repeated identity
    evidence is a set, not another station. Conflicting devices, directory links
    or enrollments are ambiguous; no directory attributes cross that boundary.
    Persisted IDs take precedence over generated IDs, including an agent-only
    station later enriched by AD. If two prior stations join, the directory row
    is canonical; retiring the old projection belongs to fenced publication.
    """
    directory = _index(directory, "ad_computer_id")
    agents = _index(agents, "agent_key")
    previous_ad = _index(existing, "ad_computer_id")
    previous_agent = _index(existing, "agent_key")
    previous_device = _index(existing, "entity_id")
    agent_devices, targets, device_agents = defaultdict(set), defaultdict(set), defaultdict(set)
    names = {}
    for row in devices:
        key, entity = row["agent_key"], row["entity_id"]
        if key in agents and row["source_instance_id"] == agents[key]["source_instance_id"]:
            agent_devices[key].add(entity)
            device_agents[entity].add(key)
            # Resource labels are current entity metadata, never identity keys.
            names[entity] = min(names.get(entity) or _text(row.get("display_name")) or "",
                                _text(row.get("display_name")) or "")
    for row in associations:
        targets[row["source_entity_id"]].add(row["target_entity_id"])

    candidates, states, entities = {}, {}, {}
    for key in agents:
        issued_devices = agent_devices[key]
        entity = next(iter(issued_devices)) if len(issued_devices) == 1 else None
        issued_targets = targets[entity] if entity is not None else set()
        shared_device = len(device_agents[entity]) > 1
        entities[key] = None if shared_device else entity
        ambiguous = len(issued_devices) > 1 or len(issued_targets) > 1 or shared_device
        target = next(iter(issued_targets)) if len(issued_targets) == 1 else None
        states[key] = "ambiguous" if ambiguous else "unlinked"
        if not ambiguous and target in directory:
            candidates[key] = target
    linked_agents = defaultdict(list)
    for key, target in candidates.items():
        linked_agents[target].append(key)
    linked = {}
    for target, keys in linked_agents.items():
        if len(keys) == 1:
            linked[target] = keys[0]
            states[keys[0]] = "unique"
        else:
            for key in keys:
                states[key] = "ambiguous"

    rows, used = [], set()

    def append(computer, key):
        ad_id = computer["ad_computer_id"] if computer else None
        entity = entities[key] if key else None
        prior = previous_ad.get(ad_id)
        if prior is None:
            prior = previous_agent.get(key) or previous_device.get(entity)
            # A previous directory identity stays with its directory station.
            if prior and prior.get("ad_computer_id") not in (None, ad_id):
                prior = None
        generated = f"ws:ad:{ad_id}" if computer else f"ws:agent:{key}"
        station_id = prior["station_id"] if prior else generated
        if station_id in used:
            station_id = generated + ":unlinked"
        if station_id in used:
            raise ValueError("workstation_inventory_identity_conflict")
        used.add(station_id)
        status = states[key] if key else "unlinked"
        metadata = _metadata(computer, computer.get("display_name") if computer else names.get(entity))
        observed = computer.get("metadata_observed_at") if computer else None
        quality = "complete"
        if not observed:
            quality = "not_collected"
        elif not all((metadata["ou_path"], metadata["operating_system"], metadata["ip_addresses"])):
            quality = "partial"
        if status == "ambiguous":
            quality = "partial"
        rows.append({
            "station_id": station_id, "entity_id": entity, "ad_computer_id": ad_id, "agent_key": key,
            "domain_id": computer.get("domain_id") if computer else None, "ou_entity_id": None,
            "station_type": _station_type(metadata["operating_system"]),
            "association_status": status, "metadata": metadata, "metadata_observed_at": observed,
            "quality": {"status": quality, "reasons": []},
        })

    for ad_id, computer in sorted(directory.items()):
        append(computer, linked.get(ad_id))
    for key in sorted(agents.keys() - set(linked.values())):
        append(None, key)
    return sorted(rows, key=lambda row: row["station_id"])
