"""Bounded display-only names for identities already authorized by the caller."""
from __future__ import annotations

import re
from uuid import UUID

# Same immutable enrollment-to-AD evidence chain as collection_health. Names
# describe the registered computer, not a fresh AD observation or an ACL grant.
_NAMES_SQL = """
select a.id::text as agent_id, a.assigned_modules, enrolled.host_name as enrolled_name
from sli_agents a
left join lateral (
    select coalesce(nullif(btrim(v.attributes_json->'attributes'->>'dns_host_name'),''),
                    nullif(btrim(v.attributes_json->'attributes'->>'display_name'),'')) as host_name
    from sli_agent_audit issued
    join sli_agent_group_approval_links c on issued.actor='enrollment:' || c.enrollment_token_id::text
    join sli_agent_group_requests r on r.id=c.request_id
    join ad_context_entity_versions v on v.id=r.computer_version_id
    where issued.target=a.id::text and issued.action='issue'
    order by issued.id desc limit 1
) enrolled on true
where a.id::text = any(%s)
"""


def human_host_name(value):
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if value.lower() in {"localhost", "unknown"}:
        return None
    try:
        UUID(value)
    except ValueError:
        return value
    return None


def reported_hostname(value):
    """Unverified display claim only; malformed optional metadata is absent."""
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        return None
    if value.lower() in {"localhost", "localhost.localdomain", "unknown"}:
        return None
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", value):
        return None
    if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
           for label in value.split(".")):
        return None
    try:
        UUID(value)
    except ValueError:
        return value
    return None


def read_agent_names(cur, agent_ids):
    # Existing report readers have no provenance UI. Do not silently introduce
    # a self-reported claim into their plain-name contract.
    return {key: item["name"] for key, item in _read_names(cur, agent_ids, reported=False).items()}


def read_agent_name_details(cur, agent_ids):
    return _read_names(cur, agent_ids, reported=True)


def _read_names(cur, agent_ids, *, reported):
    """No discovery: callers supply at most 500 already-authorized agent IDs."""
    keys = list(dict.fromkeys(str(key) for key in agent_ids))
    if len(keys) > 500:
        raise ValueError("agent_name_lookup_limit")
    if not keys:
        return {}
    sql = (_NAMES_SQL.replace("a.assigned_modules,", "a.assigned_modules, a.registration_host_name,")
           if reported else _NAMES_SQL)
    cur.execute(sql, (keys,))
    names = {}
    for row in cur.fetchall():
        name = human_host_name(row["enrolled_name"])
        source = "ad_enrollment" if name else "unknown"
        if name is None and reported:
            name = reported_hostname(row.get("registration_host_name"))
            if name:
                source = "agent_reported"
        if name is None:
            candidates = {name for module in row["assigned_modules"] or []
                          if isinstance(module, dict)
                          and module.get("module_id") in {"sli.windows.ad-dc", "sli.workstations"}
                          and isinstance(module.get("config"), dict)
                          if (name := human_host_name(module["config"].get("source_name")))}
            name = next(iter(candidates)) if len(candidates) == 1 else None
            if name:
                source = "module_config"
        names[row["agent_id"]] = {"name": name, "source": source}
    return names
