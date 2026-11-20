"""Resolve atomic server grants to registered workstation agents, fail closed."""

from collections.abc import Mapping

from server.sli.access.scope import scope_from_grant
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.reporting.v2.access import report_grant


REGISTERED = """
    select coalesce(a.source_agent_id,a.id)::text as agent_key,a.id::text as transport_agent_id,
           coalesce(a.source_host_id,a.host_id)::text as source_instance_id,
           'core:' || encode(sha256(convert_to(
               '["device","sli.agent.key","agent-registry","' || coalesce(a.source_agent_id,a.id)::text || '"]', 'UTF8')), 'hex') as identity_key
    from sli_agents a
    where a.status<>'replaced' and exists(select 1 from jsonb_array_elements(a.assigned_modules) m
                 where m->>'module_id'='sli.workstations')
"""

# Preserve provenance when following a unique, explicit directory association.
# Names, observation payloads and historical OU membership cannot confer access.
RESOURCES = """
    with registered as (""" + REGISTERED + """), devices as (
        select distinct a.agent_key,a.source_instance_id,r.entity_id,r.device_id,r.collection_scope_id
        from registered a join core_entity_scope_resources r
          on r.natural_key=a.identity_key and r.plugin_id='sli.workstations'
         and r.source_instance_id=a.source_instance_id
         and r.entity_type='device' and r.resolution='resolved'
    ), resources as (
        select a.agent_key,'sli.workstations'::text as plugin_id,a.source_instance_id,
               d.entity_id,d.device_id,d.collection_scope_id,null::text as ou_path,
               null::bigint as ad_computer_id
        from registered a left join devices d on d.agent_key=a.agent_key
        union all
        select d.agent_key,'sli.workstations',d.source_instance_id,
               e.id,e.natural_key,'ad-domain:' || e.domain_id::text,
               v.attributes_json->'attributes'->>'organizational_unit',e.id as ad_computer_id
        from devices d
        join lateral (
            select min(target_entity_id) as target_entity_id
            from core_entity_associations
            where source_entity_id=d.entity_id and relation='directory_computer'
            having count(distinct target_entity_id)=1
        ) association on true
        join entities_v2_active e on e.id=association.target_entity_id
        join storage_v2_entity_type t on t.id=e.entity_type_id and t.value='ad_computer'
        left join ad_context_entity_versions v on v.entity_id=e.id
          and v.source_section='directory_accounts' and v.valid_to_utc is null
        where (select count(distinct own.entity_id) from devices own where own.agent_key=d.agent_key)=1
          and (select count(distinct own.agent_key) from devices own where own.entity_id=d.entity_id)=1
          and not exists(select 1 from devices other join core_entity_associations link
              on link.source_entity_id=other.entity_id and link.relation='directory_computer'
              where link.target_entity_id=e.id and other.agent_key<>d.agent_key)
    )
"""


class WorkstationScopeAdapter:
    """One instance per report request; limitations contain only safe codes/text."""

    def __init__(self):
        self.limitations = []

    def agent_keys(self, access, report_key, action, required_fields):
        self.limitations = []
        report = report_grant(access, report_key)
        if not report or action not in set(report.get("allowed_actions") or []):
            raise PermissionError("report_access_denied")
        eligible = [grant for grant in report.get("grants") or []
                    if action in set(grant.get("allowed_actions") or [])
                    and required_fields.issubset(set(grant.get("field_categories") or []))]
        if not eligible:
            raise PermissionError("report_field_categories_not_allowed")
        predicates, parameters = [], []
        full_scope = False
        for grant in eligible:
            try:
                predicate, values, unrestricted = scope_predicate(grant.get("scope"))
                full_scope |= unrestricted
                predicates.append("(" + predicate + ")")
                parameters.extend(values)
            except (TypeError, ValueError):
                if not self.limitations:
                    self.limitations.append({"code": "workstation_scope_unresolved", "text":
                        "Область одного из разрешений не поддерживается или некорректна; доступ по нему не предоставлен."})
        if not predicates:
            return ()
        # Fetch one overflow key so the report's MAX_STATIONS check cannot be
        # bypassed by silently truncating an otherwise broader agent population.
        from server.sli.plugins.workstations.reports import MAX_STATIONS

        if full_scope:
            sql, parameters = REGISTERED + " order by agent_key limit %s", []
        else:
            sql = RESOURCES + " select distinct r.agent_key from resources r where " + " OR ".join(predicates)
            sql += " order by r.agent_key limit %s"
        with connect() as conn, conn.cursor() as cur:
            cur.execute("set local statement_timeout = '5000ms'")
            cur.execute(sql, (*parameters, MAX_STATIONS + 1))
            return tuple(row["agent_key"] for row in cur.fetchall())

    @staticmethod
    def _strings(values):
        return (isinstance(values, list) and 0 < len(values) <= 100
                and all(isinstance(value, str) and value.strip() == value and 0 < len(value) <= 256 for value in values)
                and len(set(values)) == len(values))


def scope_predicate(raw):
    """Compile one atomic grant against proven resources, never event payloads."""
    if not isinstance(raw, Mapping):
        raise ValueError("invalid_workstation_scope")
    if raw.get("kind") == "agent":
        keys = raw.get("ids")
        if set(raw) != {"kind", "ids"} or not WorkstationScopeAdapter._strings(keys):
            raise ValueError("invalid_agent_scope")
        return "r.agent_key = ANY(%s)", [keys], False
    if raw.get("kind") == "ou":
        paths, domain = raw.get("values"), raw.get("domain_id")
        if (set(raw) != {"kind", "domain_id", "values"} or type(domain) is not int
                or domain <= 0 or not WorkstationScopeAdapter._strings(paths)):
            raise ValueError("invalid_ou_scope")
        return "r.collection_scope_id = %s AND r.ou_path = ANY(%s)", [f"ad-domain:{domain}", paths], False
    scope = scope_from_grant(raw)
    if scope.mode == "none":
        raise ValueError("empty_workstation_scope")
    predicate, values = scope.sql_predicate({
        "plugin_ids": "r.plugin_id", "source_instance_ids": "r.source_instance_id",
        "entity_ids": "r.entity_id", "device_ids": "r.device_id",
        "collection_scope_ids": "r.collection_scope_id",
    })
    return predicate, values, scope.mode == "all"
