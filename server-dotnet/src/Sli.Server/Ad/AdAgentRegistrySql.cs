namespace Sli.Server.Ad;
internal static class AdAgentRegistrySql
{
    internal const string Bindings = """
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
""";
    internal const string Read = "/* ad_report_agent_registry */ " + Bindings + """

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
            where e.id is null or ($1::bigint[] is null or e.domain_id=any($2::bigint[]))
            order by a.id,guid.alias_value limit 10001
""";
}
