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
                   guid.alias_value as object_guid,
                   coalesce(nullif(a.rights_probe->>'agent_version',''),version.version,issued.version) as version
            from sli_agents a left join unique_bindings b on b.agent_id=a.id
            left join sli_agent_removals removal on removal.agent_id=a.id
            left join lateral (
                select details->>'agent_version' as version,details->>'server_id' as server_id
                from sli_agent_audit where target=a.id::text and action='issue' order by id desc limit 1
            ) issued on true
            left join lateral (
                select s.domain_id from sli_agent_audit recorded join servers s on s.id::text=recorded.details->>'server_id'
                where recorded.target=a.id::text and recorded.action='module_assign'
                  and recorded.actor='system:agent-registration' and recorded.details->>'module_id'='sli.windows.ad-dc'
                order by recorded.id desc limit 1
            ) registered_dc on true
            left join servers pinned_dc on pinned_dc.id::text=issued.server_id
            left join sli_agent_snapshot_bindings snapshot on snapshot.agent_id=a.id and snapshot.module_id='sli.ad-snapshot'
            left join domains snapshot_domain on snapshot_domain.domain_sid=snapshot.domain_sid and not snapshot_domain.is_archived
            cross join lateral (
                select lower(rtrim(btrim(a.registration_host_name),'.$')) as host,
                       coalesce(snapshot_domain.id,registered_dc.domain_id,pinned_dc.domain_id) as domain_id
            ) registration
            left join lateral (
                select min(computer.id) as entity_id
                from entities_v2 computer
                join domains d on d.id=computer.domain_id and not d.is_archived
                join storage_v2_entity_type t on t.id=computer.entity_type_id and t.value='ad_computer'
                left join ad_context_entity_versions v on v.entity_id=computer.id
                  and v.source_section='directory_accounts' and v.valid_to_utc is null
                left join ad_context_entity_aliases sam on sam.entity_id=computer.id and sam.domain_id=d.id
                  and sam.alias_type='sam_account_name' and sam.normalized_value=split_part(registration.host,'.',1)||'$'
                cross join lateral (select lower(rtrim(v.attributes_json->'attributes'->>'dns_host_name','.')) as dns) host
                where b.entity_id is null and not exists(select 1 from bindings known where known.agent_id=a.id)
                  and registration.host <> '' and a.status <> 'replaced'
                  and (registration.domain_id is null or registration.domain_id=d.id)
                  and (
                    (strpos(registration.host,'.') > 0 and host.dns=registration.host)
                    or ((registration.host=split_part(registration.host,'.',1)||'.'||lower(d.fqdn)
                         or (registration.domain_id=d.id and strpos(registration.host,'.')=0))
                        and (sam.entity_id is not null or split_part(host.dns,'.',1)=registration.host))
                  )
                having count(distinct computer.id)=1
            ) by_name on true
            left join entities_v2 e on e.id=coalesce(b.entity_id,by_name.entity_id)
              and e.entity_type_id=(select id from storage_v2_entity_type where value='ad_computer')
            left join ad_context_entity_aliases guid on guid.entity_id=e.id and guid.domain_id=e.domain_id and guid.alias_type='object_guid'
            left join lateral (
                select version from sli_agent_update_results u where u.agent_id=a.id
                order by observed_at desc,package_sha256,status limit 1
            ) version on true
            where e.id is null or ($1::bigint[] is null or e.domain_id=any($2::bigint[]))
            order by a.id,guid.alias_value limit 10001
""";
}
