
    with registered as (
    select coalesce(a.source_agent_id,a.id)::text as agent_key,a.id::text as transport_agent_id,
           coalesce(a.source_host_id,a.host_id)::text as source_instance_id,
           'core:' || encode(sha256(convert_to(
               '["device","sli.agent.key","agent-registry","' || coalesce(a.source_agent_id,a.id)::text || '"]', 'UTF8')), 'hex') as identity_key
    from sli_agents a
    where a.status<>'replaced' and exists(select 1 from jsonb_array_elements(a.assigned_modules) m
                 where m->>'module_id'='sli.workstations')
), devices as (
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
, station_resources as (
    select i.station_id,r.agent_key,r.plugin_id,r.source_instance_id,r.entity_id,r.device_id,
           case when i.ad_computer_id is not null then 'ad-domain:'||i.domain_id::text
                else r.collection_scope_id end as collection_scope_id,
           r.ou_path,r.ad_computer_id
    from sli_plugin_workstations.station_inventory i
      join resources r on r.agent_key=i.agent_key
    where (i.entity_id is null or exists(select 1 from devices d
               where d.agent_key=i.agent_key and d.entity_id=i.entity_id))
      and ((i.ad_computer_id is null and i.domain_id is null
            and not exists(select 1 from resources current_binding
                where current_binding.agent_key=i.agent_key and current_binding.ad_computer_id is not null))
        or exists(select 1 from resources current_binding
            where current_binding.agent_key=i.agent_key
              and current_binding.ad_computer_id=i.ad_computer_id
              and current_binding.collection_scope_id='ad-domain:'||i.domain_id::text))
    union all
    select i.station_id,null::text as agent_key,'sli.workstations'::text as plugin_id,
           null::text as source_instance_id,e.id as entity_id,e.natural_key as device_id,
           'ad-domain:' || e.domain_id::text as collection_scope_id,
           v.attributes_json->'attributes'->>'organizational_unit' as ou_path,e.id as ad_computer_id
    from sli_plugin_workstations.station_inventory i
    join entities_v2_active e on e.id=i.ad_computer_id
    join storage_v2_entity_type t on t.id=e.entity_type_id and t.value='ad_computer'
    left join ad_context_entity_versions v on v.entity_id=e.id
      and v.source_section='directory_accounts' and v.valid_to_utc is null
    where i.agent_key is null and i.domain_id=e.domain_id
)
