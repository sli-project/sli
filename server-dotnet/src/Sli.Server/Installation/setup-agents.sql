with latest_audit as materialized (
    -- Read the journal once for the whole registry, rather than once per agent
    -- and per action. Policy acknowledgements already have a target index.
    select distinct on (target,action) target,action,id,occurred_at,details
    from sli_agent_audit
    where action in ('issue','sequence_gap_accepted')
       or action='disable' and details->>'reason'='registration_replaced'
    order by target,action,id desc
), enrollment as materialized (
    select distinct on (issued.target) issued.target,d.fqdn,
        coalesce(nullif(btrim(v.attributes_json->'attributes'->>'dns_host_name'),''),
                 nullif(btrim(v.attributes_json->'attributes'->>'display_name'),'')) as host_name
    from sli_agent_audit issued
    join sli_agent_group_approval_links c on issued.actor='enrollment:' || c.enrollment_token_id::text
    join sli_agent_group_requests r on r.id=c.request_id
    join ad_context_entity_versions v on v.id=r.computer_version_id
    join sli_agent_group_tokens t on t.id=r.token_id
    join domains d on d.id=t.domain_id
    where issued.action='issue'
    order by issued.target,issued.id desc
)
select a.id::text, a.host_id::text, a.instance_name, a.status, a.last_seen,
       a.created_at, a.assigned_modules, a.collection_policy, a.registration_host_name,
       a.policy_revision, a.applied_policy_revision, a.applied_collection_state,
       a.windows_audit, a.rights_probe->'eventlog_diagnostics' as eventlog_diagnostics,
       dc.id as server_id,dc.hostname as canonical_host_name,a.rights_probe ? 'identity_conflict' as identity_conflict,
       coalesce(a.rights_probe->>'agent_version',version.version,issued_version.details->>'agent_version') as agent_version,
       exists(select 1 from sli_agent_certificates c where c.agent_id=a.id and c.revoked_at is null
           and c.not_before<=clock_timestamp() and c.not_after>clock_timestamp())
           and not exists(select 1 from sli_agent_removals r where r.agent_id=a.id) as can_restore,
       retired.details->>'replaced_by' as replaced_by,
       coalesce((a.rights_probe->>'certificate_reissue_required')::boolean,false) as certificate_reissue_required,
       (select coalesce(jsonb_agg(jsonb_build_object('module_id',b.module_id,'source_name',b.source_name)), '[]'::jsonb)
        from sli_agent_module_bindings b where b.agent_id=a.id) as source_bindings,
       ack.occurred_at as policy_applied_at, enrolled.fqdn as domain, enrolled.host_name,
       exists(select 1 from sli_agent_module_bindings b where b.agent_id=a.id
           and b.module_id='sli.windows.ad-dc' and b.password_detection_domain_id is null
           and a.status='active' and exists(select 1 from jsonb_array_elements(a.assigned_modules) m
               where m->>'module_id'=b.module_id and m->'enabled'='true'::jsonb)) as password_domain_required,
       gap.occurred_at as last_accepted_gap_at, a.packet_expiry,
       (select max(t) from (select max(received_at) t from sli_agent_receipts where agent_id=a.id and module_id<>'sli.heartbeat'
           union all select max(received_at) from sli_agent_stream_receipts
               where agent_id=a.id and module_id<>'sli.heartbeat') packets) as last_packet_at
from sli_agents a
left join latest_audit issued_version on issued_version.target=a.id::text and issued_version.action='issue'
left join latest_audit retired on retired.target=a.id::text and retired.action='disable'
left join latest_audit gap on gap.target=a.id::text and gap.action='sequence_gap_accepted'
left join enrollment enrolled on enrolled.target=a.id::text
left join lateral (
    select b.source_name from sli_agent_module_bindings b where b.agent_id=a.id and b.module_id='sli.windows.ad-dc'
) binding on true
left join lateral (
    select min(s.id) as id,min(s.hostname) as hostname from servers s
    where s.role='domain_controller' and s.is_active and binding.source_name is not null and coalesce(
        s.id::text=issued_version.details->>'server_id', (
        lower(coalesce(binding.source_name,a.registration_host_name)) in (lower(s.hostname),lower(s.fqdn))
        or strpos(coalesce(binding.source_name,a.registration_host_name),'.')=0
            and lower(coalesce(binding.source_name,a.registration_host_name))=split_part(lower(coalesce(nullif(s.fqdn,''),s.hostname)),'.',1)
        or strpos(coalesce(nullif(s.fqdn,''),s.hostname),'.')=0
            and lower(s.hostname)=split_part(lower(coalesce(binding.source_name,a.registration_host_name)),'.',1)))
    having count(*)=1
) dc on true
left join lateral (select version from sli_agent_update_results where agent_id=a.id order by observed_at desc limit 1) version on true
left join lateral (
    select occurred_at from sli_agent_audit
    where target=a.id::text and action='policy_ack'
      and details->>'revision'=a.policy_revision::text
    order by id desc limit 1
) ack on true
order by a.created_at, a.id
