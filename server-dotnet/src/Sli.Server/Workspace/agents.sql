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
