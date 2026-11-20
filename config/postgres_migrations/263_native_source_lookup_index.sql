-- Bounded committed source discovery; no policy, source or historical-data edits.
begin;
select pg_advisory_xact_lock(hashtext('sli_native_source_lookup_index_v263'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=262 and name='default_native_detections')
       or exists(select 1 from public.schema_migrations where version>=263) then
        raise exception 'migration 263 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;
create index events_v2_core_raw_packet_lookup on public.events_v2_core(raw_log_file_id,id) include(log_source_id);

create or replace function public.default_detection_sources() returns table(source jsonb)
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare login oid; installation uuid; core_sources jsonb; missing_core_scopes integer;
begin
    select oid into strict login from pg_catalog.pg_roles where rolname=session_user;
    select installation_id into strict installation from public.semantic_default_installation;
    -- Limit the receipt PK tail before joining the large inbox. An empty
    -- metadata receipt anchors the current generation, not the core witness.
    with recent as materialized (
        select module.agent_id,module.module_id,module.source_instance_id,
               receipt.packet_id,receipt.envelope,receipt.receipt,receipt.sequence
        from public.sli_agent_module_bindings module
        join public.sli_agents agent on agent.id=module.agent_id and agent.status='active'
        cross join lateral (
            select r.packet_id,r.envelope,r.receipt,r.sequence
            from public.sli_agent_receipts r
            where r.agent_id=module.agent_id and r.module_id=module.module_id
            order by r.sequence desc limit 128
        ) receipt
        where module.module_id in ('sli.windows.ad-dc','sli.vpn-nps')
          and exists(select 1 from jsonb_array_elements(agent.assigned_modules) m
              where m->>'module_id'=module.module_id and m->'enabled'='true'::jsonb)
    ), eligible as materialized (
        select r.*,inbox.packet#>>'{header,channel}' as native_channel from recent r
        join public.sli_agent_packet_inbox inbox using(packet_id)
        where r.envelope->>'source_instance_id'=r.source_instance_id
          and r.receipt->>'status'='committed' and inbox.imported_at is not null
          and inbox.envelope=r.envelope
    ), current_scope as (
        select distinct on(agent_id,module_id) agent_id,module_id,source_instance_id,
               envelope->>'generation' as generation
        from eligible order by agent_id,module_id,sequence desc
    ), witnessed as (
        select current.*,event.log_source_id
        from current_scope current
        -- Retained evidence refers to this exact stream. Prove it again in
        -- the current bounded tail; never rewrite it to a different channel.
        left join public.finding_evidence_source_bindings retained
          on retained.principal_oid=login and retained.principal_name=session_user
         and retained.installation_id=installation and retained.agent_id=current.agent_id
         and retained.plugin_id=current.module_id and retained.source_instance_id=current.source_instance_id
         and retained.source_generation=current.generation and retained.collection_scope_id=''
         and retained.storage_kind='core_event'
        left join lateral (
            select core.log_source_id from eligible witness
            cross join lateral (
                select e.log_source_id from public.raw_log_files raw
                join public.events_v2_core e on e.raw_log_file_id=raw.id
                where raw.file_path='agent-packet:'||witness.packet_id::text
                  and e.log_source_id is not null
                order by e.id limit 1
            ) core
            where witness.agent_id=current.agent_id and witness.module_id=current.module_id
              and witness.source_instance_id=current.source_instance_id
              and witness.envelope->>'generation'=current.generation
              -- The native AD/NPS v1 detectors read Security. This header
              -- comes from the committed/imported, envelope-matched inbox.
              and witness.native_channel='Security'
              and (retained.log_source_id is null or core.log_source_id=retained.log_source_id)
            order by witness.sequence desc limit 1
        ) event on true
    )
    select coalesce(jsonb_agg(jsonb_build_object('agent_id',agent_id,'plugin_id',module_id,
               'source_instance_id',source_instance_id,'source_generation',generation,
               'log_source_id',log_source_id)) filter(where log_source_id is not null),'[]'::jsonb),
           count(*) filter(where log_source_id is null)
    into core_sources,missing_core_scopes from witnessed;
    if missing_core_scopes>0 then
        -- A fixed diagnostic only: never disclose source identities or packet data.
        raise notice 'default_detection_core_witness_unavailable: %',missing_core_scopes;
    end if;

    insert into public.finding_evidence_source_bindings
        (principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,
         collection_scope_id,storage_kind,log_source_id,agent_id)
    select login,session_user,installation,source.plugin_id,source.source_instance_id,
           source.source_generation,'','core_event',source.log_source_id,source.agent_id
    from jsonb_to_recordset(core_sources) source(agent_id uuid,plugin_id text,source_instance_id text,
         source_generation text,log_source_id bigint)
    where not exists(select 1 from public.finding_evidence_source_bindings b
        where b.principal_oid=login and b.principal_name=session_user and b.plugin_id=source.plugin_id
          and b.source_instance_id=source.source_instance_id and b.source_generation=source.source_generation
          and b.collection_scope_id='' and b.storage_kind='core_event')
    on conflict do nothing;

    insert into public.finding_evidence_source_bindings
        (principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,
         collection_scope_id,storage_kind,agent_id)
    select distinct login,session_user,installation,'sli.file-audit',o.source_instance_id,o.generation,
           root->>'collection_scope_id','file_audit_observation',agent.id
    from public.sli_agents agent
    cross join lateral jsonb_array_elements(agent.assigned_modules) m
    cross join lateral jsonb_array_elements(m#>'{config,roots}') root
    cross join lateral (
        select obs.source_instance_id,obs.generation from sli_plugin_file_audit.observations obs
        join public.sli_agent_receipts r on r.agent_id=obs.agent_id
            and r.envelope->>'source_instance_id'=obs.source_instance_id
            and r.envelope->>'generation'=obs.generation
        join public.sli_agent_packet_inbox inbox on inbox.packet_id=r.packet_id
        where obs.agent_id=agent.id and obs.collection_scope_id=root->>'collection_scope_id'
          and r.module_id='sli.file-audit' and r.receipt->>'status'='committed'
          and inbox.imported_at is not null and inbox.envelope=r.envelope
          and obs.policy_revision=coalesce(m#>>'{config,policy_revision}','1')::bigint
        order by r.sequence desc limit 1
    ) o
    where agent.status='active' and m->>'module_id'='sli.file-audit' and m->'enabled'='true'::jsonb
      and not exists(select 1 from public.finding_evidence_source_bindings b
          where b.principal_oid=login and b.principal_name=session_user and b.plugin_id='sli.file-audit'
            and b.source_instance_id=o.source_instance_id and b.source_generation=o.generation
            and b.collection_scope_id=root->>'collection_scope_id' and b.storage_kind='file_audit_observation')
    on conflict do nothing;

    return query
    select jsonb_build_object('scope',jsonb_build_object('installation_id',b.installation_id::text,
        'plugin_id',b.plugin_id,'source_instance_id',b.source_instance_id,
        'source_generation',b.source_generation,'collection_scope_id',b.collection_scope_id),
        'agent_id',b.agent_id::text,'config',coalesce(m->'config','{}'::jsonb))
    from public.finding_evidence_source_bindings b
    join public.sli_agents agent on agent.id=b.agent_id and agent.status='active'
    cross join lateral jsonb_array_elements(agent.assigned_modules) m
    where b.principal_oid=login and b.principal_name=session_user
      and m->>'module_id'=b.plugin_id and m->'enabled'='true'::jsonb
      and (b.storage_kind='core_event' and exists(
              select 1 from jsonb_to_recordset(core_sources) current_source(agent_id uuid,plugin_id text,
                  source_instance_id text,source_generation text,log_source_id bigint)
              where current_source.agent_id=b.agent_id and current_source.plugin_id=b.plugin_id
                and current_source.source_instance_id=b.source_instance_id
                and current_source.source_generation=b.source_generation
                and current_source.log_source_id=b.log_source_id)
          or b.storage_kind='file_audit_observation'
          and exists(select 1 from jsonb_array_elements(m#>'{config,roots}') root
              where root->>'collection_scope_id'=b.collection_scope_id))
    order by b.plugin_id,b.source_instance_id,b.source_generation,b.collection_scope_id limit 128;
end $$;
revoke all on function public.default_detection_sources() from public;
grant execute on function public.default_detection_sources() to adlog_semantic_worker;

insert into public.schema_migrations(version,name) values(263,'native_source_lookup_index');
commit;
