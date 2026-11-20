-- Preserve source authority and results while indexing historical discovery.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_discovery_streams_v310'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=310 and name='semantic_discovery_streams')
       or exists(select 1 from public.schema_migrations where version>310)
       or (select proowner from pg_proc where oid='public.t109_detection_sources()'::regprocedure)
          is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_discovery_310_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- CREATE OR REPLACE preserves OID, owner, ACL, definer and search_path.
do $patch$
declare definition text;
    old_sql text := $old$    -- Materialize admission before probing retained core, so a large core or
    -- an empty native packet cannot cause a global events scan. No tail limit:
    -- every previously eligible historical generation remains discoverable.
    with admitted as materialized (
        select distinct b.installation_id,b.source_instance_id,b.source_generation,
            raw.id as raw_id,i.collection_channel
        from public.finding_evidence_source_bindings b
        join public.sli_agents a on a.id=b.agent_id
        cross join lateral jsonb_array_elements(a.assigned_modules) m
        join public.sli_agent_receipts r on r.agent_id=a.id and r.module_id='sli.windows.ad-dc'
            and r.envelope->>'source_instance_id'=b.source_instance_id
            and r.envelope->>'generation'=b.source_generation
        join public.sli_agent_packet_inbox i using(packet_id)
        join public.raw_log_files raw on raw.file_path='agent-packet:'||r.packet_id::text
        where b.principal_oid=login and b.principal_name=session_user and b.plugin_id='sli.windows.ad-dc'
          and b.storage_kind='core_event' and b.collection_scope_id=''
          and a.status='active' and m->>'module_id'='sli.windows.ad-dc' and m->'enabled'='true'::jsonb
          and i.collection_channel in ('System','Microsoft-Windows-PowerShell/Operational')
          and coalesce(m#>array['config','channels',i.collection_channel],'true'::jsonb)='true'::jsonb
          and r.receipt->>'status'='committed' and i.imported_at is not null and i.envelope=r.envelope
    )
    insert into public.semantic_t109_channels
    select distinct login,session_user,p.installation_id,p.source_instance_id,p.source_generation,
        e.log_source_id,p.collection_channel
    from admitted p cross join lateral (
        select distinct core.log_source_id from public.events_v2_core core
        where core.raw_log_file_id=p.raw_id offset 0
    ) e
    on conflict do nothing;
$old$;
    new_sql text := $new$    insert into public.semantic_t109_channels
    select distinct login,session_user,b.installation_id,b.source_instance_id,b.source_generation,
        e.log_source_id,i.collection_channel
    from public.finding_evidence_source_bindings b join public.sli_agents a on a.id=b.agent_id
    cross join lateral jsonb_array_elements(a.assigned_modules) m
    join public.sli_agent_receipts r on r.agent_id=a.id and r.module_id='sli.windows.ad-dc'
    join public.sli_agent_packet_inbox i using(packet_id)
    join public.raw_log_files raw on raw.file_path='agent-packet:'||r.packet_id::text
    join public.events_v2_core e on e.raw_log_file_id=raw.id
    where b.principal_oid=login and b.principal_name=session_user and b.plugin_id='sli.windows.ad-dc'
      and b.storage_kind='core_event' and b.collection_scope_id=''
      and a.status='active' and m->>'module_id'='sli.windows.ad-dc' and m->'enabled'='true'::jsonb
      and i.collection_channel in ('System','Microsoft-Windows-PowerShell/Operational')
      and coalesce(m#>array['config','channels',i.collection_channel],'true'::jsonb)='true'::jsonb
      and r.receipt->>'status'='committed' and i.imported_at is not null and i.envelope=r.envelope
      and r.envelope->>'source_instance_id'=b.source_instance_id and r.envelope->>'generation'=b.source_generation
    on conflict do nothing;
$new$;
begin
    definition:=pg_get_functiondef('public.t109_detection_sources()'::regprocedure);
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_discovery_310_rollback_definition_mismatch' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
end $patch$;
drop index public.semantic_native_inbox_v310;
drop index public.semantic_receipt_stream_v310;
delete from public.schema_migrations where version=310 and name='semantic_discovery_streams';
reset role;
commit;
