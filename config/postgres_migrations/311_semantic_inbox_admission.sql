-- Inbox-first historical discovery; preserve function OIDs, owners, ACL and search_path.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_inbox_admission_v311'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'sli_workstation_inventory_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=310 and name='semantic_discovery_streams')
       or exists(select 1 from public.schema_migrations where version>=311)
       or (select proowner from pg_proc where oid='public.t109_detection_sources()'::regprocedure)
          is distinct from 'adlog_storage_owner'::regrole
       or (select proowner from pg_proc where oid='sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure)
          is distinct from 'sli_workstation_inventory_owner'::regrole then
        raise exception 'semantic_inbox_311_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- Build first: entities_v2 writers wait for this index whatever its position.
create index inventory_directory_type_v311 on public.entities_v2(entity_type_id,id);
do $admission$
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
    new_sql text := $new$    -- Fence channel selection and assignment JSON away from receipt lookup.
    -- No history tail: all imported native packets and admitted generations count.
    with assignments as materialized (
        select b.agent_id,b.installation_id,b.source_instance_id,b.source_generation,m->'config' as config
        from public.finding_evidence_source_bindings b
        join public.sli_agents a on a.id=b.agent_id
        cross join lateral jsonb_array_elements(a.assigned_modules) m
        where b.principal_oid=login and b.principal_name=session_user and b.plugin_id='sli.windows.ad-dc'
          and b.storage_kind='core_event' and b.collection_scope_id=''
          and a.status='active' and m->>'module_id'='sli.windows.ad-dc' and m->'enabled'='true'::jsonb
    ), native as materialized (
        select i.packet_id,i.envelope,i.collection_channel
        from public.sli_agent_packet_inbox i
        where i.imported_at is not null
          and i.collection_channel in ('System','Microsoft-Windows-PowerShell/Operational')
    ), matched as materialized (
        select i.packet_id,i.collection_channel,r.agent_id,r.envelope
        from native i cross join lateral (
            -- packet_id is UNIQUE. OFFSET fences the probe even when JSON
            -- selectivity estimates collapse to one row for the whole stream.
            select r.agent_id,r.envelope from public.sli_agent_receipts r
            where r.packet_id=i.packet_id and r.module_id='sli.windows.ad-dc'
              and r.receipt->>'status'='committed' and r.envelope=i.envelope
            offset 0
        ) r
    ), admitted as materialized (
        select distinct b.installation_id,b.source_instance_id,b.source_generation,
            raw.id as raw_id,r.collection_channel
        from matched r join assignments b on b.agent_id=r.agent_id
          and r.envelope->>'source_instance_id'=b.source_instance_id
          and r.envelope->>'generation'=b.source_generation
          and coalesce(b.config#>array['channels',r.collection_channel],'true'::jsonb)='true'::jsonb
        join public.raw_log_files raw on raw.file_path='agent-packet:'||r.packet_id::text
    )
    insert into public.semantic_t109_channels
    select distinct login,session_user,p.installation_id,p.source_instance_id,p.source_generation,
        e.log_source_id,p.collection_channel
    from admitted p cross join lateral (
        select distinct core.log_source_id from public.events_v2_core core
        where core.raw_log_file_id=p.raw_id offset 0
    ) e
    on conflict do nothing;
$new$;
begin
    definition:=pg_get_functiondef('public.t109_detection_sources()'::regprocedure);
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_inbox_311_admission_definition_mismatch' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
end $admission$;
-- Keep the active-entity view and the exact directory limit. EXECUTE plans
-- with the actual catalog type ID on every call: an InitPlan/unknown parameter
-- estimates a common type and scans all entities when computers are rare.
-- Storage owner inherits the existing function owner; no new ACL is needed.
do $directory$
declare definition text; query text; replacement text; first_pos integer; last_pos integer;
    old_prefix text := $old$declare result jsonb;
begin
$old$;
    new_prefix text := $new$declare result jsonb; directory_type integer;
begin
    select t.id into directory_type from public.storage_v2_entity_type t where t.value='ad_computer';
$new$;
    old_join text := $join$        join public.storage_v2_entity_type t on t.id=e.entity_type_id and t.value='ad_computer'
$join$;
    old_filter text := $filter$          and v.valid_to_utc is null and v.source_section='directory_accounts'
$filter$;
    new_filter text := $filter$          and v.valid_to_utc is null and v.source_section='directory_accounts'
        where e.entity_type_id=$1
$filter$;
begin
    definition:=pg_get_functiondef('sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure);
    first_pos:=strpos(definition,'    with directory as materialized (');
    last_pos:=strpos(definition,') into result;');
    if first_pos=0 or last_pos<=first_pos
       or (length(definition)-length(replace(definition,old_prefix,'')))/length(old_prefix)<>1
       or (length(definition)-length(replace(definition,old_join,'')))/length(old_join)<>1
       or (length(definition)-length(replace(definition,old_filter,'')))/length(old_filter)<>1 then
        raise exception 'semantic_inbox_311_directory_definition_mismatch' using errcode='55000';
    end if;
    query:=substr(definition,first_pos,last_pos-first_pos+1);
    replacement:='    execute $directory_query$'||replace(replace(replace(query,
        old_join,''),old_filter,new_filter),'p_domain','$2')
        ||'$directory_query$ into result using directory_type,p_domain;';
    definition:=overlay(definition placing replacement from first_pos
        for last_pos-first_pos+length(') into result;'));
    execute replace(definition,old_prefix,new_prefix);
end $directory$;
set local role adlog_storage_owner;
-- The receipt-stream index encourages receipt-wide traversal and is no
-- longer used by discovery. Keep the selective native inbox index from 310.
-- Drop last: ACCESS EXCLUSIVE on receipts stops agent delivery until commit.
drop index public.semantic_receipt_stream_v310;
insert into public.schema_migrations(version,name) values(311,'semantic_inbox_admission');
reset role;
commit;
