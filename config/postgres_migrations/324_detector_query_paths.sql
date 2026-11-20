-- Online indexes are deliberately outside BEGIN/COMMIT. Both native run_sql
-- (atomic=False for post-baseline files) and the fixture invoke psql -f.
-- A failed build is not attested. On retry an invalid index must be removed
-- with DROP INDEX CONCURRENTLY by the installer before reapplying this file.
begin;
select pg_advisory_xact_lock(hashtext('sli_detector_query_paths_v324'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=323 and name='workstation_projection_drain')
       or exists(select 1 from public.schema_migrations where version>=324) then
        raise exception 'detector_query_paths_324_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create table if not exists public.detector_definitions324(signature text primary key,definition text not null,catalog jsonb not null);
revoke all on public.detector_definitions324 from public,adlog_user,adlog_semantic_worker;
insert into public.detector_definitions324
select oid::regprocedure::text,pg_get_functiondef(oid),to_jsonb(p)-'prosrc'-'provolatile'
from pg_proc p where oid in (
    'public.semantic_source_candidates320(uuid,jsonb,text,text,timestamptz,timestamptz,uuid)'::regprocedure,
    'public.semantic_import_refresh320()'::regprocedure,
    'public.read_account_watch_events(uuid,text,text,text,text,uuid)'::regprocedure,
    'public.semantic_t109_full320()'::regprocedure,
    'public.file_decoy_contexts(uuid,text,text,text)'::regprocedure,
    'sli_plugin_file_audit.collection_context_for_packet(uuid,uuid,timestamptz,timestamptz,jsonb)'::regprocedure,
    'sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure,
    'public.read_workstation_inventory_job_sources_v1()'::regprocedure)
on conflict do nothing;
alter table public.semantic_source_cursor320 add column if not exists pending_after324 bigint not null default 0;
-- Same active-row predicate and security barrier as entities_v2_active, with
-- only the four columns these readers use. Its owners retain view-only access
-- to entities: never grant them SELECT on the underlying identity spine.
create or replace view public.detector_active_entities324 with(security_barrier=true) as
select entity.id,entity.entity_type_id,entity.display_name,entity.domain_id
from public.entities_v2 entity where not exists(
    select 1 from public.entity_identity_merges_v2 merged where merged.source_entity_id=entity.id);
revoke all on public.detector_active_entities324 from public,adlog_user,adlog_semantic_worker;
do $$ declare owner_name name;begin
    for owner_name in select distinct r.rolname from pg_proc p join pg_roles r on r.oid=p.proowner
        where p.oid in ('sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure,
            'public.read_workstation_inventory_job_sources_v1()'::regprocedure) loop
        execute format('grant select on public.detector_active_entities324 to %I',owner_name);
    end loop;
end $$;

do $patch$
declare definition text; first_pos integer; last_pos integer;
    watch_ids text:='4624,4625,4634,4647,4648,4672,4740,4767,4768,4769,4770,4771,4773,4776,4720,4722,4723,4724,4725,4726,4738,4781,4728,4732,4756,4729,4733,4757';
begin
    select d.definition into strict definition from public.detector_definitions324 d where signature='semantic_import_refresh320()';
    if strpos(definition,'7045,4624,4625,4768,4769,4771,4776)')=0 then raise exception 'detector_324_refresh_shape';end if;
    execute replace(definition,'7045,4624,4625,4768,4769,4771,4776)','7045,'||watch_ids||')');
    -- Revisit retained packets in committed PK portions to include watch-only
    -- event IDs. Existing cursors receive new revisions, including late writes.
    update public.semantic_import_state320 set bootstrap_done=false,bootstrap_after=null,bootstrap_packets=0;

    select d.definition into strict definition from public.detector_definitions324 d where signature like 'semantic_source_candidates320(%';
    definition:=replace(definition,'channels_now jsonb;','channels_now jsonb; pending_low bigint; pending_high bigint;');
    definition:=replace(definition,$old$k not in ('native','decoy')$old$,$new$k not in ('native','decoy','watch')$new$);
    definition:=replace(definition,$old$k='decoy' and (octet_length(c)$old$,$new$k in ('decoy','watch') and (octet_length(c)$new$);
    first_pos:=strpos(definition,'    -- A partially populated acceleration structure');
    last_pos:=strpos(definition,'    if reference is not null then');
    if first_pos=0 or last_pos<=first_pos then raise exception 'detector_324_candidates_shape';end if;
    definition:=substr(definition,1,first_pos-1)||$sql$    -- Bootstrap and notifications already retain every packet. Advance a
    -- bounded portion instead of enumerating all retained inbox/core rows per
    -- detector call. Pending/seen remain the acknowledgement authority. Sources
    -- not reached yet are delivered on subsequent cycles, never marked seen.
    if first_at is not null and not (select bootstrap_done from public.semantic_import_state320 where singleton) then
        -- Explicit context is complete even before bootstrap. Push its bounded
        -- time and native event predicates into the indexed packet probe.
        return query select core.id from public.sli_agent_packet_inbox i
        cross join lateral (select e.id from public.events_v2_core e
            where e.raw_log_file_id=(select raw.id from public.raw_log_files raw where raw.file_path='agent-packet:'||i.packet_id::text)
              and e.event_id in (4688,4104,1102,4719,7036,7040,7045)
              and e.time_created_utc between first_at and last_at offset 0) core
        where md5(i.envelope->>'agent_id')=md5(a::text) and i.envelope->>'agent_id'=a::text
          and md5(i.envelope->>'source_instance_id')=md5(s->>'source_instance_id') and i.envelope->>'source_instance_id'=s->>'source_instance_id'
          and md5(i.envelope->>'generation')=md5(s->>'source_generation') and i.envelope->>'generation'=s->>'source_generation';
        return;
    end if;
    if not (select bootstrap_done from public.semantic_import_state320 where singleton) then
        perform public.semantic_import_refresh320();
        select revision into admitted_revision from public.semantic_import_state320 where singleton;
        if k='native' then perform public.semantic_channels_refresh320();end if;
    end if;
$sql$||substr(definition,last_pos);
    definition:=replace(definition,$old$q.kind='decoy'$old$,'q.kind=k');
    definition:=replace(definition,$old$and k='decoy' and q.scope_key=key$old$,$new$and k in ('decoy','watch') and q.scope_key=key$new$);
    -- Keep the original 256 native/decoy slots available. The new family has
    -- its own bounded 256 slots instead of consuming an existing reader's cap.
    definition:=replace(definition,'where q.principal_oid=login and q.principal_name=session_user)>=256',
        'where q.principal_oid=login and q.principal_name=session_user and ((k=''watch'')=(q.kind=''watch'')))>=256');
    definition:=replace(definition,'else f.event_id in(4624,4625,4768,4769,4771,4776) end',
        'when k=''watch'' then f.event_id in('||watch_ids||') else f.event_id in(4624,4625,4768,4769,4771,4776) end');
    -- Keep pending until this checkpoint acknowledges the latest normalized
    -- version; delayed normalization invalidates and revisits its packet.
    definition:=replace(definition,$old$or k='decoy' and not exists($old$,$new$or k in ('decoy','watch') and not exists($new$);
    definition:=replace(definition,'select 1 from public.semantic_account_decoy_checks checks',
        'select 1 from (select checkpoint_key,normalized_event_id from public.semantic_account_decoy_checks where k=''decoy'' union all select checkpoint_key,normalized_event_id from public.semantic_account_watch_checks where k=''watch'') checks');
    -- Unmatched labels are not acknowledgements. Retain their keys, but rotate
    -- bounded pages instead of re-sorting the whole pending history every time.
    -- A later label or recovered native proof can still admit a retained row.
    definition:=replace(definition,E'    delete from public.semantic_source_pending320 p\n    where',
        $sql$    if k='watch' then
        pending_low:=cursor_row.pending_after324;
        select max(page.core_id) into pending_high from (
            select p.core_id from public.semantic_source_pending320 p
            where (p.principal_oid,p.principal_name,p.scope_key,p.kind,p.checkpoint)=(login,session_user,key,k,c)
              and p.core_id>pending_low order by p.core_id limit 4096) page;
        if pending_high is null then
            pending_low:=0;
            select max(page.core_id) into pending_high from (
                select p.core_id from public.semantic_source_pending320 p
                where (p.principal_oid,p.principal_name,p.scope_key,p.kind,p.checkpoint)=(login,session_user,key,k,c)
                  and p.core_id>pending_low order by p.core_id limit 4096) page;
        end if;
    end if;
    delete from public.semantic_source_pending320 p
    where (k<>'watch' or p.core_id>pending_low and p.core_id<=pending_high) and$sql$);
    definition:=replace(definition,'where (p.principal_oid,p.principal_name,p.scope_key,p.kind,p.checkpoint)=(login,session_user,key,k,c);',
        $sql$where (p.principal_oid,p.principal_name,p.scope_key,p.kind,p.checkpoint)=(login,session_user,key,k,c)
          and (k<>'watch' or p.core_id>pending_low and p.core_id<=pending_high);
    if k='watch' then update public.semantic_source_cursor320 q set pending_after324=coalesce(pending_high,0)
        where (q.principal_oid,q.principal_name,q.scope_key,q.kind,q.checkpoint)=(login,session_user,key,k,c);end if;$sql$);
    execute definition;

    select d.definition into strict definition from public.detector_definitions324 d where signature like 'read_account_watch_events(%';
    first_pos:=strpos(definition,'        from public.normalized_events n join public.events_v2_core e');
    last_pos:=strpos(definition,'        join public.storage_v2_channel channel');
    if first_pos=0 or last_pos<=first_pos then raise exception 'detector_324_watch_shape';end if;
    definition:=substr(definition,1,first_pos-1)||$sql$        from public.semantic_source_candidates320(source_binding.agent_id,
            jsonb_build_object('installation_id',p_installation::text,'plugin_id',p_plugin,'source_instance_id',p_source,
                'source_generation',p_generation,'collection_scope_id',''),'watch',p_checkpoint,null,null,p_normalized) candidate_key
        cross join lateral (select core.* from public.events_v2_core core where core.id=candidate_key.id offset 0) e
        cross join lateral (select i.* from public.sli_agent_packet_inbox i where i.packet_id=(
            select substr(raw.file_path,14)::uuid from public.raw_log_files raw where raw.id=e.raw_log_file_id
              and raw.file_path ~ '^agent-packet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') offset 0) inbox
        cross join lateral (select normalized.* from public.normalized_events normalized where normalized.source_event_id=e.id offset 0) n
$sql$||substr(definition,last_pos);
    -- Do not carry source_identity_json and other unused wide columns into the
    -- ordered candidate relation. Every returned field is unchanged.
    definition:=replace(definition,'select n.*,e.event_id',
        'select n.normalized_event_id,n.source_event_id,n.semantic_type,n.occurred_at_utc,n.roles_json,n.quality_json,n.normalized_at,e.event_id');
    execute replace(definition,' STABLE',' VOLATILE');
end $patch$;

-- The historical discovery branch remains complete during bootstrap. Stream
-- exact inbox/receipt probes per assignment; materialize only narrow admitted
-- keys, never 150000 envelope documents twice.
do $patch$
declare definition text; first_pos integer; last_pos integer;
begin
    select d.definition into strict definition from public.detector_definitions324 d where signature='semantic_t109_full320()';
    first_pos:=strpos(definition,'    ), native as materialized (');
    last_pos:=strpos(definition,'    insert into public.semantic_t109_channels');
    if first_pos=0 or last_pos<=first_pos then raise exception 'detector_324_discovery_shape';end if;
    definition:=substr(definition,1,first_pos-1)||$sql$    ), admitted as not materialized (
        select b.installation_id,b.source_instance_id,b.source_generation,raw.id as raw_id,i.collection_channel
        from assignments b cross join lateral (
            select i.packet_id,i.envelope,i.collection_channel from public.sli_agent_packet_inbox i
            where md5(i.envelope->>'source_instance_id')=md5(b.source_instance_id)
              and md5(i.envelope->>'generation')=md5(b.source_generation)
              and i.envelope->>'source_instance_id'=b.source_instance_id
              and i.envelope->>'generation'=b.source_generation
              and i.imported_at is not null
              and i.collection_channel in ('System','Microsoft-Windows-PowerShell/Operational') offset 0
        ) i cross join lateral (
            select 1 from public.sli_agent_receipts r where r.packet_id=i.packet_id
              and r.agent_id=b.agent_id and r.module_id='sli.windows.ad-dc'
              and r.receipt->>'status'='committed' and r.envelope=i.envelope offset 0
        ) r join public.raw_log_files raw on raw.file_path='agent-packet:'||i.packet_id::text
        where coalesce(b.config#>array['channels',i.collection_channel],'true'::jsonb)='true'::jsonb
    )
$sql$||substr(definition,last_pos);
    execute definition;
end $patch$;

-- Only projected columns of the active view are used here. The exact active
-- predicate is retained; omit its unused merged-observation time aggregate.
do $patch$
declare definition text; target_signature text; first_pos integer; last_pos integer;
begin
    foreach target_signature in array array['sli_plugin_workstations.inventory_inputs_v1(bigint)',
        'read_workstation_inventory_job_sources_v1()'] loop
        select d.definition into strict definition from public.detector_definitions324 d where d.signature=target_signature;
        if strpos(definition,'public.entities_v2_active e')=0 then raise exception 'detector_324_directory_shape';end if;
        definition:=replace(definition,'public.entities_v2_active e',
            'public.detector_active_entities324 e');
        if target_signature='sli_plugin_workstations.inventory_inputs_v1(bigint)' then
            -- Classification needs only IDs/domains. Keep the EXACT global
            -- 10001 identity limit, then fetch metadata for this domain only.
            -- Otherwise every job page rebuilds attributes of every other
            -- domain as well. The open-version index guarantees <=1 version.
            first_pos:=strpos(definition,'        select e.id as ad_computer_id,e.domain_id,e.display_name,');
            last_pos:=strpos(definition,'        order by e.id limit 10001');
            if first_pos=0 or last_pos<=first_pos or strpos(definition,
                'own_directory as (select * from directory where $2>0 and domain_id=$2)')=0 then
                raise exception 'detector_324_directory_projection_shape';
            end if;
            definition:=substr(definition,1,first_pos-1)||$sql$        select e.id as ad_computer_id,e.domain_id,e.display_name
        from public.detector_active_entities324 e where e.entity_type_id=$1
$sql$||substr(definition,last_pos);
            definition:=replace(definition,'own_directory as (select * from directory where $2>0 and domain_id=$2)',
                $sql$own_directory as (
        select d.*,v.last_observed_at_utc as metadata_observed_at,
            case when v.id is not null then jsonb_build_object(
                'organizational_unit',v.attributes_json->'attributes'->'organizational_unit',
                'distinguished_name',v.attributes_json->'attributes'->'distinguished_name',
                'operating_system',v.attributes_json->'attributes'->'operating_system',
                'operating_system_version',v.attributes_json->'attributes'->'operating_system_version',
                'ip_addresses',v.attributes_json->'attributes'->'ip_addresses') end as attributes
        from directory d left join public.ad_context_entity_versions v on v.entity_id=d.ad_computer_id
            and v.valid_to_utc is null and v.source_section='directory_accounts'
        where $2>0 and d.domain_id=$2
    )$sql$);
        end if;
        if target_signature='read_workstation_inventory_job_sources_v1()' then
            definition:=replace(definition,'declare d bigint;','declare directory_type integer; d bigint;');
            definition:=replace(definition,'    select array_agg(domain_id order by domain_id) into domains from (',
                $sql$    select id into directory_type from public.storage_v2_entity_type where value='ad_computer';
    execute $domains$select array_agg(domain_id order by domain_id) from ($sql$);
            definition:=replace(definition,$old$join public.storage_v2_entity_type t on t.id=e.entity_type_id and t.value='ad_computer'$old$,'');
            definition:=replace(definition,'where e.domain_id>0','where e.entity_type_id=$1 and e.domain_id>0');
            definition:=replace(definition,'order by domain_id limit 100) q;', 'order by domain_id limit 100) q$domains$ into domains using directory_type;');
        end if;
        execute definition;
    end loop;
    select d.definition into strict definition from public.detector_definitions324 d where d.signature like 'sli_plugin_file_audit.collection_context_for_packet(%';
    definition:=replace(definition,$old$and r.envelope->>'generation'=v_generation and$old$, $new$and md5(r.envelope->>'generation')=md5(v_generation) and r.envelope->>'generation'=v_generation and$new$);
    definition:=replace(definition,$old$where i.envelope->>'agent_id'=p_agent::text and$old$, $new$where md5(i.envelope->>'agent_id')=md5(p_agent::text) and i.envelope->>'agent_id'=p_agent::text and$new$);
    definition:=replace(definition,$old$and i.envelope->>'generation'=v_generation and$old$, $new$and md5(i.envelope->>'generation')=md5(v_generation) and i.envelope->>'generation'=v_generation and$new$);
    execute definition;
end $patch$;

-- Fence the single target PK lookup. Split disjoint boot/handle branches so
-- handle context uses the selective expression index rather than a window scan.
create or replace function public.file_decoy_contexts(p_agent uuid,p_source text,p_generation text,p_native text)
returns jsonb language sql stable set search_path=pg_catalog,pg_temp as $$
    select coalesce(jsonb_agg(q.normalized order by q.record_id),'[]'::jsonb) from (
        select c.normalized,c.record_id from (
            select o.* from sli_plugin_file_audit.observations o
            where o.agent_id=p_agent and o.source_instance_id=p_source and o.generation=p_generation
              and o.evidence_key=p_native and o.event_id=4660 offset 0
        ) o cross join lateral (
            select c.normalized,c.record_id from sli_plugin_file_audit.observations c
            where c.agent_id=o.agent_id and c.source_instance_id=o.source_instance_id and c.generation=o.generation
              and c.policy_revision=o.policy_revision and c.record_id<o.record_id
              and c.observed_at between o.observed_at-interval '300 seconds' and o.observed_at
              and c.event_id in (4608,1102)
            union all
            select c.normalized,c.record_id from sli_plugin_file_audit.observations c
            where c.agent_id=o.agent_id and c.source_instance_id=o.source_instance_id and c.generation=o.generation
              and c.policy_revision=o.policy_revision and c.record_id<o.record_id
              and c.observed_at between o.observed_at-interval '300 seconds' and o.observed_at
              and c.event_id in (4656,4659,4663,4658,4660)
              and pg_catalog.jsonb_hash(c.normalized#>'{facts,subject_user_sid}')=pg_catalog.jsonb_hash(o.normalized#>'{facts,subject_user_sid}')
              and pg_catalog.jsonb_hash(c.normalized#>'{facts,logon_id_numeric}')=pg_catalog.jsonb_hash(o.normalized#>'{facts,logon_id_numeric}')
              and pg_catalog.jsonb_hash(c.normalized#>'{facts,server_process_id}')=pg_catalog.jsonb_hash(o.normalized#>'{facts,server_process_id}')
              and pg_catalog.jsonb_hash(c.normalized#>'{facts,handle_id}')=pg_catalog.jsonb_hash(o.normalized#>'{facts,handle_id}')
              and c.normalized#>'{facts,subject_user_sid}'=o.normalized#>'{facts,subject_user_sid}'
              and c.normalized#>'{facts,logon_id_numeric}'=o.normalized#>'{facts,logon_id_numeric}'
              and c.normalized#>'{facts,server_process_id}'=o.normalized#>'{facts,server_process_id}'
              and c.normalized#>'{facts,handle_id}'=o.normalized#>'{facts,handle_id}'
        ) c order by c.record_id desc limit 129
    ) q
$$;
-- Preserve OIDs/owners/ACLs and every catalog field except reviewed volatility.
do $$ declare r record;begin
    for r in select * from public.detector_definitions324 loop
        if (select to_jsonb(p)-'prosrc'-'provolatile' from pg_proc p where oid=r.signature::regprocedure) is distinct from r.catalog then
            raise exception 'detector_324_catalog_changed: %',r.signature;
        end if;
    end loop;
end $$;
reset role;
commit;

-- Session identity has historical table-owner authority, as in 315. Index
-- ownership follows the table; no runtime privilege or role grant is added.
create index concurrently if not exists detector_receipt_gap324 on public.sli_agent_receipts
    (agent_id,md5(envelope->>'generation'),((envelope->>'sequence')::bigint))
    where module_id='sli.file-audit' and envelope->>'continuity_state'='gap';
create index concurrently if not exists detector_inbox_pending324 on public.sli_agent_packet_inbox
    (md5(envelope->>'agent_id'),md5(envelope->>'generation'),((envelope->>'sequence')::bigint))
    where imported_at is null and envelope->>'module_id'='sli.file-audit';
create index concurrently if not exists detector_file_handle324 on sli_plugin_file_audit.observations
    (agent_id,source_instance_id,generation,policy_revision,
     pg_catalog.jsonb_hash(normalized#>'{facts,subject_user_sid}'),pg_catalog.jsonb_hash(normalized#>'{facts,logon_id_numeric}'),
     pg_catalog.jsonb_hash(normalized#>'{facts,server_process_id}'),pg_catalog.jsonb_hash(normalized#>'{facts,handle_id}'),observed_at,record_id)
    where event_id in (4656,4659,4663,4658,4660);
create index concurrently if not exists detector_file_boundary324 on sli_plugin_file_audit.observations
    (agent_id,source_instance_id,generation,policy_revision,observed_at,record_id) where event_id in (4608,1102);
create index concurrently if not exists detector_directory_domain324 on public.entities_v2(entity_type_id,domain_id,id);
create index concurrently if not exists detector_native_scope324 on public.sli_agent_packet_inbox
    (md5(envelope->>'source_instance_id'),md5(envelope->>'generation'),packet_id)
    where imported_at is not null and collection_channel in ('System','Microsoft-Windows-PowerShell/Operational');
create index concurrently if not exists detector_native_packet324 on public.events_v2_core(raw_log_file_id,time_created_utc,id)
    include(log_source_id,event_id) where event_id in (4688,4104,1102,4719,7036,7040,7045);

begin;
select pg_advisory_xact_lock(hashtext('sli_detector_query_paths_v324'));
set local role adlog_storage_owner;
do $$ begin
    if exists(select 1 from unnest(array['public.detector_receipt_gap324','public.detector_inbox_pending324',
        'sli_plugin_file_audit.detector_file_handle324','sli_plugin_file_audit.detector_file_boundary324',
        'public.detector_directory_domain324','public.detector_native_scope324','public.detector_native_packet324']) name
        left join pg_index i on i.indexrelid=to_regclass(name) where not coalesce(i.indisvalid and i.indisready,false)) then
        raise exception 'detector_324_index_invalid' using errcode='55000';
    end if;
end $$;
insert into public.schema_migrations(version,name) values(324,'detector_query_paths');
reset role;
commit;
