-- Receipt-led NPS reads; reuse the existing (agent_id,module_id,sequence) PK
-- backwards and the inbox packet_id PK. No extra index, payload or disk build.
begin;
select pg_advisory_xact_lock(hashtext('sli_nps_threshold_paths_v326'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=325 and name='t109_workstation_path')
       or exists(select 1 from public.schema_migrations where version>=326)
       or exists(select 1 from pg_proc where oid in (
            'public.nps_threshold_watermark(uuid,text,text,text,timestamptz)'::regprocedure,
            'public.nps_threshold_window_quality(uuid,text,text,text,timestamptz,timestamptz,timestamptz)'::regprocedure)
            and proowner<>'adlog_storage_owner'::regrole) then
        raise exception 'nps_threshold_326_preflight' using errcode='55000';
    end if;
    -- Attest the reusable access paths, just as 324/325 attest online builds.
    if exists(select 1 from unnest(array['public.sli_agent_receipts_pkey','public.sli_agent_packet_inbox_pkey',
            'public.sli_agent_packet_inbox_pending']) idx
        where not exists(select 1 from pg_index where indexrelid=to_regclass(idx) and indisvalid and indisready)) then
        raise exception 'nps_threshold_326_index_invalid' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.nps_threshold_definitions326(signature text primary key,definition text not null,catalog jsonb not null);
revoke all on public.nps_threshold_definitions326 from public,adlog_user,adlog_semantic_worker;
insert into public.nps_threshold_definitions326
select oid::regprocedure::text,pg_get_functiondef(oid),to_jsonb(p)-'prosrc'
from pg_proc p where oid in (
    'public.nps_threshold_watermark(uuid,text,text,text,timestamptz)'::regprocedure,
    'public.nps_threshold_window_quality(uuid,text,text,text,timestamptz,timestamptz,timestamptz)'::regprocedure);

create or replace function public.nps_threshold_watermark(p_installation uuid,p_plugin text,p_source text,p_generation text,p_now timestamptz)
returns timestamptz language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select coalesce((inbox.packet#>>'{header,observed_at_utc}')::timestamptz,
                    (inbox.packet#>>'{continuity,to_utc}')::timestamptz)
    from public.finding_evidence_source_bindings b join pg_catalog.pg_roles r
        on r.oid=b.principal_oid and r.rolname=b.principal_name
        cross join lateral (
            -- Backward receipt PK walk. OFFSET 0 keeps the inbox probe on the
            -- inner side: one packet_id lookup per candidate, never a JSON join
            -- over every agent's inbox. LIMIT counts accepted packets only.
            select probe.packet,probe.received_at,receipt.sequence
            from public.sli_agent_receipts receipt
            cross join lateral (
                select i.packet,i.received_at
                from public.sli_agent_packet_inbox i
                where i.packet_id=receipt.packet_id and i.imported_at is not null
                  and i.envelope=receipt.envelope and i.envelope->>'agent_id'=b.agent_id::text
                  and i.envelope->>'source_instance_id'=p_source and i.envelope->>'generation'=p_generation
                  and coalesce((i.packet#>>'{header,observed_at_utc}')::timestamptz,
                               (i.packet#>>'{continuity,to_utc}')::timestamptz)<=p_now
                offset 0
            ) probe
            where receipt.agent_id=b.agent_id and receipt.module_id=p_plugin
              and receipt.receipt->>'status'='committed'
            order by receipt.sequence desc limit 1
        ) inbox
    where r.rolname=session_user and b.installation_id=p_installation and b.plugin_id=p_plugin
      and b.source_instance_id=p_source and b.source_generation=p_generation and b.collection_scope_id=''
      and b.storage_kind='core_event'
    order by inbox.sequence desc limit 1
$$;

create or replace function public.nps_threshold_window_quality(
    p_installation uuid,p_plugin text,p_source text,p_generation text,
    p_from timestamptz,p_to timestamptz,p_now timestamptz
) returns text language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare covered tstzmultirange; latest timestamptz;
    binding record; candidate record; packet_row record;
    after_sequence bigint; page_count integer; accepted integer:=0;
    intervals tstzrange[]:='{}';
begin
    if p_from is null or p_to is null or p_now is null or p_from>=p_to or p_to>p_now
       or p_to-p_from>interval '1 hour'
       or public.finding_evidence_scope_allowed(p_installation,p_plugin,p_source,p_generation,'','core_event') is not true then
        raise exception 'nps_threshold_source_denied' using errcode='42501';
    end if;
    -- The SQL planner may sort every candidate before LIMIT after joining
    -- payloads (even with LATERAL). Page the receipt PK BEFORE inbox lookups;
    -- a rejected receipt never consumes one of the 64 accepted packet slots.
    for binding in
        select b.agent_id
        from public.finding_evidence_source_bindings b join pg_catalog.pg_roles r
            on r.oid=b.principal_oid and r.rolname=b.principal_name
        where r.rolname=session_user and b.installation_id=p_installation and b.plugin_id=p_plugin
          and b.source_instance_id=p_source and b.source_generation=p_generation and b.collection_scope_id=''
          and b.storage_kind='core_event'
    loop
        after_sequence:=null;
        loop
            page_count:=0;
            for candidate in execute $receipts$
                select receipt.packet_id,receipt.envelope,receipt.receipt,receipt.sequence
                from public.sli_agent_receipts receipt
                where receipt.agent_id=$1 and receipt.module_id=$2
                  and ($3 is null or receipt.sequence<$3)
                order by receipt.sequence desc limit 256
            $receipts$ using binding.agent_id,p_plugin,after_sequence
            loop
                page_count:=page_count+1;
                after_sequence:=candidate.sequence;
                if candidate.receipt->>'status' is distinct from 'committed' then continue;end if;
                select i.packet,i.received_at into packet_row
                from public.sli_agent_packet_inbox i
                where i.packet_id=candidate.packet_id and i.imported_at is not null
                  and i.envelope=candidate.envelope and i.envelope->>'agent_id'=binding.agent_id::text
                  and i.envelope->>'source_instance_id'=p_source and i.envelope->>'generation'=p_generation;
                if found then
                    latest:=greatest(latest,packet_row.received_at);
                    if packet_row.packet#>>'{continuity,status}'='complete'
                       and packet_row.packet#>>'{continuity,from_utc}' is not null
                       and packet_row.packet#>>'{continuity,to_utc}' is not null then
                        intervals:=array_append(intervals,tstzrange(
                            (packet_row.packet#>>'{continuity,from_utc}')::timestamptz,
                            (packet_row.packet#>>'{continuity,to_utc}')::timestamptz,'[)'));
                    end if;
                    accepted:=accepted+1;
                    exit when accepted>=64;
                end if;
            end loop;
            exit when accepted>=64 or page_count<256;
        end loop;
    end loop;
    select range_agg(r) into covered from unnest(intervals) r;
    if latest is null then return 'not_collected'; end if;
    if latest<p_now-interval '5 minutes' then return 'stale'; end if;
    if covered is null or not covered @> tstzrange(p_from,p_to,'[)') then return 'partial'; end if;
    -- Receipts are admitted in signed cursor/sequence order. Pending imports
    -- in that chain invalidate completeness even when a later tail arrived.
    if exists(select 1 from public.finding_evidence_source_bindings b join pg_catalog.pg_roles r
        on r.oid=b.principal_oid and r.rolname=b.principal_name
        cross join lateral (
            -- Pending is a separate sparse time-range check, not the imported
            -- packet history. Do not add committed or receipt.agent_id filters:
            -- the original completeness veto also includes these receipts.
            select i.packet_id,i.envelope,i.received_at,i.imported_at
            from public.sli_agent_packet_inbox i
            where i.imported_at is null and i.received_at>=p_from
              and i.envelope->>'agent_id'=b.agent_id::text
              and i.envelope->>'source_instance_id'=p_source and i.envelope->>'generation'=p_generation
            offset 0
        ) inbox
        join public.sli_agent_receipts receipt on receipt.packet_id=inbox.packet_id
        where r.rolname=session_user and b.installation_id=p_installation and b.plugin_id=p_plugin
          and b.source_instance_id=p_source and b.source_generation=p_generation
          and inbox.envelope=receipt.envelope and receipt.module_id=p_plugin
          and inbox.envelope->>'source_instance_id'=p_source and inbox.envelope->>'generation'=p_generation
          and inbox.received_at>=p_from and inbox.imported_at is null) then
        return 'partial';
    end if;
    if exists(select 1 from public.events_v2_core e
        where e.event_id=6273 and e.time_created_utc>=p_from and e.time_created_utc<p_to
          and public.resolve_finding_evidence_ref(p_installation,p_plugin,p_source,p_generation,'','core_event',
              e.id::text,encode(e.normalized_hash,'hex'))
          and not exists(select 1 from public.normalized_events n where n.source_event_id=e.id
              and n.normalizer_id='windows.named-eventdata' and n.semantic_contract_version=1
              and n.processing_status='normalized' and n.semantic_type='remote_access.authentication.denied'
              and not exists(select 1 from public.normalized_events newer
                  where newer.source_event_id=n.source_event_id and newer.normalizer_id=n.normalizer_id
                    and (newer.normalized_at,newer.normalized_event_id)>(n.normalized_at,n.normalized_event_id)))) then
        return 'partial';
    end if;
    return 'good';
end $$;

do $$ begin
    if exists(select 1 from public.nps_threshold_definitions326 d
        join pg_proc p on p.oid=d.signature::regprocedure where to_jsonb(p)-'prosrc' is distinct from d.catalog) then
        raise exception 'nps_threshold_326_catalog_changed' using errcode='55000';
    end if;
end $$;
insert into public.schema_migrations(version,name) values(326,'nps_threshold_paths');
reset role;
commit;
