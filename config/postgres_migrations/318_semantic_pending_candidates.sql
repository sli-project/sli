-- Source packets precede core/normalized candidates: imported legacy events in
-- the same log_source must never reach native proof. No watermark or early LIMIT.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_pending_v318'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=317 and name='semantic_event_candidates')
       or exists(select 1 from public.schema_migrations where version>=318) then
        raise exception 'semantic_pending_318_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $patch$
declare target oid:='public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure; definition text; original_catalog jsonb;
    old_sql text:=$old$from public.events_v2_core e
        cross join lateral (
            select i.packet_id from public.raw_log_files raw
            join public.sli_agent_packet_inbox i on i.packet_id=case
                when raw.file_path ~ '^agent-packet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                then substr(raw.file_path,14)::uuid end
            where raw.id=e.raw_log_file_id
              and i.envelope->>'agent_id'=b.agent_id::text
              and i.envelope->>'source_instance_id'=b.source_instance_id
              and i.envelope->>'generation'=b.source_generation
            offset 0
        ) inbox$old$;
    new_sql text:=$new$from (
                select i.packet_id from public.sli_agent_packet_inbox i
                where md5(i.envelope->>'agent_id')=md5(b.agent_id::text)
                  and md5(i.envelope->>'source_instance_id')=md5(b.source_instance_id)
                  and md5(i.envelope->>'generation')=md5(b.source_generation)
                  and i.envelope->>'agent_id'=b.agent_id::text
                  and i.envelope->>'source_instance_id'=b.source_instance_id
                  and i.envelope->>'generation'=b.source_generation
                offset 0
            ) inbox
            cross join lateral (
                -- Fence the raw-only probe before event/time predicates: on
                -- a skewed log_source the partial time index can otherwise
                -- scan legacy history once PER packet under a generic plan.
                select core.id,core.event_id,core.time_created_utc,core.normalized_hash,core.log_source_id from (
                    select packet.* from public.events_v2_core packet
                    where packet.raw_log_file_id=(select raw.id from public.raw_log_files raw
                        where raw.file_path='agent-packet:'||inbox.packet_id::text)
                    offset 0
                ) core
                where true
                  and (core.log_source_id=b.log_source_id or exists(select 1 from public.semantic_t109_channels c
                    where c.principal_oid=b.principal_oid and c.principal_name=b.principal_name
                      and c.installation_id=b.installation_id and c.source_instance_id=b.source_instance_id
                      and c.source_generation=b.source_generation and c.log_source_id=core.log_source_id))
                  and core.event_id in (4688,4104,1102,4719,7036,7040,7045)
                  and core.time_created_utc<=statement_timestamp()
                  and (p_start is null or core.time_created_utc between p_start and p_end)
                offset 0
            ) e$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole
       or (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_pending_318_shape: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_pending_318_catalog' using errcode='55000';
    end if;
end $patch$;
do $patch$
declare target oid:='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure; definition text; original_catalog jsonb;
    old_sql text:=$old$        from public.normalized_events n join public.events_v2_core e on e.id=n.source_event_id
        cross join lateral (
            select i.envelope from public.raw_log_files raw
            join public.sli_agent_packet_inbox i on i.packet_id=case
                when raw.file_path ~ '^agent-packet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                then substr(raw.file_path,14)::uuid end
            where raw.id=e.raw_log_file_id
              and i.envelope->>'agent_id'=source_binding.agent_id::text
              and i.envelope->>'source_instance_id'=p_source
              and i.envelope->>'generation'=p_generation
            offset 0
        ) inbox
$old$;
    new_sql text:=$new$        from (
            select i.* from public.sli_agent_packet_inbox i
            where md5(i.envelope->>'agent_id')=md5(source_binding.agent_id::text)
              and md5(i.envelope->>'source_instance_id')=md5(p_source)
              and md5(i.envelope->>'generation')=md5(p_generation)
              and i.envelope->>'agent_id'=source_binding.agent_id::text
              and i.envelope->>'source_instance_id'=p_source
              and i.envelope->>'generation'=p_generation
            offset 0
        ) inbox
        cross join lateral (
            -- UNIQUE file_path, then the existing raw-packet core index.
            -- Fence both probes: JSON selectivity must not choose a global scan.
            select core.* from (
                select packet.* from public.events_v2_core packet
                where packet.raw_log_file_id=(select raw.id from public.raw_log_files raw
                    where raw.file_path='agent-packet:'||inbox.packet_id::text)
                offset 0
            ) core
            where core.log_source_id=source_binding.log_source_id offset 0
        ) e
        cross join lateral (
            select normalized.* from public.normalized_events normalized
            where normalized.source_event_id=e.id offset 0
        ) n$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole
       or (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_pending_318_shape: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_pending_318_catalog' using errcode='55000';
    end if;
end $patch$;
-- Reuse semantic_account_inbox_v315 and events_v2_core_raw_packet_lookup.
-- No new index, disk/WAL build or hot-table build lock on 16M events.
insert into public.schema_migrations(version,name) values(318,'semantic_pending_candidates');
reset role;
commit;
