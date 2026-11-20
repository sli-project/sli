-- Event predicates precede packet/receipt probes. Native authority, source
-- equality, output, ordering and accepted-row limits are unchanged.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_event_candidates_v317'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=316 and name='semantic_t109_source_candidates')
       or exists(select 1 from public.schema_migrations where version>=317) then
        raise exception 'semantic_event_candidates_317_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $patch$
declare target oid:='public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure;
    definition text; original_catalog jsonb;
    old_sql text:=$old$from (
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
                select core.* from public.events_v2_core core
                where core.raw_log_file_id=(select raw.id from public.raw_log_files raw
                    where raw.file_path='agent-packet:'||inbox.packet_id::text)
                offset 0
            ) e$old$;
    new_sql text:=$new$from public.events_v2_core e
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
        ) inbox$new$;
begin
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_event_candidates_317_owner' using errcode='55000';
    end if;
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_event_candidates_317_shape: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_event_candidates_317_catalog' using errcode='55000';
    end if;
end $patch$;
do $patch$
declare target oid:='public.read_identity_attack_events_v301(jsonb,bigint[])'::regprocedure;
    definition text; original_catalog jsonb;
    old_sql text:=$old$from (
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
            select core.* from public.events_v2_core core
            where core.raw_log_file_id=(select raw.id from public.raw_log_files raw
                where raw.file_path='agent-packet:'||inbox.packet_id::text)
            offset 0
        ) e$old$;
    new_sql text:=$new$from public.events_v2_core e
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
        ) inbox$new$;
begin
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_event_candidates_317_owner' using errcode='55000';
    end if;
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>2 then
        raise exception 'semantic_event_candidates_317_shape: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_event_candidates_317_catalog' using errcode='55000';
    end if;
end $patch$;
do $patch$
declare target oid:='public.read_default_password_window_v2(jsonb)'::regprocedure;
    definition text; original_catalog jsonb;
    old_sql text:=$old$from (
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
            select core.* from public.events_v2_core core
            where core.raw_log_file_id=(select raw.id from public.raw_log_files raw
                where raw.file_path='agent-packet:'||inbox.packet_id::text)
            offset 0
        ) e$old$;
    new_sql text:=$new$from public.events_v2_core e
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
        ) inbox$new$;
begin
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_event_candidates_317_owner' using errcode='55000';
    end if;
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_event_candidates_317_shape: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_event_candidates_317_catalog' using errcode='55000';
    end if;
end $patch$;
do $patch$
declare target oid:='public.read_default_password_events(jsonb)'::regprocedure;
    definition text; original_catalog jsonb;
    old_sql text:=$old$from (
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
            select core.* from public.events_v2_core core
            where core.raw_log_file_id=(select raw.id from public.raw_log_files raw
                where raw.file_path='agent-packet:'||inbox.packet_id::text)
            offset 0
        ) e$old$;
    new_sql text:=$new$from public.events_v2_core e
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
        ) inbox$new$;
begin
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_event_candidates_317_owner' using errcode='55000';
    end if;
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>2 then
        raise exception 'semantic_event_candidates_317_shape: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_event_candidates_317_catalog' using errcode='55000';
    end if;
end $patch$;
do $patch$
declare target oid:='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure;
    definition text; original_catalog jsonb;
    old_sql text:=$old$        from (
            select i.* from public.sli_agent_packet_inbox i
            where md5(i.envelope->>'agent_id')=md5(source_binding.agent_id::text)
              and md5(i.envelope->>'source_instance_id')=md5(p_source)
              and md5(i.envelope->>'generation')=md5(p_generation)
            offset 0
        ) inbox
        cross join lateral (
            -- UNIQUE file_path, then the existing raw-packet core index.
            -- Fence both probes: JSON selectivity must not choose a global scan.
            select core.* from public.events_v2_core core
            where core.raw_log_file_id=(select raw.id from public.raw_log_files raw
                where raw.file_path='agent-packet:'||inbox.packet_id::text)
              and core.log_source_id=source_binding.log_source_id offset 0
        ) e
        cross join lateral (
            select normalized.* from public.normalized_events normalized
            where normalized.source_event_id=e.id offset 0
        ) n$old$;
    new_sql text:=$new$        from public.normalized_events n join public.events_v2_core e on e.id=n.source_event_id
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
$new$;
begin
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_event_candidates_317_owner' using errcode='55000';
    end if;
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_event_candidates_317_shape: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_event_candidates_317_catalog' using errcode='55000';
    end if;
end $patch$;
do $patch$
declare target oid:='public.read_account_watch_events(uuid,text,text,text,text,uuid)'::regprocedure;
    definition text; original_catalog jsonb;
    old_sql text:=$old$        from (
            select i.* from public.sli_agent_packet_inbox i
            where md5(i.envelope->>'agent_id')=md5(source_binding.agent_id::text)
              and md5(i.envelope->>'source_instance_id')=md5(p_source)
              and md5(i.envelope->>'generation')=md5(p_generation)
            offset 0
        ) inbox
        cross join lateral (
            -- UNIQUE file_path, then the existing raw-packet core index.
            -- Fence both probes: JSON selectivity must not choose a global scan.
            select core.* from public.events_v2_core core
            where core.raw_log_file_id=(select raw.id from public.raw_log_files raw
                where raw.file_path='agent-packet:'||inbox.packet_id::text)
              and core.log_source_id=source_binding.log_source_id offset 0
        ) e
        cross join lateral (
            select normalized.* from public.normalized_events normalized
            where normalized.source_event_id=e.id offset 0
        ) n$old$;
    new_sql text:=$new$        from public.normalized_events n join public.events_v2_core e on e.id=n.source_event_id
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
$new$;
begin
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_event_candidates_317_owner' using errcode='55000';
    end if;
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_event_candidates_317_shape: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_event_candidates_317_catalog' using errcode='55000';
    end if;
end $patch$;
do $patch$
declare target oid:='public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure;
    definition text; original_catalog jsonb;
    old_sql text:=$old$from public.sli_agent_receipts r join public.sli_agent_packet_inbox i using(packet_id)
            join public.raw_log_files raw on raw.file_path='agent-packet:'||r.packet_id::text
            join public.events_v2_core core on core.raw_log_file_id=raw.id$old$;
    new_sql text:=$new$from (
                select c.raw_log_file_id,c.event_record_id,c.event_id from public.events_v2_core c
                where c.event_record_id=o.record_id and c.event_id=o.event_id offset 0
            ) core
            join public.raw_log_files raw on raw.id=core.raw_log_file_id
            join public.sli_agent_packet_inbox i on i.packet_id=case
                when raw.file_path ~ '^agent-packet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                then substr(raw.file_path,14)::uuid end
            join public.sli_agent_receipts r on r.packet_id=i.packet_id$new$;
begin
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_event_candidates_317_owner' using errcode='55000';
    end if;
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_event_candidates_317_shape: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_event_candidates_317_catalog' using errcode='55000';
    end if;
end $patch$;
do $patch$
declare target oid:='public.read_identity_attack_events_v301(jsonb,bigint[])'::regprocedure; definition text; original_catalog jsonb;
    old_sql text:=$old$select max(e.time_created_utc) into tail$old$; new_sql text:=$new$select e.time_created_utc into tail$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog from pg_proc p where p.oid=target;
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole
       or (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_event_candidates_317_watermark_shape' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_event_candidates_317_catalog' using errcode='55000';
    end if;
end $patch$;
do $patch$
declare target oid:='public.read_identity_attack_events_v301(jsonb,bigint[])'::regprocedure; definition text; original_catalog jsonb;
    old_sql text:=$old$and e.time_created_utc<=statement_timestamp();$old$; new_sql text:=$new$and e.time_created_utc<=statement_timestamp() order by e.time_created_utc desc,e.id desc limit 1;$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog from pg_proc p where p.oid=target;
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole
       or (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_event_candidates_317_watermark_shape' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_event_candidates_317_catalog' using errcode='55000';
    end if;
end $patch$;
do $patch$
declare target oid:='public.read_default_password_events(jsonb)'::regprocedure; definition text; original_catalog jsonb;
    old_sql text:=$old$select max(e.time_created_utc) into tail$old$; new_sql text:=$new$select e.time_created_utc into tail$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog from pg_proc p where p.oid=target;
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole
       or (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_event_candidates_317_watermark_shape' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_event_candidates_317_catalog' using errcode='55000';
    end if;
end $patch$;
do $patch$
declare target oid:='public.read_default_password_events(jsonb)'::regprocedure; definition text; original_catalog jsonb;
    old_sql text:=$old$and e.time_created_utc<=statement_timestamp();$old$; new_sql text:=$new$and e.time_created_utc<=statement_timestamp() order by e.time_created_utc desc,e.id desc limit 1;$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog from pg_proc p where p.oid=target;
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole
       or (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_event_candidates_317_watermark_shape' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_event_candidates_317_catalog' using errcode='55000';
    end if;
end $patch$;
create index semantic_t109_seen_native_v317 on public.semantic_t109_seen(native_id);
-- Acquire hot-table build locks last. These ordinary builds hold SHARE until
-- commit and need disk/WAL; apply within the controlled update window.
create index semantic_t109_event_time_v317 on public.events_v2_core(log_source_id,time_created_utc,id)
    where event_id in (4688,4104,1102,4719,7036,7040,7045);
create index semantic_native_record_v317 on public.events_v2_core(event_record_id,event_id,raw_log_file_id);
insert into public.schema_migrations(version,name) values(317,'semantic_event_candidates');
reset role;
commit;
