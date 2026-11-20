-- Scope native candidates before expensive attestation; retain every proof,
-- output field, ordering, time bound and the 1000 accepted-row limit.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_t109_source_candidates_v316'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=315 and name='semantic_bounded_readers')
       or exists(select 1 from public.schema_migrations where version>=316)
       or (select proowner from pg_proc where oid='public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure)
            is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_t109_316_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $patch$
declare target oid:='public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure;
    definition text; original_catalog jsonb;
    old_sql text:=$old$        return query select e.id::text,e.event_id,e.time_created_utc,encode(e.normalized_hash,'hex'),
            native.doc#>>'{event_row,xml}',''::text,null::jsonb
        from public.events_v2_core e
        cross join lateral (select public.read_agent_semantic_source_v190(e.id) doc) native
        where (e.log_source_id=b.log_source_id or exists(select 1 from public.semantic_t109_channels c
            where c.principal_oid=b.principal_oid and c.principal_name=b.principal_name
              and c.installation_id=b.installation_id and c.source_instance_id=b.source_instance_id
              and c.source_generation=b.source_generation and c.log_source_id=e.log_source_id))
          and e.event_id in (4688,4104,1102,4719,7036,7040,7045)
          and e.time_created_utc<=statement_timestamp()
          and (p_start is not null and e.time_created_utc between p_start and p_end
            or p_start is null and not exists(select 1 from public.semantic_t109_seen seen
                where seen.scope_json=s and seen.native_id=e.id::text))
          and native.doc is not null and public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,
            b.source_instance_id,b.source_generation,'','core_event',e.id::text,encode(e.normalized_hash,'hex'))
        order by e.time_created_utc desc,e.id desc limit 1000;
$old$;
    new_sql text:=$new$        -- Drive from the admitted agent/source/generation packet index, then
        -- probe each UNIQUE raw path and its core index. A shared log_source_id
        -- must not invoke native proof once per event of every other host.
        for candidate in
            select e.id,e.event_id,e.time_created_utc,e.normalized_hash
            from (
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
            ) e
            where (e.log_source_id=b.log_source_id or exists(select 1 from public.semantic_t109_channels c
                where c.principal_oid=b.principal_oid and c.principal_name=b.principal_name
                  and c.installation_id=b.installation_id and c.source_instance_id=b.source_instance_id
                  and c.source_generation=b.source_generation and c.log_source_id=e.log_source_id))
              and e.event_id in (4688,4104,1102,4719,7036,7040,7045)
              and e.time_created_utc<=statement_timestamp()
              and (p_start is not null and e.time_created_utc between p_start and p_end
                or p_start is null and not exists(select 1 from public.semantic_t109_seen seen
                    where seen.scope_json=s and seen.native_id=e.id::text))
            order by e.time_created_utc desc,e.id desc
        loop
            -- Materialize once; retain complete original receipt/hash proof.
            doc:=public.read_agent_semantic_source_v190(candidate.id);
            if doc is not null and public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,
                b.source_instance_id,b.source_generation,'','core_event',candidate.id::text,encode(candidate.normalized_hash,'hex')) then
                native_id:=candidate.id::text;event_id:=candidate.event_id;occurred_at_utc:=candidate.time_created_utc;
                sha256:=encode(candidate.normalized_hash,'hex');source_xml:=doc#>>'{event_row,xml}';
                collection_scope_id:='';document:=null;return next;
                emitted:=emitted+1;if emitted>=1000 then exit;end if;
            end if;
        end loop;
$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1
       or (length(definition)-length(replace(definition,$decl$declare b public.finding_evidence_source_bindings%rowtype;$decl$,'')))/length($decl$declare b public.finding_evidence_source_bindings%rowtype;$decl$)<>1 then
        raise exception 'semantic_t109_316_definition_mismatch' using errcode='55000';
    end if;
    execute replace(replace(definition,old_sql,new_sql),$decl$declare b public.finding_evidence_source_bindings%rowtype;$decl$,$decl$declare b public.finding_evidence_source_bindings%rowtype; candidate record; doc jsonb; emitted integer:=0;$decl$);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_t109_316_catalog_changed' using errcode='55000';
    end if;
end $patch$;

-- A log source is shared by hosts. Do not include a foreign host in the
-- watermark, sentinel budget or native attestation set for this exact scope.
do $source$
declare target oid:='public.read_identity_attack_events_v301(jsonb,bigint[])'::regprocedure; definition text; original_catalog jsonb;
    old_sql text:=$old$from public.events_v2_core e$old$; new_sql text:=$new$from (
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
        ) e$new$;
begin
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_t109_316_source_owner' using errcode='55000';
    end if;
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>2 then
        raise exception 'semantic_t109_316_source_shape' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_t109_316_source_catalog' using errcode='55000';
    end if;
end $source$;

-- A log source is shared by hosts. Do not include a foreign host in the
-- watermark, sentinel budget or native attestation set for this exact scope.
do $source$
declare target oid:='public.read_default_password_window_v2(jsonb)'::regprocedure; definition text; original_catalog jsonb;
    old_sql text:=$old$from public.events_v2_core e$old$; new_sql text:=$new$from (
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
        ) e$new$;
begin
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_t109_316_source_owner' using errcode='55000';
    end if;
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_t109_316_source_shape' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_t109_316_source_catalog' using errcode='55000';
    end if;
end $source$;

-- A log source is shared by hosts. Do not include a foreign host in the
-- watermark, sentinel budget or native attestation set for this exact scope.
do $source$
declare target oid:='public.read_default_password_events(jsonb)'::regprocedure; definition text; original_catalog jsonb;
    old_sql text:=$old$from public.events_v2_core e$old$; new_sql text:=$new$from (
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
        ) e$new$;
begin
    if (select proowner from pg_proc where oid=target) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_t109_316_source_owner' using errcode='55000';
    end if;
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>2 then
        raise exception 'semantic_t109_316_source_shape' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_t109_316_source_catalog' using errcode='55000';
    end if;
end $source$;
insert into public.schema_migrations(version,name) values(316,'semantic_t109_source_candidates');
reset role;
commit;
