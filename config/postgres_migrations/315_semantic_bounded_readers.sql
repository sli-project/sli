-- Exact source/record access paths; all admission, hashes, intervals and limits remain.
-- Ordinary builds read inbox and AD versions once and hold SHARE until COMMIT:
-- reads continue, writers wait; all three indexes require extra disk/WAL and ingest work.
-- Apply in the existing maintenance window. No runtime permission is added.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_bounded_readers_v315'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=314 and name='semantic_runtime_readers')
       or exists(select 1 from public.schema_migrations where version>=315)
       or (select proowner from pg_proc where oid='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure) is distinct from 'adlog_storage_owner'::regrole
        or (select proowner from pg_proc where oid='public.read_account_watch_events(uuid,text,text,text,text,uuid)'::regprocedure) is distinct from 'adlog_storage_owner'::regrole
        or (select proowner from pg_proc where oid='public.identity_snapshot_rows_v301(jsonb,bigint[])'::regprocedure) is distinct from 'adlog_storage_owner'::regrole
        or (select proowner from pg_proc where oid='public.read_t109_agent_health(jsonb)'::regprocedure) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_bounded_315_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $patch$
declare definition text; original_catalog jsonb; target oid:='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure;
    old_sql text:=$old$        from public.normalized_events n join public.events_v2_core e on e.id=n.source_event_id
        join public.raw_log_files raw on raw.id=e.raw_log_file_id
        join public.sli_agent_packet_inbox inbox on raw.file_path='agent-packet:'||inbox.packet_id::text$old$;
    new_sql text:=$new$        from (
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
        ) n$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_bounded_315_definition_mismatch: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_bounded_315_catalog_changed' using errcode='55000';
    end if;
end $patch$;

do $patch$
declare definition text; original_catalog jsonb; target oid:='public.read_account_watch_events(uuid,text,text,text,text,uuid)'::regprocedure;
    old_sql text:=$old$        from public.normalized_events n join public.events_v2_core e on e.id=n.source_event_id
        join public.raw_log_files raw on raw.id=e.raw_log_file_id
        join public.sli_agent_packet_inbox inbox on raw.file_path='agent-packet:'||inbox.packet_id::text$old$;
    new_sql text:=$new$        from (
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
        ) n$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_bounded_315_definition_mismatch: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_bounded_315_catalog_changed' using errcode='55000';
    end if;
end $patch$;

do $patch$
declare definition text; original_catalog jsonb; target oid:='public.identity_snapshot_rows_v301(jsonb,bigint[])'::regprocedure;
    old_sql text:=$old$    join public.entities_v2 entity on entity.domain_id=run.domain_id
    join public.ad_context_entity_versions version on version.entity_id=entity.id
        and version.source_section='directory_accounts'
        and version.attributes_json->>'record_key'=evidence.locator_json->>'record_key'
        and version.valid_from_utc<=evidence.observed_at_utc
        and (version.valid_to_utc is null or version.valid_to_utc>evidence.observed_at_utc)$old$;
    new_sql text:=$new$    cross join lateral (
        -- Evidence addresses a record key, not all entities in the domain.
        -- Retained versions may come from an older run: do not join source_run_id.
        select v.* from public.ad_context_entity_versions v
        where v.source_section='directory_accounts'
          and md5(v.attributes_json->>'record_key')=md5(evidence.locator_json->>'record_key')
          and v.attributes_json->>'record_key'=evidence.locator_json->>'record_key'
          and v.valid_from_utc<=evidence.observed_at_utc
          and (v.valid_to_utc is null or v.valid_to_utc>evidence.observed_at_utc)
          and exists(select 1 from public.entities_v2 entity
              where entity.id=v.entity_id and entity.domain_id=run.domain_id)
        offset 0
    ) version$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_bounded_315_definition_mismatch: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_bounded_315_catalog_changed' using errcode='55000';
    end if;
end $patch$;

do $patch$
declare definition text; original_catalog jsonb; target oid:='public.read_t109_agent_health(jsonb)'::regprocedure;
    old_sql text:=$old$        'pending_since',(select min(pending.received_at) from public.sli_agent_receipts pending
            join public.sli_agent_packet_inbox inbox using(packet_id)
            where pending.agent_id=agent.id and pending.module_id=m->>'module_id' and inbox.imported_at is null
              and inbox.collection_revision=coalesce(m#>>'{config,policy_revision}','1')
              and inbox.collection_channel is not distinct from q.channel))), '[]'::jsonb)
    into streams from jsonb_array_elements(agent.assigned_modules) m
    cross join lateral (
        select distinct on (i.collection_channel) i.collection_channel as channel,r.received_at,i.imported_at,i.collection_read_error
        from public.sli_agent_receipts r join public.sli_agent_packet_inbox i using(packet_id)
        where r.agent_id=agent.id and r.module_id=m->>'module_id'
          and i.collection_revision=coalesce(m#>>'{config,policy_revision}','1')
          and r.receipt->>'status'='committed' and i.envelope=r.envelope
        order by i.collection_channel,r.received_at desc,r.sequence desc
    ) q where m->'enabled'='true'::jsonb;
$old$;
    new_sql text:=$new$        'pending_since',(select min(pending.received_at) from (
            -- Probe the existing partial pending-inbox index first. No receipt
            -- history traversal when this stream has no unimported packets.
            select inbox.packet_id from public.sli_agent_packet_inbox inbox
            where inbox.imported_at is null
              and inbox.collection_revision=coalesce(m#>>'{config,policy_revision}','1')
              and inbox.collection_channel is not distinct from q.channel offset 0
        ) unimported cross join lateral (
            select r.received_at from public.sli_agent_receipts r
            where r.packet_id=unimported.packet_id and r.agent_id=agent.id
              and r.module_id=m->>'module_id' offset 0
        ) pending))), '[]'::jsonb)
    into streams from jsonb_array_elements(agent.assigned_modules) m
    cross join lateral (
        -- One index seek per distinct channel, then one latest admitted packet.
        -- NULL and empty channels are distinct, as in the original DISTINCT ON.
        with recursive channels(channel) as (
            (select h.collection_channel from public.sli_agent_stream_receipts h
             where h.agent_id=agent.id and h.module_id=m->>'module_id'
               and h.collection_revision=coalesce(m#>>'{config,policy_revision}','1')
               and (h.collection_channel is null)=false
               and coalesce(h.collection_channel,'')>=''
             order by coalesce(h.collection_channel,'') limit 1)
            union all
            select next_channel.channel from channels previous cross join lateral (
                select h.collection_channel as channel from public.sli_agent_stream_receipts h
                where h.agent_id=agent.id and h.module_id=m->>'module_id'
                  and h.collection_revision=coalesce(m#>>'{config,policy_revision}','1')
                  and (h.collection_channel is null)=false
                  and coalesce(h.collection_channel,'')>previous.channel
                order by coalesce(h.collection_channel,'') limit 1
            ) next_channel
        ), all_channels as (
            select channel from channels
            union all
            (select h.collection_channel from public.sli_agent_stream_receipts h
             where h.agent_id=agent.id and h.module_id=m->>'module_id'
               and h.collection_revision=coalesce(m#>>'{config,policy_revision}','1')
               and (h.collection_channel is null)=true and coalesce(h.collection_channel,'')=''
             limit 1)
        )
        select c.channel,latest.received_at,latest.imported_at,latest.collection_read_error
        from all_channels c cross join lateral (
            select r.received_at,i.imported_at,i.collection_read_error
            from public.sli_agent_stream_receipts h
            cross join lateral (
                select r.received_at,r.envelope,r.receipt from public.sli_agent_receipts r
                where r.packet_id=h.packet_id offset 0
            ) r
            cross join lateral (
                select i.imported_at,i.collection_read_error from public.sli_agent_packet_inbox i
                where i.packet_id=h.packet_id and i.envelope=r.envelope offset 0
            ) i
            where h.agent_id=agent.id and h.module_id=m->>'module_id'
              and h.collection_revision=coalesce(m#>>'{config,policy_revision}','1')
              and (h.collection_channel is null)=(c.channel is null)
              and coalesce(h.collection_channel,'')=coalesce(c.channel,'')
              and r.receipt->>'status'='committed'
            order by h.received_at desc,h.sequence desc limit 1
        ) latest
        order by c.channel
    ) q where m->'enabled'='true'::jsonb;
$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_bounded_315_definition_mismatch: %',target::regprocedure using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_bounded_315_catalog_changed' using errcode='55000';
    end if;
end $patch$;
do $patch$
declare definition text; original_catalog jsonb; target oid:='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure;
    old_sql text:=$old$              and role.key in ('actor','affected_entity')$old$;
    new_sql text:=$new$              and role.key in ('actor','affected_entity')
              -- Digest overlap is only a prefilter; original full identity checks follow.
              and array[md5('sid:'||(v.attributes_json#>>'{identity,object_sid}')),
                md5('guid:'||lower(v.attributes_json#>>'{identity,object_guid}')),
                md5('sam-name:'||lower(v.attributes_json#>>'{attributes,sam_account_name}'))] && array[md5(role.value),
                  case when e.event_id=4625 and left(role.value,length('sam:'||lower(domain.fqdn)||':'))='sam:'||lower(domain.fqdn)||':'
                    then md5('sam-name:'||substr(role.value,length('sam:'||lower(domain.fqdn)||':')+1)) end,
                  case when e.event_id=4625 and left(role.value,length('sam:'||lower(domain.netbios_name)||':'))='sam:'||lower(domain.netbios_name)||':'
                    then md5('sam-name:'||substr(role.value,length('sam:'||lower(domain.netbios_name)||':')+1)) end]$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_bounded_315_identity_shape' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_bounded_315_catalog_changed' using errcode='55000';
    end if;
end $patch$;

do $patch$
declare definition text; original_catalog jsonb; target oid:='public.read_account_watch_events(uuid,text,text,text,text,uuid)'::regprocedure;
    old_sql text:=$old$              and role.key in ('actor','affected_entity','session_principal')$old$;
    new_sql text:=$new$              and role.key in ('actor','affected_entity','session_principal')
              -- Digest overlap is only a prefilter; original full identity checks follow.
              and array[md5('sid:'||(v.attributes_json#>>'{identity,object_sid}')),
                md5('guid:'||lower(v.attributes_json#>>'{identity,object_guid}')),
                md5('sam-name:'||lower(v.attributes_json#>>'{attributes,sam_account_name}'))] && array[md5(role.value)]$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_sql,'')))/length(old_sql)<>1 then
        raise exception 'semantic_bounded_315_identity_shape' using errcode='55000';
    end if;
    execute replace(definition,old_sql,new_sql);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_bounded_315_catalog_changed' using errcode='55000';
    end if;
end $patch$;
do $ordered_proof$
declare target oid; definition text; original_catalog jsonb;
    old_prefix text:=$prefix$with source_candidates as materialized ($prefix$; new_prefix text:=$prefix$with source_candidates as not materialized ($prefix$;
    old_batch text:=$old$        select candidate.* from source_candidates candidate
        where public.resolve_finding_evidence_ref$old$;
    new_batch text:=$new$        -- Sort before native proof. OFFSET is a predicate-pushdown fence:
        -- prove candidates in exact batch order, stopping after 128 VALID rows.
        -- Do not LIMIT before proof: unavailable native evidence must be skipped.
        select candidate.* from (
            select ordered.* from source_candidates ordered
            order by ordered.normalized_at,ordered.normalized_event_id offset 0
        ) candidate
        where public.resolve_finding_evidence_ref$new$;
begin
    foreach target in array array[
        'public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure,
        'public.read_account_watch_events(uuid,text,text,text,text,uuid)'::regprocedure] loop
        select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
            from pg_catalog.pg_proc p where p.oid=target;
        if (length(definition)-length(replace(definition,old_prefix,'')))/length(old_prefix)<>1
           or (length(definition)-length(replace(definition,old_batch,'')))/length(old_batch)<>1 then
            raise exception 'semantic_bounded_315_order_shape' using errcode='55000';
        end if;
        execute replace(replace(definition,old_prefix,new_prefix),old_batch,new_batch);
        if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
            raise exception 'semantic_bounded_315_catalog_changed' using errcode='55000';
        end if;
    end loop;
end $ordered_proof$;
do $watch_document$
declare target oid:='public.read_account_watch_events(uuid,text,text,text,text,uuid)'::regprocedure;
    definition text; original_catalog jsonb;
    old_select text:=$old$select n.*,e.event_id,e.domain_id,encode(e.normalized_hash,'hex') as native_sha256,
            to_jsonb(e)||jsonb_build_object('channel',channel.value,'provider_name',provider.value) as item$old$; new_select text:=$new$select n.*,e.event_id,e.domain_id,encode(e.normalized_hash,'hex') as native_sha256$new$;
    old_result text:=$old$),'[]'::jsonb),e.item
    from events e$old$; new_result text:=$new$),'[]'::jsonb),
        -- Rebuild the unchanged core document only for the admitted batch.
        (select to_jsonb(core)||jsonb_build_object('channel',channel.value,'provider_name',provider.value)
         from public.events_v2_core core
         join public.storage_v2_channel channel on channel.id=core.channel_id
         join public.storage_v2_provider provider on provider.id=core.provider_id
         where core.id=e.source_event_id)
    from events e$new$;
begin
    select pg_get_functiondef(target),to_jsonb(p)-'prosrc' into strict definition,original_catalog
        from pg_catalog.pg_proc p where p.oid=target;
    if (length(definition)-length(replace(definition,old_select,'')))/length(old_select)<>1
       or (length(definition)-length(replace(definition,old_result,'')))/length(old_result)<>1 then
        raise exception 'semantic_bounded_315_watch_document_shape' using errcode='55000';
    end if;
    execute replace(replace(definition,old_select,new_select),old_result,new_result);
    if (select to_jsonb(p)-'prosrc' from pg_catalog.pg_proc p where p.oid=target) is distinct from original_catalog then
        raise exception 'semantic_bounded_315_catalog_changed' using errcode='55000';
    end if;
end $watch_document$;
-- Acquire table locks only after all function patches; hot inbox comes last.
reset role;
-- The existing installer identity has table-owner authority plus CREATE on public.
-- adlog_user owns this historical table but intentionally lacks schema CREATE.
-- CREATE INDEX still assigns the index to the table owner; add no GRANT to either role.
create index identity_version_record_v315 on public.ad_context_entity_versions
    (md5(attributes_json->>'record_key'),entity_id) where source_section='directory_accounts';
-- Each accepted event resolves at most a few role keys. Avoid one complete
-- directory-version scan per returned event (128 scans per batch).
create index identity_version_keys_v315 on public.ad_context_entity_versions using gin
    ((array[md5('sid:'||(attributes_json#>>'{identity,object_sid}')),
                md5('guid:'||lower(attributes_json#>>'{identity,object_guid}')),
                md5('sam-name:'||lower(attributes_json#>>'{attributes,sam_account_name}'))])) where source_section='directory_accounts'
        and attributes_json#>>'{identity,kind}'='ad_user';
set local role adlog_storage_owner;
-- Fixed-width digest keys also admit long/malformed envelope values. The original
-- text equality predicates remain in both readers, so a digest collision grants nothing.
create index semantic_account_inbox_v315 on public.sli_agent_packet_inbox
    (md5(envelope->>'agent_id'),md5(envelope->>'source_instance_id'),md5(envelope->>'generation'));
insert into public.schema_migrations(version,name) values(315,'semantic_bounded_readers');
reset role;
commit;
