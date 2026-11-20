-- Source-scoped AD candidates; every surviving event retains current native proof.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_account_watch_source_prefilter_v271'));

do $guard$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 271 prerequisites failed';
    end if;
    if not exists(select 1 from public.schema_migrations
           where version=270 and name='account_decoy_source_prefilter')
       or exists(select 1 from public.schema_migrations where version>=271)
       or not exists(select 1 from pg_catalog.pg_proc p
           where p.oid=to_regprocedure('public.read_account_watch_events(uuid,text,text,text,text,uuid)')
             and p.proowner=(select oid from pg_catalog.pg_roles where rolname='adlog_storage_owner')
             and p.prolang=(select oid from pg_catalog.pg_language where lanname='plpgsql')
             and p.prokind='f' and p.proretset and p.prorettype='record'::regtype
             and p.prosecdef and p.provolatile='s' and not p.proisstrict and not p.proleakproof
             and p.proparallel='u' and p.pronargdefaults=0 and p.procost=100 and p.prorows=1000
             and p.proconfig=array['search_path=pg_catalog, pg_temp']
             and cardinality(p.proacl)=2
             and p.proacl @> array['adlog_storage_owner=X/adlog_storage_owner',
                 'adlog_semantic_worker=X/adlog_storage_owner']::aclitem[]
             and encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=
                 '908729a5c5eee1cae7efa4a193cf0f272fa89e882282030f98992b91e70900a9') then
        raise exception 'migration 271 prerequisites failed';
    end if;
end $guard$;
set local role adlog_storage_owner;

-- Keep the same OID and complete function catalog, changing only reviewed prosrc.
do $migration$
declare reader_oid oid:=to_regprocedure('public.read_account_watch_events(uuid,text,text,text,text,uuid)');
    original_catalog jsonb;
begin
    select to_jsonb(p)-'prosrc' into strict original_catalog from pg_catalog.pg_proc p where p.oid=reader_oid;
    execute $reader$
create or replace function public.read_account_watch_events(
    p_installation uuid,p_plugin text,p_source text,p_generation text,p_checkpoint text,p_normalized uuid
) returns table(normalized_event_id uuid,source_event_id bigint,event_id integer,semantic_type text,
    occurred_at_utc timestamptz,roles_json jsonb,quality_json jsonb,sha256 text,entries jsonb,identities jsonb,event_item jsonb)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare source_binding public.finding_evidence_source_bindings%rowtype;
begin
    if p_plugin is distinct from 'sli.windows.ad-dc' or p_checkpoint is null
       or p_checkpoint !~ '^[a-f0-9]{64}$'
       or public.finding_evidence_scope_allowed(p_installation,p_plugin,p_source,p_generation,'','core_event') is not true then
        raise exception 'account_watch_source_denied' using errcode='42501';
    end if;
    select b.* into source_binding
    from public.finding_evidence_source_bindings b join pg_catalog.pg_roles r
      on r.oid=b.principal_oid and r.rolname=b.principal_name
    where r.rolname=session_user and b.installation_id=p_installation and b.plugin_id=p_plugin
      and b.source_instance_id=p_source and b.source_generation=p_generation
      and b.collection_scope_id='' and b.storage_kind='core_event';
    if not found then
        raise exception 'account_watch_source_denied' using errcode='42501';
    end if;
    return query
    with source_candidates as materialized (
        select n.*,e.event_id,e.domain_id,encode(e.normalized_hash,'hex') as native_sha256,
            to_jsonb(e)||jsonb_build_object('channel',channel.value,'provider_name',provider.value) as item
        from public.normalized_events n join public.events_v2_core e on e.id=n.source_event_id
        join public.raw_log_files raw on raw.id=e.raw_log_file_id
        join public.sli_agent_packet_inbox inbox on raw.file_path='agent-packet:'||inbox.packet_id::text
        join public.storage_v2_channel channel on channel.id=e.channel_id
        join public.storage_v2_provider provider on provider.id=e.provider_id
        where e.log_source_id=source_binding.log_source_id
          and inbox.envelope->>'agent_id'=source_binding.agent_id::text
          and inbox.envelope->>'source_instance_id'=p_source
          and inbox.envelope->>'generation'=p_generation
          and e.event_id in (4624,4625,4634,4647,4648,4672,4740,4767,4768,4769,4770,4771,4773,4776,
            4720,4722,4723,4724,4725,4726,4738,4781,4728,4732,4756,4729,4733,4757)
          and n.processing_status='normalized' and n.normalizer_id='windows.named-eventdata'
          and n.semantic_contract_version=1
          and n.source_event_sha256=e.normalized_hash and n.occurred_at_utc=e.time_created_utc
          and n.occurred_at_utc<=statement_timestamp()
          and exists(select 1 from public.watch_entry_versions w
              where w.active and w.collection_scope_id='ad-domain:'||e.domain_id
                and w.active_from<=n.occurred_at_utc and n.occurred_at_utc<w.expires_at
                and w.valid_from<=n.occurred_at_utc and (w.valid_to is null or n.occurred_at_utc<w.valid_to))
          and ((p_normalized is not null and n.normalized_event_id=p_normalized)
            or (p_normalized is null and not exists(
                select 1 from public.semantic_account_watch_checks c
                where c.checkpoint_key=p_checkpoint and c.normalized_event_id=n.normalized_event_id)
                and not exists(select 1 from public.normalized_events newer
                    where newer.source_event_id=n.source_event_id and newer.normalizer_id=n.normalizer_id
                    and (newer.normalized_at,newer.normalized_event_id)>(n.normalized_at,n.normalized_event_id))))
    ), events as materialized (
        select candidate.* from source_candidates candidate
        where public.resolve_finding_evidence_ref(p_installation,p_plugin,p_source,p_generation,'','core_event',
            candidate.source_event_id::text,candidate.native_sha256)
        order by candidate.normalized_at,candidate.normalized_event_id limit 128
    )
    select e.normalized_event_id,e.source_event_id,e.event_id,e.semantic_type,e.occurred_at_utc,
        e.roles_json,e.quality_json,e.native_sha256,
        coalesce((select jsonb_agg(to_jsonb(w)) from (
            select d.id,d.revision,d.identity,d.active,d.active_from,d.expires_at,d.valid_from,d.valid_to
            from public.watch_entry_versions d
            where d.active and d.plugin_id='sli.ad' and d.collection_scope_id='ad-domain:'||e.domain_id
              and (d.identity->>'domain_id')::bigint=e.domain_id
              and d.active_from<=e.occurred_at_utc and e.occurred_at_utc<d.expires_at
              and d.valid_from<=e.occurred_at_utc and (d.valid_to is null or e.occurred_at_utc<d.valid_to)
            order by d.id,d.revision limit 129
        ) w),'[]'::jsonb),
        coalesce((select jsonb_agg(to_jsonb(i)) from (
            select role.key as role,role.value as key,
                jsonb_build_object('domain_id',r.domain_id,'entity_id',v.entity_id,
                    'sid',v.attributes_json#>>'{identity,object_sid}',
                    'guid',lower(v.attributes_json#>>'{identity,object_guid}')) as identity
            from public.ad_context_entity_versions v
            join public.ad_context_runs r on r.run_id=v.source_run_id
            cross join lateral jsonb_each_text(e.roles_json) role
            where r.status='completed' and r.domain_id=e.domain_id and v.source_section='directory_accounts'
              and v.attributes_json#>>'{identity,kind}'='ad_user'
              and v.valid_from_utc<=e.occurred_at_utc and (v.valid_to_utc is null or e.occurred_at_utc<v.valid_to_utc)
              and role.key in ('actor','affected_entity','session_principal')
              and (role.value='sid:'||(v.attributes_json#>>'{identity,object_sid}')
                or role.value='guid:'||lower(v.attributes_json#>>'{identity,object_guid}'))
            order by role.key,v.entity_id,v.id limit 257
        ) i),'[]'::jsonb),e.item
    from events e order by e.normalized_at,e.normalized_event_id;
end $$;

    $reader$;
    if not exists(select 1 from pg_catalog.pg_proc p where p.oid=reader_oid
        and to_jsonb(p)-'prosrc'=original_catalog
        and encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=
            '95257eff6fb8c5f13c92a5f8acba3012a8b087022495c349caaa15588f935086') then
        raise exception 'migration 271 catalog preservation failed';
    end if;
end $migration$;

insert into public.schema_migrations(version,name) values(271,'account_watch_source_prefilter');
commit;
