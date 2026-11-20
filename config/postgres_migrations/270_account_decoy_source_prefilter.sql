-- Source-scoped AD candidates; every surviving event retains current native proof.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_account_decoy_source_prefilter_v270'));

do $guard$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 270 prerequisites failed';
    end if;
    if not exists(select 1 from public.schema_migrations
           where version=269 and name='file_audit_canonical_aggregation')
       or exists(select 1 from public.schema_migrations where version>=270)
       or not exists(select 1 from pg_catalog.pg_proc p
           where p.oid=to_regprocedure('public.read_account_decoy_events(uuid,text,text,text,text,uuid)')
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
                 '474acb092d453ff79a1121dcd6bb2d930f00cdbc7cb401448cd9454f80264565') then
        raise exception 'migration 270 prerequisites failed';
    end if;
end $guard$;
set local role adlog_storage_owner;

-- Keep the same OID and complete function catalog, changing only reviewed prosrc.
do $migration$
declare reader_oid oid:=to_regprocedure('public.read_account_decoy_events(uuid,text,text,text,text,uuid)');
    original_catalog jsonb;
begin
    select to_jsonb(p)-'prosrc' into strict original_catalog from pg_catalog.pg_proc p where p.oid=reader_oid;
    execute $reader$
create or replace function public.read_account_decoy_events(
    p_installation uuid,p_plugin text,p_source text,p_generation text,p_checkpoint text,p_normalized uuid
) returns table(normalized_event_id uuid,source_event_id bigint,event_id integer,semantic_type text,
    occurred_at_utc timestamptz,roles_json jsonb,quality_json jsonb,sha256 text,labels jsonb,identities jsonb)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare source_binding public.finding_evidence_source_bindings%rowtype;
begin
    if p_plugin is distinct from 'sli.windows.ad-dc' or p_checkpoint is null
       or p_checkpoint !~ '^[a-f0-9]{64}$'
       or public.finding_evidence_scope_allowed(p_installation,p_plugin,p_source,p_generation,'','core_event') is not true then
        raise exception 'account_decoy_source_denied' using errcode='42501';
    end if;
    select b.* into source_binding
    from public.finding_evidence_source_bindings b join pg_catalog.pg_roles r
      on r.oid=b.principal_oid and r.rolname=b.principal_name
    where r.rolname=session_user and b.installation_id=p_installation and b.plugin_id=p_plugin
      and b.source_instance_id=p_source and b.source_generation=p_generation
      and b.collection_scope_id='' and b.storage_kind='core_event';
    if not found then
        raise exception 'account_decoy_source_denied' using errcode='42501';
    end if;
    return query
    with source_candidates as materialized (
        select n.*,e.event_id,e.domain_id,encode(e.normalized_hash,'hex') as native_sha256
        from public.normalized_events n join public.events_v2_core e on e.id=n.source_event_id
        join public.raw_log_files raw on raw.id=e.raw_log_file_id
        join public.sli_agent_packet_inbox inbox on raw.file_path='agent-packet:'||inbox.packet_id::text
        where e.log_source_id=source_binding.log_source_id
          and inbox.envelope->>'agent_id'=source_binding.agent_id::text
          and inbox.envelope->>'source_instance_id'=p_source
          and inbox.envelope->>'generation'=p_generation
          and e.event_id in (4624,4625,4768,4769,4771,4776)
          and n.processing_status='normalized' and n.normalizer_id='windows.named-eventdata'
          and n.semantic_contract_version=1
          and n.source_event_sha256=e.normalized_hash and n.occurred_at_utc=e.time_created_utc
          and n.occurred_at_utc<=statement_timestamp()
          and exists(select 1 from public.decoy_label_versions label
              where label.kind='account' and label.active and label.plugin_id='sli.ad'
                and label.collection_scope_id='ad-domain:'||e.domain_id
                and label.active_from<=n.occurred_at_utc
                and (label.active_to is null or n.occurred_at_utc<label.active_to))
          and ((p_normalized is not null and n.normalized_event_id=p_normalized)
            or (p_normalized is null and not exists(
                select 1 from public.semantic_account_decoy_checks c
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
        coalesce((select jsonb_agg(to_jsonb(l)) from (
            select d.id,d.revision,d.kind,d.identity,d.active,d.active_from,d.active_to
            from public.decoy_label_versions d
            where d.kind='account' and d.active and d.entity_id>0
              and d.plugin_id='sli.ad' and d.collection_scope_id='ad-domain:'||e.domain_id
              and (d.identity->>'domain_id')::bigint=e.domain_id
              and d.active_from<=e.occurred_at_utc and (d.active_to is null or e.occurred_at_utc<d.active_to)
            order by d.id,d.revision limit 129
        ) l),'[]'::jsonb),
        coalesce((select jsonb_agg(to_jsonb(i)) from (
            select role.key as role,role.value as key,
                jsonb_build_object('domain_id',r.domain_id,'entity_id',v.entity_id,
                    'sid',v.attributes_json#>>'{identity,object_sid}',
                    'guid',lower(v.attributes_json#>>'{identity,object_guid}')) as identity
            from public.ad_context_entity_versions v
            join public.ad_context_runs r on r.run_id=v.source_run_id
            join public.domains domain on domain.id=r.domain_id
            cross join lateral jsonb_each_text(e.roles_json) role
            where r.status='completed' and r.domain_id=e.domain_id and v.source_section='directory_accounts'
              and v.attributes_json#>>'{identity,kind}'='ad_user'
              and v.valid_from_utc<=e.occurred_at_utc and (v.valid_to_utc is null or e.occurred_at_utc<v.valid_to_utc)
              and role.key in ('actor','affected_entity')
              and (role.value='sid:'||(v.attributes_json#>>'{identity,object_sid}')
                or role.value='guid:'||lower(v.attributes_json#>>'{identity,object_guid}')
                or (e.event_id=4625 and (
                    role.value='sam:'||lower(domain.fqdn)||':'||lower(v.attributes_json#>>'{attributes,sam_account_name}')
                    or role.value='sam:'||lower(domain.netbios_name)||':'||lower(v.attributes_json#>>'{attributes,sam_account_name}'))))
            order by role.key,v.entity_id,v.id limit 257
        ) i),'[]'::jsonb)
    from events e order by e.normalized_at,e.normalized_event_id;
end $$;

    $reader$;
    if not exists(select 1 from pg_catalog.pg_proc p where p.oid=reader_oid
        and to_jsonb(p)-'prosrc'=original_catalog
        and encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=
            '00d0458c557bbc046492f4dfe745b673ce397c94529379ab7e01f08e6709fe94') then
        raise exception 'migration 270 catalog preservation failed';
    end if;
end $migration$;

insert into public.schema_migrations(version,name) values(270,'account_decoy_source_prefilter');
commit;
