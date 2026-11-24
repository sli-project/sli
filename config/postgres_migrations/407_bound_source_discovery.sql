begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_bound_source_discovery407'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists (select 1 from public.schema_migrations where version=404 and name='password_live_recovery')
       or exists (select 1 from public.schema_migrations where version>=407) then
        raise exception 'bound_source_discovery407_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.source_discovery_restore407(
    signature regprocedure primary key,definition text not null,owner_oid oid not null,acl aclitem[],
    installed_definition text);
revoke all on public.source_discovery_restore407 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.source_discovery_restore407(signature,definition,owner_oid,acl)
select oid,pg_get_functiondef(oid),proowner,proacl from pg_proc
where oid='public.short_detection_sources337()'::regprocedure
    and proowner='adlog_storage_owner'::regrole and prosecdef and provolatile='v'
    and proconfig=array['search_path=pg_catalog, pg_temp'];

do $patch$
declare saved record; patched text; original_at integer;
    old_declaration constant text:='declare login oid;';
    original_insert constant text:=$original$    insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
        source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
    select distinct login,session_user,(o->>'installation_id')::uuid,'sli.windows.ad-dc',
        o->>'source_instance_id',o->>'source_generation','','core_event',
        (o->>'log_source_id')::bigint,(o->>'agent_id')::uuid
    from (select method,source_sha256 from public.event_hot
          union all select method,decode(repeat('00',32),'hex') from public.event_cold_daily) h
    cross join lateral (select h.method->'$origin' as o) origin
    where h.source_sha256 is not null and o->>'plugin_id'='sli.windows.ad-dc'
      and public.semantic_source_active320((o->>'agent_id')::uuid,'sli.windows.ad-dc',h.method->>'$channel')
    on conflict do nothing;$original$;
    bounded_insert constant text:=$bounded$    -- The same authorization check applies to every identical origin/channel.
    -- Keep all retained partitions, including cold-only sources, and retain
    -- the complete projected tuple for the binding conflict check.
    with origin_channels as materialized (
        -- A two-element key keeps channel and full origin exact without
        -- multiplying the planner's distinct estimates for two expressions.
        select distinct identity from (
            select jsonb_build_array(h.method->'$origin',h.method->>'$channel') as identity
            from public.event_hot h
            where h.source_sha256 is not null and h.method#>>'{$origin,plugin_id}'='sli.windows.ad-dc'
            union all
            select jsonb_build_array(h.method->'$origin',h.method->>'$channel')
            from public.event_cold_daily h
            where h.method#>>'{$origin,plugin_id}'='sli.windows.ad-dc'
        ) admitted_rows
    ), eligible as materialized (
        select distinct (origin->>'installation_id')::uuid as installation_id,
            origin->>'source_instance_id' as source_instance_id,origin->>'source_generation' as source_generation,
            (origin->>'log_source_id')::bigint as log_source_id,(origin->>'agent_id')::uuid as agent_id
        from origin_channels
        cross join lateral (select identity->0 as origin,identity->>1 as channel) candidate
        where public.semantic_source_active320((origin->>'agent_id')::uuid,'sli.windows.ad-dc',channel)
    ), unbound as materialized (
        select e.* from eligible e where not exists (
            select 1 from public.finding_evidence_source_bindings b
            where b.principal_oid=login and b.installation_id=e.installation_id and b.plugin_id='sli.windows.ad-dc'
              and b.source_instance_id=e.source_instance_id and b.source_generation=e.source_generation
              and b.collection_scope_id='' and b.storage_kind='core_event'
        )
    ), competing as materialized (
        select 1 from unbound
        group by installation_id,source_instance_id,source_generation having count(*)>1
    ), inserted as (
        insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
            source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
        select login,session_user,u.installation_id,'sli.windows.ad-dc',u.source_instance_id,u.source_generation,
            '','core_event',u.log_source_id,u.agent_id
        from unbound u where not exists(select 1 from competing)
        on conflict do nothing
    )
    select exists(select 1 from competing) into competing_binding;

    -- Agent and log-source are outside the unique binding key. When a new key
    -- has competing candidates, let the original statement arbitrate and
    -- authorize against its own snapshot. No bounded-path insert ran.
$bounded$;
begin
    select * into strict saved from public.source_discovery_restore407;
    original_at:=strpos(saved.definition,original_insert);
    if original_at=0 or strpos(substr(saved.definition,original_at+length(original_insert)),original_insert)<>0
       or strpos(saved.definition,old_declaration)=0 then
        raise exception 'bound_source_discovery407_shape' using errcode='55000';
    end if;
    patched:=replace(saved.definition,old_declaration,'declare login oid; competing_binding boolean;');
    execute replace(patched,original_insert,bounded_insert||E'    if competing_binding then\n'||
        original_insert||E'\n    end if;');
    if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
        and p.proacl is not distinct from saved.acl) then
        raise exception 'bound_source_discovery407_metadata' using errcode='55000';
    end if;
    update public.source_discovery_restore407 set installed_definition=pg_get_functiondef(signature);
end $patch$;

reset role;
insert into public.schema_migrations(version,name) values(407,'bound_source_discovery');
commit;
