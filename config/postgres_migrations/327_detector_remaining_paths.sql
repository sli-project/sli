-- Bound identity probes by the decoy batch and active-directory probes by its
-- existing 10001-row page. One narrow partial provenance index; no payloads.
begin;
select pg_advisory_xact_lock(hashtext('sli_detector_remaining_paths_v327'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=326 and name='nps_threshold_paths')
       or exists(select 1 from public.schema_migrations where version>=327)
       or (select proowner from pg_proc where oid='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure)
            is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'detector_remaining_327_preflight' using errcode='55000';
    end if;
    if exists(select 1 from unnest(array['public.identity_version_keys_v315','public.inventory_directory_type_v311']) idx
        where not exists(select 1 from pg_index where indexrelid=to_regclass(idx) and indisvalid and indisready)) then
        raise exception 'detector_remaining_327_index_invalid' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create table if not exists public.detector_definitions327(signature text primary key,definition text not null,catalog jsonb not null);
revoke all on public.detector_definitions327 from public,adlog_user,adlog_semantic_worker;
insert into public.detector_definitions327
select oid::regprocedure::text,pg_get_functiondef(oid),to_jsonb(p)-'prosrc'
from pg_proc p where oid in (
    'public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure,
    'sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure)
on conflict do nothing;

reset role;
commit;
-- Online build, as in 324/325. Drop an interrupted invalid index CONCURRENTLY
-- before retry; IF NOT EXISTS is never sufficient to attest a failed build.
create index concurrently if not exists detector_device_provenance327
    on public.core_entity_observations(entity_id,md5(source_instance_id))
    where plugin_id='sli.workstations' and resolution='resolved';
begin;
select pg_advisory_xact_lock(hashtext('sli_detector_remaining_paths_v327'));
set local role adlog_storage_owner;
do $$ begin
    if not exists(select 1 from public.schema_migrations where version=326 and name='nps_threshold_paths')
       or exists(select 1 from public.schema_migrations where version>=327)
       or (select count(*) from public.detector_definitions327)<>2
       or exists(select 1 from public.detector_definitions327 d
            where pg_get_functiondef(d.signature::regprocedure) is distinct from d.definition) then
        raise exception 'detector_remaining_327_definition_changed' using errcode='55000';
    end if;
    if not exists(select 1 from pg_index where indexrelid=to_regclass('public.detector_device_provenance327')
        and indrelid='public.core_entity_observations'::regclass and indisvalid and indisready) then
        raise exception 'detector_remaining_327_index_invalid' using errcode='55000';
    end if;
end $$;

-- Bound the directory inside a private reader, before the security barrier
-- view can choose a full relation scan + sort. The predicate is unchanged;
-- merged identities are tested by their existing unique source index.
create function public.detector_directory_page327(p_type integer)
returns table(id integer,entity_type_id integer,display_name text,domain_id bigint)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    return query execute $page$
        select e.id,e.entity_type_id,e.display_name,e.domain_id
        from public.entities_v2 e where e.entity_type_id=$1 and not exists(
            select 1 from public.entity_identity_merges_v2 merged where merged.source_entity_id=e.id offset 0)
        order by e.id limit 10001
    $page$ using p_type;
end $$;
revoke all on function public.detector_directory_page327(integer) from public,adlog_user,adlog_semantic_worker;
-- The inventory needs existence of provenance, not every historical observation
-- of a device. Seek the registry identity first, then one indexed exact proof.
create function public.detector_workstation_devices327(p_identity text,p_source text)
returns table(entity_id integer,display_name text)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select e.id,e.display_name from public.entities_v2 e
    where e.entity_type_id=(select t.id from public.storage_v2_entity_type t where t.value='device')
      and e.natural_key=p_identity and exists(
        select 1 from public.core_entity_observations o where o.entity_id=e.id
          and o.plugin_id='sli.workstations' and o.resolution='resolved'
          and md5(o.source_instance_id)=md5(p_source) and o.source_instance_id=p_source)
$$;
revoke all on function public.detector_workstation_devices327(text,text) from public,adlog_user,adlog_semantic_worker;
do $$ declare inventory_owner name;begin
    select r.rolname into strict inventory_owner from pg_proc p join pg_roles r on r.oid=p.proowner
        where p.oid='sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure;
    execute format('grant execute on function public.detector_directory_page327(integer) to %I',inventory_owner);
    execute format('grant execute on function public.detector_workstation_devices327(text,text) to %I',inventory_owner);
end $$;
do $$ declare definition text;begin
    select d.definition into strict definition from public.detector_definitions327 d
        where signature='sli_plugin_workstations.inventory_inputs_v1(bigint)';
    if strpos(definition,'from public.detector_active_entities324 e where e.entity_type_id=$1')=0 then
        raise exception 'detector_remaining_327_directory_shape';
    end if;
    definition:=replace(definition,'from public.detector_active_entities324 e where e.entity_type_id=$1',
        'from public.detector_directory_page327($1) e');
    if strpos(definition,E'from registered a join public.core_entity_scope_resources r on r.natural_key=a.identity_key\n            and r.plugin_id=''sli.workstations'' and r.source_instance_id=a.source_instance_id\n            and r.entity_type=''device'' and r.resolution=''resolved''')=0 then
        raise exception 'detector_remaining_327_devices_shape';
    end if;
    definition:=replace(definition,
        E'from registered a join public.core_entity_scope_resources r on r.natural_key=a.identity_key\n            and r.plugin_id=''sli.workstations'' and r.source_instance_id=a.source_instance_id\n            and r.entity_type=''device'' and r.resolution=''resolved''',
        'from registered a cross join lateral public.detector_workstation_devices327(a.identity_key,a.source_instance_id) r');
    execute definition;
end $$;

do $patch$
declare definition text; first_pos integer; last_pos integer; filter_sql text;
begin
    select d.definition into strict definition from public.detector_definitions327 d
        where signature like 'read_account_decoy_events(%';
    if strpos(definition,'select n.*,e.event_id')=0 then raise exception 'detector_remaining_327_projection_shape';end if;
    definition:=replace(definition,'select n.*,e.event_id',
        'select n.normalized_event_id,n.source_event_id,n.semantic_type,n.occurred_at_utc,n.roles_json,n.quality_json,n.normalized_at,e.event_id');
    first_pos:=strpos(definition,'            from public.ad_context_entity_versions v');
    last_pos:=strpos(definition,'            order by role.key,v.entity_id,v.id limit 257');
    if first_pos=0 or last_pos<=first_pos then raise exception 'detector_remaining_327_identity_shape';end if;
    filter_sql:=substr(definition,first_pos,last_pos-first_pos);
    -- Preserve ALL identity, validity, run/domain and full-key predicates. Only
    -- the join order changes: the domain and role determine GIN lookup keys
    -- before opening AD versions, rather than evaluating the GIN expression
    -- for every version for each returned event.
    filter_sql:=replace(filter_sql,
        E'            from public.ad_context_entity_versions v\n            join public.ad_context_runs r on r.run_id=v.source_run_id\n            join public.domains domain on domain.id=r.domain_id\n            cross join lateral jsonb_each_text(e.roles_json) role\n            where r.status=''completed'' and r.domain_id=e.domain_id and v.source_section=''directory_accounts''',
        E'            from public.domains domain\n            cross join lateral jsonb_each_text(e.roles_json) role\n            cross join lateral (\n                select v.* from public.ad_context_entity_versions v\n                where v.source_section=''directory_accounts''');
    if strpos(filter_sql,'select v.*')=0 then raise exception 'detector_remaining_327_identity_join_shape';end if;
    filter_sql:=filter_sql||E'                offset 0\n            ) v\n            join public.ad_context_runs r on r.run_id=v.source_run_id\n            where r.status=''completed'' and r.domain_id=e.domain_id and domain.id=r.domain_id\n';
    definition:=substr(definition,1,first_pos-1)||filter_sql||substr(definition,last_pos);
    execute definition;
end $patch$;
do $$ begin
    if exists(select 1 from public.detector_definitions327 d join pg_proc p on p.oid=d.signature::regprocedure
        where to_jsonb(p)-'prosrc' is distinct from d.catalog) then
        raise exception 'detector_remaining_327_catalog_changed' using errcode='55000';
    end if;
end $$;
insert into public.schema_migrations(version,name) values(327,'detector_remaining_paths');
reset role;
commit;
