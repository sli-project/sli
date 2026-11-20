begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_short_cursor355'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=351 and name='inbox_payload_retention')
       or exists(select 1 from public.schema_migrations where version>=355) then
        raise exception 'semantic_short_cursor355_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- The decision cursor sees only individual, importer-attested events. A late
-- commit can fill a hole below a previously observed ID; it is never skipped.
-- No packet access, daily groups, or unproven short rows enter this surface.
create view public.semantic_event_source355 as
with short_events as (
    select h.event_id,h.time_created_utc,h.event_kind,h.domain_id,h.computer,h.method,h.outcome,h.fields,h.source_sha256,h.event_record_id
    from public.event_hot h
    union all
    select f.event_id,f.time_created_utc,f.event_kind,f.domain_id,f.computer,f.method,f.outcome,f.fields,f.source_sha256,f.event_record_id
    from public.event_cold_facts f where not exists(select 1 from public.event_hot h where h.event_id=f.event_id)
), admitted as (
    select e.*,a.server_id,a.channel_id,a.allocated_at,
        coalesce(e.method->'$principals','{}'::jsonb)||e.method||e.outcome||e.fields as data
    from short_events e join public.storage_v2_event_identity_allocations a
      on a.id=e.event_id and a.time_created_utc=e.time_created_utc
      and a.normalized_hash=e.source_sha256 and a.event_record_id=e.event_record_id
      and a.server_id::text=e.method->>'$server_id'
    join public.storage_v2_channel c on c.id=a.channel_id and c.value=e.method->>'$channel'
    where e.source_sha256 is not null and e.method#>>'{$origin,plugin_id}'='sli.windows.ad-dc'
      and nullif(e.method#>>'{$origin,log_source_id}','') is not null
)
select e.event_id as id,e.event_kind as event_id,e.time_created_utc,e.server_id,e.domain_id,e.channel_id,
    (e.method#>>'{$origin,log_source_id}')::bigint as log_source_id,e.source_sha256 as normalized_hash,
    e.allocated_at as migrated_at,null::text as correlation_id,
    e.method->>'$provider' as provider_name,e.method->>'$channel' as channel,
    coalesce(e.method->>'$machine_name',e.computer) as computer,e.event_record_id,
    e.data-'$origin'-'$principals'-'$server_id'-'$channel'-'$provider'-'$machine_name' as event_data_json,
    e.outcome->>'keywords' as keywords,
    e.data->>'SubjectUserSid' as subject_user_sid,e.data->>'SubjectUserName' as subject_user_name,
    coalesce(e.data->>'TargetSid',e.data->>'TargetUserSid') as target_user_sid,e.data->>'TargetUserName' as target_user_name,
    coalesce(e.data->>'IpAddress',e.data->>'ClientAddress',e.data->>'SourceNetworkAddress') as ip_address,
    coalesce(e.data->>'TargetLogonId',e.data->>'SubjectLogonId') as logon_id,
    null::text as noise_class,null::text as noise_catalog_version,e.method->'$origin' as source_origin
from admitted e;
revoke all on public.semantic_event_source355 from public;
grant select on public.semantic_event_source355 to adlog_semantic_worker,adlog_storage_worker;

-- Normalization invalidates a stream summary, not a legacy packet. The
-- normalized-event statement trigger must not resolve an obsolete core row.
do $patch355$ declare definition text; begin
    select pg_get_functiondef('public.semantic_import_notify320()'::regprocedure) into strict definition;
    execute replace(definition,E'\nbegin\n',E'\nbegin\n'||$branch355$
    if tg_table_name='normalized_events' then -- semantic_short_cursor355
        insert into public.semantic_default_dirty320(agent_id,module_id)
        select distinct (e.source_origin->>'agent_id')::uuid,'sli.windows.ad-dc'
        from changed n join public.semantic_event_source355 e on e.id=n.source_event_id
        order by 1,2;
        return null;
    end if;
$branch355$);
end $patch355$;

insert into public.schema_migrations(version,name) values(355,'semantic_short_cursor');
reset role;
commit;
