-- Stage 10: bounded capability-scoped reader for the immutable admin journal.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_administrative_activity_reader_v72')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 072 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=66 and name='administrative_activity_journal'
    ) then
        raise exception 'migration 072 requires schema migration 066';
    end if;
    if to_regclass('public.administrative_activity_v1') is null
       or to_regprocedure(
           'public.append_administrative_activity_v1(uuid,timestamp with time zone,text,text,text,text,text,text,text,text,jsonb,inet,uuid)'
       ) is null then
        raise exception 'migration 072 requires administrative activity foundation';
    end if;
    if exists (
        select 1 from schema_migrations
        where version=72 and name<>'administrative_activity_reader'
    ) then
        raise exception 'migration 072 marker belongs to another migration';
    end if;
end
$$;

create or replace function read_administrative_activity_v1(
    p_before_activity_id bigint,
    p_limit integer,
    p_category text
)
returns table(
    activity_id bigint,
    event_uid uuid,
    occurred_at_utc timestamptz,
    recorded_at_utc timestamptz,
    actor_kind text,
    actor_key text,
    category text,
    action_key text,
    target_kind text,
    target_key text,
    outcome text,
    reason_code text,
    details_json jsonb,
    remote_address inet,
    correlation_id uuid,
    content_hash_hex text,
    previous_record_hash_hex text,
    record_hash_hex text
)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
begin
    if p_limit is null or p_limit < 1 or p_limit > 201 then
        raise exception 'administrative activity reader limit is invalid';
    end if;
    if p_before_activity_id is not null and p_before_activity_id < 1 then
        raise exception 'administrative activity reader cursor is invalid';
    end if;
    if p_category is not null and p_category not in (
        'authentication','plugin_lifecycle','source_configuration',
        'access_management','report_publication','manual_operation'
    ) then
        raise exception 'administrative activity reader category is invalid';
    end if;

    return query
    select current.activity_id,current.event_uid,current.occurred_at_utc,
           current.recorded_at_utc,current.actor_kind,current.actor_key,
           current.category,current.action_key,current.target_kind,
           current.target_key,current.outcome,current.reason_code,
           current.details_json,current.remote_address,current.correlation_id,
           encode(current.content_hash,'hex'),
           encode(current.previous_record_hash,'hex'),
           encode(current.record_hash,'hex')
    from public.administrative_activity_v1 as current
    where (p_before_activity_id is null
           or current.activity_id < p_before_activity_id)
      and (p_category is null or current.category = p_category)
    order by current.activity_id desc
    limit p_limit;
end
$$;

revoke all on function read_administrative_activity_v1(bigint,integer,text)
    from public;
grant execute on function read_administrative_activity_v1(bigint,integer,text)
    to adlog_user;

grant usage,create on schema public
    to adlog_administrative_activity_owner;
alter function read_administrative_activity_v1(bigint,integer,text)
    owner to adlog_administrative_activity_owner;
revoke create on schema public
    from adlog_administrative_activity_owner;

insert into access_capabilities(capability_key,label,description)
values(
    'administrative.activity.view',
    'Журнал административных действий',
    'Ограниченный просмотр общего неизменяемого административного журнала'
)
on conflict(capability_key) do update
set label=excluded.label,description=excluded.description;

insert into access_package_capabilities(package_id,capability_id)
select package.id,capability.id
from access_packages package
join access_capabilities capability
  on capability.capability_key='administrative.activity.view'
where package.package_key='access_admin'
on conflict do nothing;

do $$
begin
    if not exists (
        select 1
        from access_package_capabilities mapping
        join access_packages package on package.id=mapping.package_id
        join access_capabilities capability on capability.id=mapping.capability_id
        where package.package_key='access_admin'
          and capability.capability_key='administrative.activity.view'
    ) then
        raise exception 'migration 072 access capability mapping failed';
    end if;
end
$$;

insert into schema_migrations(version,name)
values(72,'administrative_activity_reader')
on conflict(version) do update set name=excluded.name;

commit;
