-- Storage V2 direct-ingest identity foundation.
-- Additive only: migration 089 is intentionally outside this cutover.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_v2_direct_identity_v90'));

do $$
declare
    greatest_event_id bigint;
    greatest_entity_id bigint;
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'member') then
        raise exception 'migration 090 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=88 and name='source_capture_continuity_declarations'
    ) then
        raise exception 'migration 090 requires migration 088';
    end if;
    if exists(select 1 from schema_migrations where version=90) then
        raise exception 'migration 090 version is already recorded';
    end if;
    if to_regclass('public.events') is null
       or to_regclass('public.events_v2_core') is null
       or to_regclass('public.observed_entities') is null
       or to_regclass('public.entities_v2') is null
       or to_regclass('public.entities_v2_id_seq') is null then
        raise exception 'migration 090 requires intact V1 and V2 identity relations';
    end if;

    select greatest(
        coalesce((select max(id) from events), 0),
        coalesce((select max(id) from events_v2_core), 0)
    ) into greatest_event_id;
    select greatest(
        coalesce((select max(id) from observed_entities), 0),
        coalesce((select max(id) from entities_v2), 0)
    ) into greatest_entity_id;

    if greatest_event_id >= 2147483647 then
        raise exception 'migration 090 event int32 identity capacity is exhausted at %', greatest_event_id;
    end if;
    if greatest_entity_id >= 2147483647 then
        raise exception 'migration 090 entity int32 identity capacity is exhausted at %', greatest_entity_id;
    end if;
end
$$;

create sequence if not exists storage_v2_event_id_seq;
alter sequence storage_v2_event_id_seq owner to adlog_storage_owner;
alter sequence storage_v2_event_id_seq owned by events_v2_core.id;

select setval(
    'storage_v2_event_id_seq',
    greatest(
        coalesce((select max(id) from events), 0),
        coalesce((select max(id) from events_v2_core), 0),
        1
    ),
    greatest(
        coalesce((select max(id) from events), 0),
        coalesce((select max(id) from events_v2_core), 0)
    ) > 0
);

select setval(
    'entities_v2_id_seq',
    greatest(
        coalesce((select max(id) from observed_entities), 0),
        coalesce((select max(id) from entities_v2), 0),
        1
    ),
    greatest(
        coalesce((select max(id) from observed_entities), 0),
        coalesce((select max(id) from entities_v2), 0)
    ) > 0
);

alter table events_v2_core
    alter column id set default nextval('storage_v2_event_id_seq'::regclass);
alter table entities_v2
    alter column id set default nextval('entities_v2_id_seq'::regclass);

create table storage_v2_event_identity_allocations (
    id integer primary key default nextval('storage_v2_event_id_seq'::regclass),
    server_id bigint not null,
    channel_id integer not null references storage_v2_channel(id),
    event_record_id bigint not null,
    time_created_utc timestamptz not null,
    normalized_hash bytea not null check (octet_length(normalized_hash) = 32),
    allocated_at timestamptz not null default now(),
    unique (server_id, channel_id, event_record_id, time_created_utc)
);

create table storage_v2_entity_identity_allocations (
    id integer primary key default nextval('entities_v2_id_seq'::regclass),
    entity_type_id integer not null references storage_v2_entity_type(id),
    natural_key text not null,
    allocated_at timestamptz not null default now(),
    unique (entity_type_id, natural_key)
);

insert into storage_v2_event_identity_allocations(
    id,server_id,channel_id,event_record_id,time_created_utc,normalized_hash
)
select id,server_id,channel_id,event_record_id,time_created_utc,normalized_hash
from events_v2_core
where event_record_id is not null
on conflict(server_id,channel_id,event_record_id,time_created_utc) do update set
    normalized_hash=excluded.normalized_hash
where storage_v2_event_identity_allocations.id=excluded.id
  and storage_v2_event_identity_allocations.normalized_hash=excluded.normalized_hash;

insert into storage_v2_entity_identity_allocations(id,entity_type_id,natural_key)
select id,entity_type_id,natural_key
from entities_v2
on conflict(entity_type_id,natural_key) do update set id=excluded.id
where storage_v2_entity_identity_allocations.id=excluded.id;

do $$
declare
    bad_events bigint;
    bad_entities bigint;
begin
    select count(*) into bad_events
    from events_v2_core event
    left join storage_v2_event_identity_allocations allocation
      on allocation.server_id=event.server_id
     and allocation.channel_id=event.channel_id
     and allocation.event_record_id=event.event_record_id
     and allocation.time_created_utc=event.time_created_utc
    where event.event_record_id is not null
      and (
        allocation.id is null
        or allocation.id<>event.id
        or allocation.normalized_hash<>event.normalized_hash
      );
    if bad_events<>0 then
        raise exception 'Storage V2 event identity allocation seed mismatch: %', bad_events;
    end if;

    select count(*) into bad_entities
    from entities_v2 entity
    left join storage_v2_entity_identity_allocations allocation
      on allocation.entity_type_id=entity.entity_type_id
     and allocation.natural_key=entity.natural_key
    where allocation.id is null or allocation.id<>entity.id;
    if bad_entities<>0 then
        raise exception 'Storage V2 entity identity allocation seed mismatch: %', bad_entities;
    end if;
end
$$;

grant usage, select on sequence storage_v2_event_id_seq, entities_v2_id_seq
    to adlog_storage_owner;
grant select, insert on table
    storage_v2_event_identity_allocations,
    storage_v2_entity_identity_allocations
    to adlog_storage_owner;
do $$
begin
    if exists(select 1 from pg_roles where rolname='adlog_context_worker') then
        grant usage, select on sequence entities_v2_id_seq to adlog_context_worker;
    end if;
end
$$;

insert into schema_migrations(version, name)
values (90, 'storage_v2_direct_identity')
on conflict(version) do update set name=excluded.name;

commit;
