-- WR10: station-local removable storage identities and compact time membership.
begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_device_seen_v258'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=255 and name='workstation_protection_predecessor')
       or not exists(select 1 from public.schema_migrations where version=254 and name='workstation_projection_queue')
       or not exists(select 1 from public.schema_migrations where version=257 and name='semantic_legacy_admission')
       or exists(select 1 from public.schema_migrations where version>=258) then
        raise exception 'migration 258 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;

-- The full instance ID is meaningful only within this station; no serial index.
create table sli_plugin_workstations.device_seen (
    station_id text not null references sli_plugin_workstations.station_inventory(station_id),
    device_key text not null check(device_key ~ '^[a-f0-9]{64}$'),
    device_id text not null check(length(trim(device_id)) between 1 and 512),
    description text check(length(description)<=512),
    identity_quality text not null check(identity_quality='station_instance'),
    storage_evidence boolean not null check(storage_evidence),
    first_seen_at timestamptz not null,
    last_seen_at timestamptz not null check(last_seen_at>=first_seen_at),
    first_ref jsonb not null check(jsonb_typeof(first_ref)='object' and octet_length(first_ref::text)<=2048),
    last_ref jsonb not null check(jsonb_typeof(last_ref)='object' and octet_length(last_ref::text)<=2048),
    primary key(station_id,device_key)
);
create index workstation_device_history_boundary on sli_plugin_workstations.device_seen(station_id,first_seen_at);

-- One timestamp per device sighting, no XML, actors or unbounded evidence arrays.
-- Retained independently of expiring observations, including late delivery.
create table sli_plugin_workstations.device_seen_occurrences (
    station_id text not null,
    device_key text not null,
    observed_at timestamptz not null,
    primary key(station_id,device_key,observed_at),
    foreign key(station_id,device_key) references sli_plugin_workstations.device_seen(station_id,device_key)
);
create index workstation_devices_7d on sli_plugin_workstations.device_seen_occurrences(station_id,observed_at,device_key);

create trigger workstation_projection_guard before insert or update on sli_plugin_workstations.device_seen
    for each row execute function sli_plugin_workstations.guard_projection_publication();
create trigger workstation_projection_guard before insert or update on sli_plugin_workstations.device_seen_occurrences
    for each row execute function sli_plugin_workstations.guard_projection_publication();
revoke all on sli_plugin_workstations.device_seen,sli_plugin_workstations.device_seen_occurrences from public,adlog_user;
reset role;
grant select,insert,update on sli_plugin_workstations.device_seen to sli_job_publisher_light;
grant select,insert on sli_plugin_workstations.device_seen_occurrences to sli_job_publisher_light;
-- Request access is station-scoped by the WS reader; runtime may only read.
grant select on sli_plugin_workstations.device_seen,sli_plugin_workstations.device_seen_occurrences to adlog_user;
insert into public.schema_migrations(version,name) values(258,'workstation_device_seen');
commit;
