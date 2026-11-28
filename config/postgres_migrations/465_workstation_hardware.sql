begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_hardware465'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=464 and name='file_ransom_episodes')
       or exists(select 1 from public.schema_migrations where version>=465) then
        raise exception 'workstation_hardware465_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.workstation_hardware_latest465 (
    server_id bigint primary key,
    domain_id bigint not null,
    source_id uuid not null,
    observed_at timestamptz not null,
    digest text not null check (digest ~ '^[0-9a-f]{64}$'),
    inventory jsonb not null check (jsonb_typeof(inventory)='object')
);
create table public.workstation_hardware_changes465 (
    server_id bigint not null,
    domain_id bigint not null,
    source_id uuid not null,
    observed_at timestamptz not null,
    packet_id uuid not null,
    ordinal integer not null check (ordinal>=0),
    change jsonb not null check (jsonb_typeof(change)='object'),
    primary key(packet_id,ordinal)
);
create index workstation_hardware_changes465_station on public.workstation_hardware_changes465
    (server_id,domain_id,source_id,observed_at desc,packet_id,ordinal);
create index workstation_hardware_changes465_expiry on public.workstation_hardware_changes465 (observed_at,packet_id,ordinal);
revoke all on public.workstation_hardware_latest465,public.workstation_hardware_changes465 from public;
grant select,insert,update on public.workstation_hardware_latest465 to adlog_user;
grant select,insert on public.workstation_hardware_changes465 to adlog_user;

create function public.prune_workstation_hardware465(p_cutoff timestamptz,p_batch integer)
returns bigint language sql security definer set search_path=pg_catalog,pg_temp as $$
    with due as (
        select packet_id,ordinal from public.workstation_hardware_changes465
        where observed_at<p_cutoff order by observed_at,packet_id,ordinal
        limit greatest(0,least(p_batch,1000))
    ), removed as (
        delete from public.workstation_hardware_changes465 c using due
        where c.packet_id=due.packet_id and c.ordinal=due.ordinal returning 1
    )
    select count(*) from removed
$$;
revoke all on function public.prune_workstation_hardware465(timestamptz,integer) from public;
grant execute on function public.prune_workstation_hardware465(timestamptz,integer) to adlog_storage_lifecycle_delete;

insert into public.schema_migrations(version,name) values(465,'workstation_hardware');
commit;
