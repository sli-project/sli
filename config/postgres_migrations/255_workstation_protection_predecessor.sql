-- WR06: bounded predecessor lookup in the durable snapshot history from WR05.
begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_protection_predecessor_v255'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=254 and name='workstation_projection_queue')
       or exists(select 1 from public.schema_migrations where version>=255) then
        raise exception 'migration 255 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;
-- Source upserts serialize snapshots of the same agent. A per-agent work_id
-- orders their immutable captures; it is never a live import high-water mark.
create index workstation_protection_predecessor
    on sli_plugin_workstations.projection_work(agent_key,work_id desc)
    where kind='protection_state';
reset role;
-- The staging role selects only due station IDs, without reading findings,
-- identities, health details or source evidence.
grant select(station_id,protection) on sli_plugin_workstations.station_summary to sli_job_executor_light;
insert into public.schema_migrations(version,name) values(255,'workstation_protection_predecessor');
commit;
