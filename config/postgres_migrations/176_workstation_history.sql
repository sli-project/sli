-- Workstation evidence holds and scoped detail reads; no cleanup is scheduled.
begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_history_v176'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 176 requires membership in adlog_storage_owner';
    end if;
    -- 175 is reserved by independent AG-DEP work; require the known main predecessor.
    if not exists(select 1 from public.schema_migrations where version=174 and name='agent_gpo_snapshot_import')
       or exists(select 1 from public.schema_migrations where version>=176) then
        raise exception 'migration 176 requires exact migration 174 agent_gpo_snapshot_import';
    end if;
end $$;
set local role adlog_storage_owner;
create table sli_plugin_workstations.observation_holds (
    observation_id text not null references sli_plugin_workstations.observations(id) on delete restrict,
    reason text not null check(reason in ('legal_hold','evidence_reference')),
    created_at timestamptz not null default now(),
    primary key (observation_id,reason)
);
revoke all on sli_plugin_workstations.observation_holds from public,adlog_user;
grant select on sli_plugin_workstations.observation_holds to adlog_workstations_retention;
-- The report/detail applies the same atomic field grant and server station scope.
grant select(source_xml) on sli_plugin_workstations.observations to adlog_user;
reset role;
insert into public.schema_migrations(version,name) values(176,'workstation_history');
commit;
