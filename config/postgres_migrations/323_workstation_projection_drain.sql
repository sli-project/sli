-- A live projection drains across short publication transactions. Its rolling
-- deadline follows authenticated dispatcher heartbeats; expired fences stay dead.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_workstation_projection_drain_v323'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=322 and name='core_job_recovery')
       or exists(select 1 from public.schema_migrations where version>=323) then
        raise exception 'workstation_projection_323_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create or replace function public.heartbeat_core_job_v1(p_job uuid,p_token uuid,p_generation bigint) returns boolean
language plpgsql security definer set search_path=pg_catalog,public as $$
declare at_time timestamptz:=clock_timestamp();
begin
    update sli_jobs.jobs j set heartbeat_at=at_time,
        deadline_at=case when j.source_instance_id='workstations:projection'
            and public.core_workstation_projection_binding_v1(j.spec) and public.core_job_admitted_v1(j.spec)
            then greatest(j.deadline_at,at_time+interval '300 seconds') else j.deadline_at end,
        lease_until=least(case when j.source_instance_id='workstations:projection'
            and public.core_workstation_projection_binding_v1(j.spec) and public.core_job_admitted_v1(j.spec)
            then greatest(j.deadline_at,at_time+interval '300 seconds') else j.deadline_at end,at_time+interval '60 seconds')
    where j.job_id=p_job and j.lease_token=p_token and j.lease_generation=p_generation
      and j.state='leased' and j.lease_until>at_time and j.deadline_at>at_time
      and public.core_job_profile_v1(j.resource_profile,'dispatcher');
    return found;
end $$;
-- Preserve the existing function owner and dispatcher-only EXECUTE ACL.
-- Existing queue/receipt indexes already support all bounded seeks; no index DDL.
insert into public.schema_migrations(version,name) values(323,'workstation_projection_drain');
reset role;
commit;
