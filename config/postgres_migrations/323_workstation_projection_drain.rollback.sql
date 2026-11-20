begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_workstation_projection_drain_v323'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=323 and name='workstation_projection_drain')
       or exists(select 1 from public.schema_migrations where version>323) then
        raise exception 'workstation_projection_323_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create or replace function public.heartbeat_core_job_v1(p_job uuid,p_token uuid,p_generation bigint) returns boolean
language plpgsql security definer set search_path=pg_catalog,public as $$
begin
    update sli_jobs.jobs set heartbeat_at=clock_timestamp(),
        lease_until=least(deadline_at,clock_timestamp()+interval '60 seconds')
    where job_id=p_job and lease_token=p_token and lease_generation=p_generation
      and state='leased' and lease_until>clock_timestamp() and deadline_at>clock_timestamp()
      and public.core_job_profile_v1(resource_profile,'dispatcher');
    return found;
end $$;
delete from public.schema_migrations where version=323 and name='workstation_projection_drain';
reset role;
commit;
