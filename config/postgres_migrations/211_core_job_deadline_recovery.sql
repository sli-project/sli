-- Recovery must preserve deadline_at > available_at even after the deadline.
-- Terminal jobs keep their schedule time; retry backoff stays before the deadline.
begin;
select pg_advisory_xact_lock(hashtext('sli_core_job_deadline_recovery_v211'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'sli_job_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=154 and name='core_job_queue')
       or not exists(select 1 from public.schema_migrations where version=210 and name='vpn_session_indexed_identity')
       or exists(select 1 from public.schema_migrations where version>=211) then
        raise exception 'migration 211 prerequisites failed';
    end if;
end $$;
grant usage,create on schema public to sli_job_owner;
set local role sli_job_owner;

create or replace function public.claim_core_job_v1(p_profile text,p_executor text,p_identities jsonb) returns jsonb
language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_job sli_jobs.jobs%rowtype; v_now timestamptz:=clock_timestamp();
begin
    if not public.core_job_profile_v1(p_profile,'dispatcher') then raise exception 'core_job_profile_denied'; end if;
    -- Reap exhausted/crashed jobs instead of leaving permanently invisible leases.
    with expired as (
        update sli_jobs.jobs set state=case when attempts>=max_attempts or deadline_at<=v_now
                then 'quarantined' else 'retry_wait' end,
            available_at=case when attempts>=max_attempts or deadline_at<=v_now then available_at
                else least(v_now+make_interval(secs=>least(3600,30*power(2,least(greatest(attempts-1,0),7)))::integer),
                           deadline_at-interval '1 microsecond') end,
            lease_token=null,lease_until=null,error_code='lease_expired'
        where resource_profile=p_profile and ((state='leased' and lease_until<=v_now)
            or (state in ('queued','retry_wait') and deadline_at<=v_now))
        returning job_id,state,lease_generation,error_code
    ) insert into sli_jobs.audit(job_id,transition,lease_generation,error_code)
        select job_id,state,lease_generation,error_code from expired;
    for v_job in select * from sli_jobs.jobs j
        where j.resource_profile=p_profile and j.state in ('queued','retry_wait')
          and j.attempts<j.max_attempts and j.available_at<=v_now and j.deadline_at>v_now
          and public.core_job_admitted_v1(j.spec)
          and exists(select 1 from jsonb_array_elements(p_identities) i
            where i->>'plugin_id'=j.plugin_id and i->>'handler_id'=j.spec->>'handler_id'
              and i->>'handler_version'=j.spec->>'handler_version'
              and i->>'plugin_version'=j.spec->>'plugin_version'
              and i->>'manifest_sha256'=j.spec->>'manifest_sha256')
          and not exists(select 1 from sli_jobs.jobs active where active.plugin_id=j.plugin_id
            and active.source_instance_id=j.source_instance_id and active.partition_key=j.partition_key
            and active.state='leased')
        -- Aging gives background work a bounded priority advantage.
        order by j.priority+floor(extract(epoch from (v_now-j.created_at))/300) desc,j.created_at,j.job_id
        for update skip locked limit 16
    loop
        if not pg_try_advisory_xact_lock(hashtextextended(
            v_job.plugin_id||':'||v_job.source_instance_id||':'||v_job.partition_key,0)) then continue; end if;
        if exists(select 1 from sli_jobs.jobs active where active.plugin_id=v_job.plugin_id
            and active.source_instance_id=v_job.source_instance_id and active.partition_key=v_job.partition_key
            and active.state='leased') then continue; end if;
        update sli_jobs.jobs set state='leased',attempts=attempts+1,
            lease_token=gen_random_uuid(),lease_generation=lease_generation+1,executor_id=p_executor,
            heartbeat_at=v_now,lease_until=least(deadline_at,v_now+interval '60 seconds')
            where job_id=v_job.job_id returning * into v_job;
        insert into sli_jobs.audit(job_id,transition,lease_generation) values(v_job.job_id,'leased',v_job.lease_generation);
        return v_job.spec||jsonb_build_object('job_id',v_job.job_id,'lease_token',v_job.lease_token,
            'lease_generation',v_job.lease_generation,'attempts',v_job.attempts,
            'remaining_seconds',extract(epoch from (v_job.deadline_at-clock_timestamp())));
    end loop;
    return null;
end $$;

create or replace function public.fail_core_job_v1(p_job uuid,p_token uuid,p_generation bigint,p_code text,p_permanent boolean)
returns boolean language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_job sli_jobs.jobs%rowtype;
begin
    if p_code !~ '^[a-z][a-z0-9_]{0,119}$' then raise exception 'core_job_error_code_invalid'; end if;
    update sli_jobs.jobs set state=case when p_permanent or attempts>=max_attempts then 'quarantined' else 'retry_wait' end,
        available_at=case when p_permanent or attempts>=max_attempts then available_at
            else least(clock_timestamp()+make_interval(secs=>least(3600,30*power(2,least(attempts-1,7)))::integer),
                       deadline_at-interval '1 microsecond') end,
        lease_token=null,lease_until=null,error_code=p_code
    where job_id=p_job and state='leased' and lease_token=p_token and lease_generation=p_generation
      and lease_until>clock_timestamp() and deadline_at>clock_timestamp()
      and public.core_job_profile_v1(resource_profile,'dispatcher') returning * into v_job;
    if not found then return false; end if;
    insert into sli_jobs.audit(job_id,transition,lease_generation,error_code)
        values(p_job,v_job.state,p_generation,p_code);
    return true;
end $$;

reset role;
revoke create on schema public from sli_job_owner;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(211,'core_job_deadline_recovery');
commit;
