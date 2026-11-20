-- Live queries are not process failures. Keep lock acquisition limits and all
-- existing job leases, admission, hashes and publication fences unchanged.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_core_job_recovery_v322'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=321)
       or exists(select 1 from public.schema_migrations where version>=322) then
        raise exception 'core_job_322_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.core_job_role_limits322(role_name name primary key,statement_limit text,idle_limit text);
revoke all on public.core_job_role_limits322 from public,adlog_user;
insert into public.core_job_role_limits322
select rolname,
    (select substr(setting,length('statement_timeout=')+1) from unnest(rolconfig) setting where setting like 'statement_timeout=%'),
    (select substr(setting,length('idle_in_transaction_session_timeout=')+1) from unnest(rolconfig) setting where setting like 'idle_in_transaction_session_timeout=%')
from pg_roles where rolname in (
    'sli_job_dispatcher_light','sli_job_executor_light','sli_job_publisher_light',
    'sli_job_dispatcher_heavy','sli_job_executor_heavy','sli_job_publisher_heavy',
    'sli_job_dispatcher_long','sli_job_executor_long','sli_job_publisher_long');
reset role;
do $$ declare r record; begin
    if (select count(*) from public.core_job_role_limits322)<>9 then
        raise exception 'core_job_322_roles_missing' using errcode='55000';
    end if;
    for r in select role_name from public.core_job_role_limits322 loop
        execute format('alter role %I reset statement_timeout',r.role_name);
        execute format('alter role %I reset idle_in_transaction_session_timeout',r.role_name);
    end loop;
end $$;
-- workstation_projection_pending(projector_key,projection_version,work_id)
-- WHERE applied_at IS NULL (254) already supports the per-consumer bounded
-- lateral seeks. No duplicate index, blocking build or retained-data scan.
set local role adlog_storage_owner;
create function public.read_workstation_projection_progress_v322() returns text
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if not public.core_job_profile_v1('light','dispatcher') then
        raise exception 'core_job_profile_denied' using errcode='42501';
    end if;
    -- Index seeks only: this token permits another bounded job immediately
    -- after progress, while an unchanged/empty source retains interval polling.
    return (select encode(sha256(convert_to(coalesce(jsonb_agg(jsonb_build_array(c.projector_key,c.projection_version,
        c.backfill_position,c.backfill_complete,p.work_id) order by c.projector_key,c.projection_version),'[]'::jsonb)::text,'UTF8')),'hex')
        from sli_plugin_workstations.projection_consumers c left join lateral (
            select r.work_id from sli_plugin_workstations.projection_receipts r
            where r.projector_key=c.projector_key and r.projection_version=c.projection_version and r.applied_at is null
            order by r.work_id limit 1
        ) p on true);
end $$;
revoke all on function public.read_workstation_projection_progress_v322() from public,adlog_user;
grant execute on function public.read_workstation_projection_progress_v322() to sli_job_dispatcher_light;
create function public.read_core_job_quarantine_v322(p_profile text) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if not public.core_job_profile_v1(p_profile,'dispatcher') then
        raise exception 'core_job_profile_denied' using errcode='42501';
    end if;
    return (select coalesce(jsonb_agg(jsonb_build_object(
        'error_code',error_code,'handler_id',handler_id,'count',n,'sample_job_id',sample_id,'retry_candidate',candidate)),'[]'::jsonb)
        from (select error_code,spec->>'handler_id' handler_id,count(*) n,min(job_id::text) sample_id,
            bool_and(source_instance_id='workstations:projection' and result_sha256 is null
                and lease_token is null and lease_until is null
                and error_code in ('lease_expired','job_statement_cancelled','job_lock_unavailable','job_connection_lost','job_deadline_exceeded')
                and public.core_workstation_projection_binding_v1(spec)) candidate
            from sli_jobs.jobs where state='quarantined' and resource_profile=p_profile
            group by error_code,spec->>'handler_id' order by error_code,spec->>'handler_id') counts);
end $$;
create function public.retry_core_job_v322(p_job uuid,p_expected_code text) returns boolean
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare j sli_jobs.jobs%rowtype; at_time timestamptz:=clock_timestamp();
begin
    if not public.core_job_profile_v1('light','dispatcher') then
        raise exception 'core_job_profile_denied' using errcode='42501';
    end if;
    select * into j from sli_jobs.jobs where job_id=p_job;
    if not found then return false; end if;
    perform pg_advisory_xact_lock(hashtextextended('core-job-source:'||j.plugin_id||':'||j.source_instance_id,0));
    select * into j from sli_jobs.jobs where job_id=p_job for update;
    -- Only a read-current-queue projection can be replayed automatically.
    -- Hash conflicts, unknown execution failures and destructive retention need
    -- individual review. Never reset a published result or a live fence.
    if p_expected_code is null or j.error_code is null or j.state<>'quarantined' or j.error_code is distinct from p_expected_code
       or j.error_code not in ('lease_expired','job_statement_cancelled','job_lock_unavailable','job_connection_lost','job_deadline_exceeded')
       or j.source_instance_id<>'workstations:projection'
       or j.result_sha256 is not null or j.result_ref is not null or j.result_payload is not null
       or j.lease_token is not null or j.lease_until is not null
       or not public.core_workstation_projection_binding_v1(j.spec)
       or not public.core_job_admitted_v1(j.spec)
       or exists(select 1 from sli_jobs.jobs active where active.job_id<>p_job
            and active.plugin_id=j.plugin_id and active.source_instance_id=j.source_instance_id
            and active.state in ('queued','retry_wait','leased')) then return false; end if;
    insert into sli_jobs.audit(job_id,transition,lease_generation,error_code)
        values(p_job,'recovery_requested',j.lease_generation,j.error_code);
    update sli_jobs.jobs set state='queued',attempts=0,available_at=at_time,deadline_at=at_time+interval '300 seconds',
        executor_id=null,heartbeat_at=null,error_code=null,
        spec=spec||jsonb_build_object('available_at_utc',at_time,'deadline_at_utc',at_time+interval '300 seconds')
        where job_id=p_job;
    insert into sli_jobs.audit(job_id,transition,lease_generation) values(p_job,'queued',j.lease_generation);
    return true;
end $$;
revoke all on function public.read_core_job_quarantine_v322(text),public.retry_core_job_v322(uuid,text) from public,adlog_user;
grant execute on function public.read_core_job_quarantine_v322(text) to sli_job_dispatcher_light,sli_job_dispatcher_heavy,sli_job_dispatcher_long;
grant execute on function public.retry_core_job_v322(uuid,text) to sli_job_dispatcher_light;
insert into public.schema_migrations(version,name) values(322,'core_job_recovery');
reset role;
commit;
