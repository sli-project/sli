-- Admit bounded workstation history jobs; source evidence stays publisher-fenced.
begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_retention_jobs_v192'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=191 and name='file_audit_reports')
       or not exists(select 1 from public.schema_migrations where version=176 and name='workstation_history')
       or exists(select 1 from public.schema_migrations where version>=192) then
        raise exception 'migration 192 prerequisites failed';
    end if;
end $$;

grant usage,create on schema public to sli_job_owner;
set local role sli_job_owner;
alter table sli_jobs.jobs drop constraint jobs_rights_profile_check;
alter table sli_jobs.jobs add constraint jobs_rights_profile_check
    check ((resource_profile='light' and rights_profile in ('vpn-read','workstations-retention'))
        or (resource_profile='heavy' and rights_profile='ad-read')
        or (resource_profile='long' and rights_profile='gpo-read'));

create function public.core_workstation_job_binding_v1(p_spec jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select coalesce(p_spec->>'plugin_id'='sli.workstations'
      and p_spec->>'plugin_version'='1.0.0' and p_spec->>'handler_version'='1.0.0'
      and p_spec->>'handler_id'='workstations.evidence-retention'
      and p_spec->>'job_type'='reconcile'
      and p_spec->>'resource_profile'='light' and p_spec->>'rights_profile'='workstations-retention'
      and p_spec->>'input_contract'='workstations.retention-policy.v1'
      and p_spec->>'result_contract'='sli.core-job-result.v1'
      and p_spec->>'source_instance_id'='workstations:history'
      and p_spec->>'partition_key'='workstations.evidence-retention'
      and p_spec->>'manifest_sha256'='96cd5c3da068f437223d5122164089bace3170aa6590bc4f77c9ce8ca7bcfec8'
      and p_spec->'access_scope'=jsonb_build_object('mode','restricted',
        'clauses',jsonb_build_array(jsonb_build_object(
          'source_instance_ids',jsonb_build_array('workstations:history'),
          'collection_scope_ids','[]'::jsonb,'device_ids','[]'::jsonb,'entity_ids','[]'::jsonb)),
        'decision_id','core-workstation-retention-v1','policy_revision','1')
      and not exists(select 1 from public.plugin_installations_v1 i where i.plugin_id='sli.workstations'
        and (i.package_lifecycle<>'registered' or i.package_version<>'1.0.0'
          or i.desired_activation<>'enabled_manual' or i.component_runtime<>'running')),false)
$$;

alter function public.core_job_admitted_v1(jsonb) rename to core_job_admitted_before_workstations_v1;
create function public.core_job_admitted_v1(p_spec jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select case when p_spec->>'plugin_id'='sli.workstations'
      then public.core_workstation_job_binding_v1(p_spec)
      else public.core_job_admitted_before_workstations_v1(p_spec) end
$$;

create function public.read_workstation_retention_job_source_v1() returns jsonb
language sql stable security definer set search_path=pg_catalog,public as $$
    select jsonb_build_object('plugin_id','sli.workstations','source_instance_id','workstations:history',
      'revision','1','access_scope',jsonb_build_object('mode','restricted',
        'clauses',jsonb_build_array(jsonb_build_object(
          'source_instance_ids',jsonb_build_array('workstations:history'),
          'collection_scope_ids','[]'::jsonb,'device_ids','[]'::jsonb,'entity_ids','[]'::jsonb)),
        'decision_id','core-workstation-retention-v1','policy_revision','1'))
    where public.core_job_profile_v1('light','dispatcher')
$$;

create function public.core_workstation_job_write_allowed_v1() returns boolean
language sql volatile security definer set search_path=pg_catalog,public as $$
    select exists(select 1 from sli_jobs.jobs j
      where j.job_id::text=current_setting('sli.job_id',true)
        and j.lease_token::text=current_setting('sli.job_token',true)
        and j.lease_generation::text=current_setting('sli.job_generation',true)
        and j.state='leased' and j.lease_until>clock_timestamp() and j.deadline_at>clock_timestamp()
        and public.core_workstation_job_binding_v1(j.spec)
        and public.core_job_profile_v1('light','publisher'))
$$;

revoke all on function public.core_workstation_job_binding_v1(jsonb),public.core_job_admitted_v1(jsonb),
    public.read_workstation_retention_job_source_v1(),public.core_workstation_job_write_allowed_v1() from public;
grant execute on function public.read_workstation_retention_job_source_v1() to sli_job_dispatcher_light;
grant execute on function public.core_workstation_job_write_allowed_v1() to sli_job_publisher_light;
reset role;
revoke create on schema public from sli_job_owner;

-- No role membership and no executor DELETE. UPDATE(id) is needed solely for
-- SELECT FOR UPDATE; the trigger refuses all publisher updates.
grant usage on schema sli_plugin_workstations to sli_job_executor_light,sli_job_publisher_light;
grant select on sli_plugin_workstations.observations,sli_plugin_workstations.observation_holds
    to sli_job_executor_light,sli_job_publisher_light;
grant select(key,value) on public.platform_settings to sli_job_executor_light,sli_job_publisher_light;
grant delete,update(id) on sli_plugin_workstations.observations to sli_job_publisher_light;

set local role adlog_storage_owner;
create function sli_plugin_workstations.guard_core_retention() returns trigger
language plpgsql set search_path=pg_catalog,public as $$
begin
    if current_user='sli_job_publisher_light' then
        if tg_op<>'DELETE' or old.family not in ('processes','usb')
           or not public.core_workstation_job_write_allowed_v1()
           or exists(select 1 from sli_plugin_workstations.observation_holds h where h.observation_id=old.id) then
            raise exception 'workstation_retention_write_denied';
        end if;
    end if;
    if tg_op='DELETE' then return old; end if;
    return new;
end $$;
revoke all on function sli_plugin_workstations.guard_core_retention() from public;
create trigger workstation_core_retention_guard before delete or update on sli_plugin_workstations.observations
    for each row execute function sli_plugin_workstations.guard_core_retention();
reset role;

grant create on schema public to sli_job_owner;
set local role sli_job_owner;
create or replace function public.enqueue_core_job_v1(p_spec jsonb) returns uuid
language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_job sli_jobs.jobs%rowtype; v_id uuid;
begin
    if not public.core_job_profile_v1(p_spec->>'resource_profile','dispatcher')
       or not (p_spec->>'rights_profile'='vpn-read' or public.core_ad_job_binding_v1(p_spec)
           or public.core_workstation_job_binding_v1(p_spec))
       or p_spec->>'contract_id'<>'sli.core-job.v1' then
        raise exception 'core_job_profile_denied';
    end if;
    select * into v_job from sli_jobs.jobs where idempotency_key=p_spec->>'idempotency_key';
    if found then
        -- Availability/deadline describe the first enqueue, not a replay's clock.
        if (v_job.spec-'available_at_utc'-'deadline_at_utc')<>
           (p_spec-'available_at_utc'-'deadline_at_utc') then return null; end if;
        return v_job.job_id;
    end if;
    if not public.core_job_admitted_v1(p_spec) then
        return '00000000-0000-0000-0000-000000000000'::uuid;
    end if;
    perform pg_advisory_xact_lock(hashtextextended(
        'core-job-source:'||(p_spec->>'plugin_id')||':'||(p_spec->>'source_instance_id'),0));
    -- Recheck after serializing concurrent schedulers.
    select * into v_job from sli_jobs.jobs where idempotency_key=p_spec->>'idempotency_key';
    if found then
        if (v_job.spec-'available_at_utc'-'deadline_at_utc')<>
           (p_spec-'available_at_utc'-'deadline_at_utc') then return null; end if;
        return v_job.job_id;
    end if;
    -- A schedule slot pins its first accepted input snapshot. Polling/clock folds
    -- cannot create another job when the source acquires new deliveries.
    select * into v_job from sli_jobs.jobs where schedule_key=p_spec->>'schedule_key';
    if found then return v_job.job_id; end if;
    if (select count(*) from sli_jobs.jobs where plugin_id=p_spec->>'plugin_id'
        and source_instance_id=p_spec->>'source_instance_id' and state in ('queued','retry_wait','leased'))
        >= least(16,(p_spec->>'max_inflight_per_source')::integer) then
        return '00000000-0000-0000-0000-000000000000'::uuid;
    end if;
    v_id := gen_random_uuid();
    insert into sli_jobs.jobs(job_id,spec,idempotency_key,schedule_key,plugin_id,source_instance_id,partition_key,
        resource_profile,rights_profile,priority,max_attempts,available_at,deadline_at)
    values(v_id,p_spec,p_spec->>'idempotency_key',p_spec->>'schedule_key',p_spec->>'plugin_id',p_spec->>'source_instance_id',
        p_spec->>'partition_key',p_spec->>'resource_profile',p_spec->>'rights_profile',
        case p_spec->>'priority' when 'security' then 2 when 'normal' then 1 else 0 end,
        (p_spec->>'max_attempts')::integer,(p_spec->>'available_at_utc')::timestamptz,
        (p_spec->>'deadline_at_utc')::timestamptz);
    insert into sli_jobs.audit(job_id,transition,lease_generation) values(v_id,'queued',0);
    return v_id;
end $$;
reset role;
revoke create on schema public from sli_job_owner;

insert into public.schema_migrations(version,name) values(192,'workstation_retention_jobs');
commit;
