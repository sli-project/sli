-- Add AD/GPO adapters to the stage-3 ledger without changing its history.
begin;
select pg_advisory_xact_lock(hashtext('sli_ad_gpo_core_jobs_v158'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=154 and name='core_job_queue')
       or to_regclass('public.ad_snapshot_projection_outputs') is null then
        raise exception 'migration 158 prerequisites failed';
    end if;
    if exists(select 1 from public.schema_migrations where version=158) then
        raise exception 'migration 158 already applied';
    end if;
end $$;

grant usage,create on schema public to sli_job_owner;
grant select on public.ad_snapshot_manifests,public.ad_snapshot_manifest_sources,
    public.ad_snapshot_projection_receipts to sli_job_owner;
set local role sli_job_owner;
alter table sli_jobs.jobs drop constraint jobs_rights_profile_check;
alter table sli_jobs.jobs add constraint jobs_rights_profile_check
    check ((resource_profile='light' and rights_profile='vpn-read')
        or (resource_profile='heavy' and rights_profile='ad-read')
        or (resource_profile='long' and rights_profile='gpo-read'));

-- The report-only stage-2 packages have no lifecycle row yet. Observe any
-- existing lifecycle row without activating a package or creating installations.
create function public.core_ad_job_plugin_enabled_v1(p_plugin text) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select p_plugin in ('sli.ad','sli.gpo') and not exists(
        select 1 from public.plugin_installations_v1 i where i.plugin_id=p_plugin
          and (i.package_lifecycle<>'registered' or i.package_version<>'1.0.0'
               or i.desired_activation<>'enabled_manual'
               or i.component_runtime<>'running'))
$$;

-- Bind the read-only directory adapter's stable source identity to an immutable
-- manifest. No acquisition credential or directory name enters the queue.
create function public.core_ad_job_binding_v1(p_spec jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select public.core_ad_job_plugin_enabled_v1(p_spec->>'plugin_id')
      and p_spec->>'plugin_version'='1.0.0' and p_spec->>'handler_version'='1.0.0'
      and p_spec->>'partition_key'='ad-snapshot'
      and p_spec->>'input_contract'='sli.ad-snapshot-job-input.v1'
      and p_spec->>'result_contract'='sli.ad-snapshot-job-output.v1'
      and ((p_spec->>'plugin_id'='sli.ad' and p_spec->>'resource_profile'='heavy'
          and p_spec->>'rights_profile'='ad-read' and p_spec->>'handler_id' in (
            'ad-snapshot-manifest-coordinator','ad-snapshot-projection','ad-context-snapshot',
            'computers-v6-source','users-report-v2-snapshot')
          and p_spec->>'manifest_sha256'='bc08471ce76d315edcc7d7920a00dc49d61ba055f93d8137d03779790f67303c')
        or (p_spec->>'plugin_id'='sli.gpo' and p_spec->>'resource_profile'='long'
          and p_spec->>'rights_profile'='gpo-read'
          and p_spec->>'handler_id' in ('gpo-snapshot','gpo-acquisition')
          and p_spec->>'manifest_sha256'='ff2855b77e4575502c1da55e60288a281377921bc2b76a91c899c86cc54b36c1'))
      and exists(select 1 from public.ad_snapshot_manifests m
        where m.manifest_id::text=p_spec->'pinned_input'->>'manifest_id'
          and m.domain_id::text=p_spec->'pinned_input'->>'domain_id'
          and 'ad-domain:'||m.domain_id::text=p_spec->>'source_instance_id'
          and encode(m.manifest_sha256,'hex')=p_spec->'pinned_input'->>'snapshot_sha256'
          and p_spec->'access_scope'=jsonb_build_object(
            'mode','restricted','clauses',jsonb_build_array(jsonb_build_object(
              'source_instance_ids',jsonb_build_array('ad-domain:'||m.domain_id::text),
              'collection_scope_ids',jsonb_build_array('ad-domain:'||m.domain_id::text),
              'device_ids','[]'::jsonb,'entity_ids','[]'::jsonb)),
            'decision_id','core-ad-snapshot-scheduler-v1','policy_revision','1'))
$$;

-- Retain the RADIUS admission adapter byte for byte, including source gating.
alter function public.core_job_admitted_v1(jsonb) rename to core_job_admitted_radius_v1;
create function public.core_job_admitted_v1(p_spec jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select case when p_spec->>'plugin_id' in ('sli.ad','sli.gpo')
        then public.core_ad_job_binding_v1(p_spec)
        else public.core_job_admitted_radius_v1(p_spec) end
$$;

-- Filled from migration 154's enqueue implementation; only rights admission changes.
create or replace function public.enqueue_core_job_v1(p_spec jsonb) returns uuid
language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_job sli_jobs.jobs%rowtype; v_id uuid;
begin
    if not public.core_job_profile_v1(p_spec->>'resource_profile','dispatcher')
       or not (p_spec->>'rights_profile'='vpn-read' or public.core_ad_job_binding_v1(p_spec))
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

create function public.read_ad_snapshot_job_sources_v1(p_plugin text) returns setof jsonb
language sql stable security definer set search_path=pg_catalog,public as $$
    select jsonb_build_object('plugin_id',p_plugin,'source_instance_id','ad-domain:'||m.domain_id::text,
        'domain_id',m.domain_id,'manifest_id',m.manifest_id::text,
        'snapshot_sha256',encode(m.manifest_sha256,'hex'),'revision','1',
        'access_scope',jsonb_build_object('mode','restricted','clauses',jsonb_build_array(
          jsonb_build_object('source_instance_ids',jsonb_build_array('ad-domain:'||m.domain_id::text),
            'collection_scope_ids',jsonb_build_array('ad-domain:'||m.domain_id::text),
            'device_ids','[]'::jsonb,'entity_ids','[]'::jsonb)),
          'decision_id','core-ad-snapshot-scheduler-v1','policy_revision','1'))
    from public.ad_snapshot_manifests m
    where public.core_ad_job_plugin_enabled_v1(p_plugin)
      and public.core_job_profile_v1(case p_plugin when 'sli.ad' then 'heavy' else 'long' end,'dispatcher')
      and exists(select 1 from public.ad_snapshot_projection_receipts r
        where r.manifest_id=m.manifest_id and r.status<>'completed'
          and ((p_plugin='sli.ad' and r.projection_key in ('ad.state','ad.users.v2','ad.computers.v6'))
            or (p_plugin='sli.gpo' and r.projection_key='ad.gpo.v2'))
          and not exists(select 1 from sli_jobs.jobs j where j.plugin_id=p_plugin
            and j.spec->'pinned_input'->>'manifest_id'=m.manifest_id::text
            and j.spec->>'handler_id'=case r.projection_key
                when 'ad.state' then 'ad-snapshot-manifest-coordinator'
                when 'ad.users.v2' then 'users-report-v2-snapshot'
                when 'ad.computers.v6' then 'ad-snapshot-projection' else 'gpo-snapshot' end
            and j.state in ('blocked','cancelled','quarantined')))
    order by m.slot_start_utc,m.manifest_id limit 16
$$;

-- Permanent writes require a current publisher fence, also enforced by RLS.
-- GUCs are transaction-local coordinates, not an authority on their own.
create function public.core_ad_job_write_allowed_v1(p_manifest uuid,p_key text) returns boolean
language sql volatile security definer set search_path=pg_catalog,public as $$
    select exists(select 1 from sli_jobs.jobs j
      where j.job_id::text=current_setting('sli.job_id',true)
        and j.lease_token::text=current_setting('sli.job_token',true)
        and j.lease_generation::text=current_setting('sli.job_generation',true)
        and j.state='leased' and j.lease_until>clock_timestamp() and j.deadline_at>clock_timestamp()
        and j.spec->'pinned_input'->>'manifest_id'=p_manifest::text
        and public.core_ad_job_binding_v1(j.spec)
        and public.core_job_profile_v1(j.resource_profile,'publisher')
        and ((j.plugin_id='sli.ad' and
            ((j.spec->>'handler_id'='ad-snapshot-manifest-coordinator' and p_key='ad.state')
             or (j.spec->>'handler_id'='ad-snapshot-projection' and p_key='ad.computers.v6')
             or (j.spec->>'handler_id'='users-report-v2-snapshot' and p_key='ad.users.v2')))
          or (j.plugin_id='sli.gpo' and j.spec->>'handler_id'='gpo-snapshot' and p_key='ad.gpo.v2')))
$$;
revoke all on function public.core_ad_job_plugin_enabled_v1(text),
    public.core_ad_job_binding_v1(jsonb),public.core_job_admitted_v1(jsonb),
    public.read_ad_snapshot_job_sources_v1(text),public.core_ad_job_write_allowed_v1(uuid,text) from public;
grant execute on function public.read_ad_snapshot_job_sources_v1(text) to sli_job_dispatcher_heavy,sli_job_dispatcher_long;
grant execute on function public.core_ad_job_write_allowed_v1(uuid,text) to sli_job_publisher_heavy,sli_job_publisher_long;
reset role;
revoke create on schema public from sli_job_owner;

-- Separate AD and GPO rights/resource pairs. No memberships or DDL grants.
grant select(manifest_id,domain_id,coverage_state,manifest_sha256) on public.ad_snapshot_manifests
    to sli_job_executor_heavy,sli_job_publisher_heavy,sli_job_executor_long,sli_job_publisher_long;
grant select(manifest_id,family,source_id,payload_sha256) on public.ad_snapshot_manifest_sources
    to sli_job_executor_heavy,sli_job_publisher_heavy,sli_job_executor_long,sli_job_publisher_long;
grant select(run_id,domain_id,observed_at_utc,status,bundle_sha256) on public.ad_context_runs
    to sli_job_executor_heavy,sli_job_publisher_heavy;
grant select(snapshot_id,payload_json,payload_sha256) on public.users_report_v2_snapshots
    to sli_job_executor_heavy,sli_job_publisher_heavy;
grant select(snapshot_uuid,payload_json,payload_sha256) on public.computers_v6_source_snapshots
    to sli_job_executor_heavy,sli_job_publisher_heavy;
grant select(source_run_id,payload_json,payload_sha256) on public.gpo_report_v2_source_snapshots
    to sli_job_executor_long,sli_job_publisher_long;
grant select,update on public.ad_snapshot_projection_receipts to sli_job_publisher_heavy,sli_job_publisher_long;
grant select,insert on public.ad_snapshot_projection_outputs to sli_job_publisher_heavy,sli_job_publisher_long;

alter table public.ad_snapshot_projection_receipts enable row level security;
alter table public.ad_snapshot_projection_outputs enable row level security;
-- Preserve the legacy ACLs: policies cannot grant privileges, and core job
-- identities are explicitly excluded from the compatibility policy.
create policy ad_receipts_legacy on public.ad_snapshot_projection_receipts
    using (current_user not like 'sli_job_%') with check (current_user not like 'sli_job_%');
create policy ad_outputs_legacy on public.ad_snapshot_projection_outputs
    using (current_user not like 'sli_job_%') with check (current_user not like 'sli_job_%');
create policy ad_receipts_core_read on public.ad_snapshot_projection_receipts for select
    to sli_job_publisher_heavy using (projection_key in ('ad.state','ad.users.v2','ad.computers.v6'));
create policy ad_receipts_scheduler_read on public.ad_snapshot_projection_receipts for select
    to sli_job_owner using (true);
create policy gpo_receipts_core_read on public.ad_snapshot_projection_receipts for select
    to sli_job_publisher_long using (projection_key='ad.gpo.v2');
create policy ad_outputs_core_read on public.ad_snapshot_projection_outputs for select
    to sli_job_publisher_heavy using (projection_key in ('ad.state','ad.users.v2','ad.computers.v6'));
create policy gpo_outputs_core_read on public.ad_snapshot_projection_outputs for select
    to sli_job_publisher_long using (projection_key='ad.gpo.v2');
create policy snapshot_receipts_core_write on public.ad_snapshot_projection_receipts for update
    to sli_job_publisher_heavy,sli_job_publisher_long
    using (public.core_ad_job_write_allowed_v1(manifest_id,projection_key))
    with check (public.core_ad_job_write_allowed_v1(manifest_id,projection_key));
create policy snapshot_outputs_core_write on public.ad_snapshot_projection_outputs for insert
    to sli_job_publisher_heavy,sli_job_publisher_long
    with check (public.core_ad_job_write_allowed_v1(manifest_id,projection_key));

insert into public.schema_migrations(version,name) values(158,'ad_gpo_core_jobs');
commit;
