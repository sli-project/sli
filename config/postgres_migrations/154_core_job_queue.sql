-- Core owns leases/results; executors cannot write permanent plugin effects.
begin;
select pg_advisory_xact_lock(hashtext('sli_core_job_queue_v154'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=153 and name='semantic_governance') then
        raise exception 'migration 154 prerequisites failed';
    end if;
    if exists(select 1 from public.schema_migrations where version=154) then
        raise exception 'migration 154 already applied';
    end if;
end $$;
create role sli_job_owner nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication;
grant sli_job_owner to adlog_storage_owner;
create schema sli_jobs authorization sli_job_owner;
revoke all on schema sli_jobs from public;
do $$
declare profile text; purpose text; role_name text;
begin
    foreach profile in array array['light','heavy','long'] loop
        foreach purpose in array array['dispatcher','executor','publisher'] loop
            role_name := 'sli_job_'||purpose||'_'||profile;
            execute format('create role %I nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication',role_name);
            execute format('alter role %I set search_path=pg_catalog,public',role_name);
            execute format('alter role %I set statement_timeout=''10s''',role_name);
            execute format('alter role %I set lock_timeout=''1s''',role_name);
            execute format('alter role %I set idle_in_transaction_session_timeout=''15s''',role_name);
            execute format('grant usage on schema public to %I',role_name);
        end loop;
    end loop;
end $$;
-- Only the light VPN publisher inherits the existing restricted consumer DML.
-- Handler identities have no memberships and no payload table privileges.
grant adlog_radius_session_consumer to sli_job_publisher_light with inherit true, set false;
grant select(evidence_uid,canonical_record_sha256) on public.core_evidence_manifests to sli_job_publisher_light;
grant execute on function public.read_plugin_component_runtime_guard_v1(text,text) to sli_job_owner;
grant select on public.acquisition_consumer_subscriptions to sli_job_owner;
grant select on public.acquisition_delivery_outbox to sli_job_owner;
grant select(plugin_id,manifest_sha256,package_version,package_lifecycle,desired_activation,component_runtime)
    on public.plugin_installations_v1 to sli_job_owner;
grant select(source_instance_id) on public.acquisition_source_instances to sli_job_owner;
grant usage,create on schema public to sli_job_owner;
set local role sli_job_owner;
create table sli_jobs.jobs (
    job_id uuid primary key,
    spec jsonb not null check (jsonb_typeof(spec)='object'),
    idempotency_key text not null unique check (idempotency_key ~ '^[0-9a-f]{64}$'),
    schedule_key text unique check (schedule_key is null or schedule_key ~ '^[0-9a-f]{64}$'),
    plugin_id text not null, source_instance_id text not null, partition_key text not null,
    resource_profile text not null check (resource_profile in ('light','heavy','long')),
    rights_profile text not null check (rights_profile='vpn-read'),
    state text not null default 'queued' check (state in
        ('queued','leased','retry_wait','completed','quarantined','blocked','cancelled')),
    priority integer not null check (priority between 0 and 2),
    attempts integer not null default 0,
    max_attempts integer not null check (max_attempts between 1 and 32),
    available_at timestamptz not null, deadline_at timestamptz not null,
    created_at timestamptz not null default clock_timestamp(),
    lease_token uuid, lease_generation bigint not null default 0,
    executor_id text, lease_until timestamptz, heartbeat_at timestamptz,
    result_sha256 text, result_ref jsonb, result_payload jsonb, error_code text,
    check ((state='leased')=(lease_token is not null and lease_until is not null)),
    check (deadline_at>available_at)
);
create unique index core_job_partition_writer on sli_jobs.jobs(plugin_id,source_instance_id,partition_key)
    where state='leased';
create index core_job_claim on sli_jobs.jobs(resource_profile,available_at,created_at)
    where state in ('queued','retry_wait');
create table sli_jobs.audit (
    audit_id bigint generated always as identity primary key,
    job_id uuid not null references sli_jobs.jobs, transition text not null,
    lease_generation bigint not null, error_code text, at_utc timestamptz not null default clock_timestamp()
);
revoke all on all tables in schema sli_jobs from public;
revoke all on all sequences in schema sli_jobs from public;

create function public.core_job_profile_v1(p_profile text,p_purpose text) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select p_profile in ('light','heavy','long') and p_purpose in ('dispatcher','executor','publisher')
        and pg_has_role(session_user,'sli_job_'||p_purpose||'_'||p_profile,'MEMBER')
$$;
create function public.core_job_admitted_v1(p_spec jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select case when p_spec->>'plugin_id'='sli.remote-access' then
        -- The pilot adapter retains the canonical v2 installation/admission axes.
        p_spec->>'plugin_id'='sli.remote-access'
        and p_spec->>'handler_id'='radius-session-observation'
        and exists(select 1 from public.read_plugin_component_runtime_guard_v1(
            'sli.remote-access','radius-session-observation') g
            where g.desired_activation='enabled_manual' and g.component_runtime='running' and g.admission_mode='open')
        and exists(select 1 from public.acquisition_consumer_subscriptions s
            where s.subscription_id=p_spec->'pinned_input'->>'subscription_id'
              and s.source_instance_id=p_spec->>'source_instance_id'
              and s.consumer_id='sli.windows.vpn-radius'
              and s.consumer_component_id='radius-session-observation')
    else
        (p_spec->>'plugin_id'='sli.core' or exists(
            select 1 from public.plugin_installations_v1 i
            where i.plugin_id=p_spec->>'plugin_id' and i.package_lifecycle='registered'
                and i.desired_activation='enabled_manual' and i.component_runtime='running'
                and i.package_version=p_spec->>'plugin_version' and i.manifest_sha256=p_spec->>'manifest_sha256'))
        and exists(select 1 from public.acquisition_source_instances s
            where s.source_instance_id=p_spec->>'source_instance_id')
    end
$$;
create function public.enqueue_core_job_v1(p_spec jsonb) returns uuid
language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_job sli_jobs.jobs%rowtype; v_id uuid;
begin
    if not public.core_job_profile_v1(p_spec->>'resource_profile','dispatcher')
       or p_spec->>'rights_profile'<>'vpn-read'
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

create function public.claim_core_job_v1(p_profile text,p_executor text,p_identities jsonb) returns jsonb
language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_job sli_jobs.jobs%rowtype; v_now timestamptz:=clock_timestamp();
begin
    if not public.core_job_profile_v1(p_profile,'dispatcher') then raise exception 'core_job_profile_denied'; end if;
    -- Reap exhausted/crashed jobs instead of leaving permanently invisible leases.
    with expired as (
        update sli_jobs.jobs set state=case when attempts>=max_attempts or deadline_at<=v_now
                then 'quarantined' else 'retry_wait' end,
            available_at=v_now+make_interval(secs=>least(3600,30*power(2,least(greatest(attempts-1,0),7)))::integer),
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

create function public.heartbeat_core_job_v1(p_job uuid,p_token uuid,p_generation bigint) returns boolean
language plpgsql security definer set search_path=pg_catalog,public as $$
begin
    update sli_jobs.jobs set heartbeat_at=clock_timestamp(),
        lease_until=least(deadline_at,clock_timestamp()+interval '60 seconds')
    where job_id=p_job and lease_token=p_token and lease_generation=p_generation
      and state='leased' and lease_until>clock_timestamp() and deadline_at>clock_timestamp()
      and public.core_job_profile_v1(resource_profile,'dispatcher');
    return found;
end $$;
create function public.fail_core_job_v1(p_job uuid,p_token uuid,p_generation bigint,p_code text,p_permanent boolean)
returns boolean language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_job sli_jobs.jobs%rowtype;
begin
    if p_code !~ '^[a-z][a-z0-9_]{0,119}$' then raise exception 'core_job_error_code_invalid'; end if;
    update sli_jobs.jobs set state=case when p_permanent or attempts>=max_attempts then 'quarantined' else 'retry_wait' end,
        available_at=clock_timestamp()+make_interval(secs=>least(3600,30*power(2,least(attempts-1,7)))::integer),
        lease_token=null,lease_until=null,error_code=p_code
    where job_id=p_job and state='leased' and lease_token=p_token and lease_generation=p_generation
      and lease_until>clock_timestamp() and deadline_at>clock_timestamp()
      and public.core_job_profile_v1(resource_profile,'dispatcher') returning * into v_job;
    if not found then return false; end if;
    insert into sli_jobs.audit(job_id,transition,lease_generation,error_code)
        values(p_job,v_job.state,p_generation,p_code);
    return true;
end $$;

create function public.begin_core_job_result_v1(p_job uuid,p_token uuid,p_generation bigint,p_hash text)
returns text language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_job sli_jobs.jobs%rowtype;
begin
    select * into v_job from sli_jobs.jobs where job_id=p_job for update;
    if not found or not public.core_job_profile_v1(v_job.resource_profile,'publisher')
        or p_hash !~ '^[0-9a-f]{64}$' then return 'lost'; end if;
    -- A duplicate is accepted only from the exact previously committed fence.
    if v_job.state in ('completed','blocked','cancelled')
        and v_job.lease_generation=p_generation and v_job.lease_token=p_token then
        if v_job.result_sha256=p_hash then return 'duplicate'; end if;
        update sli_jobs.jobs set state='quarantined',lease_token=null,lease_until=null,
            error_code='result_hash_conflict' where job_id=p_job;
        insert into sli_jobs.audit(job_id,transition,lease_generation,error_code)
            values(p_job,'quarantined',p_generation,'result_hash_conflict');
        return 'conflict';
    end if;
    if v_job.state<>'leased' or v_job.lease_token is distinct from p_token
        or v_job.lease_generation<>p_generation or v_job.lease_until<=clock_timestamp()
        or v_job.deadline_at<=clock_timestamp() then return 'lost'; end if;
    if v_job.plugin_id='sli.remote-access' and not exists(
        select 1 from public.acquisition_consumer_subscriptions s
        where s.subscription_id=v_job.spec->'pinned_input'->>'subscription_id'
          and s.source_instance_id=v_job.source_instance_id
          and s.consumer_id='sli.windows.vpn-radius' and s.consumer_component_id='radius-session-observation') then
        return 'lost';
    end if;
    return 'publish';
end $$;
create function public.finish_core_job_result_v1(p_job uuid,p_token uuid,p_generation bigint,p_hash text,p_result jsonb,p_output jsonb)
returns boolean language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_job sli_jobs.jobs%rowtype;
begin
    if p_result->>'status' is null or p_result->>'status' not in ('success','partial','blocked','cancelled')
        or p_result->>'contract_id' is distinct from 'sli.core-job-result.v1'
        or p_result->>'result_sha256' is distinct from p_hash
        or p_result->>'job_id' is distinct from p_job::text
        or p_result->>'lease_token' is distinct from p_token::text
        or (p_result->>'lease_generation')::bigint is distinct from p_generation then return false; end if;
    update sli_jobs.jobs set state=case p_result->>'status' when 'blocked' then 'blocked'
        when 'cancelled' then 'cancelled' else 'completed' end,
        result_sha256=p_hash,result_ref=p_result,result_payload=p_output,lease_until=null,
        error_code=p_result->>'error_code'
    where job_id=p_job and state='leased' and lease_token=p_token and lease_generation=p_generation
        and lease_until>clock_timestamp() and deadline_at>clock_timestamp()
        and public.core_job_profile_v1(resource_profile,'publisher') returning * into v_job;
    if not found then return false; end if;
    insert into sli_jobs.audit(job_id,transition,lease_generation,error_code)
        values(p_job,v_job.state,p_generation,v_job.error_code);
    return true;
end $$;

-- The child sees only bounded delivery identifiers, never credentials/raw fields.
create function public.read_radius_job_input_v1(p_job uuid,p_token uuid,p_generation bigint)
returns table(delivery_id bigint) language sql security definer set search_path=pg_catalog,public as $$
    select d.delivery_id from sli_jobs.jobs j
    join public.acquisition_consumer_subscriptions s
      on s.subscription_id=j.spec->'pinned_input'->>'subscription_id' and s.source_instance_id=j.source_instance_id
    join public.acquisition_delivery_outbox d on d.subscription_id=s.subscription_id
    where j.job_id=p_job and j.state='leased' and j.lease_token=p_token and j.lease_generation=p_generation
      and j.lease_until>clock_timestamp() and j.deadline_at>clock_timestamp()
      and public.core_job_profile_v1(j.resource_profile,'executor')
      and d.delivery_id in (select value::bigint from jsonb_array_elements_text(j.spec->'pinned_input'->'delivery_ids'))
      and d.available_at<=clock_timestamp() and d.attempt_count<5
      and (d.delivery_state in ('queued','failed') or (d.delivery_state='leased' and d.lease_until<=clock_timestamp()))
    order by d.available_at,d.created_at,d.delivery_id limit 50
$$;
create function public.read_radius_job_source_v1(p_source text) returns jsonb
language sql security definer set search_path=pg_catalog,public as $$
    select jsonb_build_object('source_instance_id',s.source_instance_id,'subscription_id',s.subscription_id,
        'delivery_ids',coalesce((select jsonb_agg(batch.delivery_id) from (
            select d.delivery_id from public.acquisition_delivery_outbox d
            where d.subscription_id=s.subscription_id and d.available_at<=clock_timestamp() and d.attempt_count<5
                and (d.delivery_state in ('queued','failed') or (d.delivery_state='leased' and d.lease_until<=clock_timestamp()))
            order by d.available_at,d.created_at,d.delivery_id limit 50
        ) batch),'[]'::jsonb),
        'revision',s.consumer_component_version::text,'access_scope',jsonb_build_object(
            'mode','restricted','clauses',jsonb_build_array(jsonb_build_object(
                'source_instance_ids',jsonb_build_array(s.source_instance_id),
                'device_ids','[]'::jsonb,'entity_ids','[]'::jsonb,'collection_scope_ids','[]'::jsonb)),
            'decision_id','core-radius-scheduler-v1','policy_revision',s.consumer_component_version::text))
    from public.acquisition_consumer_subscriptions s
    where public.core_job_profile_v1('light','dispatcher')
      and s.consumer_id='sli.windows.vpn-radius' and s.consumer_component_id='radius-session-observation'
      and s.source_instance_id=p_source
    order by s.subscription_id limit 1
$$;

-- No PUBLIC function execution; each login is bound to one resource/rights pair.
do $$
declare f record; profile text;
begin
    for f in select oid::regprocedure as signature from pg_proc
        where pronamespace='public'::regnamespace and proowner='sli_job_owner'::regrole loop
        execute format('revoke all on function %s from public',f.signature);
    end loop;
    foreach profile in array array['light','heavy','long'] loop
        execute format('grant execute on function public.enqueue_core_job_v1(jsonb),public.claim_core_job_v1(text,text,jsonb),public.heartbeat_core_job_v1(uuid,uuid,bigint),public.fail_core_job_v1(uuid,uuid,bigint,text,boolean) to %I','sli_job_dispatcher_'||profile);
        execute format('grant execute on function public.begin_core_job_result_v1(uuid,uuid,bigint,text),public.finish_core_job_result_v1(uuid,uuid,bigint,text,jsonb,jsonb) to %I','sli_job_publisher_'||profile);
    end loop;
end $$;
grant execute on function public.read_radius_job_input_v1(uuid,uuid,bigint) to sli_job_executor_light;
grant execute on function public.read_radius_job_source_v1(text) to sli_job_dispatcher_light;
reset role;
revoke create on schema public from sli_job_owner;
insert into public.schema_migrations(version,name) values(154,'core_job_queue');
commit;
