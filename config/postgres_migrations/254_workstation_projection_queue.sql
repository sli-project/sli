-- WR05: transactionally captured inputs, bounded publication and replay receipts.
begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_projection_queue_v254'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=253 and name='account_watch')
       or not exists(select 1 from public.schema_migrations where version=252 and name='workstation_overview_projections')
       or exists(select 1 from public.schema_migrations where version>=254) then
        raise exception 'migration 254 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;
create table sli_plugin_workstations.projection_work (
    work_id bigint generated always as identity primary key,
    kind text not null check(kind in ('observations','protection_state','station_inventory')),
    source_id text not null,
    agent_key text,
    station_id text,
    payload jsonb not null check(jsonb_typeof(payload)='object' and not (payload ? 'source_xml')),
    payload_sha256 text not null check(payload_sha256 ~ '^[a-f0-9]{64}$'),
    created_at timestamptz not null default now(),
    unique(kind,source_id),
    check(agent_key is not null or station_id is not null)
);
create table sli_plugin_workstations.projection_consumers (
    projector_key text not null check(length(projector_key) between 1 and 128),
    projection_version integer not null check(projection_version>0),
    backfill_position bigint not null default 0 check(backfill_position>=0),
    backfill_complete boolean not null default false,
    primary key(projector_key,projection_version)
);
create table sli_plugin_workstations.projection_receipts (
    work_id bigint not null references sli_plugin_workstations.projection_work(work_id),
    projector_key text not null check(length(projector_key) between 1 and 128),
    projection_version integer not null check(projection_version>0),
    payload_sha256 text not null check(payload_sha256 ~ '^[a-f0-9]{64}$'),
    applied_at timestamptz,
    primary key(work_id,projector_key,projection_version),
    foreign key(projector_key,projection_version)
        references sli_plugin_workstations.projection_consumers(projector_key,projection_version)
);
create index workstation_projection_pending on sli_plugin_workstations.projection_receipts(projector_key,projection_version,work_id)
    where applied_at is null;

-- Source INSERT/UPDATE and the dirty input commit together. Store normalized
-- facts/snapshots, never XML; protection transitions survive later snapshots.
-- There is deliberately no sequence/hash/time high-water mark for live work.
create function sli_plugin_workstations.enqueue_projection_input(p_kind text,p_payload jsonb) returns void
language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_source text; v_payload jsonb; v_hash text; v_work_id bigint;
begin
    if p_kind not in ('observations','protection_state','station_inventory') then
        raise exception 'workstation_projection_kind_invalid';
    end if;
    perform pg_advisory_xact_lock_shared(hashtext('workstations.projection-consumers'));
    v_payload := p_payload-'source_xml';
    -- Mutable enrichment metadata must not turn an exact observation replay
    -- into a second immutable source input.
    v_source := case p_kind when 'observations' then p_payload->>'id'
        when 'protection_state' then encode(sha256(convert_to(
            (p_payload->>'agent_key')||':'||extract(epoch from (p_payload->>'observed_at')::timestamptz)::text
                ||':'||(p_payload->>'state_sha256'),'UTF8')),'hex')
        else (p_payload->>'station_id')||':'||(p_payload->>'revision') end;
    v_hash := encode(sha256(convert_to(v_payload::text,'UTF8')),'hex');
    insert into sli_plugin_workstations.projection_work(kind,source_id,agent_key,station_id,payload,payload_sha256)
        values(p_kind,v_source,p_payload->>'agent_key',p_payload->>'station_id',v_payload,v_hash)
        on conflict(kind,source_id) do nothing returning work_id into v_work_id;
    if v_work_id is not null then
        insert into sli_plugin_workstations.projection_receipts(work_id,projector_key,projection_version,payload_sha256)
            select v_work_id,projector_key,projection_version,v_hash from sli_plugin_workstations.projection_consumers;
    end if;
end $$;
revoke all on function sli_plugin_workstations.enqueue_projection_input(text,jsonb) from public,adlog_user;
create function sli_plugin_workstations.capture_projection_input() returns trigger
language plpgsql security definer set search_path=pg_catalog,public as $$
begin
    perform sli_plugin_workstations.enqueue_projection_input(tg_table_name,to_jsonb(new)-'source_xml');
    return new;
end $$;
revoke all on function sli_plugin_workstations.capture_projection_input() from public,adlog_user;
create trigger workstation_observation_dirty after insert on sli_plugin_workstations.observations
    for each row execute function sli_plugin_workstations.capture_projection_input();
create trigger workstation_protection_dirty after insert or update on sli_plugin_workstations.protection_state
    for each row execute function sli_plugin_workstations.capture_projection_input();
create trigger workstation_inventory_dirty after insert or update on sli_plugin_workstations.station_inventory
    for each row execute function sli_plugin_workstations.capture_projection_input();
revoke all on sli_plugin_workstations.projection_work,sli_plugin_workstations.projection_receipts,
    sli_plugin_workstations.projection_consumers
    from public,adlog_user;
reset role;

grant create on schema public to sli_job_owner;
set local role sli_job_owner;
alter table sli_jobs.jobs drop constraint jobs_rights_profile_check;
alter table sli_jobs.jobs add constraint jobs_rights_profile_check
    check ((resource_profile='light' and rights_profile in ('vpn-read','workstations-retention','workstations-projection'))
        or (resource_profile='heavy' and rights_profile='ad-read')
        or (resource_profile='long' and rights_profile='gpo-read'));
create function public.core_workstation_projection_binding_v1(p_spec jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select coalesce(p_spec->>'plugin_id'='sli.workstations'
      and p_spec->>'plugin_version'='1.0.0' and p_spec->>'handler_version'='1.0.0'
      and p_spec->>'handler_id'='workstations.overview-project'
      and p_spec->>'job_type'='reconcile'
      and p_spec->>'resource_profile'='light' and p_spec->>'rights_profile'='workstations-projection'
      and p_spec->>'input_contract'='workstations.projection-input.v1'
      and p_spec->>'result_contract'='sli.core-job-result.v1'
      and p_spec->>'source_instance_id'='workstations:projection'
      and p_spec->>'partition_key'='workstations.overview-project'
      and p_spec->>'manifest_sha256'='2a198ad3cfc421c48610daa11cb7b7a49d1bd7c136e99316a354256dccb144cb'
      and p_spec->'access_scope'=jsonb_build_object('mode','restricted',
        'clauses',jsonb_build_array(jsonb_build_object(
          'source_instance_ids',jsonb_build_array('workstations:projection'),
          'collection_scope_ids','[]'::jsonb,'device_ids','[]'::jsonb,'entity_ids','[]'::jsonb)),
        'decision_id','core-workstation-projection-v1','policy_revision','1')
      and exists(select 1 from public.plugin_installations_v1 i where i.plugin_id='sli.workstations'
        and i.package_lifecycle='registered' and i.package_version='1.0.0'
        and i.desired_activation='enabled_manual' and i.component_runtime='running'),false)
$$;
-- Keep the original retention manifest and its privileges/fence intact.
alter function public.core_workstation_job_binding_v1(jsonb) rename to core_workstation_retention_binding_v192;
create function public.core_workstation_job_binding_v1(p_spec jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select public.core_workstation_retention_binding_v192(p_spec)
        or public.core_workstation_projection_binding_v1(p_spec)
$$;
create or replace function public.core_workstation_job_write_allowed_v1() returns boolean
language sql volatile security definer set search_path=pg_catalog,public as $$
    select exists(select 1 from sli_jobs.jobs j
      where j.job_id::text=current_setting('sli.job_id',true)
        and j.lease_token::text=current_setting('sli.job_token',true)
        and j.lease_generation::text=current_setting('sli.job_generation',true)
        and j.state='leased' and j.lease_until>clock_timestamp() and j.deadline_at>clock_timestamp()
        and public.core_workstation_retention_binding_v192(j.spec)
        and public.core_job_profile_v1('light','publisher'))
$$;
create function public.core_workstation_projection_write_allowed_v1() returns boolean
language sql volatile security definer set search_path=pg_catalog,public as $$
    select exists(select 1 from sli_jobs.jobs j
      where j.job_id::text=current_setting('sli.job_id',true)
        and j.lease_token::text=current_setting('sli.job_token',true)
        and j.lease_generation::text=current_setting('sli.job_generation',true)
        and j.state='leased' and j.lease_until>clock_timestamp() and j.deadline_at>clock_timestamp()
        and public.core_workstation_projection_binding_v1(j.spec)
        and public.core_job_profile_v1('light','publisher'))
$$;
create function public.read_workstation_projection_job_source_v1() returns jsonb
language sql stable security definer set search_path=pg_catalog,public as $$
    select jsonb_build_object('plugin_id','sli.workstations','source_instance_id','workstations:projection',
      'revision','1','access_scope',jsonb_build_object('mode','restricted',
        'clauses',jsonb_build_array(jsonb_build_object(
          'source_instance_ids',jsonb_build_array('workstations:projection'),
          'collection_scope_ids','[]'::jsonb,'device_ids','[]'::jsonb,'entity_ids','[]'::jsonb)),
        'decision_id','core-workstation-projection-v1','policy_revision','1'))
    where public.core_job_profile_v1('light','dispatcher')
$$;
revoke all on function public.core_workstation_retention_binding_v192(jsonb),
    public.core_workstation_job_binding_v1(jsonb),public.core_workstation_projection_binding_v1(jsonb),
    public.core_workstation_projection_write_allowed_v1(),public.read_workstation_projection_job_source_v1() from public;
grant execute on function public.core_workstation_projection_write_allowed_v1() to sli_job_publisher_light,adlog_storage_owner;
grant execute on function public.read_workstation_projection_job_source_v1() to sli_job_dispatcher_light;
reset role;
revoke create on schema public from sli_job_owner;

set local role adlog_storage_owner;
create function sli_plugin_workstations.guard_projection_publication() returns trigger
language plpgsql set search_path=pg_catalog,public as $$
begin
    if current_user='sli_job_publisher_light' and not public.core_workstation_projection_write_allowed_v1() then
        raise exception 'workstation_projection_write_denied';
    end if;
    return new;
end $$;
revoke all on function sli_plugin_workstations.guard_projection_publication() from public;
do $$ declare v_table text; begin
    foreach v_table in array array['projection_work','projection_receipts','projection_consumers','projection_checkpoints',
        'station_summary','check_findings','station_changes'] loop
        execute format('create trigger workstation_projection_guard before insert or update on sli_plugin_workstations.%I
            for each row execute function sli_plugin_workstations.guard_projection_publication()',v_table);
    end loop;
end $$;
create function sli_plugin_workstations.register_projection_consumer(p_key text,p_version integer) returns void
language plpgsql security definer set search_path=pg_catalog,public as $$
begin
    if not public.core_workstation_projection_write_allowed_v1() then
        raise exception 'workstation_projection_write_denied';
    end if;
    if exists(select 1 from sli_plugin_workstations.projection_consumers
        where projector_key=p_key and projection_version=p_version) then return; end if;
    -- Wait for pre-registration import transactions. Later imports see the new
    -- consumer and create their receipt even when their lower work_id commits
    -- after a backfill page. This cursor is never used as a live watermark.
    perform pg_advisory_xact_lock(hashtext('workstations.projection-consumers'));
    insert into sli_plugin_workstations.projection_consumers(projector_key,projection_version)
        values(p_key,p_version) on conflict do nothing;
end $$;
create function sli_plugin_workstations.backfill_projection_input(p_kind text,p_key text) returns void
language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_column text; v_payload jsonb;
begin
    if not public.core_workstation_projection_write_allowed_v1() then
        raise exception 'workstation_projection_write_denied';
    end if;
    v_column := case p_kind when 'observations' then 'id'
        when 'protection_state' then 'agent_key' when 'station_inventory' then 'station_id' end;
    if v_column is null then raise exception 'workstation_projection_kind_invalid'; end if;
    execute format('select to_jsonb(s)-''source_xml'' from sli_plugin_workstations.%I s where %I=$1',p_kind,v_column)
        into v_payload using p_key;
    if v_payload is not null then
        perform sli_plugin_workstations.enqueue_projection_input(p_kind,v_payload);
    end if;
end $$;
revoke all on function sli_plugin_workstations.register_projection_consumer(text,integer),
    sli_plugin_workstations.backfill_projection_input(text,text) from public,adlog_user;
reset role;
grant select on sli_plugin_workstations.projection_work,sli_plugin_workstations.projection_receipts,
    sli_plugin_workstations.station_inventory
    to sli_job_executor_light,sli_job_publisher_light;
grant select on sli_plugin_workstations.protection_state to sli_job_publisher_light;
grant select,insert,update on sli_plugin_workstations.projection_checkpoints,
    sli_plugin_workstations.station_summary,sli_plugin_workstations.check_findings to sli_job_publisher_light;
grant select,insert,update on sli_plugin_workstations.projection_receipts,sli_plugin_workstations.projection_consumers
    to sli_job_publisher_light;
grant select,insert on sli_plugin_workstations.station_changes to sli_job_publisher_light;
grant execute on function sli_plugin_workstations.register_projection_consumer(text,integer),
    sli_plugin_workstations.backfill_projection_input(text,text) to sli_job_publisher_light;
insert into public.schema_migrations(version,name) values(254,'workstation_projection_queue');
commit;
