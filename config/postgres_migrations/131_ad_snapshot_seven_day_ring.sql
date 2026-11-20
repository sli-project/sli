select pg_advisory_xact_lock(
  hashtext('ad_log_reports_ad_snapshot_seven_day_ring_v131')
);

-- The supplied manifest is accepted only when it is the latest published scheduled
-- manifest for its domain. Publication is the immutable, exact nine-family source set.
do $$
begin
  if exists (
    select 1 from public.schema_migrations
    where version = 131
      and name is distinct from 'ad_snapshot_seven_day_ring'
  ) then
    raise exception 'migration 131 is already registered with a different name';
  end if;

  if not exists (
    select 1 from public.schema_migrations
    where version = 121
      and name = 'ad_snapshot_manifest_foundation'
  ) then
    raise exception 'migration 131 requires 121 ad_snapshot_manifest_foundation';
  end if;

  if not exists (
    select 1 from public.schema_migrations
    where version = 128
      and name = 'ad_snapshot_v2_schedule'
  ) then
    raise exception 'migration 131 requires 128 ad_snapshot_v2_schedule';
  end if;

  if not exists (
    select 1 from public.schema_migrations
    where version = 129
      and name = 'ad_snapshot_projection_retention'
  ) then
    raise exception 'migration 131 requires 129 ad_snapshot_projection_retention';
  end if;

  if not exists (
    select 1 from public.schema_migrations
    where version = 130
      and name = 'what_where_when_hourly_compaction'
  ) then
    raise exception 'migration 131 requires 130 what_where_when_hourly_compaction';
  end if;

  if not exists (select 1 from pg_roles where rolname = 'adlog_user') then
    raise exception 'migration 131 requires runtime role adlog_user';
  end if;

  if to_regclass('public.ad_snapshot_manifests') is null
     or to_regclass('public.ad_snapshot_manifest_sources') is null
     or to_regclass('public.ad_snapshot_projection_receipts') is null
     or to_regclass('public.ad_snapshot_projection_outputs') is null
     or to_regclass('public.users_report_v2_snapshots') is null
     or to_regclass('public.computers_v6_source_snapshots') is null
     or to_regclass('public.gpo_report_v2_source_snapshots') is null
     or to_regclass('public.what_where_when_observations') is null
     or to_regclass('public.what_where_when_projection_state') is null then
    raise exception 'migration 131 requires AD snapshot and What-Where-When tables';
  end if;

  if to_regprocedure('public.ad_snapshot_manifest_reject_mutation()') is null
     or to_regprocedure('public.ad_snapshot_projection_output_reject_mutation()') is null then
    raise exception 'migration 131 requires immutable manifest and output triggers';
  end if;
end
$$;

alter table public.what_where_when_observations
  drop constraint if exists what_where_when_observations_computer_source_snapshot_id_fkey;
alter table public.what_where_when_observations
  drop constraint if exists what_where_when_observations_user_snapshot_id_fkey;
alter table public.what_where_when_projection_state
  drop constraint if exists what_where_when_projection_sta_computer_source_snapshot_id_fkey;
alter table public.what_where_when_projection_state
  drop constraint if exists what_where_when_projection_state_user_snapshot_id_fkey;

alter table public.what_where_when_observations
  alter column computer_source_snapshot_id drop not null;
alter table public.what_where_when_observations
  alter column user_snapshot_id drop not null;

alter table public.what_where_when_observations
  add constraint what_where_when_observations_computer_source_snapshot_id_fkey
  foreign key (computer_source_snapshot_id)
  references public.computers_v6_source_snapshots(source_snapshot_id)
  on delete set null;
alter table public.what_where_when_observations
  add constraint what_where_when_observations_user_snapshot_id_fkey
  foreign key (user_snapshot_id)
  references public.users_report_v2_snapshots(snapshot_id)
  on delete set null;
alter table public.what_where_when_projection_state
  add constraint www_projection_state_computer_source_snapshot_fkey
  foreign key (computer_source_snapshot_id)
  references public.computers_v6_source_snapshots(source_snapshot_id)
  on delete set null;
alter table public.what_where_when_projection_state
  add constraint what_where_when_projection_state_user_snapshot_id_fkey
  foreign key (user_snapshot_id)
  references public.users_report_v2_snapshots(snapshot_id)
  on delete set null;

-- Immutable manifests and outputs remain immutable to all direct statements.
-- The transaction-local gate is enabled only by the restricted expiry procedure.
create or replace function public.ad_snapshot_manifest_reject_mutation()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if tg_op = 'DELETE'
     and session_user = 'adlog_user'
     and current_setting('ad_snapshot_retention.expiry_active', true) = 'on' then
    return old;
  end if;
  raise exception 'AD snapshot manifests are immutable';
end
$$;
alter function public.ad_snapshot_manifest_reject_mutation() owner to postgres;

create or replace function public.ad_snapshot_projection_output_reject_mutation()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if tg_op = 'DELETE'
     and session_user = 'adlog_user'
     and current_setting('ad_snapshot_retention.expiry_active', true) = 'on' then
    return old;
  end if;
  raise exception 'AD snapshot projection outputs are immutable';
end
$$;
alter function public.ad_snapshot_projection_output_reject_mutation() owner to postgres;

create or replace procedure public.expire_ad_snapshot_seven_day_ring(
  p_published_manifest_id uuid
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  anchor_domain_id bigint;
  anchor_scheduled_local_at timestamp without time zone;
  cutoff_local_at timestamp without time zone;
  cutoff_at_utc timestamptz;
  source_family_count integer;
  source_count integer;
begin
  if session_user <> 'adlog_user' then
    raise exception 'AD snapshot expiry may be called only by adlog_user'
      using errcode = '42501';
  end if;

  if p_published_manifest_id is null then
    raise exception 'AD snapshot expiry requires a published manifest id';
  end if;

  perform pg_advisory_xact_lock(
    hashtext('ad_log_reports_ad_snapshot_seven_day_ring_expiry')
  );

  select manifest.domain_id, manifest.scheduled_local_at
  into anchor_domain_id, anchor_scheduled_local_at
  from public.ad_snapshot_manifests manifest
  where manifest.manifest_id = p_published_manifest_id
    and manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
    and manifest.schedule_timezone = 'Asia/Novosibirsk'
    and manifest.scheduled_local_at is not null;

  if not found then
    raise exception 'AD snapshot expiry requires a published scheduled v2 manifest';
  end if;

  select count(*) filter (
           where source.family in ('users_v2', 'computers_v6', 'gpo_v2')
         ),
         count(*)
  into source_family_count, source_count
  from public.ad_snapshot_manifest_sources source
  where source.manifest_id = p_published_manifest_id;

  if source_family_count <> 3 or source_count <> 9 then
    raise exception 'AD snapshot expiry requires the complete published source family set';
  end if;

  if exists (
    select 1
    from public.ad_snapshot_manifests later_manifest
    where later_manifest.domain_id = anchor_domain_id
      and later_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
      and later_manifest.schedule_timezone = 'Asia/Novosibirsk'
      and later_manifest.scheduled_local_at > anchor_scheduled_local_at
  ) then
    raise exception 'AD snapshot expiry refuses a non-latest published scheduled manifest';
  end if;

  cutoff_local_at := anchor_scheduled_local_at - interval '7 days';
  cutoff_at_utc := cutoff_local_at at time zone 'Asia/Novosibirsk';
  perform set_config('ad_snapshot_retention.expiry_active', 'on', true);

  delete from public.users_report_v2_snapshots snapshot
  where snapshot.domain_id = anchor_domain_id
    and snapshot.captured_at_utc <= cutoff_at_utc
    and not exists (
      select 1
      from public.ad_snapshot_manifest_sources retained_source
      join public.ad_snapshot_manifests retained_manifest
        on retained_manifest.manifest_id = retained_source.manifest_id
      where retained_source.family = 'users_v2'
        and retained_source.source_id = snapshot.snapshot_id::text
        and retained_manifest.domain_id = anchor_domain_id
        and retained_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
        and retained_manifest.schedule_timezone = 'Asia/Novosibirsk'
        and retained_manifest.scheduled_local_at > cutoff_local_at
    );

  delete from public.computers_v6_source_snapshots snapshot
  where snapshot.domain_id = anchor_domain_id
    and snapshot.captured_at_utc <= cutoff_at_utc
    and not exists (
      select 1
      from public.ad_snapshot_manifest_sources retained_source
      join public.ad_snapshot_manifests retained_manifest
        on retained_manifest.manifest_id = retained_source.manifest_id
      where retained_source.family = 'computers_v6'
        and retained_source.source_id = snapshot.snapshot_uuid::text
        and retained_manifest.domain_id = anchor_domain_id
        and retained_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
        and retained_manifest.schedule_timezone = 'Asia/Novosibirsk'
        and retained_manifest.scheduled_local_at > cutoff_local_at
    );

  -- GPO snapshots have no captured_at_utc; migration 116 indexes created_at for retention.
  delete from public.gpo_report_v2_source_snapshots snapshot
  where snapshot.domain_id = anchor_domain_id
    and snapshot.created_at <= cutoff_at_utc
    and not exists (
      select 1
      from public.ad_snapshot_manifest_sources retained_source
      join public.ad_snapshot_manifests retained_manifest
        on retained_manifest.manifest_id = retained_source.manifest_id
      where retained_source.family = 'gpo_v2'
        and retained_source.source_id = snapshot.source_run_id::text
        and retained_manifest.domain_id = anchor_domain_id
        and retained_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
        and retained_manifest.schedule_timezone = 'Asia/Novosibirsk'
        and retained_manifest.scheduled_local_at > cutoff_local_at
    );

  delete from public.ad_snapshot_projection_outputs output
  using public.ad_snapshot_manifests expired_manifest
  where output.manifest_id = expired_manifest.manifest_id
    and expired_manifest.domain_id = anchor_domain_id
    and expired_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
    and expired_manifest.schedule_timezone = 'Asia/Novosibirsk'
    and expired_manifest.scheduled_local_at <= cutoff_local_at;

  delete from public.ad_snapshot_projection_receipts receipt
  using public.ad_snapshot_manifests expired_manifest
  where receipt.manifest_id = expired_manifest.manifest_id
    and expired_manifest.domain_id = anchor_domain_id
    and expired_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
    and expired_manifest.schedule_timezone = 'Asia/Novosibirsk'
    and expired_manifest.scheduled_local_at <= cutoff_local_at;

  delete from public.ad_snapshot_manifest_sources source
  using public.ad_snapshot_manifests expired_manifest
  where source.manifest_id = expired_manifest.manifest_id
    and expired_manifest.domain_id = anchor_domain_id
    and expired_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
    and expired_manifest.schedule_timezone = 'Asia/Novosibirsk'
    and expired_manifest.scheduled_local_at <= cutoff_local_at;

  delete from public.ad_snapshot_manifests manifest
  where manifest.domain_id = anchor_domain_id
    and manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'
    and manifest.schedule_timezone = 'Asia/Novosibirsk'
    and manifest.scheduled_local_at <= cutoff_local_at;

  perform set_config('ad_snapshot_retention.expiry_active', 'off', true);
end
$$;
alter procedure public.expire_ad_snapshot_seven_day_ring(uuid) owner to postgres;
revoke all on procedure public.expire_ad_snapshot_seven_day_ring(uuid) from public;
grant execute on procedure public.expire_ad_snapshot_seven_day_ring(uuid) to adlog_user;

do $$
declare
  constraint_name text;
  constraint_definition text;
  manifest_gate_definition text;
  output_gate_definition text;
  expiry_definition text;
  expiry_is_security_definer boolean;
  expiry_owner text;
begin
  foreach constraint_name in array array[
    'what_where_when_observations_computer_source_snapshot_id_fkey',
    'what_where_when_observations_user_snapshot_id_fkey',
    'www_projection_state_computer_source_snapshot_fkey',
    'what_where_when_projection_state_user_snapshot_id_fkey'
  ] loop
    select pg_get_constraintdef(constraint_record.oid)
    into constraint_definition
    from pg_constraint constraint_record
    where constraint_record.conname = constraint_name
      and constraint_record.contype = 'f'
      and constraint_record.conrelid in (
        'public.what_where_when_observations'::regclass,
        'public.what_where_when_projection_state'::regclass
      );

    if constraint_definition is null
       or position('ON DELETE SET NULL' in upper(constraint_definition)) = 0 then
      raise exception 'migration 131 What-Where-When snapshot foreign key readback failed: %', constraint_name;
    end if;
  end loop;

  if exists (
    select 1
    from pg_attribute attribute_record
    where attribute_record.attrelid = 'public.what_where_when_observations'::regclass
      and attribute_record.attname in (
        'computer_source_snapshot_id',
        'user_snapshot_id'
      )
      and attribute_record.attnotnull
      and not attribute_record.attisdropped
  ) then
    raise exception 'migration 131 observation snapshot columns remain not null';
  end if;

  select pg_get_functiondef('public.ad_snapshot_manifest_reject_mutation()'::regprocedure)
  into manifest_gate_definition;
  select pg_get_functiondef('public.ad_snapshot_projection_output_reject_mutation()'::regprocedure)
  into output_gate_definition;
  if position('AD_SNAPSHOT_RETENTION.EXPIRY_ACTIVE' in upper(manifest_gate_definition)) = 0
     or position('AD_SNAPSHOT_RETENTION.EXPIRY_ACTIVE' in upper(output_gate_definition)) = 0
     or not exists (
       select 1 from pg_trigger trigger_record
       where trigger_record.tgrelid = 'public.ad_snapshot_manifests'::regclass
         and trigger_record.tgname = 'trg_ad_snapshot_manifests_immutable'
         and not trigger_record.tgisinternal
     )
     or not exists (
       select 1 from pg_trigger trigger_record
       where trigger_record.tgrelid = 'public.ad_snapshot_manifest_sources'::regclass
         and trigger_record.tgname = 'trg_ad_snapshot_manifest_sources_immutable'
         and not trigger_record.tgisinternal
     )
     or not exists (
       select 1 from pg_trigger trigger_record
       where trigger_record.tgrelid = 'public.ad_snapshot_projection_outputs'::regclass
         and trigger_record.tgname = 'trg_ad_snapshot_projection_outputs_immutable'
         and not trigger_record.tgisinternal
     ) then
    raise exception 'migration 131 immutable trigger gate readback failed';
  end if;

  select procedure_record.prosecdef,
         pg_get_userbyid(procedure_record.proowner),
         pg_get_functiondef(procedure_record.oid)
  into expiry_is_security_definer, expiry_owner, expiry_definition
  from pg_proc procedure_record
  where procedure_record.oid =
    'public.expire_ad_snapshot_seven_day_ring(uuid)'::regprocedure;

  if expiry_is_security_definer is not true
     or expiry_owner <> 'postgres'
     or position('SESSION_USER <> ''ADLOG_USER''' in upper(expiry_definition)) = 0
     or position('INTERVAL ''7 DAYS''' in upper(expiry_definition)) = 0
     or not has_function_privilege(
       'adlog_user',
       'public.expire_ad_snapshot_seven_day_ring(uuid)',
       'EXECUTE'
     )
     or exists (
       select 1
       from pg_proc acl_procedure,
            lateral aclexplode(
              coalesce(acl_procedure.proacl, acldefault('f', acl_procedure.proowner))
            ) privilege_record
       where acl_procedure.oid =
         'public.expire_ad_snapshot_seven_day_ring(uuid)'::regprocedure
         and privilege_record.grantee = 0
         and privilege_record.privilege_type = 'EXECUTE'
     ) then
    raise exception 'migration 131 expiry procedure privilege readback failed';
  end if;
end
$$;

insert into public.schema_migrations(version, name)
values (131, 'ad_snapshot_seven_day_ring')
on conflict(version) do nothing;
