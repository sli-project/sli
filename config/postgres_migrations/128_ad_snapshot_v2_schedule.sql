select pg_advisory_xact_lock(
  hashtext('ad_log_reports_ad_snapshot_v2_schedule_v128')
);

do $$
begin
  if exists (
    select 1 from schema_migrations
    where version = 128
      and name is distinct from 'ad_snapshot_v2_schedule'
  ) then
    raise exception 'migration 128 is already registered with a different name';
  end if;

  if not exists (
    select 1 from schema_migrations
    where version = 121
      and name = 'ad_snapshot_manifest_foundation'
  ) then
    raise exception 'migration 121 ad_snapshot_manifest_foundation is required';
  end if;

  if not exists (
    select 1 from schema_migrations
    where version = 123
      and name = 'ad_snapshot_manifest_utc_slots'
  ) then
    raise exception 'migration 123 ad_snapshot_manifest_utc_slots is required';
  end if;

  if to_regclass('public.ad_snapshot_manifests') is null then
    raise exception 'migration 128 requires ad_snapshot_manifests';
  end if;
end
$$;

alter table ad_snapshot_manifests
  add column if not exists schedule_timezone text;

alter table ad_snapshot_manifests
  add column if not exists scheduled_local_at timestamp without time zone;

create or replace function ad_snapshot_manifest_apply_v2_schedule_header()
returns trigger language plpgsql as $$
declare
  expected_local_at timestamp without time zone;
begin
  if new.contract_version = 'sli.ad-snapshot-manifest/2.0' then
    expected_local_at := new.slot_start_utc at time zone 'Asia/Novosibirsk';
    if new.schedule_timezone is null then
      new.schedule_timezone := 'Asia/Novosibirsk';
    elsif new.schedule_timezone <> 'Asia/Novosibirsk' then
      raise exception 'v2 AD snapshot manifests require Asia/Novosibirsk schedule_timezone';
    end if;
    if new.scheduled_local_at is null then
      new.scheduled_local_at := expected_local_at;
    elsif new.scheduled_local_at is distinct from expected_local_at then
      raise exception 'v2 AD snapshot scheduled_local_at must match slot_start_utc';
    end if;
  elsif new.contract_version = 'sli.ad-snapshot-manifest/1.0' then
    if new.schedule_timezone is not null or new.scheduled_local_at is not null then
      raise exception 'v1 AD snapshot manifests cannot declare a schedule header';
    end if;
  end if;
  return new;
end
$$;

drop trigger if exists trg_ad_snapshot_manifests_v2_schedule_header
  on ad_snapshot_manifests;
create trigger trg_ad_snapshot_manifests_v2_schedule_header
before insert on ad_snapshot_manifests
for each row execute function ad_snapshot_manifest_apply_v2_schedule_header();

alter table ad_snapshot_manifests
  drop constraint ad_snapshot_manifests_contract_version_check;

alter table ad_snapshot_manifests
  add constraint ad_snapshot_manifests_contract_version_check
  check (contract_version in (
    'sli.ad-snapshot-manifest/1.0',
    'sli.ad-snapshot-manifest/2.0'
  ));

alter table ad_snapshot_manifests
  drop constraint ad_snapshot_manifests_slot_start_utc_check;

alter table ad_snapshot_manifests
  add constraint ad_snapshot_manifests_slot_start_utc_check
  check (
    (
      contract_version = 'sli.ad-snapshot-manifest/1.0'
      and schedule_timezone is null
      and scheduled_local_at is null
      and (
        (slot_start_utc at time zone 'UTC') = date_trunc('day', slot_start_utc at time zone 'UTC')
        or (slot_start_utc at time zone 'UTC') = date_trunc('day', slot_start_utc at time zone 'UTC') + interval '12 hours'
      )
    )
    or
    (
      contract_version = 'sli.ad-snapshot-manifest/2.0'
      and schedule_timezone = 'Asia/Novosibirsk'
      and scheduled_local_at is not null
      and scheduled_local_at = date_trunc('minute', scheduled_local_at)
      and scheduled_local_at::time in (time '06:00:00', time '18:00:00')
      and slot_start_utc = scheduled_local_at at time zone 'Asia/Novosibirsk'
    )
  );

do $$
declare
  definition text;
  header_trigger_exists boolean;
begin
  select pg_get_constraintdef(oid)
  into definition
  from pg_constraint
  where conrelid = 'ad_snapshot_manifests'::regclass
    and conname = 'ad_snapshot_manifests_slot_start_utc_check'
    and contype = 'c'
    and convalidated;

  select exists (
    select 1
    from pg_trigger
    where tgrelid = 'ad_snapshot_manifests'::regclass
      and tgname = 'trg_ad_snapshot_manifests_v2_schedule_header'
      and not tgisinternal
  ) into header_trigger_exists;

  if definition is null
     or position('SLI.AD-SNAPSHOT-MANIFEST/1.0' in upper(definition)) = 0
     or position('SLI.AD-SNAPSHOT-MANIFEST/2.0' in upper(definition)) = 0
     or position('ASIA/NOVOSIBIRSK' in upper(definition)) = 0
     or not header_trigger_exists then
    raise exception 'migration 128 version-aware schedule constraint readback failed';
  end if;
end
$$;

insert into schema_migrations(version, name)
values (128, 'ad_snapshot_v2_schedule')
on conflict(version) do nothing;
