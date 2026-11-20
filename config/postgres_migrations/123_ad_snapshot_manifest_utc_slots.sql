select pg_advisory_xact_lock(
  hashtext('ad_log_reports_ad_snapshot_manifest_utc_slots_v123')
);

do $$
begin
  if exists (
    select 1 from schema_migrations
    where version = 123
      and name is distinct from 'ad_snapshot_manifest_utc_slots'
  ) then
    raise exception 'migration 123 is already registered with a different name';
  end if;

  if not exists (
    select 1 from schema_migrations
    where version = 121
      and name = 'ad_snapshot_manifest_foundation'
  ) then
    raise exception 'migration 121 ad_snapshot_manifest_foundation is required';
  end if;

  if to_regclass('public.ad_snapshot_manifests') is null then
    raise exception 'migration 123 requires ad_snapshot_manifests';
  end if;
end
$$;

alter table ad_snapshot_manifests
  drop constraint ad_snapshot_manifests_slot_start_utc_check;

alter table ad_snapshot_manifests
  add constraint ad_snapshot_manifests_slot_start_utc_check
  check (
    (slot_start_utc at time zone 'UTC') =
      date_trunc('day', slot_start_utc at time zone 'UTC')
    or
    (slot_start_utc at time zone 'UTC') =
      date_trunc('day', slot_start_utc at time zone 'UTC') + interval '12 hours'
  );

do $$
declare
  definition text;
begin
  select pg_get_constraintdef(oid)
  into definition
  from pg_constraint
  where conrelid = 'ad_snapshot_manifests'::regclass
    and conname = 'ad_snapshot_manifests_slot_start_utc_check'
    and contype = 'c'
    and convalidated;

  if definition is null
     or position('AT TIME ZONE ''UTC''' in upper(definition)) = 0 then
    raise exception 'migration 123 UTC slot constraint readback failed';
  end if;
end
$$;

insert into schema_migrations(version, name)
values (123, 'ad_snapshot_manifest_utc_slots')
on conflict(version) do nothing;
