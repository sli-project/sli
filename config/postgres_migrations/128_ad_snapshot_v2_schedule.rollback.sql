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
    raise exception 'refusing migration 128 rollback: version is registered with a different name';
  end if;

  if not exists (
    select 1 from schema_migrations
    where version = 128
      and name = 'ad_snapshot_v2_schedule'
  ) then
    raise exception 'refusing migration 128 rollback: migration is not registered';
  end if;

  if exists (
    select 1 from ad_snapshot_manifests
    where contract_version = 'sli.ad-snapshot-manifest/2.0'
  ) then
    raise exception 'refusing migration 128 rollback: v2 manifest rows exist';
  end if;
end
$$;

drop trigger if exists trg_ad_snapshot_manifests_v2_schedule_header
  on ad_snapshot_manifests;
drop function if exists ad_snapshot_manifest_apply_v2_schedule_header();

alter table ad_snapshot_manifests
  drop constraint ad_snapshot_manifests_slot_start_utc_check;

alter table ad_snapshot_manifests
  add constraint ad_snapshot_manifests_slot_start_utc_check
  check (
    (slot_start_utc at time zone 'UTC') = date_trunc('day', slot_start_utc at time zone 'UTC')
    or (slot_start_utc at time zone 'UTC') = date_trunc('day', slot_start_utc at time zone 'UTC') + interval '12 hours'
  );

alter table ad_snapshot_manifests
  drop constraint ad_snapshot_manifests_contract_version_check;

alter table ad_snapshot_manifests
  add constraint ad_snapshot_manifests_contract_version_check
  check (contract_version = 'sli.ad-snapshot-manifest/1.0');

alter table ad_snapshot_manifests
  drop column scheduled_local_at,
  drop column schedule_timezone;

delete from schema_migrations where version = 128 and name = 'ad_snapshot_v2_schedule';
