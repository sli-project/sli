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
    raise exception 'refusing migration 123 rollback: version is registered with a different name';
  end if;
end
$$;

alter table ad_snapshot_manifests
  drop constraint ad_snapshot_manifests_slot_start_utc_check;

alter table ad_snapshot_manifests
  add constraint ad_snapshot_manifests_slot_start_utc_check
  check (
    slot_start_utc=date_trunc('day',slot_start_utc)
    or slot_start_utc=date_trunc('day',slot_start_utc)+interval '12 hours'
  ) not valid;

delete from schema_migrations where version = 123 and name = 'ad_snapshot_manifest_utc_slots';
