select pg_advisory_xact_lock(
  hashtext('ad_log_reports_what_where_when_hourly_compaction_v130')
);

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 130
      and name = 'what_where_when_hourly_compaction'
  ) then
    raise exception 'refusing migration 130 rollback: migration is not registered';
  end if;

  if not pg_try_advisory_xact_lock(
    hashtext('ad_log_reports_runtime_what_where_when_projection')
  ) then
    raise exception 'migration 130 rollback requires the what_where_when_projection worker to be stopped';
  end if;
end
$$;

alter table public.what_where_when_observations
  drop constraint if exists what_where_when_observations_hourly_identity;
alter table public.what_where_when_observations
  drop column if exists observed_hour_local;
alter table public.what_where_when_observations
  drop column if exists user_key;

delete from public.schema_migrations
where version=130 and name='what_where_when_hourly_compaction';

-- Hourly rows discarded by the forward migration are intentionally not restorable.
