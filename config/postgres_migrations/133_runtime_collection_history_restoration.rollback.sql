select pg_advisory_xact_lock(
  hashtext('ad_log_reports_runtime_collection_history_restoration_v133')
);

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 133
      and name = 'runtime_collection_history_restoration'
  ) then
    raise exception 'migration 133 rollback requires exact marker';
  end if;

  if to_regclass('public.runtime_collection_runs') is null then
    raise exception 'migration 133 rollback requires runtime_collection_runs relation';
  end if;

  if exists (select 1 from public.runtime_collection_runs) then
    raise exception 'migration 133 rollback refuses non-empty runtime_collection_runs';
  end if;
end
$$;

drop table public.runtime_collection_runs;

delete from public.schema_migrations
where version = 133
  and name = 'runtime_collection_history_restoration';
