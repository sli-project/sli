begin;

select pg_advisory_xact_lock(hashtext('ad_log_semantic_cross_dc_partitions_v135'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 134 and name = 'security_events_chains_report'
  ) then
    raise exception 'migration 135 requires exact migration 134 security_events_chains_report';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 135 and name is distinct from 'semantic_cross_dc_partitions'
  ) then
    raise exception 'migration version 135 is already owned by another contract';
  end if;
end
$$;

alter table semantic_correlation_candidates
  drop constraint if exists semantic_correlation_candidates_partition_key_check;
alter table semantic_correlation_candidates
  add constraint semantic_correlation_candidates_partition_key_check
  check (length(partition_key) between 1 and 512);

alter table semantic_correlation_dispatch_jobs
  drop constraint if exists semantic_correlation_dispatch_jobs_partition_key_check;
alter table semantic_correlation_dispatch_jobs
  add constraint semantic_correlation_dispatch_jobs_partition_key_check
  check (length(partition_key) between 1 and 512);

insert into public.schema_migrations(version,name)
values (135, 'semantic_cross_dc_partitions')
on conflict(version) do nothing;

commit;
