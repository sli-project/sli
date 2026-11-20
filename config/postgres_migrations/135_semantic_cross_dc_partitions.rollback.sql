begin;

select pg_advisory_xact_lock(hashtext('ad_log_semantic_cross_dc_partitions_v135'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 135 and name = 'semantic_cross_dc_partitions'
  ) then
    raise exception 'migration 135 rollback requires exact marker';
  end if;
  if exists (
    select 1 from semantic_correlation_candidates where length(partition_key) > 160
  ) or exists (
    select 1 from semantic_correlation_dispatch_jobs where length(partition_key) > 160
  ) then
    raise exception 'migration 135 rollback refuses cross-DC partition keys over 160 characters';
  end if;
end
$$;

alter table semantic_correlation_candidates
  drop constraint if exists semantic_correlation_candidates_partition_key_check;
alter table semantic_correlation_candidates
  add constraint semantic_correlation_candidates_partition_key_check
  check (length(partition_key) between 1 and 160);

alter table semantic_correlation_dispatch_jobs
  drop constraint if exists semantic_correlation_dispatch_jobs_partition_key_check;
alter table semantic_correlation_dispatch_jobs
  add constraint semantic_correlation_dispatch_jobs_partition_key_check
  check (length(partition_key) between 1 and 160);

delete from public.schema_migrations
where version = 135 and name = 'semantic_cross_dc_partitions';

commit;
