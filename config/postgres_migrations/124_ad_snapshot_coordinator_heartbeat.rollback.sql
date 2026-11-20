select pg_advisory_xact_lock(
  hashtext('ad_log_reports_ad_snapshot_coordinator_heartbeat_v124')
);

do $$
begin
  if not exists (
    select 1 from schema_migrations
    where version=124 and name='ad_snapshot_coordinator_heartbeat'
  ) then
    raise exception 'migration 124 is not applied';
  end if;
end
$$;

alter table runtime_worker_heartbeats
  drop constraint if exists runtime_worker_heartbeats_name;

alter table runtime_worker_heartbeats
  add constraint runtime_worker_heartbeats_name check (
    worker_name in (
      'collection',
      'ad_context_snapshot',
      'computers_v5_snapshot',
      'computers_v6_snapshot',
      'computers_v6_source',
      'users_v2_snapshot',
      'storage_v2_outbox',
      'storage_lifecycle',
      'post_collection',
      'entity_state',
      'semantic'
    )
  );

delete from schema_migrations
where version=124 and name='ad_snapshot_coordinator_heartbeat';
