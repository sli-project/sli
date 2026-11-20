select pg_advisory_xact_lock(
  hashtext('ad_log_reports_ad_snapshot_coordinator_heartbeat_v124')
);

do $$
begin
  if exists (
    select 1 from schema_migrations
    where version=124 and name='ad_snapshot_coordinator_heartbeat'
  ) then
    raise exception 'migration 124 is already applied';
  end if;
  if to_regclass('runtime_worker_heartbeats') is null then
    raise exception 'migration 124 requires runtime_worker_heartbeats';
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
      'ad_snapshot_manifest_coordinator',
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

insert into schema_migrations(version,name)
values (124,'ad_snapshot_coordinator_heartbeat');
