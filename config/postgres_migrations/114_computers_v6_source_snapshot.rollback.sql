begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_computers_v6_source_snapshot_rollback'));

delete from runtime_worker_heartbeats where worker_name='computers_v6_source';
alter table runtime_worker_heartbeats
  drop constraint if exists runtime_worker_heartbeats_name;
alter table runtime_worker_heartbeats
  add constraint runtime_worker_heartbeats_name check (
    worker_name in (
      'collection','ad_context_snapshot','computers_v5_snapshot',
      'computers_v6_snapshot','users_v2_snapshot','storage_v2_outbox',
      'storage_lifecycle','post_collection','entity_state','semantic'
    )
  );

drop table computers_v6_source_snapshots;
delete from schema_migrations
where version=114 and name='computers_v6_source_snapshot';
commit;
