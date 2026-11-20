begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_computers_v5_snapshot_heartbeat_rollback'));

delete from runtime_worker_heartbeats where worker_name='computers_v5_snapshot';
alter table runtime_worker_heartbeats drop constraint if exists runtime_worker_heartbeats_name;
alter table runtime_worker_heartbeats add constraint runtime_worker_heartbeats_name check (
  worker_name in (
    'collection','ad_context_snapshot','storage_v2_outbox','storage_lifecycle',
    'post_collection','entity_state','semantic'
  )
);
delete from schema_migrations where version=109;
commit;
