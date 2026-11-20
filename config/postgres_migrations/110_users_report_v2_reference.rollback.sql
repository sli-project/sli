begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_users_report_v2_reference_rollback'));

delete from runtime_worker_heartbeats where worker_name='users_v2_snapshot';
alter table runtime_worker_heartbeats drop constraint if exists runtime_worker_heartbeats_name;
alter table runtime_worker_heartbeats add constraint runtime_worker_heartbeats_name check (
  worker_name in (
    'collection','ad_context_snapshot','computers_v5_snapshot','storage_v2_outbox',
    'storage_lifecycle','post_collection','entity_state','semantic'
  )
);

delete from access_package_reports where report_key='ad.users.v2';
delete from access_report_assignments where report_key='ad.users.v2';
delete from report_registry_v4 where report_key='ad.users.v2' and version=1;
delete from report_datasets_v4 where dataset_key='ad.accounts.users.reference.v2' and version=1;
drop table if exists users_report_v2_snapshots;
delete from schema_migrations where version=110;
commit;
