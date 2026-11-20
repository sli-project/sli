begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_runtime_worker_heartbeats_v32'));

revoke all on table runtime_worker_heartbeats from adlog_user, adlog_storage_worker;
drop table if exists runtime_worker_heartbeats;
delete from schema_migrations where version=32 and name='runtime_worker_heartbeats';

commit;
