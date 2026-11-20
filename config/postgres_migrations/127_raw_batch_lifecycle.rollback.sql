begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_raw_batch_lifecycle_v127_rollback'));

drop table if exists raw_batch_lifecycle;
delete from schema_migrations where version = 127 and name = 'raw_batch_lifecycle';
commit;
