begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_v2_runtime_authorization_v91'));

drop table if exists storage_v2_runtime_authorizations;

delete from schema_migrations
where version=91 and name='storage_v2_runtime_authorization';

commit;
