begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_users_report_v1'));

delete from access_package_reports where report_key='ad.users';
delete from access_report_assignments where report_key='ad.users';
delete from report_registry_v4 where report_key='ad.users';
delete from report_datasets_v4 where dataset_key='ad.accounts.users';
delete from access_package_capabilities
where capability_id in (select id from access_capabilities where capability_key='account_risks.accept');
delete from access_capability_assignments
where capability_id in (select id from access_capabilities where capability_key='account_risks.accept');
delete from access_capabilities where capability_key='account_risks.accept';
delete from schema_migrations where version=99 and name='users_report_v1';

commit;
