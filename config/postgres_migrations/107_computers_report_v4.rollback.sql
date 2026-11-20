begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_computers_report_v4'));
delete from access_package_reports where report_key='ad.computers.v4';
delete from access_report_assignments where report_key='ad.computers.v4';
delete from report_registry_v4 where report_key='ad.computers.v4';
delete from report_datasets_v4 where dataset_key='ad.assets.computers.v4';
delete from schema_migrations where version=107 and name='computers_report_v4';
commit;
