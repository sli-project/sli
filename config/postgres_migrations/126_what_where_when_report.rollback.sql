begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_what_where_when_report_v126_rollback'));

delete from user_report_preferences where report_key='ad.computer-logons';
delete from access_report_assignments where report_key='ad.computer-logons';
delete from access_package_reports where report_key='ad.computer-logons';
delete from report_registry_v4 where report_key='ad.computer-logons' and version=1;
delete from report_datasets_v4 where dataset_key='ad.authentication.computer-logons' and version=1;

delete from access_package_capabilities link
using access_packages package,access_capabilities capability
where link.package_id=package.id and link.capability_id=capability.id
  and package.package_key in ('security_analyst','project_operations')
  and capability.capability_key='field.computer_logon_observation';
delete from access_capabilities where capability_key='field.computer_logon_observation';

delete from schema_migrations where version=126 and name='what_where_when_report';
commit;
