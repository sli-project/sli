begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_ad_audit_vpn_gpo_source'));

delete from access_package_reports where report_key='vpn.audit';
delete from access_report_assignments where report_key='vpn.audit';
delete from report_registry_v4 where report_key='vpn.audit' and version=1;
delete from report_datasets_v4 where dataset_key='ad.accounts.vpn' and version=1;
delete from schema_migrations where version=36;

commit;
