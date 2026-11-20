begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_gpo_report_v2_reference'));

delete from access_package_reports where report_key='ad.gpo.v2';
delete from report_registry_v4 where report_key='ad.gpo.v2' and version=1;
delete from report_datasets_v4 where dataset_key='ad.gpo.reference.v2' and version=1;
drop table if exists gpo_report_v2_source_snapshots;
delete from schema_migrations where version=116 and name='gpo_report_v2_reference';
commit;
