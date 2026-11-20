begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_computers_report_v5_rollback'));

delete from access_package_reports where report_key='ad.computers.v5';
delete from access_report_assignments where report_key='ad.computers.v5';
delete from report_registry_v4 where report_key='ad.computers.v5' and version=1;
delete from report_datasets_v4 where dataset_key='ad.assets.computers.v5' and version=1;

drop table if exists computers_report_v5_snapshots;

update report_registry_v4 set status='published' where report_key in ('ad.computers.v2','ad.computers.v4');
update report_datasets_v4 set status='published' where dataset_key in ('ad.assets.computers.v2','ad.assets.computers.v4');
insert into access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select package.id,report_key,array['identity_basic','technical','security'],array['view','export'],jsonb_build_object('kind','domain','ids',jsonb_build_array(domain.id))
from access_packages package cross join domains domain cross join (values('ad.computers.v2'),('ad.computers.v4')) retired(report_key)
where package.package_key='ad_auditor' and lower(domain.fqdn)='example.local'
on conflict(package_id,report_key) do update set field_categories=excluded.field_categories,allowed_actions=excluded.allowed_actions,scope_json=excluded.scope_json;

delete from schema_migrations where version=108;
commit;
