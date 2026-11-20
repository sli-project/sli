begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_users_report_domain_scope'));

update access_package_reports
set scope_json='{"kind":"all"}'::jsonb
where report_key='ad.users';

delete from schema_migrations where version=100 and name='users_report_domain_scope';

commit;
