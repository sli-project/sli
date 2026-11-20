begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_platform_owner_access'));

delete from schema_migrations where version=37 and name='platform_owner_access';
drop table if exists access_platform_owners;

commit;
