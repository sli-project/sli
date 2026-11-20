begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_investigation_public_identity_rollback'));

drop index if exists investigations_public_id_uidx;
alter table investigations drop column if exists public_id;
delete from schema_migrations where version=18 and name='investigation_public_identity';

commit;
