-- Rollback for migration 146: drops the platform settings table. Values set
-- in the interface are lost; the report domain falls back to the
-- ADLOG_REPORT_DOMAIN_FQDN environment variable.

begin;

drop table if exists public.platform_settings;

delete from schema_migrations where version = 146;

commit;
