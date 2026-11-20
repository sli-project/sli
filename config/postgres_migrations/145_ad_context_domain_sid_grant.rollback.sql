-- Rollback for migration 145: revoke only the column grant. Domain SIDs
-- already recorded stay; a later first AD Context import of a domain without
-- a SID fails again with "permission denied for table domains".

begin;

revoke update (domain_sid) on public.domains from adlog_context_worker;

delete from schema_migrations where version = 145;

commit;
