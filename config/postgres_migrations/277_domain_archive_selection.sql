-- Archive is an administrator decision, never inferred from observation age.
-- Existing domains remain eligible; no installation-specific backfill.
begin;
alter table domains add column if not exists is_archived boolean not null default false;

insert into public.schema_migrations(version,name) values(277,'domain_archive_selection');
commit;
