-- Register the bundled file-audit catalogue at the canonical migration boundary.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_catalog_revision_v206'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=205 and name='security_event_identity_category')
       or not exists(select 1 from public.schema_migrations where version=183 and name='file_audit_contracts')
       or not exists(select 1 from public.schema_migrations where version=51 and name='event_catalog_revision_reference')
       or exists(select 1 from public.schema_migrations where version>=206) then
        raise exception 'migration 206 prerequisites failed';
    end if;
    if not exists(select 1 from pg_trigger
        where tgname='events_v2_core_catalog_revision' and tgrelid='public.events_v2_core'::regclass
          and tgfoid='public.set_event_noise_catalog_revision()'::regprocedure
          and not tgisinternal and tgenabled in ('O','A')) then
        raise exception 'migration 206 requires the catalog revision trigger';
    end if;
end $$;
set local role adlog_storage_owner;
-- This is the exact revision in config/file_audit_event_catalog.json.
-- Existing facts, immutable source hashes and the admission trigger stay intact.
insert into public.event_catalog_revisions(version) values('1.0.0') on conflict(version) do nothing;
insert into public.schema_migrations(version,name) values(206,'file_audit_catalog_revision');
commit;
