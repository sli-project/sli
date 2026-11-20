-- Admit the exact revision emitted by the bundled directory-change catalog.
begin;
select pg_advisory_xact_lock(hashtext('sli_directory_change_catalog_revision_v215'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=214 and name='file_audit_scoped_context')
       or exists(select 1 from public.schema_migrations where version>=215)
       or to_regclass('public.event_catalog_revisions') is null then
        raise exception 'migration 215 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

-- Keep prior revisions and the enforcing trigger intact for historical replay.
insert into public.event_catalog_revisions(version) values('2026-10-16-descriptor-v8-directory-change')
on conflict(version) do nothing;

insert into public.schema_migrations(version,name) values(215,'directory_change_catalog_revision');
commit;
