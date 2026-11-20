-- Roll back with the old lifecycle binary: wk45 exact reads require the indexes.
select pg_advisory_lock(hashtext('sli_storage_lifecycle_copy_links_v329'));
begin;
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=328 and name='storage_lifecycle_evidence_lock')
       or not exists(select 1 from public.schema_migrations where version=329 and name='storage_lifecycle_copy_links')
       or exists(select 1 from public.schema_migrations where version>329) then
        raise exception 'storage_lifecycle_copy_links_329_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
commit;
set role adlog_storage_owner;
drop index concurrently if exists public.sli_lifecycle_links_multi_v329;
drop index concurrently if exists public.sli_lifecycle_links_single_v329;
reset role;
begin;
set local role adlog_storage_owner;
delete from public.schema_migrations where version=329 and name='storage_lifecycle_copy_links';
reset role;
commit;
select pg_advisory_unlock(hashtext('sli_storage_lifecycle_copy_links_v329'));
