begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_catalog_cache457'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or exists(select 1 from public.schema_migrations where version>457)
       or not exists(select 1 from public.schema_migrations where version=457 and name='file_audit_catalog_cache') then
        raise exception 'file_audit_catalog_cache457_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.file_permissions_allowed405(uuid,text,text,boolean);
alter function public.file_permissions_single457(uuid,text,text,boolean)
    rename to file_permissions_allowed405;
drop trigger file_audit_catalog_cache_source457 on public.sli_file_audit_smb_catalog;
drop function public.clear_file_audit_catalog_cache457();
alter table public.sli_file_audit_smb_catalog drop column cached_shares,drop column cached_at;
delete from public.schema_migrations where version=457 and name='file_audit_catalog_cache';
reset role;
commit;
