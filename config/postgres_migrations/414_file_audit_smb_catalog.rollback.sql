begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_file_audit_smb_catalog414'));
do $$ begin
    if exists(select 1 from public.schema_migrations where version>414)
       or not exists(select 1 from public.schema_migrations where version=414 and name='file_audit_smb_catalog') then
        raise exception 'file_audit_smb_catalog414_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop table public.sli_file_audit_smb_catalog;
reset role;
set local role adlog_file_audit_owner;
drop function sli_plugin_file_audit.catalog_policy_matches(uuid,text,bigint,jsonb);
reset role;
delete from public.schema_migrations where version=414 and name='file_audit_smb_catalog';
commit;
