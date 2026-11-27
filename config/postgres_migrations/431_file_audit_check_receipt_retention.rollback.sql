begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_check_receipt_retention431'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=431 and name='file_audit_check_receipt_retention')
       or exists(select 1 from public.schema_migrations where version>431) then
        raise exception 'file_audit_check_receipt_retention431_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

drop function public.prune_file_audit_check_receipts431(integer);
alter table sli_plugin_file_audit.audit_receipts drop column legacy_check_receipt;
delete from public.schema_migrations where version=431 and name='file_audit_check_receipt_retention';
commit;
