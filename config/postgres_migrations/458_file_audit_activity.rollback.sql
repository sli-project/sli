begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_activity458'));
set local role adlog_storage_owner;
do $$ begin
    if exists(select 1 from public.schema_migrations where version>458) then
        raise exception 'file_audit_activity458_rollback_preflight' using errcode='55000';
    end if;
end $$;
drop function public.file_audit_scan_prefix458(uuid,text,uuid,integer,timestamptz);
delete from public.schema_migrations where version=458 and name='file_audit_activity';
reset role;
commit;
