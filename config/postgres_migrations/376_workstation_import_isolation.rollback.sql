begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_import_isolation376'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=376 and name='workstation_import_isolation')
       or exists(select 1 from public.schema_migrations where version>376) then
        raise exception 'workstation_import_isolation376_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.workstation_runtime_enabled_v376();
delete from public.schema_migrations where version=376;
reset role;
commit;
