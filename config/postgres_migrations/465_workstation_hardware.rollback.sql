begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_hardware465'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=465 and name='workstation_hardware')
       or exists(select 1 from public.schema_migrations where version>465) then
        raise exception 'workstation_hardware465_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.prune_workstation_hardware465(timestamptz,integer);
drop table public.workstation_hardware_changes465,public.workstation_hardware_latest465;
delete from public.schema_migrations where version=465 and name='workstation_hardware';
commit;
