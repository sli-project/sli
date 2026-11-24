begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_native_radius_accounting_admission406'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations
                     where version=406 and name='native_radius_accounting_admission')
       or exists(select 1 from public.schema_migrations where version>406) then
        raise exception 'native_radius_accounting_admission406_rollback_preflight' using errcode='55000';
    end if;
end $$;
select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'));
set local role adlog_storage_owner;
drop function public.radius_accounting_source_ready406(text,text,text,text,boolean);
delete from public.schema_migrations where version=406 and name='native_radius_accounting_admission';
reset role;
set local role adlog_plugin_lifecycle_owner;
drop function public.radius_accounting_plugin_ready406();
reset role;
commit;
