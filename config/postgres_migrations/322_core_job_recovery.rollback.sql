begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_core_job_recovery_v322'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=322 and name='core_job_recovery')
       or exists(select 1 from public.schema_migrations where version>322) then
        raise exception 'core_job_322_rollback_preflight' using errcode='55000';
    end if;
end $$;
do $$ declare r record; begin
    for r in select * from public.core_job_role_limits322 loop
        if r.statement_limit is null then
            execute format('alter role %I reset statement_timeout',r.role_name);
        else
            execute format('alter role %I set statement_timeout=%L',r.role_name,r.statement_limit);
        end if;
        if r.idle_limit is null then
            execute format('alter role %I reset idle_in_transaction_session_timeout',r.role_name);
        else
            execute format('alter role %I set idle_in_transaction_session_timeout=%L',r.role_name,r.idle_limit);
        end if;
    end loop;
end $$;
set local role adlog_storage_owner;
drop function public.retry_core_job_v322(uuid,text),public.read_core_job_quarantine_v322(text),public.read_workstation_projection_progress_v322();
drop table public.core_job_role_limits322;
delete from public.schema_migrations where version=322 and name='core_job_recovery';
reset role;
commit;
