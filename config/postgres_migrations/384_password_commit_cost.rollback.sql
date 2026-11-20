begin;
select pg_advisory_xact_lock(hashtext('sli_password_commit_cost384'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=384 and name='password_commit_cost')
       or exists(select 1 from public.schema_migrations where version>384) then
        raise exception 'password_commit_cost384_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
do $$ declare r record; begin
    for r in select * from public.password_commit_restore384 where kind='function' loop
        if pg_get_functiondef(r.signature::regprocedure) is distinct from r.installed_definition
           or exists(select 1 from pg_proc where oid=r.signature::regprocedure
               and (proowner is distinct from r.owner_oid or proacl is distinct from r.acl)) then
            raise exception 'password_commit_cost384_rollback_changed' using errcode='55000'; end if;
    end loop;
    for r in select * from public.password_commit_restore384 where kind='trigger' loop
        if not exists(select 1 from pg_trigger where tgname=r.signature and pg_get_triggerdef(oid)=r.installed_definition) then
            raise exception 'password_commit_cost384_rollback_trigger_changed' using errcode='55000'; end if;
    end loop;
end $$;
drop trigger password_v2_ledger_complete on public.semantic_password_episode_budgets;
drop trigger password_v2_qw_complete on public.semantic_qw_signals;
drop trigger password_v2_jobs_complete on public.semantic_risk_evaluation_jobs;
drop trigger password_v2_episode_batch384 on public.password_episode_checks384;
drop trigger password_episode_checkpoint384 on public.semantic_password_checkpoints;
do $$ declare r record; begin
    for r in select * from public.password_commit_restore384 where kind='function' loop execute r.definition; end loop;
    for r in select * from public.password_commit_restore384 where kind='trigger' loop execute r.definition; end loop;
end $$;
alter table public.password_state_checks375 drop column checked_checkpoint;
drop function public.password_schedule_episode384();
drop function public.password_invalidate_episode384();
drop table public.password_episode_checks384;
drop table public.password_commit_restore384;
delete from public.schema_migrations where version=384 and name='password_commit_cost';
reset role;
commit;
