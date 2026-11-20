begin;
select pg_advisory_xact_lock(hashtext('sli_password_first_batch375'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=375 and name='password_first_batch')
       or exists(select 1 from public.schema_migrations where version>375) then
        raise exception 'password_first_batch375_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
do $$ declare r record; begin
    for r in select * from public.password_batch_restore375 where kind='function' order by signature loop
        if pg_get_functiondef(r.signature::regprocedure) is distinct from r.installed_definition
           or exists(select 1 from pg_proc where oid=r.signature::regprocedure
               and (proowner is distinct from r.owner_oid or proacl is distinct from r.acl)) then
            raise exception 'password_first_batch375_rollback_changed' using errcode='55000'; end if;
    end loop;
    for r in select * from public.password_batch_restore375 where kind='trigger' order by signature loop
        if not exists(select 1 from pg_trigger t where t.tgname=r.signature
            and t.tgrelid in ('public.semantic_password_checkpoints'::regclass,'public.semantic_password_window_members'::regclass)
            and pg_get_triggerdef(t.oid)=r.installed_definition) then
            raise exception 'password_first_batch375_rollback_changed' using errcode='55000'; end if;
    end loop;
end $$;
drop trigger password_v2_state_batch_complete on public.password_state_checks375;
drop trigger password_v2_state_ledger_complete on public.semantic_password_checkpoints;
drop trigger password_v2_members_complete on public.semantic_password_window_members;
do $$ declare r record; begin
    for r in select * from public.password_batch_restore375 order by kind,signature loop execute r.definition; end loop;
end $$;
drop function public.password_schedule_state_check375();
drop table public.password_state_checks375;
drop table public.password_batch_restore375;
delete from public.schema_migrations where version=375 and name='password_first_batch';
reset role;
commit;
