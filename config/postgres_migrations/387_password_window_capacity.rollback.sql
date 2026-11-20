begin;
select pg_advisory_xact_lock(hashtext('sli_password_window_capacity387'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=387 and name='password_window_capacity')
       or exists(select 1 from public.schema_migrations where version>387) then
        raise exception 'password_window_capacity387_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
do $$ declare r record; begin
    for r in select * from public.password_restore387 loop
        if pg_get_functiondef(r.signature::regprocedure) is distinct from r.installed_definition
           or exists(select 1 from pg_proc where oid=r.signature::regprocedure
                and (proowner is distinct from r.owner_oid or proacl is distinct from r.acl)) then
            raise exception 'password_window_capacity387_rollback_changed' using errcode='55000'; end if;
        execute r.definition;
    end loop;
end $$;
drop table public.password_restore387;
delete from public.schema_migrations where version=387 and name='password_window_capacity';
reset role;
commit;
