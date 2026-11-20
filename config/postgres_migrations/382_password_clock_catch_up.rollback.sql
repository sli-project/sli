begin;
select pg_advisory_xact_lock(hashtext('sli_password_clock_catch_up382'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=382 and name='password_clock_catch_up')
       or exists(select 1 from public.schema_migrations where version>382) then
        raise exception 'password_clock_catch_up382_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
do $$ declare r record; begin
    for r in select * from public.password_clock_restore382 loop
        if pg_get_functiondef(r.signature::regprocedure) is distinct from r.installed_definition
           or exists(select 1 from pg_proc where oid=r.signature::regprocedure
               and (proowner is distinct from r.owner_oid or proacl is distinct from r.acl)) then
            raise exception 'password_clock_catch_up382_rollback_changed' using errcode='55000'; end if;
        execute r.definition;
    end loop;
end $$;
drop function public.password_producer_source382(jsonb,boolean);
drop table public.password_clock_restore382;
delete from public.schema_migrations where version=382 and name='password_clock_catch_up';
reset role;
commit;
