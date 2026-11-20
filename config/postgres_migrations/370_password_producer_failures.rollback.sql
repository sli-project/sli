begin;
select pg_advisory_xact_lock(hashtext('sli_password_producer_failures370'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=370 and name='password_producer_failures')
       or exists(select 1 from public.schema_migrations where version>370) then
        raise exception 'password_producer370_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $$ declare r record; begin
    for r in select * from public.password_producer_restore370 order by signature loop
        if pg_get_functiondef(r.signature::regprocedure) is distinct from r.installed_definition
           or exists(select 1 from pg_proc where oid=r.signature::regprocedure
               and (proowner is distinct from r.owner_oid or proacl is distinct from r.acl)) then
            raise exception 'password_producer370_rollback_changed' using errcode='55000';
        end if;
        execute r.definition;
    end loop;
end $$;
drop table public.password_producer_restore370;
delete from public.schema_migrations where version=370 and name='password_producer_failures';
reset role;
commit;
