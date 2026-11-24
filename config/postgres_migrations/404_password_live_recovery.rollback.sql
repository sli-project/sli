begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_live_recovery404'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=404 and name='password_live_recovery')
       or exists(select 1 from public.schema_migrations where version>404) then
        raise exception 'password_live_recovery404_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

do $$ declare saved record; begin
    -- Before the first fork or after promotion the old single-slot planner
    -- can represent every active range. Rollback between those points would
    -- strand the exact deferred interval, so leave both intervals runnable.
    if exists(select 1 from public.password_parked_history404(null,null)) then
        raise exception 'password_live_recovery404_pending_history' using errcode='55000';
    end if;
    for saved in select * from public.password_restore404 loop
        if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
            and p.proacl is not distinct from saved.acl and pg_get_functiondef(p.oid)=saved.installed_definition) then
            raise exception 'password_live_recovery404_rollback_metadata' using errcode='55000';
        end if;
        execute saved.definition;
    end loop;
end $$;

drop function public.password_parked_history404(bytea,text);
drop table public.password_recovery_candidates404;
drop table public.password_restore404;
reset role;
delete from public.schema_migrations where version=404 and name='password_live_recovery';
commit;
