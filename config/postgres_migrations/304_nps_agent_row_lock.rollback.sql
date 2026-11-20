begin;
select pg_advisory_xact_lock(hashtext('sli_nps_agent_lock_v304'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'rollback 304 requires adlog_storage_owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=304 and name='nps_agent_row_lock')
       or exists(select 1 from public.schema_migrations where version>304) then
        raise exception 'rollback requires exact migration 304 and no successors';
    end if;
    if not exists(select 1 from pg_catalog.pg_proc p
        where p.oid=to_regprocedure('public.lock_nps_import_agent_v304(uuid)')
          and p.proowner='adlog_storage_owner'::regrole and p.prosecdef and p.provolatile='v') then
        raise exception 'rollback 304 function owner or contract changed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;
drop function public.lock_nps_import_agent_v304(uuid);
delete from public.schema_migrations where version=304 and name='nps_agent_row_lock';
reset role;
commit;
