-- GAP109: let the dedicated NPS worker take the same agent row lock without
-- granting it arbitrary UPDATE on the agent registry.
begin;
select pg_advisory_xact_lock(hashtext('sli_nps_agent_lock_v304'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 304 requires adlog_storage_owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=301 and name='identity_attack_rules')
       or not exists(select 1 from public.schema_migrations where version=302 and name='attack_precursors')
       or not exists(select 1 from public.schema_migrations where version=303 and name='evsearch_fact_publication')
       or exists(select 1 from public.schema_migrations where version>=304) then
        raise exception 'migration 304 requires exact migrations 301, 302 and 303 and no successors';
    end if;
    if (select c.relowner from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid=c.relnamespace
        where n.nspname='public' and c.relname='sli_agents' and c.relkind='r')
        is distinct from 'adlog_storage_owner'::regrole
       or to_regprocedure('public.lock_nps_import_agent_v304(uuid)') is not null then
        raise exception 'migration 304 agent owner or function prerequisite failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;
create function public.lock_nps_import_agent_v304(p_agent uuid)
returns table(status text, assigned_modules jsonb)
language sql volatile security definer set search_path=pg_catalog,pg_temp
as $$
    select a.status,a.assigned_modules from public.sli_agents a
    where a.id=p_agent for update
$$;
revoke all on function public.lock_nps_import_agent_v304(uuid) from public;
grant execute on function public.lock_nps_import_agent_v304(uuid)
    to adlog_nps_agent_import_worker,adlog_user;
insert into public.schema_migrations(version,name) values(304,'nps_agent_row_lock');
reset role;
commit;
