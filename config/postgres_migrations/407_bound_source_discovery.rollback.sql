begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_bound_source_discovery407'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists (select 1 from public.schema_migrations where version=407 and name='bound_source_discovery')
       or exists (select 1 from public.schema_migrations where version>407) then
        raise exception 'bound_source_discovery407_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

do $$ declare saved record; begin
    select * into strict saved from public.source_discovery_restore407;
    if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
        and p.proacl is not distinct from saved.acl and pg_get_functiondef(p.oid)=saved.installed_definition) then
        raise exception 'bound_source_discovery407_rollback_metadata' using errcode='55000';
    end if;
    execute saved.definition;
end $$;

drop table public.source_discovery_restore407;
reset role;
delete from public.schema_migrations where version=407 and name='bound_source_discovery';
commit;
