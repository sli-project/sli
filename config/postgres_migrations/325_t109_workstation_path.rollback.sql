-- Restore the exact 324 definition, OID, owner and ACL before index removal.
begin;
select pg_advisory_xact_lock(hashtext('sli_t109_workstation_path_v325'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=324 and name='detector_query_paths')
       or to_regclass('public.t109_definitions325') is null
       or exists(select 1 from public.schema_migrations where version>325) then
        raise exception 't109_workstation_325_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $$ declare saved record;begin
    select * into strict saved from public.t109_definitions325;
    execute saved.definition;
    if (select to_jsonb(p)-'prosrc' from pg_proc p where oid=saved.signature::regprocedure) is distinct from saved.catalog then
        raise exception 't109_workstation_325_rollback_catalog_changed' using errcode='55000';
    end if;
end $$;
reset role;
commit;
drop index concurrently if exists sli_plugin_workstations.t109_workstation_candidates325;
begin;
set local role adlog_storage_owner;
drop table public.t109_definitions325;
delete from public.schema_migrations where version=325 and name='t109_workstation_path';
reset role;
commit;
