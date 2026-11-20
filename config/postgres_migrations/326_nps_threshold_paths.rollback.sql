-- Restore exact predecessor definitions, including owner, OID and ACL.
begin;
select pg_advisory_xact_lock(hashtext('sli_nps_threshold_paths_v326'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=325 and name='t109_workstation_path')
       or not exists(select 1 from public.schema_migrations where version=326 and name='nps_threshold_paths')
       or to_regclass('public.nps_threshold_definitions326') is null
       or exists(select 1 from public.schema_migrations where version>326) then
        raise exception 'nps_threshold_326_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $$ declare saved record;begin
    if (select count(*) from public.nps_threshold_definitions326)<>2 then
        raise exception 'nps_threshold_326_rollback_definitions' using errcode='55000';
    end if;
    for saved in select * from public.nps_threshold_definitions326 loop
        execute saved.definition;
        if (select to_jsonb(p)-'prosrc' from pg_proc p where oid=saved.signature::regprocedure) is distinct from saved.catalog then
            raise exception 'nps_threshold_326_rollback_catalog_changed' using errcode='55000';
        end if;
    end loop;
end $$;
drop table public.nps_threshold_definitions326;
delete from public.schema_migrations where version=326 and name='nps_threshold_paths';
reset role;
commit;
