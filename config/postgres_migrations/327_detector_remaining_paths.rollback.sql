begin;
select pg_advisory_xact_lock(hashtext('sli_detector_remaining_paths_v327'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=326 and name='nps_threshold_paths')
       or not exists(select 1 from public.schema_migrations where version=327 and name='detector_remaining_paths')
       or exists(select 1 from public.schema_migrations where version>327)
       or to_regclass('public.detector_definitions327') is null then
        raise exception 'detector_remaining_327_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $$ declare saved record;begin
    if (select count(*) from public.detector_definitions327)<>2 then
        raise exception 'detector_remaining_327_rollback_definitions' using errcode='55000';
    end if;
    for saved in select * from public.detector_definitions327 loop
        execute saved.definition;
        if (select to_jsonb(p)-'prosrc' from pg_proc p where oid=saved.signature::regprocedure) is distinct from saved.catalog then
            raise exception 'detector_remaining_327_rollback_catalog';
        end if;
    end loop;
end $$;
drop function public.detector_directory_page327(integer);
drop function public.detector_workstation_devices327(text,text);
drop table public.detector_definitions327;
delete from public.schema_migrations where version=327 and name='detector_remaining_paths';
reset role;
commit;

-- Release the online index outside the restore transaction.
drop index concurrently if exists public.detector_device_provenance327;
