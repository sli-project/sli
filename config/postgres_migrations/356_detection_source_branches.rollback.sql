begin;
select pg_advisory_xact_lock(hashtext('sli_detection_source_branches356'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=356 and name='detection_source_branches')
       or exists(select 1 from public.schema_migrations where version>356) then
        raise exception 'detection_source_branches356_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $$ declare definition text; begin
    select d.definition into strict definition from public.detection_source_definitions356 d;
    execute definition;
end $$;
drop table public.detection_source_definitions356;
delete from public.schema_migrations where version=356 and name='detection_source_branches';
reset role;
commit;
