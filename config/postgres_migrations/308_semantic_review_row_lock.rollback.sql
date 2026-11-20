begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_review_row_lock_v308'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=308 and name='semantic_review_row_lock')
       or exists(select 1 from public.schema_migrations where version>308)
       or (select proowner from pg_catalog.pg_proc where oid='public.lock_semantic_review_scenario_v308(uuid)'::regprocedure)
          is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_review_308_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.lock_semantic_review_scenario_v308(uuid);
delete from public.schema_migrations where version=308 and name='semantic_review_row_lock';
reset role;
commit;
