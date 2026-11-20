begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_backfill_window_v332'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=331 and name='semantic_producer_coverage')
       or not exists(select 1 from public.schema_migrations where version=332 and name='semantic_backfill_window')
       or exists(select 1 from public.schema_migrations where version>332) then
        raise exception 'semantic_backfill_window_332_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.semantic_backfill_window_v332(bigint,integer,text,text);
alter table public.semantic_producer_coverage drop column source_unavailable_ids;
delete from public.schema_migrations where version=332 and name='semantic_backfill_window';
reset role;
commit;
