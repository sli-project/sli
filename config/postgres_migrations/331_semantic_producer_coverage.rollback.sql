begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_producer_coverage_v331'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=330 and name='storage_lifecycle_agent_continuity')
       or not exists(select 1 from public.schema_migrations where version=331 and name='semantic_producer_coverage')
       or exists(select 1 from public.schema_migrations where version>331) then
        raise exception 'semantic_producer_coverage_331_rollback_preflight' using errcode='55000';
    end if;
end $$;
drop function public.lock_semantic_decisions_v331();
revoke update on public.semantic_processing_outbox from adlog_storage_lifecycle_guard;
grant update(source_event_id) on public.semantic_processing_outbox to adlog_storage_lifecycle_guard;
set local role adlog_storage_owner;
drop table public.semantic_producer_coverage;
delete from public.schema_migrations where version=331 and name='semantic_producer_coverage';
reset role;
commit;
