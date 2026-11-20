begin;
select pg_advisory_xact_lock(hashtext('sli_db_load_indexes377'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=377 and name='db_load_indexes')
       or exists(select 1 from public.schema_migrations where version>377) then
        raise exception 'db_load_indexes377_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $$ declare saved public.db_load_restore377; begin
    select * into strict saved from public.db_load_restore377;
    if not exists(select 1 from pg_proc where oid='public.semantic_finding_review_v160(bigint)'::regprocedure
        and pg_get_functiondef(oid)=saved.installed_definition and proowner=saved.owner_oid
        and proacl is not distinct from saved.acl) then
        raise exception 'db_load_indexes377_rollback_changed' using errcode='55000'; end if;
    execute saved.definition;
end $$;
drop table public.db_load_restore377;
drop index public.event_hot_review_context377;
drop index public.finding_occurrences377;
drop index public.semantic_normalize_pending377;
drop index public.semantic_repair_reference377;
drop index public.semantic_replay_reference377;
revoke update,delete on public.semantic_processing_outbox from adlog_storage_lifecycle_delete;
revoke insert,update on public.semantic_producer_coverage from adlog_storage_lifecycle_delete;
revoke select on public.entity_identity_semantic_replays_v2 from adlog_storage_lifecycle_delete;
delete from public.schema_migrations where version=377 and name='db_load_indexes';
reset role;
commit;
