begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_outbox_retention426'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=426 and name='semantic_outbox_retention')
       or exists(select 1 from public.schema_migrations where version>426) then
        raise exception 'semantic_outbox_retention426_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;

alter table public.semantic_processing_outbox
    reset (autovacuum_vacuum_scale_factor, autovacuum_vacuum_threshold);
drop index public.semantic_outbox_completed426;

reset role;
delete from public.schema_migrations where version=426 and name='semantic_outbox_retention';
commit;
