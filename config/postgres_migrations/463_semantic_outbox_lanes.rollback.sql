begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_outbox_lanes463'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=463 and name='semantic_outbox_lanes')
       or exists(select 1 from public.schema_migrations where version>463) then
        raise exception 'semantic_outbox_lanes463_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop index public.semantic_outbox_lane_age463;
drop index public.semantic_outbox_lane_claim463;
delete from public.schema_migrations where version=463 and name='semantic_outbox_lanes';
commit;
