begin;
select pg_advisory_xact_lock(hashtext('sli_short_event_id_indexes357'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=357 and name='short_event_id_indexes')
       or exists(select 1 from public.schema_migrations where version>357) then
        raise exception 'short_event_id_indexes357_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- Dropping the parent also drops its attached leaf indexes. Event rows,
-- semantic decisions and outbox jobs are untouched.
drop index public.event_hot_event_id357;
drop index public.event_cold_facts_event_id357;
delete from public.schema_migrations where version=357 and name='short_event_id_indexes';
reset role;
commit;
