begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_journal_finding_event_lookup425'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=425 and name='journal_finding_event_lookup')
       or exists(select 1 from public.schema_migrations where version>425) then
        raise exception 'journal_finding_event_lookup425_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

drop index public.finding_event_journal425;

reset role;
delete from public.schema_migrations where version=425 and name='journal_finding_event_lookup';
commit;
