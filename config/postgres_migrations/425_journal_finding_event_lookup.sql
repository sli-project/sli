begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_journal_finding_event_lookup425'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=421 and name='sli_own_actions')
       or exists(select 1 from public.schema_migrations where version>=425) then
        raise exception 'journal_finding_event_lookup425_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create index finding_event_journal425 on public.finding_event_copies337(event_id,finding_id);

reset role;
insert into public.schema_migrations(version,name) values(425,'journal_finding_event_lookup');
commit;
