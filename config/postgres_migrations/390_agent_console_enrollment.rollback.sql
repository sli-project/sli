begin;
select pg_advisory_xact_lock(hashtext('sli_agent_console_enrollment390'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=390 and name='agent_console_enrollment')
       or exists(select 1 from public.schema_migrations where version>390) then
        raise exception 'agent_console_enrollment390_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Keep completed registrations, issued certificates and the audit trail.
alter table public.sli_agent_enrollment_tokens drop column console_token_id;
drop table public.sli_agent_console_tokens;
delete from public.schema_migrations where version=390 and name='agent_console_enrollment';
reset role;
commit;
