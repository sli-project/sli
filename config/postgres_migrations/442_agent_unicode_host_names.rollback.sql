begin;
select pg_advisory_xact_lock(hashtext('sli_agent_unicode_host_names442'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=442 and name='agent_unicode_host_names')
       or exists(select 1 from public.schema_migrations where version>442) then
        raise exception 'agent_unicode_host_names442_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Hold the table lock across validation and replacement. Any failure rolls
-- back the constraint change and leaves every registration in place.
alter table public.sli_agents drop constraint sli_agents_registration_host_name_check;
do $$ begin
    if exists(select 1 from public.sli_agents
              where octet_length(registration_host_name) <> char_length(registration_host_name)) then
        raise exception 'Cannot roll back migration 442: non-ASCII agent registration host names exist'
            using errcode='55000';
    end if;
end $$;
alter table public.sli_agents
    add constraint sli_agents_registration_host_name_check check (registration_host_name is null or (
        char_length(registration_host_name) between 1 and 253
        and registration_host_name ~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
    ));

delete from public.schema_migrations where version=442 and name='agent_unicode_host_names';
commit;
