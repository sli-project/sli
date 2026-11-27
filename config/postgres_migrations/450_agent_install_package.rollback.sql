begin;
select pg_advisory_xact_lock(hashtext('sli_agent_install_package450'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=450 and name='agent_install_package')
       or exists(select 1 from public.schema_migrations where version>450) then
        raise exception 'agent_install_package450_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

drop index public.sli_agent_audit_enrollment_rejections;
alter table public.sli_agents drop column machine_role;

-- Preserve the agents already enrolled. The relationship is ON DELETE SET NULL.
delete from public.sli_agent_console_tokens where installer is not null;
drop index public.sli_agent_install_package_one_active;
revoke update (installer, expires_at, host_limit) on public.sli_agent_console_tokens from adlog_user;
alter table public.sli_agent_console_tokens
    drop constraint sli_agent_console_tokens_limits,
    drop column installer,
    alter column expires_at set not null,
    alter column host_limit set not null,
    alter column remaining set not null,
    add constraint sli_agent_console_tokens_host_limit_check check (host_limit between 1 and 100),
    add constraint sli_agent_console_tokens_check
        check (expires_at > created_at and expires_at <= created_at + interval '1 hour');

delete from public.schema_migrations where version=450 and name='agent_install_package';
commit;
