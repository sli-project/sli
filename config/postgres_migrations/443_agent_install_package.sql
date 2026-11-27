begin;
select pg_advisory_xact_lock(hashtext('sli_agent_install_package443'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=442 and name='agent_unicode_host_names')
       or exists(select 1 from public.schema_migrations where version>=443) then
        raise exception 'agent_install_package443_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

alter table public.sli_agent_console_tokens
    alter column expires_at drop not null,
    alter column host_limit drop not null,
    alter column remaining drop not null,
    drop constraint sli_agent_console_tokens_check,
    drop constraint sli_agent_console_tokens_host_limit_check,
    add column installer jsonb,
    add constraint sli_agent_console_tokens_limits check (
        (installer is not null or (expires_at is not null and host_limit is not null and host_limit between 1 and 100
            and expires_at > created_at
            and expires_at <= created_at + interval '1 hour'))
        and (host_limit is null or host_limit > 0)
        and ((host_limit is null and remaining is null) or (host_limit is not null and remaining is not null))
    );
create unique index sli_agent_install_package_one_active on public.sli_agent_console_tokens ((true))
    where installer is not null and revoked_at is null;
grant update (installer, expires_at, host_limit) on public.sli_agent_console_tokens to adlog_user;

alter table public.sli_agents add column machine_role text
    check (machine_role in ('domain_controller', 'file_server', 'workstation'));
grant update (machine_role) on public.sli_agents to adlog_user;
create index sli_agent_audit_enrollment_rejections on public.sli_agent_audit (occurred_at desc, id desc)
    where action='issue' and actor='enrollment' and details->>'outcome'='rejected';

insert into public.schema_migrations(version,name) values(443,'agent_install_package');
commit;
