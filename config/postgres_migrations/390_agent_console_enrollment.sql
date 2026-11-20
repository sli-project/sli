begin;
select pg_advisory_xact_lock(hashtext('sli_agent_console_enrollment390'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=389 and name='file_action_intake')
       or exists(select 1 from public.schema_migrations where version>=390) then
        raise exception 'agent_console_enrollment390_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.sli_agent_console_tokens (
    id uuid primary key,
    token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null,
    expires_at timestamptz not null,
    revoked_at timestamptz,
    host_limit integer not null check (host_limit between 1 and 100),
    remaining integer not null check (remaining between 0 and host_limit),
    check (expires_at > created_at and expires_at <= created_at + interval '1 hour')
);
create index sli_agent_console_tokens_expiry on public.sli_agent_console_tokens(expires_at);
alter table public.sli_agent_enrollment_tokens
    add column console_token_id uuid references public.sli_agent_console_tokens(id) on delete set null,
    add constraint sli_agent_console_host_unique unique (console_token_id, host_id),
    add constraint sli_agent_console_key_unique unique (console_token_id, key_fingerprint);

grant select, insert, delete on public.sli_agent_console_tokens to adlog_user;
grant update (remaining, revoked_at) on public.sli_agent_console_tokens to adlog_user;
insert into public.schema_migrations(version,name) values(390,'agent_console_enrollment');
reset role;
commit;
