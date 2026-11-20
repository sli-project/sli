begin;
select pg_advisory_xact_lock(hashtext('ad_log_agent_registry_v156'));
do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 156 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from schema_migrations where version=155 and name='core_identity_scope') then
        raise exception 'migration 156 requires exact migration 155 core_identity_scope';
    end if;
    if exists(select 1 from schema_migrations where version=156 and name <> 'agent_registry') then
        raise exception 'migration 156 is owned by another contract';
    end if;
end $$;
-- Delegate ledger privileges before switching owner, as in migration 019.
-- Agent FKs below reference only objects created by this same owner.
grant usage, create on schema public to adlog_storage_owner;
grant select, insert on schema_migrations to adlog_storage_owner;
grant usage, select on sequence schema_migrations_id_seq to adlog_storage_owner;
set local role adlog_storage_owner;

create table sli_agents (
    id uuid primary key,
    host_id uuid not null unique,
    key_fingerprint text not null check (key_fingerprint ~ '^[0-9a-f]{64}$'),
    status text not null default 'active' check (status in ('active','disabled')),
    assigned_modules jsonb not null default '[]'::jsonb
        check (jsonb_typeof(assigned_modules)='array' and jsonb_array_length(assigned_modules)<=64),
    created_at timestamptz not null default clock_timestamp(),
    last_seen timestamptz
);
create table sli_agent_enrollment_tokens (
    id uuid primary key,
    token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
    host_id uuid not null,
    key_fingerprint text not null check (key_fingerprint ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null,
    expires_at timestamptz not null,
    used_at timestamptz,
    revoked_at timestamptz,
    check (expires_at > created_at and expires_at <= created_at + interval '1 hour')
);
create table sli_agent_certificates (
    id bigint generated always as identity primary key,
    agent_id uuid not null references sli_agents(id),
    serial text not null unique check (serial ~ '^[0-9a-f]{1,40}$'),
    fingerprint text not null unique check (fingerprint ~ '^[0-9a-f]{64}$'),
    not_before timestamptz not null,
    not_after timestamptz not null check (not_after > not_before),
    revoked_at timestamptz
);
create index sli_agent_certificates_agent on sli_agent_certificates(agent_id);
create table sli_agent_audit (
    id bigint generated always as identity primary key,
    action text not null check (action in ('token_create','token_list','token_revoke','agent_list','issue','renew','revoke','disable')),
    actor text not null check (length(actor) between 1 and 128),
    target text not null check (length(target) between 1 and 128),
    occurred_at timestamptz not null default clock_timestamp(),
    details jsonb not null default '{}'::jsonb
);
create index sli_agent_audit_revocations on sli_agent_audit(id) where action='revoke';
revoke all on sli_agents, sli_agent_enrollment_tokens, sli_agent_certificates, sli_agent_audit from public;
grant select, insert on sli_agents, sli_agent_enrollment_tokens, sli_agent_certificates to adlog_user;
grant update(status,key_fingerprint,last_seen) on sli_agents to adlog_user;
grant update(used_at,revoked_at) on sli_agent_enrollment_tokens to adlog_user;
grant update(revoked_at) on sli_agent_certificates to adlog_user;
grant select, insert on sli_agent_audit to adlog_user;
grant usage, select on sequence sli_agent_certificates_id_seq, sli_agent_audit_id_seq to adlog_user;
insert into schema_migrations(version,name) values(156,'agent_registry');
commit;
