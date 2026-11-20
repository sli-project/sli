-- Group tokens admit pending requests only. No deployment or approval is enabled.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_group_enrollment_v175'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 175 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from public.schema_migrations where version=174 and name='agent_gpo_snapshot_import')
       or exists(select 1 from public.schema_migrations where version>=175) then
        raise exception 'migration 175 requires exact migration 174 agent_gpo_snapshot_import';
    end if;
end $$;
grant references(id) on public.domains,public.entities_v2,public.ad_context_entity_versions to adlog_storage_owner;
set local role adlog_storage_owner;
create table public.sli_agent_group_tokens (
    id uuid primary key,
    token_hash text not null unique check(token_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null,
    expires_at timestamptz not null,
    max_uses integer not null check(max_uses between 1 and 10000),
    uses_count integer not null default 0 check(uses_count between 0 and max_uses),
    domain_id bigint not null references public.domains(id),
    ou_entity_ids bigint[] not null check(cardinality(ou_entity_ids) between 1 and 128
        and array_position(ou_entity_ids,null) is null),
    revoked_at timestamptz,
    check(expires_at >= created_at+interval '60 seconds' and expires_at <= created_at+interval '24 hours')
);
create table public.sli_agent_group_requests (
    id uuid primary key,
    token_id uuid not null references public.sli_agent_group_tokens(id),
    host_id uuid not null,
    instance_name text check(instance_name ~ '^[a-z0-9][a-z0-9_-]{0,47}$'),
    key_fingerprint text not null check(key_fingerprint ~ '^[0-9a-f]{64}$'),
    -- Eligibility references are claims until independent key-to-machine verification.
    computer_entity_id bigint not null references public.entities_v2(id),
    computer_version_id bigint not null references public.ad_context_entity_versions(id),
    status text not null default 'pending' check(status in ('pending','cancelled')),
    created_at timestamptz not null default clock_timestamp(),
    unique nulls not distinct(token_id,key_fingerprint,instance_name)
);
revoke all on public.sli_agent_group_tokens,public.sli_agent_group_requests from public,adlog_user;
grant select,insert on public.sli_agent_group_tokens,public.sli_agent_group_requests to adlog_user;
grant update(uses_count,revoked_at) on public.sli_agent_group_tokens to adlog_user;
grant update(status) on public.sli_agent_group_requests to adlog_user;
do $$
declare prior_check text;
begin
    select pg_get_expr(conbin,conrelid) into strict prior_check from pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action in (''group_token_create'',''group_token_list'',''group_token_revoke'',''group_request''))',prior_check);
end $$;
reset role;
insert into public.schema_migrations(version,name) values(175,'agent_group_enrollment');
commit;
