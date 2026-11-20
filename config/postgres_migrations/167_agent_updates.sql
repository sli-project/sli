-- Additive signed agent packages, explicit owner policy and update outcomes.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_updates_v167'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 167 requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from public.schema_migrations where version=167) then
        raise exception 'migration 167 already recorded';
    end if;
    if not exists(select 1 from public.schema_migrations where version=166 and name='registered_plugin_activation')
       or exists(select 1 from public.schema_migrations where version>166) then
        raise exception 'migration 167 requires exact migration 166 registered_plugin_activation';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.sli_agent_update_packages (
    sha256 text primary key check(sha256 ~ '^[0-9a-f]{64}$'),
    version text not null check(version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
    manifest jsonb not null check(manifest->>'component'='agent' and manifest->>'package_id'='sli.agent'),
    archive bytea not null check(octet_length(archive) between 1 and 268435456),
    created_at timestamptz not null default clock_timestamp()
);
create table public.sli_agent_update_policy (
    agent_id uuid primary key references public.sli_agents(id),
    package_sha256 text references public.sli_agent_update_packages(sha256)
);
create table public.sli_agent_update_results (
    agent_id uuid not null references public.sli_agents(id),
    package_sha256 text not null references public.sli_agent_update_packages(sha256),
    status text not null check(status in ('updated','rejected','rolled_back')),
    reason text check(reason in ('agent_update_verification_failed','agent_update_stage_failed',
        'agent_update_start_failed','agent_update_self_check_failed','agent_update_timeout',
        'agent_update_incompatible_version','agent_update_incompatible_platform','agent_update_incompatible_api',
        'agent_update_insufficient_disk','agent_update_download_failed')),
    reason_key text generated always as (coalesce(reason,'')) stored,
    version text not null check(version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
    observed_at timestamptz not null default clock_timestamp(),
    primary key(agent_id,package_sha256,status,reason_key),
    check((status='updated')=(reason is null))
);
revoke all on public.sli_agent_update_packages, public.sli_agent_update_policy, public.sli_agent_update_results from public;
grant select,insert on public.sli_agent_update_packages, public.sli_agent_update_policy, public.sli_agent_update_results to adlog_user;
grant update(package_sha256) on public.sli_agent_update_policy to adlog_user;
alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
alter table public.sli_agent_audit add constraint sli_agent_audit_action_check
    check(action in ('token_create','token_list','token_revoke','agent_list','issue','renew','revoke','disable','module_assign',
        'policy_ack','probe_request','probe_report','update_upload','update_list','update_assign','update_result'));
create index sli_agent_audit_update_assignment on public.sli_agent_audit(target,(details->>'sha256'))
    where action='update_assign';
reset role;
insert into public.schema_migrations(version,name) values(167,'agent_updates');
commit;
