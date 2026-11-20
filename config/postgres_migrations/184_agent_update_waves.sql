-- Preparation only: no package assignment or fleet update is started.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_update_waves_v184'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 184 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from public.schema_migrations where version=183 and name='file_audit_contracts')
       or exists(select 1 from public.schema_migrations where version>=184) then
        raise exception 'migration 184 requires exact migration 183 file_audit_contracts and unused version 184';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.sli_agent_update_waves (
    id uuid primary key,
    package_sha256 text not null references public.sli_agent_update_packages(sha256),
    version text not null check(version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
    batch_size integer not null check(batch_size between 1 and 100),
    error_threshold integer not null check(error_threshold between 0 and 1000),
    group_token_id uuid references public.sli_agent_group_tokens(id),
    created_by text not null,
    created_at timestamptz not null default clock_timestamp(),
    current_batch integer not null default 0 check(current_batch between 0 and 1000),
    status text not null default 'running' check(status in ('running','stopped','completed')),
    reason text check(reason in ('agent_update_error_threshold_exceeded',
        'agent_update_agent_inactive','agent_update_stopped_by_admin')),
    finished_at timestamptz,
    unique(id,package_sha256),
    check((status='running')=(finished_at is null)),
    check((status='stopped')=(reason is not null))
);
create table public.sli_agent_update_wave_members (
    wave_id uuid not null,
    agent_id uuid not null references public.sli_agents(id),
    package_sha256 text not null,
    batch_number integer not null check(batch_number between 1 and 1000),
    state text not null default 'queued' check(state in ('queued','pending','updated','failed')),
    reason text check(reason in ('agent_update_version_mismatch','agent_update_verification_failed',
        'agent_update_stage_failed','agent_update_start_failed','agent_update_self_check_failed','agent_update_timeout',
        'agent_update_incompatible_version','agent_update_incompatible_platform','agent_update_incompatible_api',
        'agent_update_insufficient_disk','agent_update_download_failed')),
    had_error boolean not null default false,
    reserved boolean not null default true,
    issued_at timestamptz,
    reported_at timestamptz,
    primary key(wave_id,agent_id),
    foreign key(wave_id,package_sha256) references public.sli_agent_update_waves(id,package_sha256),
    unique(agent_id,package_sha256),
    check((state='queued')=(issued_at is null)),
    check((state='failed')=(reason is not null)),
    check(state not in ('updated','failed') or reported_at is not null)
);
create unique index sli_agent_update_wave_reservation on public.sli_agent_update_wave_members(agent_id) where reserved;
create index sli_agent_update_wave_batch on public.sli_agent_update_wave_members(wave_id,batch_number);
revoke all on public.sli_agent_update_waves,public.sli_agent_update_wave_members from public,adlog_user;
grant select,insert on public.sli_agent_update_waves,public.sli_agent_update_wave_members to adlog_user;
grant update(current_batch,status,reason,finished_at) on public.sli_agent_update_waves to adlog_user;
grant update(state,reason,had_error,reserved,issued_at,reported_at) on public.sli_agent_update_wave_members to adlog_user;
do $$
declare prior_check text;
begin
    select pg_get_expr(conbin,conrelid) into strict prior_check from pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action in (''update_wave_create'',''update_wave_batch'',''update_wave_stop'',''update_wave_complete'',''update_wave_list'',''update_wave_result''))',prior_check);
end $$;
reset role;
insert into public.schema_migrations(version,name) values(184,'agent_update_waves');
commit;
