-- Removal commands never delete registry identities, policy or evidence.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_removal_v177'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 177 requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from public.schema_migrations where version=177) then
        raise exception 'migration 177 already recorded';
    end if;
    if not exists(select 1 from public.schema_migrations where version=176 and name='workstation_history')
       or exists(select 1 from public.schema_migrations where version>176) then
        raise exception 'migration 177 requires exact migration 176 workstation_history';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.sli_agent_removals (
    agent_id uuid primary key references public.sli_agents(id),
    operation_id uuid not null,
    command_id uuid not null unique,
    state text not null default 'pending' check(state in ('pending','cleanup_failed','state_cleaned')),
    reason text check(reason in ('agent_removal_requires_admin','agent_removal_unmanaged','agent_removal_cleanup_failed')),
    requested_at timestamptz not null default clock_timestamp(),
    reported_at timestamptz,
    check((state='cleanup_failed')=(reason is not null)),
    check((state='pending')=(reported_at is null))
);
create index sli_agent_removals_operation on public.sli_agent_removals(operation_id);
revoke all on public.sli_agent_removals from public,adlog_user;
grant select,insert on public.sli_agent_removals to adlog_user;
grant update(state,reason,reported_at) on public.sli_agent_removals to adlog_user;
do $$
declare prior_check text;
begin
    select pg_get_expr(conbin,conrelid) into strict prior_check from pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action in (''removal_request'',''removal_result''))',prior_check);
end $$;
reset role;
insert into public.schema_migrations(version,name) values(177,'agent_removal');
commit;
