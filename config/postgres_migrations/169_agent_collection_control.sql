begin;
select pg_advisory_xact_lock(hashtext('sli_agent_collection_control_v169'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 169 requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from public.schema_migrations where version=169) then
        raise exception 'migration 169 already applied';
    end if;
    if not exists(select 1 from public.schema_migrations where version=168 and name='plugin_core_drain_handoff')
       or exists(select 1 from public.schema_migrations where version>168) then
        raise exception 'migration 169 requires exact migration 168 plugin_core_drain_handoff';
    end if;
end $$;
set local role adlog_storage_owner;
alter table public.sli_agents
    add column collection_policy jsonb not null default
        '{"state":"active","interval_seconds":60,"batch_size":32,"rate_limit_per_minute":120,"spool_max_bytes":67108864}'::jsonb
        check(jsonb_typeof(collection_policy)='object'),
    add column applied_collection_state text not null default 'unknown'
        check(applied_collection_state in ('unknown','active','paused'));
grant update(collection_policy,applied_collection_state) on public.sli_agents to adlog_user;
-- Retain owner-issued module policies for packets already captured in a spool.
-- Snapshots belong to one agent and are append-only to the runtime role.
create table public.sli_agent_policy_history (
    agent_id uuid not null references public.sli_agents(id),
    revision bigint not null check(revision between 1 and 9007199254740991),
    assigned_modules jsonb not null check(jsonb_typeof(assigned_modules)='array'),
    collection_policy jsonb not null check(jsonb_typeof(collection_policy)='object'),
    created_at timestamptz not null default clock_timestamp(),
    primary key(agent_id,revision)
);
insert into public.sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy)
    select id,policy_revision,assigned_modules,collection_policy from public.sli_agents;
revoke all on public.sli_agent_policy_history from public,adlog_user;
grant select,insert on public.sli_agent_policy_history to adlog_user;
-- Preserve actions introduced by predecessors while adding this command.
do $$
declare prior_check text;
begin
    select pg_get_expr(conbin,conrelid) into strict prior_check from pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action=''policy_update'')',prior_check);
end $$;
create index sli_agent_audit_policy_target on public.sli_agent_audit(target,id desc)
    where action in ('module_assign','policy_update','policy_ack');
insert into public.schema_migrations(version,name) values(169,'agent_collection_control');
commit;
