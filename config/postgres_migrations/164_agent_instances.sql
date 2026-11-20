-- Owner-approved service instances may share a host, never a registry identity.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_instances_v164'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 164 requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from public.schema_migrations where version=164) then
        raise exception 'migration 164 already recorded';
    end if;
    if not exists(select 1 from public.schema_migrations where version=163 and name='agent_policy_revisions')
       or exists(select 1 from public.schema_migrations where version>163) then
        raise exception 'migration 164 requires exact migration 163 agent_policy_revisions';
    end if;
end $$;
set local role adlog_storage_owner;
alter table public.sli_agents
    add column instance_name text check(instance_name ~ '^[a-z0-9][a-z0-9_-]{0,47}$');
alter table public.sli_agent_enrollment_tokens
    add column instance_name text check(instance_name ~ '^[a-z0-9][a-z0-9_-]{0,47}$');
alter table public.sli_agents drop constraint sli_agents_host_id_key;
create unique index sli_agents_unnamed_host on public.sli_agents(host_id) where instance_name is null;
create unique index sli_agents_named_host on public.sli_agents(host_id,instance_name) where instance_name is not null;
-- Keep host/instance approvals immutable to the runtime; existing column UPDATE
-- grants do not include the new columns. Existing rows remain unnamed.
insert into public.schema_migrations(version,name) values(164,'agent_instances');
commit;
