begin;
select pg_advisory_xact_lock(hashtext('sli_agent_windows_audit_v171'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 171 requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from public.schema_migrations where version=171) then
        raise exception 'migration 171 already applied';
    end if;
    if not exists(select 1 from public.schema_migrations where version=170 and name='agent_snapshot_stream')
       or exists(select 1 from public.schema_migrations where version>170) then
        raise exception 'migration 171 requires exact migration 170 agent_snapshot_stream';
    end if;
end $$;
set local role adlog_storage_owner;
-- Management flags live in the existing revisioned collection_policy JSON.
-- An empty observation is unknown; it never means that Windows was changed.
alter table public.sli_agents
    add column windows_audit jsonb not null default '{}'::jsonb
        check(jsonb_typeof(windows_audit)='object' and octet_length(windows_audit::text)<=16384);
grant update(windows_audit) on public.sli_agents to adlog_user;
insert into public.schema_migrations(version,name) values(171,'agent_windows_audit');
commit;
