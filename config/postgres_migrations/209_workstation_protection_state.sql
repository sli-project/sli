-- Current agent-attested protection flags are snapshots, never native events.
begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_protection_state_v209'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 209 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from public.schema_migrations where version=208 and name='file_audit_collection_replay')
       or not exists(select 1 from public.schema_migrations where version=159 and name='workstation_security')
       or exists(select 1 from public.schema_migrations where version>=209) then
        raise exception 'migration 209 requires workstation security and exact migration 208';
    end if;
end $$;
set local role adlog_storage_owner;
create table sli_plugin_workstations.protection_state (
    id text primary key check(id ~ '^[a-f0-9]{64}$'),
    agent_key text not null unique check(length(trim(agent_key)) between 1 and 256),
    entity_id bigint not null check(entity_id>0),
    ad_computer_id bigint check(ad_computer_id>0),
    observed_at timestamptz not null,
    state jsonb not null check(jsonb_typeof(state)='object'),
    state_sha256 text not null check(state_sha256 ~ '^[a-f0-9]{64}$')
);
revoke all on sli_plugin_workstations.protection_state from public,adlog_user;
grant select,insert,update on sli_plugin_workstations.protection_state to adlog_user;
reset role;
insert into public.schema_migrations(version,name) values(209,'workstation_protection_state');
commit;
