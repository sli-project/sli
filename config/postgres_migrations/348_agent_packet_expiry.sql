begin;
select pg_advisory_xact_lock(hashtext('sli_agent_packet_expiry_v348'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=340 and name='default_policy_reconcile')
       or exists(select 1 from public.schema_migrations where version>=348) then
        raise exception 'agent_packet_expiry_348_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- Bounded transport state: the last expired envelope and latest gap per module.
alter table public.sli_agents add column packet_expiry jsonb not null default '{}'::jsonb
    check(jsonb_typeof(packet_expiry)='object');
grant select(packet_expiry),update(packet_expiry) on public.sli_agents to adlog_user;
insert into public.schema_migrations(version,name) values(348,'agent_packet_expiry');
reset role;
commit;
