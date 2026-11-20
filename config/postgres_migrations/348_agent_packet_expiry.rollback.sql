begin;
select pg_advisory_xact_lock(hashtext('sli_agent_packet_expiry_v348'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=348 and name='agent_packet_expiry')
       or exists(select 1 from public.schema_migrations where version>348) then
        raise exception 'agent_packet_expiry_348_rollback_preflight' using errcode='55000';
    end if;
    -- Rollback cannot forget a transport tip which the agent has already acknowledged.
    if exists(select 1 from public.sli_agents where packet_expiry<>'{}'::jsonb) then
        raise exception 'agent_packet_expiry_348_rollback_has_state' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
alter table public.sli_agents drop column packet_expiry;
delete from public.schema_migrations where version=348 and name='agent_packet_expiry';
reset role;
commit;
