begin;
select pg_advisory_xact_lock(hashtext('sli_inbox_payload_retention351'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=351 and name='inbox_payload_retention')
       or exists(select 1 from public.schema_migrations where version>351) then
        raise exception 'inbox_payload_retention351_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- Expired bodies cannot be reconstructed. Never pretend rollback restores them.
do $$ begin
    if exists(select 1 from public.sli_agent_packet_inbox where packet is null or event_rows is null) then
        raise exception 'inbox_payload_retention351_rollback_payloads_expired' using errcode='55000';
    end if;
end $$;
alter table public.sli_agent_packet_inbox drop constraint sli_agent_inbox_payload351;
alter table public.sli_agent_packet_inbox alter column packet set not null;
alter table public.sli_agent_packet_inbox alter column event_rows set not null;
alter table public.sli_agent_packet_inbox alter column packet set statistics -1;
alter table public.sli_agent_packet_inbox alter column event_rows set statistics -1;
create or replace function public.agent_inbox_payload_bytes_v217()
returns trigger language plpgsql security invoker set search_path=pg_catalog,pg_temp as $$
begin
    new.quota_payload_bytes := 1024 + octet_length(new.envelope::text)
        + octet_length(new.packet::text) + octet_length(new.event_rows::text);
    return new;
end $$;
revoke select on public.storage_v2_event_identity_allocations,public.sli_agent_packet_quarantine from adlog_storage_lifecycle_delete;
revoke select(id,status) on public.sli_agents from adlog_storage_lifecycle_delete;
revoke update(id) on public.sli_agents from adlog_storage_lifecycle_delete;
revoke update(packet,event_rows) on public.sli_agent_packet_inbox from adlog_storage_lifecycle_delete;
do $$ declare definition text; begin
    select pg_get_functiondef('public.record_agent_stream_receipt_v313()'::regprocedure) into strict definition;
    execute replace(definition,E'\n        if new.packet is null then return null; end if; -- payload_retention351','');
    select pg_get_functiondef('public.read_t109_agent_health(jsonb)'::regprocedure) into strict definition;
    execute replace(definition,'select i.imported_at,h.collection_read_error from public.sli_agent_packet_inbox i',
        'select i.imported_at,i.collection_read_error from public.sli_agent_packet_inbox i');
end $$;
drop index public.sli_agent_inbox_received351;
delete from public.schema_migrations where version=351 and name='inbox_payload_retention';
reset role;
commit;
