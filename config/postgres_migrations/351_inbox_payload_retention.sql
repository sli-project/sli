-- Online build follows the autocommit migration path used by migration 329.
select pg_advisory_lock(hashtext('sli_inbox_payload_retention351'));
begin;
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=349 and name='short_event_packet_admission')
       or exists(select 1 from public.schema_migrations where version>=351) then
        raise exception 'inbox_payload_retention351_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
commit;
set role adlog_storage_owner;
-- An interrupted concurrent build must not leave an invalid index on retry.
drop index concurrently if exists public.sli_agent_inbox_received351;
create index concurrently sli_agent_inbox_received351 on public.sli_agent_packet_inbox(received_at);
reset role;
begin;
set local role adlog_storage_owner;
alter table public.sli_agent_packet_inbox alter column packet drop not null;
alter table public.sli_agent_packet_inbox alter column event_rows drop not null;
alter table public.sli_agent_packet_inbox add constraint sli_agent_inbox_payload351 check (
    (packet is not null and event_rows is not null) or
    (packet is null and event_rows is null and imported_at is not null));
-- ANALYZE must not detoast payloads to build unused JSONB statistics.
alter table public.sli_agent_packet_inbox alter column packet set statistics 0;
alter table public.sli_agent_packet_inbox alter column event_rows set statistics 0;
create or replace function public.agent_inbox_payload_bytes_v217()
returns trigger language plpgsql security invoker set search_path=pg_catalog,pg_temp as $$
begin
    new.quota_payload_bytes := 1024 + octet_length(new.envelope::text)
        + coalesce(octet_length(new.packet::text),0) + coalesce(octet_length(new.event_rows::text),0);
    return new;
end $$;
grant select on public.storage_v2_event_identity_allocations,public.sli_agent_packet_quarantine to adlog_storage_lifecycle_delete;
grant select(id,status) on public.sli_agents to adlog_storage_lifecycle_delete;
grant update(id) on public.sli_agents to adlog_storage_lifecycle_delete;
grant update(packet,event_rows) on public.sli_agent_packet_inbox to adlog_storage_lifecycle_delete;
-- Clearing the body changes the generated inbox channel/read-error columns.
-- The durable stream receipt must retain the original collection metadata.
do $$ declare definition text; begin
    select pg_get_functiondef('public.record_agent_stream_receipt_v313()'::regprocedure) into strict definition;
    execute replace(definition,'if tg_op=''UPDATE'' then',
        'if tg_op=''UPDATE'' then
        if new.packet is null then return null; end if; -- payload_retention351');
end $$;
do $$ declare definition text; begin
    select pg_get_functiondef('public.read_t109_agent_health(jsonb)'::regprocedure) into strict definition;
    execute replace(definition,'select i.imported_at,i.collection_read_error from public.sli_agent_packet_inbox i',
        'select i.imported_at,h.collection_read_error from public.sli_agent_packet_inbox i');
end $$;
do $$ begin
    if not exists(select 1 from pg_index where indexrelid='public.sli_agent_inbox_received351'::regclass and indisvalid and indisready) then
        raise exception 'inbox_payload_retention351_index_invalid' using errcode='55000';
    end if;
end $$;
insert into public.schema_migrations(version,name) values(351,'inbox_payload_retention');
reset role;
commit;
select pg_advisory_unlock(hashtext('sli_inbox_payload_retention351'));
