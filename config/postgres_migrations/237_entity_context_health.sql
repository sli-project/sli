-- Collection health must not decode every historical packet on each shell poll.
begin;
select pg_advisory_xact_lock(hashtext('sli_entity_context_health_v237'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=236 and name='file_audit_evidence')
       or exists(select 1 from public.schema_migrations where version>=237) then
        raise exception 'migration 237 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

-- Generated values backfill existing packets and remain consistent on ingest.
-- The native channel is in the packet header for multiplexed AD/DC and
-- workstation streams; their envelope channel is only the stream identity.
alter table public.sli_agent_packet_inbox
    add column collection_revision text generated always as (envelope->>'policy_revision') stored,
    add column collection_channel text generated always as (coalesce(packet->'header'->>'channel',envelope->>'channel')) stored,
    add column collection_read_error boolean generated always as
        (coalesce(packet->'context'->'workstations'->>'read_error',
                  packet->'context'->'ad_dc'->>'read_error','')<>'') stored;

-- Serve both the latest receipt per agent and the complete historical stream
-- aggregates without fetching receipt documents or large packet payloads.
create index sli_agent_receipts_collection_health
    on public.sli_agent_receipts (agent_id,received_at desc) include(packet_id,module_id,sequence);
create index sli_agent_inbox_collection_health
    on public.sli_agent_packet_inbox (packet_id)
    include(collection_revision,collection_channel,collection_read_error,imported_at);

reset role;
insert into public.schema_migrations(version,name) values(237,'entity_context_health');
commit;
