-- PostgreSQL cannot index receipt order and inbox stream keys across a join.
-- Keep only that join's metadata, never payload. Inbox retention cascades here;
-- a latest-only summary would incorrectly keep a deleted packet as the latest.
-- Build/backfill walks retained history once and blocks inbox writers until
-- commit. Apply in the owner's controlled update window, never from runtime.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_agent_collection_stream_index_v313'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=312 and name='semantic_workstation_discovery')
       or not exists(select 1 from public.schema_migrations where version=297 and name='agent_stream_import_health')
       or exists(select 1 from public.schema_migrations where version>=313) then
        raise exception 'agent_collection_stream_index_313_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
lock table public.sli_agent_packet_inbox in share row exclusive mode;

create table public.sli_agent_stream_receipts (
    packet_id uuid primary key references public.sli_agent_packet_inbox(packet_id) on delete cascade,
    agent_id uuid not null,
    module_id text not null,
    collection_revision text,
    collection_channel text,
    received_at timestamptz not null,
    sequence bigint not null,
    collection_read_error boolean
);
revoke all on public.sli_agent_stream_receipts from public,adlog_user;
grant select on public.sli_agent_stream_receipts to adlog_user;

-- Receipt identity, time and sequence remain authoritative; inbox timestamps
-- and agent-supplied envelope identity cannot substitute for them.
insert into public.sli_agent_stream_receipts
    (packet_id,agent_id,module_id,collection_revision,collection_channel,received_at,sequence,collection_read_error)
select r.packet_id,r.agent_id,r.module_id,i.collection_revision,i.collection_channel,r.received_at,r.sequence,i.collection_read_error
from public.sli_agent_packet_inbox i join public.sli_agent_receipts r using(packet_id);

-- The null flag makes NULL and the empty channel separate exact index ranges.
-- No IS NOT DISTINCT FROM filter can force a walk through another channel.
create index sli_agent_stream_receipts_lookup on public.sli_agent_stream_receipts
    (agent_id,module_id,collection_revision,(collection_channel is null),
     (coalesce(collection_channel,'')),received_at desc,sequence desc)
    include(packet_id,collection_read_error);

create function public.record_agent_stream_receipt_v313() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    -- Imported-at progress does not rewrite this receipt index. Migration 297
    -- continues to maintain the independent, exact last-import fact.
    if tg_op='UPDATE' then
        if (new.collection_revision,new.collection_channel,new.collection_read_error)
            is not distinct from (old.collection_revision,old.collection_channel,old.collection_read_error) then
            return null;
        end if;
    end if;
    insert into public.sli_agent_stream_receipts as current
        (packet_id,agent_id,module_id,collection_revision,collection_channel,received_at,sequence,collection_read_error)
    select r.packet_id,r.agent_id,r.module_id,new.collection_revision,new.collection_channel,r.received_at,r.sequence,new.collection_read_error
    from public.sli_agent_receipts r where r.packet_id=new.packet_id
    on conflict(packet_id) do update set
        agent_id=excluded.agent_id,module_id=excluded.module_id,
        collection_revision=excluded.collection_revision,collection_channel=excluded.collection_channel,
        received_at=excluded.received_at,sequence=excluded.sequence,collection_read_error=excluded.collection_read_error;
    return null;
end $$;
revoke all on function public.record_agent_stream_receipt_v313() from public,adlog_user;
create trigger sli_agent_stream_receipts_write
    after insert or update on public.sli_agent_packet_inbox
    for each row execute function public.record_agent_stream_receipt_v313();
analyze public.sli_agent_stream_receipts;

insert into public.schema_migrations(version,name) values(313,'agent_collection_stream_index');
reset role;
commit;
