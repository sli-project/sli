-- Exact last import per stream. The inbox write and this fact commit together,
-- including deferred inputs and quarantine replay; receipt order is not FIFO.
-- Backfill walks history ONCE. Apply through the controlled update path:
-- the inbox lock blocks writers while the trigger and backfill are installed.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_stream_import_health_v297'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations
                     where version=286 and name='sigma_rule_labels')
       or exists(select 1 from public.schema_migrations where version>=297) then
        raise exception 'migration 297 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;
lock table public.sli_agent_packet_inbox in share row exclusive mode;

create table public.sli_agent_stream_import_health (
    agent_id uuid not null,
    module_id text not null,
    revision text,
    channel text,
    last_import_at timestamptz not null,
    constraint sli_agent_stream_import_health_key
        unique nulls not distinct(agent_id,module_id,revision,channel) include(last_import_at)
);
revoke all on public.sli_agent_stream_import_health from public,adlog_user;
grant select on public.sli_agent_stream_import_health to adlog_user;

-- Trigger covers every imported_at writer, including the maintenance replay
-- path, without granting runtime direct write access to the summary. Stream
-- identity comes from the durable receipt and migration237 generated columns.
create function public.record_agent_stream_import_v297() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    insert into public.sli_agent_stream_import_health as current
        (agent_id,module_id,revision,channel,last_import_at)
    select r.agent_id,r.module_id,new.collection_revision,new.collection_channel,new.imported_at
    from public.sli_agent_receipts r where r.packet_id=new.packet_id
    on conflict on constraint sli_agent_stream_import_health_key do update
        set last_import_at=greatest(current.last_import_at,excluded.last_import_at);
    return null;
end $$;
revoke all on function public.record_agent_stream_import_v297() from public,adlog_user;
create trigger sli_agent_stream_import_health_write
    after insert or update of imported_at on public.sli_agent_packet_inbox
    for each row when (new.imported_at is not null)
    execute function public.record_agent_stream_import_v297();

insert into public.sli_agent_stream_import_health(agent_id,module_id,revision,channel,last_import_at)
select r.agent_id,r.module_id,i.collection_revision,i.collection_channel,max(i.imported_at)
from public.sli_agent_receipts r join public.sli_agent_packet_inbox i using(packet_id)
where i.imported_at is not null
group by r.agent_id,r.module_id,i.collection_revision,i.collection_channel;

reset role;
insert into public.schema_migrations(version,name) values(297,'agent_stream_import_health');
commit;
