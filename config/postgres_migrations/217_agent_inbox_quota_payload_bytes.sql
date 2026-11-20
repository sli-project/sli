-- Charge exact durable JSONB bytes without detoasting every pending payload
-- while ingress holds both the agent row and the global quota lock.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_inbox_quota_payload_bytes_v217'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=216 and name='semantic_quarantine_requeue')
       or exists(select 1 from public.schema_migrations where version>=217) then
        raise exception 'migration 217 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

-- A nullable ordinary column avoids rewriting the whole historical inbox.
-- Only pending inputs need a backfill; legacy NULLs retain exact fallback math.
alter table public.sli_agent_packet_inbox add column quota_payload_bytes bigint
    check(quota_payload_bytes>=1024);
update public.sli_agent_packet_inbox
set quota_payload_bytes=1024 + octet_length(envelope::text)
    + octet_length(packet::text) + octet_length(event_rows::text)
where imported_at is null;

create function public.agent_inbox_payload_bytes_v217()
returns trigger language plpgsql security invoker set search_path=pg_catalog,pg_temp as $$
begin
    -- The caller cannot understate the charge, including on a direct UPDATE.
    new.quota_payload_bytes := 1024 + octet_length(new.envelope::text)
        + octet_length(new.packet::text) + octet_length(new.event_rows::text);
    return new;
end $$;
revoke all on function public.agent_inbox_payload_bytes_v217() from public;
create trigger agent_inbox_payload_bytes_v217
before insert or update of envelope,packet,event_rows,quota_payload_bytes
on public.sli_agent_packet_inbox for each row
execute function public.agent_inbox_payload_bytes_v217();

insert into public.schema_migrations(version,name) values(217,'agent_inbox_quota_payload_bytes');
commit;
