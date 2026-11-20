begin;
select pg_advisory_xact_lock(hashtext('ad_log_agent_packets_v157'));
do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 157 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from schema_migrations where version=156 and name='agent_registry') then
        raise exception 'migration 157 requires exact migration 156 agent_registry';
    end if;
    if exists(select 1 from schema_migrations where version=157) then
        raise exception 'migration 157 already applied or owned by another contract';
    end if;
end $$;
grant usage, create on schema public to adlog_storage_owner;
grant select, insert on schema_migrations to adlog_storage_owner;
grant usage, select on sequence schema_migrations_id_seq to adlog_storage_owner;
set local role adlog_storage_owner;

-- Explicit owner-provisioned policy; empty on installation. Runtime can only read.
-- Agent-provided source/module names never establish authority.
create table sli_agent_module_bindings (
    agent_id uuid not null references sli_agents(id),
    module_id text not null check (module_id='sli.windows-eventlog'),
    source_instance_id text not null check (length(source_instance_id) between 1 and 512),
    source_name text not null check (length(source_name) between 1 and 512),
    channel text not null check (length(channel) between 1 and 512),
    module_version text not null check (module_version='1.0.0'),
    policy_revision text not null check (length(policy_revision) between 1 and 512),
    primary key(agent_id,module_id),
    unique(agent_id,source_instance_id,channel)
);
create table sli_agent_receipts (
    agent_id uuid not null references sli_agents(id),
    module_id text not null check (length(module_id) between 1 and 128),
    sequence bigint not null check (sequence>0),
    packet_id uuid not null unique,
    envelope_sha256 text not null check (envelope_sha256 ~ '^[0-9a-f]{64}$'),
    envelope jsonb not null check (jsonb_typeof(envelope)='object'),
    receipt jsonb not null check (receipt->>'status'='committed'),
    received_at timestamptz not null default clock_timestamp(),
    primary key(agent_id,module_id,sequence)
);
create table sli_agent_packet_inbox (
    packet_id uuid primary key references sli_agent_receipts(packet_id),
    envelope jsonb not null check (jsonb_typeof(envelope)='object'),
    packet jsonb not null check (packet->>'contract'='sli.collection-packet.v1'),
    event_rows jsonb not null check (jsonb_typeof(event_rows)='array'),
    received_at timestamptz not null default clock_timestamp(),
    imported_at timestamptz
);
create index sli_agent_packet_inbox_pending on sli_agent_packet_inbox(received_at,packet_id)
    where imported_at is null;
revoke all on sli_agent_module_bindings,sli_agent_receipts,sli_agent_packet_inbox from public,adlog_user;
grant select on sli_agent_module_bindings to adlog_user;
grant select,insert on sli_agent_receipts,sli_agent_packet_inbox to adlog_user;
grant update(imported_at) on sli_agent_packet_inbox to adlog_user;
insert into schema_migrations(version,name) values(157,'agent_packets');
commit;
