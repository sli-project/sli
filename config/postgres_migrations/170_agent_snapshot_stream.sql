-- Opt-in snapshot transport only. No directory/GPO imports or assignments.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_snapshot_stream_v170'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 170 requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from public.schema_migrations where version=170) then
        raise exception 'migration 170 already recorded';
    end if;
    -- 168/169 belong to independent PRs; never synthesize their markers here.
    if not exists(select 1 from public.schema_migrations where version=167 and name='agent_updates')
       or not exists(select 1 from public.schema_migrations where version=168)
       or not exists(select 1 from public.schema_migrations where version=169 and name='agent_collection_control')
       or exists(select 1 from public.schema_migrations where version>169) then
        raise exception 'migration 170 requires migrations 167,168 and exact migration 169 agent_collection_control';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.sli_agent_snapshot_bindings (
    agent_id uuid not null references public.sli_agents(id),
    module_id text not null check(module_id in ('sli.ad-snapshot','sli.gpo-snapshot')),
    config jsonb not null check(jsonb_typeof(config)='object'),
    domain_sid text generated always as (config->>'domain_sid') stored not null,
    enabled boolean not null default false,
    primary key(agent_id,module_id)
);
create unique index sli_agent_snapshot_domain_collector on public.sli_agent_snapshot_bindings(domain_sid,module_id)
    where enabled;
-- A frozen cycle may reach ingress after its first ACK was lost or after the
-- policy changed. Retain revisions; a retired policy cannot start future slots.
create table public.sli_agent_snapshot_policies (
    agent_id uuid not null,
    module_id text not null,
    config jsonb not null check(jsonb_typeof(config)='object'),
    policy_revision text generated always as (config->>'policy_revision') stored not null,
    enabled boolean not null default false,
    superseded_at timestamptz,
    primary key(agent_id,module_id,policy_revision),
    foreign key(agent_id,module_id) references public.sli_agent_snapshot_bindings(agent_id,module_id)
);
create table public.sli_agent_snapshot_cycles (
    cycle_id uuid primary key,
    agent_id uuid not null,
    module_id text not null,
    slot_start_utc text not null,
    domain_sid text not null,
    policy jsonb not null check(jsonb_typeof(policy)='object'),
    transport_state text not null default 'pending' check(transport_state in ('pending','complete')),
    created_at timestamptz not null default clock_timestamp(),
    completed_at timestamptz,
    foreign key(agent_id,module_id) references public.sli_agent_snapshot_bindings(agent_id,module_id),
    unique(domain_sid,module_id,slot_start_utc),
    check((transport_state='complete')=(completed_at is not null)),
    check(domain_sid=policy->>'domain_sid')
);
create table public.sli_agent_snapshot_chunks (
    packet_id uuid primary key references public.sli_agent_receipts(packet_id),
    cycle_id uuid not null references public.sli_agent_snapshot_cycles(cycle_id),
    family text not null check(family in ('ad_context_base','ad_privileged_membership','ad_vpn_membership',
        'ad_domain_posture','ad_domain_health','computers_v6','ad_gpo_governance','gpo_v2')),
    chunk_index integer not null check(chunk_index between 0 and 2047),
    payload jsonb not null check(jsonb_typeof(payload)='object'
        and payload->>'contract' in ('sli.ad-snapshot.chunk.v1','sli.gpo-snapshot.chunk.v1')
        and octet_length(payload::text)<=61440),
    unique(cycle_id,family,chunk_index),
    check(family=payload->>'family' and chunk_index=(payload->>'chunk_index')::integer
        and cycle_id::text=payload->>'cycle_id')
);
create index sli_agent_snapshot_cycles_pending on public.sli_agent_snapshot_cycles(cycle_id)
    where transport_state='pending';
revoke all on public.sli_agent_snapshot_bindings,public.sli_agent_snapshot_policies,public.sli_agent_snapshot_cycles,public.sli_agent_snapshot_chunks
    from public,adlog_user;
grant select,insert on public.sli_agent_snapshot_bindings,public.sli_agent_snapshot_policies,public.sli_agent_snapshot_cycles,public.sli_agent_snapshot_chunks
    to adlog_user;
grant update(config,enabled) on public.sli_agent_snapshot_bindings to adlog_user;
grant update(superseded_at) on public.sli_agent_snapshot_policies to adlog_user;
grant update(transport_state,completed_at) on public.sli_agent_snapshot_cycles to adlog_user;
reset role;
insert into public.schema_migrations(version,name) values(170,'agent_snapshot_stream');
commit;
