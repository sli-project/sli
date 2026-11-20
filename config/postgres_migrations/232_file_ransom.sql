-- R01: dormant, source-bound file episodes; publication uses the N07 bridge.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_ransom_v232'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=231 and name='agent_gpo_plans')
       or exists(select 1 from public.schema_migrations where version>=232) then
        raise exception 'migration 232 prerequisites failed';
    end if;
end $$;
set local role adlog_file_audit_owner;
grant select on sli_plugin_file_audit.rule_results,sli_plugin_file_audit.rule_actions,
    sli_plugin_file_audit.actions,sli_plugin_file_audit.action_evidence,
    sli_plugin_file_audit.policy_revisions to adlog_storage_owner;
reset role;
set local role adlog_storage_owner;

create function public.file_ransom_scope_allowed(s jsonb,p_agent uuid default null) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists(select 1 from public.finding_evidence_source_bindings b
        join pg_catalog.pg_roles r on r.oid=b.principal_oid and r.rolname=b.principal_name
        where r.rolname=session_user and b.installation_id=(s->>'installation_id')::uuid
          and b.plugin_id='sli.file-audit' and s->>'plugin_id'='sli.file-audit'
          and b.source_instance_id=s->>'source_instance_id' and b.source_generation=s->>'source_generation'
          and b.collection_scope_id=s->>'collection_scope_id' and b.collection_scope_id<>''
          and b.storage_kind='file_audit_observation' and (p_agent is null or b.agent_id=p_agent))
$$;
revoke all on function public.file_ransom_scope_allowed(jsonb,uuid) from public;
grant execute on function public.file_ransom_scope_allowed(jsonb,uuid) to adlog_semantic_worker;

create table public.semantic_file_ransom_episodes (
    episode_key text primary key check(episode_key ~ '^[a-f0-9]{64}$'),
    checkpoint_key text not null check(checkpoint_key ~ '^[a-f0-9]{64}$'),
    scope_json jsonb not null check(jsonb_typeof(scope_json)='object' and octet_length(scope_json::text)<=4096),
    entity_key text not null check(entity_key ~ '^[a-f0-9]{64}$'),
    first_seen timestamptz not null,
    last_seen timestamptz not null check(last_seen>=first_seen),
    incomplete boolean not null
);
create index file_ransom_episode_lookup on public.semantic_file_ransom_episodes(checkpoint_key,entity_key,last_seen);
create table public.semantic_file_ransom_members (
    checkpoint_key text not null check(checkpoint_key ~ '^[a-f0-9]{64}$'),
    result_id text not null check(result_id ~ '^[a-f0-9]{64}$'),
    episode_key text not null references public.semantic_file_ransom_episodes(episode_key) on delete restrict,
    scope_json jsonb not null check(jsonb_typeof(scope_json)='object' and octet_length(scope_json::text)<=4096),
    primary key(checkpoint_key,result_id)
);
revoke all on public.semantic_file_ransom_episodes,public.semantic_file_ransom_members
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant select,insert on public.semantic_file_ransom_episodes,public.semantic_file_ransom_members to adlog_semantic_worker;
grant update(first_seen,last_seen,incomplete) on public.semantic_file_ransom_episodes to adlog_semantic_worker;
alter table public.semantic_file_ransom_episodes enable row level security;
alter table public.semantic_file_ransom_members enable row level security;
create policy file_ransom_episode_scope on public.semantic_file_ransom_episodes to adlog_semantic_worker
    using(public.file_ransom_scope_allowed(scope_json)) with check(public.file_ransom_scope_allowed(scope_json));
create policy file_ransom_member_scope on public.semantic_file_ransom_members to adlog_semantic_worker
    using(public.file_ransom_scope_allowed(scope_json)) with check(public.file_ransom_scope_allowed(scope_json));

-- Exact root membership for technical delete/context observations is proven by
-- a retained, confirmed mass action, not by giving access to the technical scope.
create function public.file_ransom_evidence_in_root(p_agent uuid,p_source text,p_collection text,p_native text)
returns boolean language sql stable set search_path=pg_catalog,pg_temp as $$
    select exists(select 1 from sli_plugin_file_audit.action_evidence e
        join sli_plugin_file_audit.actions a using(action_id)
        join sli_plugin_file_audit.rule_actions ra using(action_id)
        join sli_plugin_file_audit.rule_results rr using(result_id)
        where e.evidence_key=p_native and a.agent_id=p_agent and a.source_instance_id=p_source
          and a.collection_scope_id=p_collection and a.outcome='success'
          and a.operation in ('write','delete') and a.correlation_state='complete'
          and rr.agent_id=p_agent and rr.source_instance_id=p_source and rr.collection_scope_id=p_collection
          and rr.rule_code in ('file-audit.mass-write','file-audit.mass-delete') and rr.conclusion_state='observed')
$$;
revoke all on function public.file_ransom_evidence_in_root(uuid,text,text,text) from public;

create function public.read_file_ransom_results(
    s jsonb,p_agent uuid,p_revision text,p_checkpoint text,p_files integer,p_seconds integer
) returns table(result jsonb,evidence jsonb,complete boolean)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare continuous boolean;
begin
    if not public.file_ransom_scope_allowed(s,p_agent) then
        raise exception 'file_ransom_source_denied' using errcode='42501';
    end if;
    if not exists(select 1 from sli_plugin_file_audit.policy_revisions p
        where p.agent_id=p_agent and p.source_instance_id=s->>'source_instance_id'
          and p.revision=p_revision::bigint
          and coalesce((p.policy->>'mass_operation_files')::integer,100)=p_files
          and coalesce((p.policy->>'mass_operation_seconds')::integer,300)=p_seconds) then
        raise exception 'file_ransom_source_policy_mismatch';
    end if;
    -- Conservative generation-wide continuity: any unknown/gap or pending
    -- receipt keeps episodes incomplete and prevents an invented quiet period.
    select coalesce(bool_and(coalesce(r.envelope->>'continuity_state'='complete'
               and r.receipt->>'status'='committed' and i.imported_at is not null
               and i.envelope=r.envelope,false)),false)
           and min((r.envelope->>'sequence')::bigint)=1
           and count(*)=max((r.envelope->>'sequence')::bigint)-min((r.envelope->>'sequence')::bigint)+1
    into continuous
    from public.sli_agent_receipts r join public.sli_agent_packet_inbox i using(packet_id)
    where r.agent_id=p_agent and r.module_id='sli.file-audit'
      and r.envelope->>'source_instance_id'=s->>'source_instance_id'
      and r.envelope->>'generation'=s->>'source_generation';
    return query
    select rr.result,refs.items,coalesce(continuous,false)
    from sli_plugin_file_audit.rule_results rr
    cross join lateral (
        select jsonb_agg(jsonb_build_object('native_id',q.evidence_key,'sha256',q.payload_sha256)
                         order by q.evidence_key) as items,
               bool_and(q.agent_id=p_agent and q.source_instance_id=s->>'source_instance_id'
                   and q.generation=s->>'source_generation' and q.policy_revision=p_revision::bigint) as valid
        from (select distinct o.evidence_key,o.payload_sha256,o.agent_id,o.source_instance_id,o.generation,o.policy_revision
            from sli_plugin_file_audit.rule_actions ra
            join sli_plugin_file_audit.action_evidence e using(action_id)
            join sli_plugin_file_audit.observations o using(evidence_key)
            where ra.result_id=rr.result_id) q
    ) refs
    where rr.agent_id=p_agent and rr.source_instance_id=s->>'source_instance_id'
      and rr.collection_scope_id=s->>'collection_scope_id'
      and rr.rule_code in ('file-audit.mass-write','file-audit.mass-delete') and rr.conclusion_state='observed'
      and (rr.result#>>'{details,threshold}')::integer=p_files
      and (rr.result#>>'{details,window_seconds}')::integer=p_seconds and refs.valid
      and not exists(select 1 from public.semantic_file_ransom_members m
          where m.checkpoint_key=p_checkpoint and m.result_id=rr.result_id)
    order by rr.observed_at,rr.result_id limit 32;
end $$;
revoke all on function public.read_file_ransom_results(jsonb,uuid,text,text,integer,integer) from public;
grant execute on function public.read_file_ransom_results(jsonb,uuid,text,text,integer,integer) to adlog_semantic_worker;

-- The other native kinds retain their original verification, including hashes
-- and committed source admission. No fabricated core-event IDs are introduced.
create or replace function public.resolve_finding_evidence_ref(
    p_installation uuid,p_plugin text,p_source text,p_generation text,p_collection text,
    p_kind text,p_native text,p_sha256 text
) returns boolean language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype;
begin
    if p_sha256 is null or p_sha256 !~ '^[a-f0-9]{64}$' or p_native is null then return false; end if;
    select a.* into b from public.finding_evidence_source_bindings a join pg_catalog.pg_roles r
        on r.oid=a.principal_oid and r.rolname=a.principal_name
        where r.rolname=session_user and a.installation_id=p_installation and a.plugin_id=p_plugin
          and a.source_instance_id=p_source and a.source_generation=p_generation
          and a.collection_scope_id=p_collection and a.storage_kind=p_kind;
    if not found then return false; end if;
    if p_kind='core_event' then
        if p_native !~ '^[1-9][0-9]{0,18}$' or p_native::numeric>=9223372036854775808 then return false; end if;
        return exists(select 1 from public.events_v2_core e
            join public.raw_log_files raw on raw.id=e.raw_log_file_id
            join public.sli_agent_packet_inbox inbox on raw.file_path='agent-packet:'||inbox.packet_id::text
            join public.sli_agent_receipts receipt on receipt.packet_id=inbox.packet_id
            where e.id=p_native::bigint and e.log_source_id=b.log_source_id
              and encode(e.normalized_hash,'hex')=p_sha256 and inbox.imported_at is not null
              and receipt.receipt->>'status'='committed' and inbox.envelope=receipt.envelope
              and receipt.module_id=p_plugin and inbox.envelope->>'agent_id'=b.agent_id::text
              and inbox.envelope->>'source_instance_id'=p_source
              and inbox.envelope->>'generation'=p_generation);
    elsif p_kind='workstation_observation' and p_native ~ '^[a-f0-9]{64}$' then
        return exists(select 1 from sli_plugin_workstations.observations o
            where o.id=p_native and o.agent_key=b.agent_key and o.observation_sha256=p_sha256
              and o.observation->>'generation'=p_generation and o.observation->>'agent_key'=b.agent_key
              and encode(sha256(convert_to(o.source_xml,'UTF8')),'hex')=o.observation->>'source_sha256');
    elsif p_kind='file_audit_observation' and p_native ~ '^[a-f0-9]{64}$' then
        return exists(select 1 from sli_plugin_file_audit.observations o
            where o.evidence_key=p_native and o.agent_id=b.agent_id and o.source_instance_id=p_source
              and o.generation=p_generation and o.payload_sha256=p_sha256
              and o.normalized->>'payload_sha256'=p_sha256 and o.normalized->>'evidence_key'=p_native
              and (o.collection_scope_id=p_collection
                   or public.file_ransom_evidence_in_root(b.agent_id,p_source,p_collection,p_native)));
    end if;
    return false;
end $$;
reset role;
insert into public.schema_migrations(version,name) values(232,'file_ransom');
commit;
