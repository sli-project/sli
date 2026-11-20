-- Sigma stage 13: typed native evidence links, dormant until explicitly bound.
begin;
select pg_advisory_xact_lock(hashtext('sli_finding_evidence_refs_v219'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=218 and name='sigma_registry')
       or exists(select 1 from public.schema_migrations where version>=219) then
        raise exception 'migration 219 prerequisites failed';
    end if;
end $$;

-- Only the maintenance role gets native reads; no worker-wide plugin grants.
grant usage on schema sli_plugin_file_audit to adlog_storage_owner;
grant select on sli_plugin_file_audit.observations to adlog_storage_owner;
grant select,insert on public.finding_evidence to adlog_storage_owner;
grant usage,select on sequence public.finding_evidence_id_seq to adlog_storage_owner;
set local role adlog_storage_owner;

-- Empty by default. A storage administrator binds the actual authenticated
-- login to an exact installation/source/generation and (for FS) collection root.
-- Both OID and name prevent privileges surviving a dropped/recreated login.
create table public.finding_evidence_source_bindings (
    principal_oid oid not null,
    principal_name name not null,
    installation_id uuid not null,
    plugin_id text not null,
    source_instance_id text not null check(length(source_instance_id) between 1 and 256),
    source_generation text not null check(length(source_generation) between 1 and 512),
    collection_scope_id text not null default '' check(length(collection_scope_id)<=256),
    storage_kind text not null,
    log_source_id bigint check(log_source_id>0),
    agent_key text check(length(agent_key) between 1 and 256),
    agent_id uuid,
    primary key(principal_oid,installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind),
    check (
        (storage_kind='core_event' and plugin_id='sli.windows.ad-dc' and collection_scope_id=''
            and log_source_id is not null and agent_key is null and agent_id is not null)
        or (storage_kind='workstation_observation' and plugin_id='sli.workstations' and collection_scope_id=''
            and log_source_id is null and agent_key is not null and agent_id is null)
        or (storage_kind='file_audit_observation' and plugin_id='sli.file-audit' and collection_scope_id<>''
            and log_source_id is null and agent_key is null and agent_id is not null)
    )
);
revoke all on public.finding_evidence_source_bindings from public,adlog_user,adlog_semantic_worker;

create function public.finding_evidence_scope_allowed(
    p_installation uuid,p_plugin text,p_source text,p_generation text,p_collection text,p_kind text
) returns boolean language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists(select 1 from public.finding_evidence_source_bindings b join pg_catalog.pg_roles r
        on r.oid=b.principal_oid and r.rolname=b.principal_name
        where r.rolname=session_user and b.installation_id=p_installation and b.plugin_id=p_plugin
          and b.source_instance_id=p_source and b.source_generation=p_generation
          and b.collection_scope_id=p_collection and b.storage_kind=p_kind);
$$;
revoke all on function public.finding_evidence_scope_allowed(uuid,text,text,text,text,text) from public;
grant execute on function public.finding_evidence_scope_allowed(uuid,text,text,text,text,text) to adlog_semantic_worker;

-- Companion to legacy integer-only finding_evidence. No placeholder core rows,
-- no cascade to source tables: references survive source payload retention.
create table public.finding_evidence_refs (
    finding_id bigint not null references public.findings(id) on delete restrict,
    installation_id uuid not null,
    plugin_id text not null,
    source_instance_id text not null check(length(source_instance_id) between 1 and 256),
    source_generation text not null check(length(source_generation) between 1 and 512),
    collection_scope_id text not null check(length(collection_scope_id)<=256),
    storage_kind text not null,
    native_id text not null,
    sha256 text not null check(sha256 ~ '^[a-f0-9]{64}$'),
    evidence_role text not null default 'semantic_scenario' check(evidence_role='semantic_scenario'),
    created_at timestamptz not null default now(),
    primary key(finding_id,installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind,native_id,evidence_role),
    check (
        (storage_kind='core_event' and plugin_id='sli.windows.ad-dc' and collection_scope_id=''
            and case when native_id ~ '^[1-9][0-9]{0,18}$' then native_id::numeric<9223372036854775808 else false end)
        or (storage_kind='workstation_observation' and plugin_id='sli.workstations' and collection_scope_id=''
            and native_id ~ '^[a-f0-9]{64}$')
        or (storage_kind='file_audit_observation' and plugin_id='sli.file-audit' and collection_scope_id<>''
            and native_id ~ '^[a-f0-9]{64}$')
    )
);
revoke all on public.finding_evidence_refs from public,adlog_user,adlog_semantic_worker;
grant select on public.finding_evidence_refs to adlog_semantic_worker;
alter table public.finding_evidence_refs enable row level security;
create policy finding_evidence_refs_read on public.finding_evidence_refs for select to adlog_semantic_worker
    using(public.finding_evidence_scope_allowed(installation_id,plugin_id,source_instance_id,
        source_generation,collection_scope_id,storage_kind));

create function public.finding_evidence_refs_immutable() returns trigger language plpgsql as $$
begin
    raise exception 'finding_evidence_refs_immutable' using errcode='42501';
end $$;
create trigger finding_evidence_refs_immutable before update or delete on public.finding_evidence_refs
    for each row execute function public.finding_evidence_refs_immutable();
create trigger finding_evidence_refs_no_truncate before truncate on public.finding_evidence_refs
    for each statement execute function public.finding_evidence_refs_immutable();
revoke all on function public.finding_evidence_refs_immutable() from public;

create function public.resolve_finding_evidence_ref(
    p_installation uuid,p_plugin text,p_source text,p_generation text,p_collection text,
    p_kind text,p_native text,p_sha256 text
) returns boolean language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype;
begin
    if p_sha256 is null or p_sha256 !~ '^[a-f0-9]{64}$' or p_native is null then
        return false;
    end if;
    select a.* into b from public.finding_evidence_source_bindings a join pg_catalog.pg_roles r
        on r.oid=a.principal_oid and r.rolname=a.principal_name
        where r.rolname=session_user and a.installation_id=p_installation and a.plugin_id=p_plugin
          and a.source_instance_id=p_source and a.source_generation=p_generation
          and a.collection_scope_id=p_collection and a.storage_kind=p_kind;
    if not found then return false; end if;
    if p_kind='core_event' then
        if p_native !~ '^[1-9][0-9]{0,18}$' or p_native::numeric>=9223372036854775808 then
            return false;
        end if;
        -- Match the committed native packet's source/generation, not Computer
        -- or a caller-supplied integer. Expired/unavailable input fails closed.
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
              and o.observation->>'generation'=p_generation
              and o.observation->>'agent_key'=b.agent_key
              and encode(sha256(convert_to(o.source_xml,'UTF8')),'hex')=o.observation->>'source_sha256');
    elsif p_kind='file_audit_observation' and p_native ~ '^[a-f0-9]{64}$' then
        return exists(select 1 from sli_plugin_file_audit.observations o
            where o.evidence_key=p_native and o.agent_id=b.agent_id and o.source_instance_id=p_source
              and o.generation=p_generation and o.collection_scope_id=p_collection and o.payload_sha256=p_sha256
              and o.normalized->>'payload_sha256'=p_sha256 and o.normalized->>'evidence_key'=p_native);
    end if;
    return false;
end $$;
revoke all on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) from public;
grant execute on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) to adlog_semantic_worker;

create function public.link_finding_evidence_ref(
    p_finding bigint,p_installation uuid,p_plugin text,p_source text,p_generation text,p_collection text,
    p_kind text,p_native text,p_sha256 text
) returns boolean language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare v_added boolean; v_count bigint; v_existing text;
begin
    if public.resolve_finding_evidence_ref(p_installation,p_plugin,p_source,p_generation,p_collection,
            p_kind,p_native,p_sha256) is not true then
        raise exception 'evidence_unavailable_or_denied' using errcode='42501';
    end if;
    insert into public.finding_evidence_refs(finding_id,installation_id,plugin_id,source_instance_id,
        source_generation,collection_scope_id,storage_kind,native_id,sha256)
    values(p_finding,p_installation,p_plugin,p_source,p_generation,p_collection,p_kind,p_native,p_sha256)
    on conflict do nothing;
    get diagnostics v_count = row_count;
    v_added := v_count>0;
    select sha256 into strict v_existing from public.finding_evidence_refs
        where finding_id=p_finding and installation_id=p_installation and plugin_id=p_plugin
          and source_instance_id=p_source and source_generation=p_generation and collection_scope_id=p_collection
          and storage_kind=p_kind and native_id=p_native and evidence_role='semantic_scenario';
    if v_existing is distinct from p_sha256 then
        raise exception 'evidence_hash_conflict';
    end if;
    if p_kind='core_event' then
        insert into public.finding_evidence(finding_id,event_id,evidence_role,note)
        values(p_finding,p_native::bigint,'semantic_scenario','enabled semantic scenario evidence')
        on conflict(finding_id,event_id,evidence_role) do nothing;
        get diagnostics v_count = row_count;
        v_added := v_count>0;
    end if;
    return v_added;
end $$;
revoke all on function public.link_finding_evidence_ref(bigint,uuid,text,text,text,text,text,text,text) from public;
grant execute on function public.link_finding_evidence_ref(bigint,uuid,text,text,text,text,text,text,text) to adlog_semantic_worker;

insert into public.schema_migrations(version,name) values(219,'finding_evidence_refs');
commit;
