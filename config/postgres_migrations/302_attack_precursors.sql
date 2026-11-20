-- T109b: early warnings. No collector activation or application raw reads.
begin;
select pg_advisory_xact_lock(hashtext('sli_attack_precursors_v302'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 302 prerequisites failed';
    end if;
    if not exists(select 1 from public.schema_migrations where version=278 and name='file_ransom_policy_readiness')
       or exists(select 1 from public.schema_migrations where version>=302) then
        raise exception 'migration 302 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;
create or replace function public.ensure_default_qw_policy_v262(p_id text,p_version integer,p_document text) returns boolean
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare d jsonb:=p_document::jsonb; pin jsonb:=d#>'{source_selector,execution}'; s jsonb; digest bytea;
begin
    s:=pin->'scope'; digest:=sha256(convert_to(p_document,'UTF8'));
    if p_version<>1 or octet_length(p_document)>65536 or p_id not like 'default:qw.%'
       or d->>'type' is distinct from 'scenario_policy'
       or d#>>'{source_selector,rule_id}' is distinct from pin->>'rule_id'
       or pin->>'rule_id' not in ('qw.account-decoy','qw.account-watch','qw.file-decoy','qw.file-ransom',
           'qw.nps-denials','qw.password-spray','qw.password-brute-force','qw.disabled-account-logon',
           'qw.ransom-precursor','qw.security-log-cleared','qw.audit-disabled','qw.agent-tamper',
           'qw.agent-silenced','qw.file-ransom-fast','qw.mass-file-read')
       or public.finding_evidence_scope_allowed((s->>'installation_id')::uuid,s->>'plugin_id',
           s->>'source_instance_id',s->>'source_generation',s->>'collection_scope_id',
           case when s->>'plugin_id'='sli.file-audit' then 'file_audit_observation'
                when s->>'plugin_id'='sli.workstations' then 'workstation_observation' else 'core_event' end) is not true then
        raise exception 'default_detection_policy_denied' using errcode='42501';
    end if;
    -- A prior decision for this exact execution wins, even under a custom ID.
    if exists(select 1 from public.semantic_risk_policies p
        left join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.source_kind='qw_signal' and p.definition_json#>'{source_selector,execution}'=pin
          and (a.enabled is false or p.lifecycle_status in ('disabled','deprecated'))) then
        return false;
    end if;
    insert into public.semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
    values(p_id,p_version,'qw_signal','draft',d,digest) on conflict do nothing;
    perform 1 from public.semantic_risk_policies where policy_id=p_id and policy_version=p_version
        and definition_sha256=digest and definition_json=d for update;
    if not found then raise exception 'default_detection_policy_conflict'; end if;
    insert into public.semantic_risk_policy_subscriptions(policy_id,policy_version,source_kind,selector_value,definition_sha256)
    select p_id,p_version,'qw_signal',pin->>'rule_id',digest
    where not exists(select 1 from public.semantic_risk_policy_subscriptions where policy_id=p_id and policy_version=p_version);
    update public.semantic_risk_policies set lifecycle_status='shadow',updated_at=now()
        where policy_id=p_id and policy_version=p_version and lifecycle_status='draft';
    insert into public.semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
    select p_id,p_version,true,'system:defaults' where exists(
        select 1 from public.semantic_risk_policies where policy_id=p_id and policy_version=p_version
          and lifecycle_status in ('shadow','enabled'))
    on conflict(policy_id,policy_version) do nothing;
    return exists(select 1 from public.semantic_risk_policies p join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.policy_id=p_id and p.policy_version=p_version and a.enabled
          and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled');
end $$;
revoke all on function public.ensure_default_qw_policy_v262(text,integer,text) from public,adlog_semantic_worker;

create function public.t109_scope_allowed(s jsonb,k text) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select public.finding_evidence_scope_allowed((s->>'installation_id')::uuid,s->>'plugin_id',
        s->>'source_instance_id',s->>'source_generation',s->>'collection_scope_id',k)
$$;
revoke all on function public.t109_scope_allowed(jsonb,text) from public;
grant execute on function public.t109_scope_allowed(jsonb,text) to adlog_semantic_worker;

create table public.semantic_t109_episodes(
    execution_key text not null check(execution_key ~ '^[a-f0-9]{64}$'),
    episode_key text not null check(episode_key ~ '^[a-f0-9]{64}$'),
    scope_json jsonb not null check(jsonb_typeof(scope_json)='object' and octet_length(scope_json::text)<=4096),
    storage_kind text not null check(storage_kind in ('core_event','workstation_observation','file_audit_observation')),
    anchor_ref jsonb not null check(jsonb_typeof(anchor_ref)='object' and octet_length(anchor_ref::text)<=4096),
    first_seen timestamptz not null,last_seen timestamptz not null check(last_seen>=first_seen),
    primary key(execution_key,episode_key)
);
revoke all on public.semantic_t109_episodes from public,adlog_user,adlog_semantic_worker;
grant select,insert on public.semantic_t109_episodes to adlog_semantic_worker;
grant update(first_seen,last_seen) on public.semantic_t109_episodes to adlog_semantic_worker;
alter table public.semantic_t109_episodes enable row level security;
create policy t109_episode_scope on public.semantic_t109_episodes to adlog_semantic_worker
    using(public.t109_scope_allowed(scope_json,storage_kind))
    with check(public.t109_scope_allowed(scope_json,storage_kind));

create table public.semantic_t109_seen(
    source_key text not null check(source_key ~ '^[a-f0-9]{64}$'),
    native_id text not null check(length(native_id) between 1 and 64),
    scope_json jsonb not null check(jsonb_typeof(scope_json)='object' and octet_length(scope_json::text)<=4096),
    storage_kind text not null check(storage_kind in ('core_event','workstation_observation','file_audit_observation')),
    primary key(source_key,native_id)
);
revoke all on public.semantic_t109_seen from public,adlog_user,adlog_semantic_worker;
grant select,insert on public.semantic_t109_seen to adlog_semantic_worker;
alter table public.semantic_t109_seen enable row level security;
create policy t109_seen_scope on public.semantic_t109_seen to adlog_semantic_worker
    using(public.t109_scope_allowed(scope_json,storage_kind))
    with check(public.t109_scope_allowed(scope_json,storage_kind));
create index t109_seen_native_scope on public.semantic_t109_seen(native_id,scope_json);

-- Extra native channels have their OWN admission; an existing Security binding
-- is never rewritten to System. No worker can write or enumerate this ledger.
create table public.semantic_t109_channels(
    principal_oid oid not null,principal_name name not null,installation_id uuid not null,
    source_instance_id text not null,source_generation text not null,log_source_id bigint not null,
    native_channel text not null check(native_channel in ('System','Microsoft-Windows-PowerShell/Operational')),
    primary key(principal_oid,installation_id,source_instance_id,source_generation,log_source_id)
);
revoke all on public.semantic_t109_channels from public,adlog_user,adlog_semantic_worker;

create function public.read_t109_policy() returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare document text;
begin
    select value into document from public.platform_settings where key='security.t109.policy';
    if document is null then return '{}'::jsonb; end if;
    if octet_length(document)>32768 or jsonb_typeof(document::jsonb)<>'object' then
        raise exception 't109_policy_invalid';
    end if;
    return document::jsonb;
end
$$;
revoke all on function public.read_t109_policy() from public;
grant execute on function public.read_t109_policy() to adlog_semantic_worker;

create function public.t109_detection_sources() returns table(source jsonb)
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare login oid; installation uuid;
begin
    select oid into strict login from pg_catalog.pg_roles where rolname=session_user;
    select installation_id into strict installation from public.semantic_default_installation;
    -- Existing DC/file bindings retain their exact committed receipt checks.
    return query select d.source || jsonb_build_object('instance_name',a.instance_name,'host_name',a.registration_host_name)
      from public.default_detection_sources() d
      join public.sli_agents a on a.id::text=d.source->>'agent_id'
      where d.source#>>'{scope,plugin_id}' in ('sli.windows.ad-dc','sli.file-audit');
    insert into public.semantic_t109_channels
    select distinct login,session_user,b.installation_id,b.source_instance_id,b.source_generation,
        e.log_source_id,i.collection_channel
    from public.finding_evidence_source_bindings b join public.sli_agents a on a.id=b.agent_id
    cross join lateral jsonb_array_elements(a.assigned_modules) m
    join public.sli_agent_receipts r on r.agent_id=a.id and r.module_id='sli.windows.ad-dc'
    join public.sli_agent_packet_inbox i using(packet_id)
    join public.raw_log_files raw on raw.file_path='agent-packet:'||r.packet_id::text
    join public.events_v2_core e on e.raw_log_file_id=raw.id
    where b.principal_oid=login and b.principal_name=session_user and b.plugin_id='sli.windows.ad-dc'
      and b.storage_kind='core_event' and b.collection_scope_id=''
      and a.status='active' and m->>'module_id'='sli.windows.ad-dc' and m->'enabled'='true'::jsonb
      and i.collection_channel in ('System','Microsoft-Windows-PowerShell/Operational')
      and coalesce(m#>array['config','channels',i.collection_channel],'true'::jsonb)='true'::jsonb
      and r.receipt->>'status'='committed' and i.imported_at is not null and i.envelope=r.envelope
      and r.envelope->>'source_instance_id'=b.source_instance_id and r.envelope->>'generation'=b.source_generation
    on conflict do nothing;
    -- WS XML is already admitted by the native importer; discovery additionally
    -- requires an active assignment and a committed, imported matching stream.
    insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,
        plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind,agent_key)
    select distinct login,session_user,installation,'sli.workstations',a.host_id::text,
        o.observation->>'generation','','workstation_observation',a.id::text
    from public.sli_agents a join sli_plugin_workstations.observations o on o.agent_key=a.id::text
    where a.status='active' and exists(select 1 from jsonb_array_elements(a.assigned_modules) m
        where m->>'module_id'='sli.workstations' and m->'enabled'='true'::jsonb)
      and exists(select 1 from public.sli_agent_receipts r join public.sli_agent_packet_inbox i using(packet_id)
        where r.agent_id=a.id and r.module_id='sli.workstations' and r.receipt->>'status'='committed'
          and i.imported_at is not null and i.envelope=r.envelope
          and r.envelope->>'source_instance_id'=a.host_id::text)
    on conflict do nothing;
    return query select jsonb_build_object('scope',jsonb_build_object('installation_id',b.installation_id::text,
        'plugin_id',b.plugin_id,'source_instance_id',b.source_instance_id,'source_generation',b.source_generation,
        'collection_scope_id',''),'agent_id',a.id::text,'instance_name',a.instance_name,'config',m->'config')
    from public.finding_evidence_source_bindings b join public.sli_agents a on a.id::text=b.agent_key
    cross join lateral jsonb_array_elements(a.assigned_modules) m
    where b.principal_oid=login and b.principal_name=session_user and b.plugin_id='sli.workstations'
      and a.status='active' and m->>'module_id'='sli.workstations' and m->'enabled'='true'::jsonb
    order by a.id,b.source_generation limit 128;
end $$;
revoke all on function public.t109_detection_sources() from public;
grant execute on function public.t109_detection_sources() to adlog_semantic_worker;

-- Extend technical delete evidence only through a confirmed action in the
-- already authorized exact root, preserving committed provenance and hashes.
alter function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)
    rename to resolve_finding_evidence_ref_before_t109;
revoke all on function public.resolve_finding_evidence_ref_before_t109(uuid,text,text,text,text,text,text,text)
    from public,adlog_semantic_worker;
create function public.resolve_finding_evidence_ref(
    p_installation uuid,p_plugin text,p_source text,p_generation text,p_collection text,
    p_kind text,p_native text,p_sha256 text
) returns boolean language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare agent uuid;
begin
    if public.resolve_finding_evidence_ref_before_t109(p_installation,p_plugin,p_source,p_generation,
        p_collection,p_kind,p_native,p_sha256) then return true; end if;
    if p_kind='core_event' and p_plugin='sli.windows.ad-dc' and p_collection=''
       and p_native ~ '^[1-9][0-9]{0,18}$' and p_native::numeric<9223372036854775808
       and p_sha256 ~ '^[a-f0-9]{64}$' then
        return exists(select 1 from public.semantic_t109_channels c
          join pg_catalog.pg_roles login on login.oid=c.principal_oid and login.rolname=c.principal_name
          join public.finding_evidence_source_bindings b on b.principal_oid=c.principal_oid
            and b.principal_name=c.principal_name and b.installation_id=c.installation_id
            and b.plugin_id=p_plugin and b.source_instance_id=c.source_instance_id
            and b.source_generation=c.source_generation and b.storage_kind='core_event' and b.collection_scope_id=''
          join public.sli_agents a on a.id=b.agent_id
          cross join lateral jsonb_array_elements(a.assigned_modules) m
          join public.events_v2_core e on e.log_source_id=c.log_source_id
          join public.raw_log_files raw on raw.id=e.raw_log_file_id
          join public.sli_agent_packet_inbox i on raw.file_path='agent-packet:'||i.packet_id::text
          join public.sli_agent_receipts r on r.packet_id=i.packet_id
          where login.rolname=session_user and c.installation_id=p_installation
            and c.source_instance_id=p_source and c.source_generation=p_generation
            and e.id=p_native::bigint and encode(e.normalized_hash,'hex')=p_sha256
            and ((c.native_channel='System' and e.event_id in (7036,7040,7045))
              or (c.native_channel='Microsoft-Windows-PowerShell/Operational' and e.event_id=4104))
            and a.status='active' and m->>'module_id'=p_plugin and m->'enabled'='true'::jsonb
            and coalesce(m#>array['config','channels',c.native_channel],'true'::jsonb)='true'::jsonb
            and r.agent_id=a.id and r.module_id=p_plugin and r.receipt->>'status'='committed'
            and i.imported_at is not null and i.envelope=r.envelope and i.collection_channel=c.native_channel
            and r.envelope->>'source_instance_id'=p_source and r.envelope->>'generation'=p_generation);
    end if;
    if p_kind<>'file_audit_observation' or p_plugin<>'sli.file-audit' or p_collection=''
        or p_native !~ '^[a-f0-9]{64}$' or p_sha256 !~ '^[a-f0-9]{64}$' then return false; end if;
    select b.agent_id into agent from public.finding_evidence_source_bindings b
      join pg_catalog.pg_roles r on r.oid=b.principal_oid and r.rolname=b.principal_name
      where r.rolname=session_user and b.installation_id=p_installation and b.plugin_id=p_plugin
        and b.source_instance_id=p_source and b.source_generation=p_generation
        and b.collection_scope_id=p_collection and b.storage_kind=p_kind;
    if agent is null then return false; end if;
    return exists(select 1 from sli_plugin_file_audit.observations o
        join sli_plugin_file_audit.action_evidence e using(evidence_key)
        join sli_plugin_file_audit.actions a using(action_id)
        where o.evidence_key=p_native and o.agent_id=agent and o.source_instance_id=p_source
          and o.generation=p_generation and o.payload_sha256=p_sha256
          and o.normalized->>'payload_sha256'=p_sha256 and o.normalized->>'evidence_key'=p_native
          and a.agent_id=agent and a.source_instance_id=p_source and a.collection_scope_id=p_collection
          and a.operation='delete' and a.outcome='success' and a.correlation_state='complete'
          and exists(select 1 from public.sli_agent_receipts r join public.sli_agent_packet_inbox i using(packet_id)
            where r.agent_id=agent and r.module_id='sli.file-audit' and r.receipt->>'status'='committed'
              and i.imported_at is not null and i.envelope=r.envelope
              and r.envelope->>'source_instance_id'=p_source and r.envelope->>'generation'=p_generation
              and exists(select 1 from public.raw_log_files raw join public.events_v2_core core on core.raw_log_file_id=raw.id
                where raw.file_path='agent-packet:'||r.packet_id::text and core.event_record_id=o.record_id
                  and core.event_id=o.event_id)));
end $$;
revoke all on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) from public;
grant execute on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) to adlog_semantic_worker;

create function public.read_t109_native(s jsonb,p_start timestamptz default null,p_end timestamptz default null)
returns table(native_id text,event_id integer,occurred_at_utc timestamptz,sha256 text,
    source_xml text,collection_scope_id text,document jsonb)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype;
begin
    select binding.* into b from public.finding_evidence_source_bindings binding
      join pg_catalog.pg_roles r on r.oid=binding.principal_oid and r.rolname=binding.principal_name
      where r.rolname=session_user and binding.installation_id=(s->>'installation_id')::uuid
        and binding.plugin_id=s->>'plugin_id' and binding.source_instance_id=s->>'source_instance_id'
        and binding.source_generation=s->>'source_generation' and binding.collection_scope_id=s->>'collection_scope_id'
        and binding.storage_kind in ('core_event','workstation_observation','file_audit_observation');
    if not found then raise exception 't109_source_denied' using errcode='42501'; end if;
    if (p_start is null)<>(p_end is null) or p_end<p_start or p_end-p_start>interval '2 days' then
        raise exception 't109_window_invalid';
    end if;
    if b.storage_kind='core_event' then
        return query select e.id::text,e.event_id,e.time_created_utc,encode(e.normalized_hash,'hex'),
            native.doc#>>'{event_row,xml}',''::text,null::jsonb
        from public.events_v2_core e
        cross join lateral (select public.read_agent_semantic_source_v190(e.id) doc) native
        where (e.log_source_id=b.log_source_id or exists(select 1 from public.semantic_t109_channels c
            where c.principal_oid=b.principal_oid and c.principal_name=b.principal_name
              and c.installation_id=b.installation_id and c.source_instance_id=b.source_instance_id
              and c.source_generation=b.source_generation and c.log_source_id=e.log_source_id))
          and e.event_id in (4688,4104,1102,4719,7036,7040,7045)
          and e.time_created_utc<=statement_timestamp()
          and (p_start is not null and e.time_created_utc between p_start and p_end
            or p_start is null and not exists(select 1 from public.semantic_t109_seen seen
                where seen.scope_json=s and seen.native_id=e.id::text))
          and native.doc is not null and public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,
            b.source_instance_id,b.source_generation,'','core_event',e.id::text,encode(e.normalized_hash,'hex'))
        order by e.time_created_utc desc,e.id desc limit 1000;
    elsif b.storage_kind='workstation_observation' then
        return query select o.id,o.event_id,o.observed_at,o.observation_sha256,o.source_xml,''::text,null::jsonb
        from sli_plugin_workstations.observations o
        where o.agent_key=b.agent_key and o.observation->>'generation'=b.source_generation
          and o.event_id in (4688,4104,1102,4719,7036,7040,7045)
          and o.observed_at<=statement_timestamp()
          and (p_start is not null and o.observed_at between p_start and p_end
            or p_start is null and not exists(select 1 from public.semantic_t109_seen seen
                where seen.scope_json=s and seen.native_id=o.id))
          and public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,
            b.source_generation,'','workstation_observation',o.id,o.observation_sha256)
        order by o.observed_at desc,o.id desc limit 1000;
    else
        -- Read across individually authorized roots; QW re-verifies EACH root
        -- and native hash on ingress/publication. No aggregate wildcard grant.
        return query select o.evidence_key,o.event_id,a.observed_at,o.payload_sha256,null::text,
            a.collection_scope_id,to_jsonb(a)||jsonb_build_object('event_id',o.event_id,
              'operation',case when a.operation='access_check' and o.event_id=5145
                              and a.access_mask & 1=1 then 'read_check' else a.operation end)
        from sli_plugin_file_audit.actions a join sli_plugin_file_audit.action_evidence ae using(action_id)
        join sli_plugin_file_audit.observations o using(evidence_key)
        join sli_plugin_file_audit.policy_revisions p on p.agent_id=o.agent_id
          and p.source_instance_id=o.source_instance_id and p.revision=o.policy_revision
        where a.agent_id=b.agent_id and a.source_instance_id=b.source_instance_id
          and o.agent_id=b.agent_id and o.generation=b.source_generation and ae.role='primary'
          and a.outcome='success' and a.object_type='file' and a.correlation_state='complete'
          and (a.operation in ('read','write','delete') or a.operation='access_check' and o.event_id=5145 and a.access_mask & 1=1)
          and a.observed_at<=statement_timestamp()
          and (p_start is not null and a.observed_at between p_start and p_end
            or p_start is null and not exists(select 1 from public.semantic_t109_seen seen
                where seen.scope_json=s and seen.native_id=o.evidence_key))
          and exists(select 1 from public.sli_agents agent cross join lateral jsonb_array_elements(agent.assigned_modules) m
            where agent.id=b.agent_id and agent.status='active' and m->>'module_id'='sli.file-audit'
              and m->'enabled'='true'::jsonb and coalesce(m#>>'{config,policy_revision}','1')=p.revision::text
              and exists(select 1 from jsonb_array_elements(m#>'{config,roots}') root
                where root->>'collection_scope_id'=a.collection_scope_id))
          and public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,
            b.source_generation,a.collection_scope_id,'file_audit_observation',o.evidence_key,o.payload_sha256)
          and exists(select 1 from public.sli_agent_receipts r join public.sli_agent_packet_inbox i using(packet_id)
            join public.raw_log_files raw on raw.file_path='agent-packet:'||r.packet_id::text
            join public.events_v2_core core on core.raw_log_file_id=raw.id
            where r.agent_id=b.agent_id and r.module_id='sli.file-audit' and r.receipt->>'status'='committed'
              and i.imported_at is not null and i.envelope=r.envelope
              and r.envelope->>'source_instance_id'=b.source_instance_id
              and r.envelope->>'generation'=b.source_generation
              and core.event_record_id=o.record_id and core.event_id=o.event_id)
        order by a.observed_at desc,a.action_id desc limit case when p_start is null then 1000 else 10001 end;
    end if;
end $$;
revoke all on function public.read_t109_native(jsonb,timestamptz,timestamptz) from public;
grant execute on function public.read_t109_native(jsonb,timestamptz,timestamptz) to adlog_semantic_worker;

create function public.read_t109_recent_threats(s jsonb) returns table(signal_id text)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if not public.t109_scope_allowed(s,case when s->>'plugin_id'='sli.workstations'
        then 'workstation_observation' else 'core_event' end) then
        raise exception 't109_source_denied' using errcode='42501';
    end if;
    return query select q.signal_id from public.semantic_qw_signals q
      where q.document_json#>'{evidence_refs,0,scope}'=s
        and q.document_json->>'rule_id' in ('qw.ransom-precursor','qw.security-log-cleared','qw.audit-disabled')
        and q.created_at>=statement_timestamp()-interval '1 day'
      order by q.created_at desc,q.signal_id limit 32;
end $$;
revoke all on function public.read_t109_recent_threats(jsonb) from public;
grant execute on function public.read_t109_recent_threats(jsonb) to adlog_semantic_worker;

create function public.read_t109_agent_health(s jsonb) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare agent public.sli_agents%rowtype; streams jsonb;
begin
    select a.* into agent from public.sli_agents a join public.finding_evidence_source_bindings b
      on (a.id=b.agent_id or a.id::text=b.agent_key)
      join pg_catalog.pg_roles r on r.oid=b.principal_oid and r.rolname=b.principal_name
      where r.rolname=session_user and b.installation_id=(s->>'installation_id')::uuid
        and b.plugin_id=s->>'plugin_id' and b.source_instance_id=s->>'source_instance_id'
        and b.source_generation=s->>'source_generation' and b.collection_scope_id=s->>'collection_scope_id'
        and a.status='active' limit 1;
    if not found then raise exception 't109_source_denied' using errcode='42501'; end if;
    -- Build only the assigned current stream metadata used by collection_health.
    select coalesce(jsonb_agg(jsonb_build_object('agent_id',agent.id::text,'module_id',m->>'module_id',
        'revision',coalesce(m#>>'{config,policy_revision}','1'),'channel',q.channel,
        'last_packet_at',q.received_at,'last_import_at',q.imported_at,'read_error',q.collection_read_error,
        'pending_since',(select min(pending.received_at) from public.sli_agent_receipts pending
            join public.sli_agent_packet_inbox inbox using(packet_id)
            where pending.agent_id=agent.id and pending.module_id=m->>'module_id' and inbox.imported_at is null
              and inbox.collection_revision=coalesce(m#>>'{config,policy_revision}','1')
              and inbox.collection_channel is not distinct from q.channel))), '[]'::jsonb)
    into streams from jsonb_array_elements(agent.assigned_modules) m
    cross join lateral (
        select distinct on (i.collection_channel) i.collection_channel as channel,r.received_at,i.imported_at,i.collection_read_error
        from public.sli_agent_receipts r join public.sli_agent_packet_inbox i using(packet_id)
        where r.agent_id=agent.id and r.module_id=m->>'module_id'
          and i.collection_revision=coalesce(m#>>'{config,policy_revision}','1')
          and r.receipt->>'status'='committed' and i.envelope=r.envelope
        order by i.collection_channel,r.received_at desc,r.sequence desc
    ) q where m->'enabled'='true'::jsonb;
    return jsonb_build_object('agent',jsonb_build_object('id',agent.id::text,'host_id',agent.host_id::text,
        'instance_name',agent.instance_name,'status',agent.status,'last_seen',agent.last_seen,
        'last_packet_at',null,'created_at',agent.created_at,'assigned_modules',agent.assigned_modules,
        'policy_applied_at',(select max(occurred_at) from public.sli_agent_audit
            where target=agent.id::text and action='policy_ack' and details->>'revision'=agent.policy_revision::text),
        'collection_policy',agent.collection_policy,'policy_revision',agent.policy_revision,
        'applied_policy_revision',agent.applied_policy_revision,'applied_collection_state',agent.applied_collection_state),
        'streams',streams);
end $$;
revoke all on function public.read_t109_agent_health(jsonb) from public;
grant execute on function public.read_t109_agent_health(jsonb) to adlog_semantic_worker;
insert into public.schema_migrations(version,name) values(302,'attack_precursors');
commit;
