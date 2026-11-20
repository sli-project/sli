-- Managed, source-bound native detections. Existing L1 admission is unchanged.
begin;
select pg_advisory_xact_lock(hashtext('sli_default_native_detections_v262'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=261 and name='telegram_delivery')
       or exists(select 1 from public.schema_migrations where version>=262) then
        raise exception 'migration 262 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
grant select on sli_plugin_file_audit.observations to adlog_storage_owner;
grant usage on schema sli_sigma to adlog_storage_owner;
grant select on sli_sigma.sigma_rule_revisions to adlog_storage_owner;
set local role adlog_storage_owner;
create table public.semantic_default_installation (
    singleton boolean primary key default true check(singleton),
    installation_id uuid not null default gen_random_uuid()
);
insert into public.semantic_default_installation(singleton) values(true);
revoke all on public.semantic_default_installation from public,adlog_user,adlog_semantic_worker;

-- Bind only committed agent evidence to this authenticated worker login. No
-- source activation, collector policy change, directory read or remote I/O.
create function public.default_detection_sources() returns table(source jsonb)
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare login oid; installation uuid;
begin
    select oid into strict login from pg_catalog.pg_roles where rolname=session_user;
    select installation_id into strict installation from public.semantic_default_installation;
    insert into public.finding_evidence_source_bindings
        (principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,
         collection_scope_id,storage_kind,log_source_id,agent_id)
    select distinct login,session_user,installation,r.module_id,r.envelope->>'source_instance_id',
           r.envelope->>'generation','','core_event',event.log_source_id,r.agent_id
    from public.sli_agent_module_bindings module
    join public.sli_agents agent on agent.id=module.agent_id and agent.status='active'
    cross join lateral (
        select receipt.* from public.sli_agent_receipts receipt
        join public.sli_agent_packet_inbox inbox using(packet_id)
        where receipt.agent_id=module.agent_id and receipt.module_id=module.module_id
          and receipt.envelope->>'source_instance_id'=module.source_instance_id
          and receipt.receipt->>'status'='committed' and inbox.imported_at is not null
          and inbox.envelope=receipt.envelope
        order by receipt.sequence desc limit 1
    ) r
    cross join lateral (
        select e.log_source_id from public.raw_log_files raw join public.events_v2_core e on e.raw_log_file_id=raw.id
        where raw.file_path='agent-packet:'||r.packet_id::text order by e.id limit 1
    ) event
    where module.module_id in ('sli.windows.ad-dc','sli.vpn-nps')
      and exists(select 1 from jsonb_array_elements(agent.assigned_modules) m
          where m->>'module_id'=module.module_id and m->'enabled'='true'::jsonb)
      and not exists(select 1 from public.finding_evidence_source_bindings b
          where b.principal_oid=login and b.principal_name=session_user and b.plugin_id=r.module_id
            and b.source_instance_id=r.envelope->>'source_instance_id' and b.source_generation=r.envelope->>'generation'
            and b.collection_scope_id='' and b.storage_kind='core_event')
    on conflict do nothing;

    insert into public.finding_evidence_source_bindings
        (principal_oid,principal_name,installation_id,plugin_id,source_instance_id,source_generation,
         collection_scope_id,storage_kind,agent_id)
    select distinct login,session_user,installation,'sli.file-audit',o.source_instance_id,o.generation,
           root->>'collection_scope_id','file_audit_observation',agent.id
    from public.sli_agents agent
    cross join lateral jsonb_array_elements(agent.assigned_modules) m
    cross join lateral jsonb_array_elements(m#>'{config,roots}') root
    cross join lateral (
        select obs.source_instance_id,obs.generation from sli_plugin_file_audit.observations obs
        join public.sli_agent_receipts r on r.agent_id=obs.agent_id
            and r.envelope->>'source_instance_id'=obs.source_instance_id
            and r.envelope->>'generation'=obs.generation
        join public.sli_agent_packet_inbox inbox on inbox.packet_id=r.packet_id
        where obs.agent_id=agent.id and obs.collection_scope_id=root->>'collection_scope_id'
          and r.module_id='sli.file-audit' and r.receipt->>'status'='committed'
          and inbox.imported_at is not null and inbox.envelope=r.envelope
          and obs.policy_revision=coalesce(m#>>'{config,policy_revision}','1')::bigint
        order by r.sequence desc limit 1
    ) o
    where agent.status='active' and m->>'module_id'='sli.file-audit' and m->'enabled'='true'::jsonb
      and not exists(select 1 from public.finding_evidence_source_bindings b
          where b.principal_oid=login and b.principal_name=session_user and b.plugin_id='sli.file-audit'
            and b.source_instance_id=o.source_instance_id and b.source_generation=o.generation
            and b.collection_scope_id=root->>'collection_scope_id' and b.storage_kind='file_audit_observation')
    on conflict do nothing;

    return query
    select jsonb_build_object('scope',jsonb_build_object('installation_id',b.installation_id::text,
        'plugin_id',b.plugin_id,'source_instance_id',b.source_instance_id,
        'source_generation',b.source_generation,'collection_scope_id',b.collection_scope_id),
        'agent_id',b.agent_id::text,'config',coalesce(m->'config','{}'::jsonb))
    from public.finding_evidence_source_bindings b
    join public.sli_agents agent on agent.id=b.agent_id and agent.status='active'
    cross join lateral jsonb_array_elements(agent.assigned_modules) m
    where b.principal_oid=login and b.principal_name=session_user
      and m->>'module_id'=b.plugin_id and m->'enabled'='true'::jsonb
      and (b.storage_kind='core_event' or b.storage_kind='file_audit_observation'
          and exists(select 1 from jsonb_array_elements(m#>'{config,roots}') root
              where root->>'collection_scope_id'=b.collection_scope_id))
    order by b.plugin_id,b.source_instance_id,b.source_generation,b.collection_scope_id limit 128;
end $$;
revoke all on function public.default_detection_sources() from public;
grant execute on function public.default_detection_sources() to adlog_semantic_worker;

-- Keep admission writes behind a bounded definer rather than granting worker
-- UPDATE on all owner choices. The ordinary admission trigger audits defaults.
create function public.ensure_default_qw_policy(p_id text,p_version integer,p_document text) returns boolean
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare d jsonb:=p_document::jsonb; pin jsonb:=d#>'{source_selector,execution}'; s jsonb; digest bytea;
begin
    s:=pin->'scope'; digest:=sha256(convert_to(p_document,'UTF8'));
    if p_version<>1 or octet_length(p_document)>65536 or p_id not like 'default:qw.%'
       or d->>'type' is distinct from 'scenario_policy'
       or d#>>'{source_selector,rule_id}' is distinct from pin->>'rule_id'
       or pin->>'rule_id' not in ('qw.account-decoy','qw.account-watch','qw.file-decoy','qw.file-ransom',
           'qw.nps-denials','qw.password-spray','qw.password-brute-force','qw.disabled-account-logon')
       or public.finding_evidence_scope_allowed((s->>'installation_id')::uuid,s->>'plugin_id',
           s->>'source_instance_id',s->>'source_generation',s->>'collection_scope_id',
           case when s->>'plugin_id'='sli.file-audit' then 'file_audit_observation' else 'core_event' end) is not true then
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
revoke all on function public.ensure_default_qw_policy(text,integer,text) from public;
grant execute on function public.ensure_default_qw_policy(text,integer,text) to adlog_semantic_worker;

-- At most two complete source-time buckets, with a sentinel for truncation.
-- XML is read through the existing committed packet verifier, never from a
-- mutable display/report field. No normalization backlog is required.
create function public.read_default_password_events(s jsonb)
returns table(source_event_id bigint,event_id integer,occurred_at_utc timestamptz,sha256 text,source_xml text)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype; tail timestamptz;
begin
    select binding.* into b from public.finding_evidence_source_bindings binding
    join pg_catalog.pg_roles r on r.oid=binding.principal_oid and r.rolname=binding.principal_name
    where r.rolname=session_user and binding.installation_id=(s->>'installation_id')::uuid
      and binding.plugin_id='sli.windows.ad-dc' and s->>'plugin_id'='sli.windows.ad-dc'
      and binding.source_instance_id=s->>'source_instance_id' and binding.source_generation=s->>'source_generation'
      and binding.collection_scope_id='' and binding.storage_kind='core_event';
    if not found then raise exception 'password_attack_source_denied' using errcode='42501'; end if;
    select max(e.time_created_utc) into tail from public.events_v2_core e
    where e.log_source_id=b.log_source_id and e.event_id in (4625,4771,4776)
      and e.time_created_utc<=statement_timestamp();
    return query
    select e.id,e.event_id,e.time_created_utc,encode(e.normalized_hash,'hex'),native.document#>>'{event_row,xml}'
    from public.events_v2_core e
    cross join lateral (select public.read_agent_semantic_source_v190(e.id) as document) native
    where e.log_source_id=b.log_source_id and e.event_id in (4625,4771,4776)
      and e.time_created_utc>=to_timestamp(floor(extract(epoch from tail)/300)*300)-interval '300 seconds'
      and e.time_created_utc<=tail
      and public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,
          b.source_generation,'','core_event',e.id::text,encode(e.normalized_hash,'hex'))
      and native.document is not null
    order by e.time_created_utc,e.id limit 10001;
end $$;
revoke all on function public.read_default_password_events(jsonb) from public;
grant execute on function public.read_default_password_events(jsonb) to adlog_semantic_worker;

create table public.semantic_sigma_live_cursors (
    policy_id text not null,
    policy_version integer not null,
    last_event_id bigint not null check(last_event_id>=0),
    primary key(policy_id,policy_version),
    foreign key(policy_id,policy_version) references public.semantic_risk_policies(policy_id,policy_version)
);
revoke all on public.semantic_sigma_live_cursors from public,adlog_user,adlog_semantic_worker;
grant select,insert,update on public.semantic_sigma_live_cursors to adlog_semantic_worker;
create function public.read_admitted_sigma_revision(p_id text,p_version integer) returns jsonb
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('execution',p.definition_json#>'{source_selector,execution}',
        'raw_yaml',r.raw_yaml,'source_uri',r.source_uri,'upstream_commit',r.upstream_commit,'license',r.license)
    from public.semantic_risk_policies p join public.semantic_policy_admission a using(policy_id,policy_version)
    join sli_sigma.sigma_rule_revisions r
      on r.installation_id=(p.definition_json#>>'{source_selector,execution,scope,installation_id}')::uuid
     and r.plugin_id=p.definition_json#>>'{source_selector,execution,scope,plugin_id}'
     and r.source_instance_id=p.definition_json#>>'{source_selector,execution,scope,source_instance_id}'
     and r.rule_id::text=p.definition_json#>>'{source_selector,rule_id}'
     and r.raw_sha256=p.definition_json#>>'{source_selector,execution,rule_sha256}'
    where p.policy_id=p_id and p.policy_version=p_version and p.source_kind='detection_match' and a.enabled
      and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled'
      and public.finding_evidence_scope_allowed(r.installation_id,r.plugin_id,r.source_instance_id,
          p.definition_json#>>'{source_selector,execution,scope,source_generation}','','core_event')
$$;
revoke all on function public.read_admitted_sigma_revision(text,integer) from public;
grant execute on function public.read_admitted_sigma_revision(text,integer) to adlog_semantic_worker;
create function public.read_admitted_sigma_events(s jsonb,p_after bigint)
returns table(source_event_id bigint,sha256 text,source_xml text)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype;
begin
    select binding.* into b from public.finding_evidence_source_bindings binding
    join pg_catalog.pg_roles r on r.oid=binding.principal_oid and r.rolname=binding.principal_name
    where r.rolname=session_user and binding.installation_id=(s->>'installation_id')::uuid
      and binding.plugin_id='sli.windows.ad-dc' and s->>'plugin_id'='sli.windows.ad-dc'
      and binding.source_instance_id=s->>'source_instance_id' and binding.source_generation=s->>'source_generation'
      and binding.collection_scope_id='' and binding.storage_kind='core_event';
    if not found then raise exception 'sigma_live_source_denied' using errcode='42501'; end if;
    return query select e.id,encode(e.normalized_hash,'hex'),native.document#>>'{event_row,xml}'
    from public.events_v2_core e
    cross join lateral (select public.read_agent_semantic_source_v190(e.id) as document) native
    where e.id>p_after and e.log_source_id=b.log_source_id
      and public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,
          b.source_generation,'','core_event',e.id::text,encode(e.normalized_hash,'hex'))
      and native.document is not null
    order by e.id limit 128;
end $$;
revoke all on function public.read_admitted_sigma_events(jsonb,bigint) from public;
grant execute on function public.read_admitted_sigma_events(jsonb,bigint) to adlog_semantic_worker;

-- Plugin evidence has no integer core event ID. Derive its domain from the
-- retained imported receipt and configured server, without placeholder events.
create function public.semantic_finding_in_domains_v262(p_finding bigint,p_domains bigint[]) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    with native_domains as materialized (
        -- Resolve the receipt source once per scope, not once per file in a
        -- mass-operation episode. Pending packets are not evidence witnesses.
        select scopes.*,case when count(distinct b.agent_id)=1 then min(b.agent_id::text)::uuid end as agent_id,
            case when count(distinct server.domain_id)=1 and bool_and(server.domain_id is not null)
                 then min(server.domain_id) end as domain_id
        from (select distinct installation_id,plugin_id,source_instance_id,source_generation,
                    collection_scope_id,storage_kind from public.finding_evidence_refs
              where finding_id=p_finding and storage_kind<>'core_event') scopes
        left join public.finding_evidence_source_bindings b
          on b.installation_id=scopes.installation_id and b.plugin_id=scopes.plugin_id
         and b.source_instance_id=scopes.source_instance_id and b.source_generation=scopes.source_generation
         and b.collection_scope_id=scopes.collection_scope_id and b.storage_kind=scopes.storage_kind
        left join (public.sli_agent_receipts receipt join public.sli_agent_packet_inbox inbox
            on inbox.packet_id=receipt.packet_id and inbox.imported_at is not null
           and inbox.envelope=receipt.envelope and receipt.receipt->>'status'='committed')
          on receipt.agent_id=b.agent_id and receipt.module_id='sli.file-audit'
         and receipt.envelope->>'generation'=b.source_generation
         and receipt.envelope->>'source_instance_id'=b.source_instance_id
        left join public.servers server on server.hostname=inbox.packet#>>'{header,source}'
        group by scopes.installation_id,scopes.plugin_id,scopes.source_instance_id,scopes.source_generation,
                 scopes.collection_scope_id,scopes.storage_kind
    ), evidence_domains as (
        select e.domain_id from public.finding_evidence fe
        left join public.events_v2_core e on e.id=fe.event_id where fe.finding_id=p_finding
        union all
        select case when o.evidence_key is not null then domains.domain_id end
        from public.finding_evidence_refs ref
        left join native_domains domains
          on domains.installation_id=ref.installation_id and domains.plugin_id=ref.plugin_id
         and domains.source_instance_id=ref.source_instance_id and domains.source_generation=ref.source_generation
         and domains.collection_scope_id=ref.collection_scope_id and domains.storage_kind=ref.storage_kind
        left join sli_plugin_file_audit.observations o on o.evidence_key=ref.native_id
          and o.agent_id=domains.agent_id and o.source_instance_id=ref.source_instance_id
          and o.generation=ref.source_generation and o.payload_sha256=ref.sha256
        where ref.finding_id=p_finding and ref.storage_kind<>'core_event'
    )
    select count(*)>0 and coalesce(bool_and(domain_id is not null and domain_id=any(p_domains)),false)
    from evidence_domains
$$;
revoke all on function public.semantic_finding_in_domains_v262(bigint,bigint[]) from public;
grant execute on function public.semantic_finding_in_domains_v262(bigint,bigint[]) to adlog_user;
insert into public.schema_migrations(version,name) values(262,'default_native_detections');
commit;
