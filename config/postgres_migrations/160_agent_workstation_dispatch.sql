-- Additive authority for the owner assignment route and attested device identity.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_workstation_dispatch_v160'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 160 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from public.schema_migrations where version=159 and name='workstation_security')
       or exists(select 1 from public.schema_migrations where version>=160) then
        raise exception 'migration 160 requires exact migration 159 workstation_security';
    end if;
end $$;
set local role adlog_storage_owner;
grant update(assigned_modules) on public.sli_agents to adlog_user;
alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
alter table public.sli_agent_audit add constraint sli_agent_audit_action_check
    check(action in ('token_create','token_list','token_revoke','agent_list','issue','renew','revoke','disable','module_assign'));

-- Registered bundled importer, disabled until the owner explicitly opts in.
reset role;
set local role adlog_plugin_lifecycle_owner;
insert into public.plugin_installations_v1(
    plugin_id,manifest_id,manifest_sha256,package_version,package_lifecycle,
    desired_activation,observed_health,component_runtime,queue_state,revision,immutable_evidence_count)
values('sli.workstations','sli.workstations.package.v3',
    '776a31b27c86e1e9d0d991f3357f57eb464ffb0770f8ce729b6f2fe2035650fe',
    '1.0.0','registered','disabled','unknown','stopped','drained',1,1);
insert into public.plugin_state_v1(plugin_id,configured) values('sli.workstations',true);
reset role;
set local role adlog_storage_owner;

-- Caller cannot mint arbitrary generic identities or claim a directory match.
-- The function derives its only stable identifier from the admitted agent UUID.
create function public.resolve_agent_workstation_v160(p_agent uuid,p_packet uuid)
returns table(entity_id bigint,ad_computer_id bigint)
language plpgsql security definer set search_path=pg_catalog,public as $$
declare
    v_host uuid;
    v_received timestamptz;
    v_type integer;
    v_entity bigint;
    v_existing bigint;
    v_key text;
    v_hash bytea;
    v_ad bigint;
begin
    select a.host_id into v_host from public.sli_agents a
    where a.id=p_agent and a.status='active' and exists(
        select 1 from jsonb_array_elements(a.assigned_modules) m
        where m->>'module_id'='sli.workstations' and m->'enabled'='true'::jsonb)
    for update;
    if not found then return; end if;
    select r.received_at into v_received from public.sli_agent_receipts r
    where r.packet_id=p_packet and r.agent_id=p_agent and r.module_id='sli.workstations';
    if not found then return; end if;
    perform pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'));
    if not exists(select 1 from public.read_plugin_states_v1() s
        where s.plugin_id='sli.workstations' and s.installed and s.enabled) then return; end if;
    v_key := 'core:'||encode(sha256(convert_to(
        '["device","sli.agent.key","agent-registry","'||p_agent::text||'"]','UTF8')),'hex');
    v_hash := sha256(convert_to('agent-packet:'||p_packet::text,'UTF8'));
    insert into public.storage_v2_entity_type(value) values('device')
        on conflict(value) do update set value=excluded.value returning id into v_type;
    insert into public.storage_v2_entity_identity_allocations(entity_type_id,natural_key)
        values(v_type,v_key) on conflict(entity_type_id,natural_key) do nothing;
    select a.id into v_entity from public.storage_v2_entity_identity_allocations a
        where a.entity_type_id=v_type and a.natural_key=v_key;
    insert into public.entities_v2(id,entity_type_id,natural_key,display_name,first_seen_utc,last_seen_utc,source_core_sha256)
        values(v_entity,v_type,v_key,'device identity',v_received,v_received,v_hash)
        on conflict(entity_type_id,natural_key) do update set
            first_seen_utc=least(entities_v2.first_seen_utc,excluded.first_seen_utc),
            last_seen_utc=greatest(entities_v2.last_seen_utc,excluded.last_seen_utc)
        returning id into v_existing;
    if v_existing<>v_entity then raise exception 'core_identity_allocation_conflict'; end if;
    insert into public.core_entity_identifiers(entity_id,entity_kind,namespace,scope_id,value,strength)
        values(v_entity,'device','sli.agent.key','agent-registry',p_agent::text,'stable') on conflict do nothing;
    select i.entity_id into v_existing from public.core_entity_identifiers i
        where i.entity_kind='device' and i.namespace='sli.agent.key' and i.scope_id='agent-registry'
          and i.value=p_agent::text and i.strength='stable';
    if v_existing is distinct from v_entity then raise exception 'core_identity_identifier_conflict'; end if;
    insert into public.core_entity_observations(observation_sha256,plugin_id,source_instance_id,entity_kind,
        entity_id,observed_at_utc,identifiers_json,evidence_refs,resolution,candidate_ids,reason)
        values(v_hash,'sli.workstations',v_host::text,'device',v_entity,v_received,
            jsonb_build_array(jsonb_build_object('namespace','sli.agent.key','scope_id','agent-registry',
                'value',p_agent::text,'strength','stable')),array['agent-packet:'||p_packet::text],
            'resolved','{}'::integer[],null) on conflict(observation_sha256) do nothing;
    -- Enrich only with a unique explicit association; never match by hostname.
    select case when count(distinct a.target_entity_id)=1
        and bool_and(t.value='ad_computer') then min(a.target_entity_id) end into v_ad
        from public.core_entity_associations a
        join public.entities_v2 e on e.id=a.target_entity_id
        join public.storage_v2_entity_type t on t.id=e.entity_type_id
        where a.source_entity_id=v_entity and a.relation='directory_computer';
    return query select v_entity,v_ad;
end $$;
revoke all on function public.resolve_agent_workstation_v160(uuid,uuid) from public;
grant execute on function public.resolve_agent_workstation_v160(uuid,uuid) to adlog_user;
insert into public.schema_migrations(version,name) values(160,'agent_workstation_dispatch');
commit;
