begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_package459'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or exists(select 1 from public.schema_migrations where version>459) then
        raise exception 'workstation_package459_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create or replace function public.set_workstation_journal_grant412(p_agent uuid,p_enabled boolean) returns boolean
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare agent public.sli_agents%rowtype; assignment jsonb; station record;
begin
    select * into strict agent from public.sli_agents where id=p_agent for update;
    if p_enabled is distinct from true then
        update public.workstation_journal_grants412 set enabled=false where agent_id=p_agent;
        return true;
    end if;
    if agent.status<>'active' or nullif(agent.registration_host_name,'') is null
       or not public.workstation_runtime_enabled_v376() then return false; end if;
    select m into strict assignment from jsonb_array_elements(agent.assigned_modules) m
        where coalesce(m->>'module_id',m#>>'{}')='sli.workstations';
    if assignment->'enabled' is distinct from 'true'::jsonb
       or jsonb_typeof(assignment->'config') is distinct from 'object' then return false; end if;
    select s.id,s.domain_id,s.fqdn,s.hostname into strict station from public.servers s
        where s.is_active and s.role='workstation' and (lower(s.hostname)=lower(agent.registration_host_name)
            or lower(s.fqdn)=lower(agent.registration_host_name));
    update public.workstation_journal_grants412 p set enabled=false
        from public.sli_agents previous
        where previous.id=p.agent_id and previous.status<>'active' and p.enabled
          and (p.server_id=station.id or p.source_id=coalesce(agent.source_host_id,agent.host_id));
    insert into public.workstation_journal_grants412(agent_id,source_id,server_id,domain_id,computer,registered_name,alias,config,enabled)
        values(p_agent,coalesce(agent.source_host_id,agent.host_id),station.id,station.domain_id,
            coalesce(nullif(station.fqdn,''),station.hostname),agent.registration_host_name,station.hostname,assignment->'config',true)
    on conflict(agent_id) do update set source_id=excluded.source_id,server_id=excluded.server_id,domain_id=excluded.domain_id,
        computer=excluded.computer,registered_name=excluded.registered_name,alias=excluded.alias,config=excluded.config,enabled=true;
    return true;
exception when no_data_found or too_many_rows or unique_violation then return false;
end $$;

create or replace function public.workstation_journal_proof412(p_packet uuid,p_ordinal integer,p_event bigint,
    p_at timestamptz,p_kind integer,p_domain bigint,p_computer text,p_method jsonb)
returns table(origin jsonb,record_id bigint)
language sql stable set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('installation_id',installation.installation_id::text,
        'plugin_id','sli.workstations','agent_id',r.agent_id::text,
        'source_instance_id',i.envelope->>'source_instance_id','source_generation',i.envelope->>'generation',
        'collection_scope_id','','log_source_id',ls.id), a.event_record_id
    from public.sli_agent_packet_inbox i
    join public.sli_agent_receipts r on r.packet_id=i.packet_id and r.envelope=i.envelope
        and r.module_id='sli.workstations' and r.receipt->>'status'='committed'
    cross join lateral public.workstation_journal_scope412(r.agent_id,i.envelope->>'source_instance_id',i.envelope->>'policy_revision') p
    join public.storage_v2_event_identity_allocations a on a.id=p_event and a.server_id=p.server_id and a.time_created_utc=p_at
    join public.storage_v2_channel ch on ch.id=a.channel_id and ch.value=i.collection_channel and ch.value=p_method->>'$channel'
    join public.log_sources ls on ls.name=ch.value
    join public.event_source_representations_v2 rep on rep.event_id=a.id and rep.normalized_hash=a.normalized_hash
    cross join lateral (select i.event_rows->p_ordinal as doc) native
    cross join lateral (select regexp_match(native.doc->>'time_created',
        '^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})\.([0-9]{6})([0-9]+)(Z|[+-][0-9]{2}:[0-9]{2})$') as parts) clock
    cross join public.semantic_default_installation installation
    where i.packet_id=p_packet and p_ordinal>=0 and i.module_disabled_at is null
      and p.domain_id=p_domain and p.computer=p_computer and p.server_id::text=p_method->>'$server_id'
      and p_kind in (1102,4624,4625,4698,4732,4733,5001,5010,5012,7036,7040,7045)
      and i.envelope->>'module_id'=r.module_id and i.envelope->>'agent_id'=r.agent_id::text
      and i.envelope->>'packet_id'=i.packet_id::text and i.envelope->>'payload_contract'='sli.collection-packet.v1'
      and i.envelope->>'channel'='workstations' and i.envelope->>'generation'=i.envelope->>'source_instance_id'
      and nullif(i.envelope->>'source_instance_id','') is not null and nullif(i.envelope->>'policy_revision','') is not null
      and not exists(select 1 from public.sli_agent_packet_quarantine q where q.packet_id=i.packet_id)
      and native.doc=rep.representation and native.doc=i.packet->'records'->p_ordinal->'payload'
      and lower(native.doc->>'machine_name') in (lower(p.computer),lower(p.alias))
      and native.doc->>'computer_name'=i.envelope->>'source_instance_id'
      and native.doc->>'record_id'=a.event_record_id::text and native.doc->>'event_id'=p_kind::text
      and native.doc->>'channel'=ch.value and native.doc->>'provider_name'=p_method->>'$provider'
      and (case when clock.parts is not null then (clock.parts[1]||clock.parts[4])::timestamptz
            + (clock.parts[2]::integer + case when left(clock.parts[3],1) in ('6','7','8','9')
              or left(clock.parts[3],1)='5' and (substr(clock.parts[3],2) ~ '[1-9]'
                  or clock.parts[2]::integer%2=1) then 1 else 0 end)*interval '1 microsecond'
          when pg_input_is_valid(native.doc->>'time_created','timestamp with time zone')
              then (native.doc->>'time_created')::timestamptz end)=p_at
$$;

-- Keep the enrolled identities, grants and published events for historical reads.
drop function public.workstation_package_approved459(uuid);
delete from public.schema_migrations where version=459 and name='workstation_package';
reset role;
commit;
