begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_journal_admission413'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=410 and name='password_origin_prefix')
       or not exists(select 1 from public.schema_migrations where version=412 and name='sigma_history_test')
       or exists(select 1 from public.schema_migrations where version>=413) then
        raise exception 'workstation_journal_admission413_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_user;
-- Source identifiers are retained on rollback with the events that use them.
insert into public.log_sources(name) values('Security'),('System'),('Microsoft-Windows-Windows Defender/Operational')
on conflict(name) do nothing;
reset role;
set local role adlog_storage_owner;

create table public.workstation_journal_grants412 (
    agent_id uuid primary key references public.sli_agents(id) on delete cascade,
    source_id uuid not null,
    server_id bigint not null,
    domain_id bigint not null,
    computer text not null,
    registered_name text not null,
    alias text not null,
    config jsonb not null,
    enabled boolean not null
);
create unique index workstation_journal_source412 on public.workstation_journal_grants412(source_id) where enabled;
create unique index workstation_journal_server412 on public.workstation_journal_grants412(server_id) where enabled;
revoke all on public.workstation_journal_grants412 from public,adlog_user,adlog_storage_worker;

-- The assignment transaction already owns the agent lock. No name or scope is
-- taken from the log packet. Ambiguous or unregistered computers stay closed.
create function public.set_workstation_journal_grant412(p_agent uuid,p_enabled boolean) returns boolean
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

create function public.workstation_journal_scope412(p_agent uuid,p_source text,p_revision text)
returns table(server_id bigint,domain_id bigint,computer text,alias text,config jsonb)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select p.server_id,p.domain_id,p.computer,p.alias,p.config
    from public.workstation_journal_grants412 p
    join public.sli_agents a on a.id=p.agent_id and a.status='active'
    join public.servers s on s.id=p.server_id and s.domain_id=p.domain_id and s.hostname=p.alias
        and s.is_active and s.role='workstation' and coalesce(nullif(s.fqdn,''),s.hostname)=p.computer
    cross join lateral jsonb_array_elements(a.assigned_modules) m
    where p.enabled and p.agent_id=p_agent and public.workstation_runtime_enabled_v376()
      and a.registration_host_name=p.registered_name and coalesce(a.source_host_id,a.host_id)=p.source_id
      and (p_source is null or p_source=p.source_id::text)
      and (p_revision is null or p_revision=p.config->>'policy_revision')
      and (select count(*) from jsonb_array_elements(a.assigned_modules) e
           where coalesce(e->>'module_id',e#>>'{}')='sli.workstations')=1
      and m->>'module_id'='sli.workstations' and m->'enabled'='true'::jsonb and m->'config'=p.config
$$;

create function public.workstation_journal_packet_allowed412(p_envelope jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select coalesce(p_envelope->>'module_id'='sli.workstations' and p_envelope->>'channel'='workstations'
        and nullif(p_envelope->>'source_instance_id','') is not null and nullif(p_envelope->>'policy_revision','') is not null
        and exists(select 1 from public.workstation_journal_scope412(
            case when pg_input_is_valid(p_envelope->>'agent_id','uuid') then (p_envelope->>'agent_id')::uuid end,
            p_envelope->>'source_instance_id',p_envelope->>'policy_revision')),false)
$$;

create function public.workstation_journal_proof412(p_packet uuid,p_ordinal integer,p_event bigint,
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
revoke all on function public.workstation_journal_proof412(uuid,integer,bigint,timestamptz,integer,bigint,text,jsonb) from public;

create table public.workstation_journal_restore412(original text not null, installed text not null);
revoke all on public.workstation_journal_restore412 from public,adlog_user,adlog_storage_worker;
do $$ declare body text; patched text; marker text:=E'    if not found then\n        select proof.origin,proof.record_id'; begin
    select pg_get_functiondef('public.attest_short_event337()'::regprocedure) into strict body;
    if strpos(body,marker)=0 then raise exception 'workstation_journal_admission413_trigger_shape'; end if;
    patched:=replace(body,marker,$branch$    if not found then
        select proof.origin,proof.record_id into origin,record_id
        from public.workstation_journal_proof412(admission_packet::uuid,admission_ordinal::integer,
            new.event_id,new.time_created_utc,new.event_kind,new.domain_id,new.computer,new.method) proof;
        if found then
            new.method:=new.method||jsonb_build_object('$origin',origin);
            new.event_record_id:=record_id;
            return new;
        end if;
    end if;
$branch$||marker);
    execute patched;
    insert into public.workstation_journal_restore412 values(body,pg_get_functiondef('public.attest_short_event337()'::regprocedure));
end $$;

-- Locks and publication are in the same transaction as the regular inbox
-- acknowledgement. Workstation provenance never sets the DC digest.
create function public.write_workstation_journal412(p_packet uuid,p_rows jsonb) returns void
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare packet public.sli_agent_packet_inbox%rowtype; incoming record; evidence record; written record;
begin
    select * into strict packet from public.sli_agent_packet_inbox where packet_id=p_packet for update;
    if not public.workstation_journal_packet_allowed412(packet.envelope) or packet.module_disabled_at is not null then
        raise exception 'module_disabled' using errcode='55000';
    end if;
    if jsonb_typeof(p_rows) is distinct from 'array' or jsonb_array_length(p_rows)<>jsonb_array_length(packet.event_rows) then
        raise exception 'workstation_journal_attestation_failed' using errcode='55000';
    end if;
    for incoming in select j.value->>'layer' as layer,r.*,j.ordinal-1 as packet_ordinal
            from jsonb_array_elements(p_rows) with ordinality j(value,ordinal)
            cross join lateral jsonb_populate_record(null::public.event_hot,j.value) r loop
        if incoming.method->>'$packet_id' is distinct from p_packet::text
           or incoming.method->>'$packet_ordinal' is distinct from incoming.packet_ordinal::text
           or incoming.layer is distinct from (case when incoming.event_kind in (4624,4625) then 'summary' else 'fact' end)
           or not exists(select 1 from public.workstation_journal_proof412(p_packet,incoming.packet_ordinal::integer,
                incoming.event_id,incoming.time_created_utc,incoming.event_kind,incoming.domain_id,incoming.computer,incoming.method)) then
            raise exception 'workstation_journal_attestation_failed' using errcode='55000';
        end if;
    end loop;
    select * into strict written from public.write_short_events349(p_rows);
    if written.groups<>written.summaries then raise exception 'short_event_summary_conflict' using errcode='55000'; end if;
    for incoming in select r.*,j.ordinal-1 as packet_ordinal from jsonb_array_elements(p_rows) with ordinality j(value,ordinal)
            cross join lateral jsonb_populate_record(null::public.event_hot,j.value) r loop
        select * into strict evidence from public.workstation_journal_proof412(p_packet,incoming.packet_ordinal::integer,
            incoming.event_id,incoming.time_created_utc,incoming.event_kind,incoming.domain_id,incoming.computer,incoming.method);
        if not exists(select 1 from public.event_hot h where h.event_id=incoming.event_id and h.time_created_utc=incoming.time_created_utc
            and h.event_record_id=evidence.record_id and h.method->'$origin'=evidence.origin and h.source_sha256 is null
            and (h.event_kind,h.domain_id,h.actor,h.target,h.source,h.computer,h.method-'$origin',h.outcome,h.fields)
              is not distinct from (incoming.event_kind,incoming.domain_id,incoming.actor,incoming.target,incoming.source,incoming.computer,
                incoming.method-'$origin'-'$packet_id'-'$packet_ordinal',incoming.outcome,incoming.fields)) then
            raise exception 'workstation_journal_attestation_failed' using errcode='55000';
        end if;
    end loop;
end $$;

revoke all on function public.set_workstation_journal_grant412(uuid,boolean), public.workstation_journal_scope412(uuid,text,text),
    public.workstation_journal_packet_allowed412(jsonb), public.write_workstation_journal412(uuid,jsonb) from public;
grant execute on function public.set_workstation_journal_grant412(uuid,boolean), public.workstation_journal_scope412(uuid,text,text),
    public.workstation_journal_packet_allowed412(jsonb), public.write_workstation_journal412(uuid,jsonb) to adlog_user;
insert into public.schema_migrations(version,name) values(413,'workstation_journal_admission');
reset role;
commit;
