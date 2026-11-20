-- Stage 3: attested evidence context and append-only file action publication.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_collection_v186'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 186 requires storage owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=185 and name='file_audit_management')
       or exists(select 1 from public.schema_migrations where version>=186) then
        raise exception 'migration 186 requires exact migration 185 file_audit_management and unused version 186';
    end if;
end $$;
set local role adlog_storage_owner;
alter table public.event_facts_v2 add column file_audit_facts_json text
    check(octet_length(file_audit_facts_json)<=65536 and jsonb_typeof(file_audit_facts_json::jsonb)='object');
grant select(packet_id,agent_id,module_id,envelope) on public.sli_agent_receipts to adlog_file_audit_owner;
grant select(packet_id,envelope,imported_at) on public.sli_agent_packet_inbox to adlog_file_audit_owner;
reset role;
set local role adlog_file_audit_owner;

-- Shared logon/control observations reference the core's AD-owned evidence;
-- they do not register another source pack or normalizer for these events.
alter table sli_plugin_file_audit.observations drop constraint observations_event_id_check;
alter table sli_plugin_file_audit.observations add constraint observations_event_id_check
    check(event_id in (4656,4658,4659,4660,4663,4664,4670,4907,5140,5142,5143,5144,5145,5168,4608,4624,4625,4634,4719,1102));
alter table sli_plugin_file_audit.observations drop constraint observations_provider_check;
alter table sli_plugin_file_audit.observations add constraint observations_provider_check
    check(provider=case when event_id=1102 then 'Microsoft-Windows-Eventlog' else 'Microsoft-Windows-Security-Auditing' end);
alter table sli_plugin_file_audit.observations add column normalized jsonb
    check(jsonb_typeof(normalized)='object' and octet_length(normalized::text)<=65536);
alter table sli_plugin_file_audit.actions add column denial_layer text check(denial_layer in ('smb','ntfs','logon'));
-- Retained hashes cover the complete projection, including overlapping SMB
-- contexts and evidence links. A different replay cannot silently overwrite it.
create table sli_plugin_file_audit.collection_publications (
    packet_id uuid primary key,
    agent_id uuid not null,
    projection_sha256 text not null check(projection_sha256 ~ '^[a-f0-9]{64}$')
);
revoke all on sli_plugin_file_audit.collection_publications from public,adlog_user;

create function sli_plugin_file_audit.collection_context(p_agent uuid,p_packet uuid,p_start timestamptz,p_end timestamptz)
returns jsonb language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare
    v_source text;
    v_generation text;
    v_sequence bigint;
    v_first_record bigint;
    v_complete boolean;
    v_rows jsonb;
begin
    select r.envelope->>'source_instance_id',r.envelope->>'generation',(r.envelope->>'sequence')::bigint
    into v_source,v_generation,v_sequence
    from public.sli_agent_receipts r join public.sli_agent_packet_inbox i on i.packet_id=r.packet_id
    join public.sli_agents a on a.id=r.agent_id
    where r.agent_id=p_agent and r.packet_id=p_packet and r.module_id='sli.file-audit'
      and a.status='active' and a.host_id::text=r.envelope->>'source_instance_id' and i.imported_at is null;
    if not found or p_start is null or p_end is null or p_end<p_start or p_end-p_start>interval '1 day' then
        raise exception 'file_audit_collection_not_admitted';
    end if;
    select coalesce(jsonb_agg(q.normalized order by q.record_id),'[]'::jsonb) into v_rows
    from (select o.normalized,o.record_id from sli_plugin_file_audit.observations o
          where o.agent_id=p_agent and o.source_instance_id=v_source and o.generation=v_generation
            and o.normalized is not null and o.observed_at between p_start and p_end
          order by o.record_id desc limit 1025) q;
    select min((o->>'record_id')::bigint) into v_first_record from jsonb_array_elements(v_rows) o;
    v_complete := jsonb_array_length(v_rows)<=1024 and not exists(
        select 1 from public.sli_agent_receipts r
        where r.agent_id=p_agent and r.module_id='sli.file-audit'
          and r.envelope->>'generation'=v_generation and (r.envelope->>'sequence')::bigint<v_sequence
          and r.envelope->>'continuity_state'='gap'
          and (nullif(r.envelope->'cursor_after'->>'token','')::jsonb->>'record_id')::bigint>=v_first_record)
        and not exists(select 1 from public.sli_agent_packet_inbox i
            where i.envelope->>'agent_id'=p_agent::text and i.envelope->>'module_id'='sli.file-audit'
              and i.envelope->>'generation'=v_generation and i.imported_at is null
              and (i.envelope->>'sequence')::bigint<v_sequence);
    return jsonb_build_object('complete',v_complete,
                             'observations',case when jsonb_array_length(v_rows)<=1024 then v_rows else '[]'::jsonb end);
end $$;

create function sli_plugin_file_audit.store_collection(p_agent uuid,p_packet uuid,p_projection jsonb)
returns void language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare
    v_envelope jsonb;
    v_hash text;
    v_previous text;
    v_item jsonb;
    v_evidence jsonb;
    v_normalized jsonb;
begin
    select r.envelope into strict v_envelope
    from public.sli_agent_receipts r join public.sli_agent_packet_inbox i on i.packet_id=r.packet_id
    join public.sli_agents a on a.id=r.agent_id
    where r.agent_id=p_agent and r.packet_id=p_packet and r.module_id='sli.file-audit'
      and a.status='active' and a.host_id::text=r.envelope->>'source_instance_id' and i.imported_at is null;
    if jsonb_typeof(p_projection->'observations') is distinct from 'array'
       or jsonb_typeof(p_projection->'actions') is distinct from 'array'
       or jsonb_array_length(p_projection->'observations')>256
       or jsonb_array_length(p_projection->'actions')>102400
       or octet_length(p_projection::text)>16777216 then
        raise exception 'file_audit_projection_invalid';
    end if;
    v_hash := encode(sha256(convert_to(p_projection::text,'UTF8')),'hex');
    insert into sli_plugin_file_audit.collection_publications(packet_id,agent_id,projection_sha256)
        values(p_packet,p_agent,v_hash) on conflict(packet_id) do nothing;
    select projection_sha256 into strict v_previous from sli_plugin_file_audit.collection_publications where packet_id=p_packet;
    if v_previous<>v_hash then raise exception 'file_audit_replay_conflict'; end if;
    for v_item in select jsonb_array_elements(p_projection->'observations') loop
        if v_item->>'agent_id' is distinct from p_agent::text
           or v_item->>'source_instance_id' is distinct from v_envelope->>'source_instance_id'
           or v_item->>'generation' is distinct from v_envelope->>'generation'
           or v_item->>'policy_revision' is distinct from v_envelope->>'policy_revision' then
            raise exception 'file_audit_projection_binding_invalid';
        end if;
        insert into sli_plugin_file_audit.observations
            (evidence_key,agent_id,source_instance_id,collection_scope_id,channel,provider,generation,record_id,
             event_id,event_version,observed_at,policy_revision,core_evidence_ref,payload_sha256,normalized)
        values(v_item->>'evidence_key',p_agent,v_item->>'source_instance_id',
            coalesce(v_item->'scopes'->0->>'collection_scope_id','technical'),v_item->>'channel',v_item->>'provider',
            v_item->>'generation',(v_item->>'record_id')::bigint,(v_item->>'event_id')::integer,
            (v_item->>'event_version')::integer,(v_item->>'observed_at')::timestamptz,
            (v_item->>'policy_revision')::bigint,v_item->>'core_evidence_ref',v_item->>'payload_sha256',v_item)
        on conflict(evidence_key) do nothing;
        select normalized into strict v_normalized from sli_plugin_file_audit.observations where evidence_key=v_item->>'evidence_key';
        if v_normalized is distinct from v_item then raise exception 'file_audit_replay_conflict'; end if;
    end loop;
    for v_item in select jsonb_array_elements(p_projection->'actions') loop
        if v_item->>'agent_id' is distinct from p_agent::text
           or v_item->>'source_instance_id' is distinct from v_envelope->>'source_instance_id' then
            raise exception 'file_audit_projection_binding_invalid';
        end if;
        if not exists(
            select 1 from jsonb_array_elements(v_item->'evidence') e
            join sli_plugin_file_audit.observations o on o.evidence_key=e->>'evidence_key',
            jsonb_array_elements(o.normalized->'scopes') s
            where o.agent_id=p_agent and o.source_instance_id=v_envelope->>'source_instance_id'
              and o.generation=v_envelope->>'generation'
              and s->>'collection_scope_id'=v_item->>'collection_scope_id'
              and o.normalized->>'path' is not distinct from v_item->>'path'
              and (e->>'role'='primary' or v_item->>'operation'='delete' and e->>'role'='handle_context')) then
            raise exception 'file_audit_action_scope_invalid';
        end if;
        insert into sli_plugin_file_audit.actions
            (action_id,contract_version,agent_id,source_instance_id,collection_scope_id,observed_at,
             subject_sid,logon_id,path,share_name,object_type,access_mask,operation,outcome,client_ip,client_ip_source,
             server_process_id,handle_id,correlation_state,projection_version,denial_layer)
        values(v_item->>'action_id',1,p_agent,v_item->>'source_instance_id',v_item->>'collection_scope_id',
            (v_item->>'observed_at')::timestamptz,v_item->>'subject_sid',v_item->>'logon_id',v_item->>'path',
            v_item->>'share_name',v_item->>'object_type',(v_item->>'access_mask')::bigint,v_item->>'operation',
            v_item->>'outcome',(v_item->>'client_ip')::inet,v_item->>'client_ip_source',
            (v_item->>'server_process_id')::bigint,v_item->>'handle_id',v_item->>'correlation_state',1,v_item->>'denial_layer')
        on conflict(action_id) do nothing;
        for v_evidence in select jsonb_array_elements(v_item->'evidence') loop
            if not exists(select 1 from sli_plugin_file_audit.observations o
                where o.evidence_key=v_evidence->>'evidence_key' and o.agent_id=p_agent
                  and o.source_instance_id=v_envelope->>'source_instance_id' and o.generation=v_envelope->>'generation'
                  and o.core_evidence_ref=v_evidence->>'core_evidence_ref') then
                raise exception 'file_audit_action_evidence_invalid';
            end if;
            insert into sli_plugin_file_audit.action_evidence(action_id,core_evidence_ref,evidence_key,role)
            values(v_item->>'action_id',v_evidence->>'core_evidence_ref',v_evidence->>'evidence_key',v_evidence->>'role')
            on conflict(action_id,core_evidence_ref) do nothing;
        end loop;
    end loop;
end $$;
revoke all on function sli_plugin_file_audit.collection_context(uuid,uuid,timestamptz,timestamptz),
    sli_plugin_file_audit.store_collection(uuid,uuid,jsonb) from public;
grant execute on function sli_plugin_file_audit.collection_context(uuid,uuid,timestamptz,timestamptz),
    sli_plugin_file_audit.store_collection(uuid,uuid,jsonb) to adlog_user;
reset role;
insert into public.schema_migrations(version,name) values(186,'file_audit_collection');
commit;
