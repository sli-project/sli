-- Keep unrelated Security traffic out of bounded file correlation context.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_scoped_context_v214'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=213 and name='ad_directory_display_names')
       or exists(select 1 from public.schema_migrations where version>=214) then
        raise exception 'migration 214 prerequisites failed';
    end if;
end $$;
set local role adlog_file_audit_owner;

create function sli_plugin_file_audit.collection_context_for_packet(p_agent uuid,p_packet uuid,p_start timestamptz,p_end timestamptz,p_keys jsonb)
returns jsonb language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare
    v_source text;
    v_generation text;
    v_sequence bigint;
    v_first_record bigint;
    v_complete boolean;
    v_rows jsonb;
begin
    if jsonb_typeof(p_keys) is distinct from 'array' or jsonb_array_length(p_keys)>256
       or octet_length(p_keys::text)>1048576 then
        raise exception 'file_audit_context_keys_invalid';
    end if;
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
            and exists(select 1 from jsonb_array_elements(p_keys) k
                where o.normalized->>'policy_revision'=k->>'policy_revision' and (
                    o.event_id in (4608,1102)
                    or o.event_id=4634 and o.normalized->'facts'->'logon_id_numeric'=k->'facts'->'logon_id_numeric'
                    or o.event_id=4624
                       and o.normalized->'facts'->'subject_user_sid'=k->'facts'->'subject_user_sid'
                       and o.normalized->'facts'->'logon_id_numeric'=k->'facts'->'logon_id_numeric'
                    or o.event_id in (4656,4659,4663,4658,4660)
                       and o.normalized->'facts'->'subject_user_sid'=k->'facts'->'subject_user_sid'
                       and o.normalized->'facts'->'logon_id_numeric'=k->'facts'->'logon_id_numeric'
                       and o.normalized->'facts'->'server_process_id'=k->'facts'->'server_process_id'
                       and o.normalized->'facts'->'handle_id'=k->'facts'->'handle_id'))
          order by o.record_id desc limit 1025) q;
    -- Gap admission covers the entire time window, including unrelated rows
    -- omitted by the correlation selector above.
    select min(o.record_id) into v_first_record from sli_plugin_file_audit.observations o
    where o.agent_id=p_agent and o.source_instance_id=v_source and o.generation=v_generation
      and o.normalized is not null and o.observed_at between p_start and p_end;
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
revoke all on function sli_plugin_file_audit.collection_context_for_packet(uuid,uuid,timestamptz,timestamptz,jsonb) from public;
grant execute on function sli_plugin_file_audit.collection_context_for_packet(uuid,uuid,timestamptz,timestamptz,jsonb) to adlog_user;
reset role;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(214,'file_audit_scoped_context');
commit;
