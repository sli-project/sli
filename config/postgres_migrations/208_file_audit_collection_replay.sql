-- Reuse immutable file projections only for an attested pending packet.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_collection_replay_v208'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=207 and name='agent_packet_projection_recovery')
       or exists(select 1 from public.schema_migrations where version>=208) then
        raise exception 'migration 208 prerequisites failed';
    end if;
end $$;
set local role adlog_file_audit_owner;

create function sli_plugin_file_audit.collection_replay(p_agent uuid,p_packet uuid)
returns jsonb language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare
    v_envelope jsonb;
    v_first bigint;
    v_last bigint;
    v_observed bigint;
    v_actions bigint;
begin
    select r.envelope into v_envelope
    from public.sli_agent_receipts r join public.sli_agent_packet_inbox i on i.packet_id=r.packet_id
    join public.sli_agents a on a.id=r.agent_id
    where r.agent_id=p_agent and r.packet_id=p_packet and r.module_id='sli.file-audit'
      and a.status='active' and a.host_id::text=r.envelope->>'source_instance_id' and i.imported_at is null;
    if not found then raise exception 'file_audit_collection_not_admitted'; end if;
    if not exists(select 1 from sli_plugin_file_audit.collection_publications p
                  where p.packet_id=p_packet and p.agent_id=p_agent) then
        return null;
    end if;
    v_first := (nullif(v_envelope->'cursor_before'->>'token','')::jsonb->>'record_id')::bigint;
    v_last := (nullif(v_envelope->'cursor_after'->>'token','')::jsonb->>'record_id')::bigint;
    select count(distinct o.evidence_key),count(distinct e.action_id) into v_observed,v_actions
    from sli_plugin_file_audit.observations o
    left join sli_plugin_file_audit.action_evidence e on e.evidence_key=o.evidence_key and e.role='primary'
    where o.agent_id=p_agent and o.source_instance_id=v_envelope->>'source_instance_id'
      and o.generation=v_envelope->>'generation' and o.record_id>coalesce(v_first,0) and o.record_id<=v_last;
    return jsonb_build_object('observed',v_observed,'actions',v_actions);
end $$;
revoke all on function sli_plugin_file_audit.collection_replay(uuid,uuid) from public;
grant execute on function sli_plugin_file_audit.collection_replay(uuid,uuid) to adlog_user;

reset role;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(208,'file_audit_collection_replay');
commit;
