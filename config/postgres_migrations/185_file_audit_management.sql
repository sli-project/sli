-- Stage 2: revisioned AG-AUDIT requests and append-only local inventory.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_management_v185'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 185 requires storage owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=184 and name='agent_update_waves')
       or exists(select 1 from public.schema_migrations where version>=185) then
        raise exception 'migration 185 requires exact migration 184 agent_update_waves and unused version 185';
    end if;
end $$;
set local role adlog_storage_owner;
alter table public.sli_agents add column file_audit jsonb not null default '{}'::jsonb
    check(jsonb_typeof(file_audit)='object' and octet_length(file_audit::text)<=131072);
grant update(file_audit) on public.sli_agents to adlog_user;
grant select(id,host_id,policy_revision,status,file_audit) on public.sli_agents to adlog_file_audit_owner;
reset role;
set local role adlog_file_audit_owner;

-- Core calls these after administrator scope checks / locked mTLS admission.
-- No application table access, membership or raw-evidence grants are added.
create function sli_plugin_file_audit.enqueue_audit(
    p_agent uuid,p_source text,p_policy jsonb,p_command jsonb,p_actor_kind text,p_actor_id bigint
) returns void language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare
    v_revision bigint := (p_command->>'policy_revision')::bigint;
begin
    if not exists(select 1 from public.sli_agents where id=p_agent and status='active'
        and host_id::text=p_source and policy_revision+1=v_revision)
       or p_policy->>'policy_revision' is distinct from p_command->>'policy_revision'
       or jsonb_typeof(p_command->'collection_scope_ids') is distinct from 'array'
       or p_command->>'contract_id' is distinct from 'sli.file-audit.audit-command.v1' then
        raise exception 'file_audit_command_invalid';
    end if;
    insert into sli_plugin_file_audit.policy_revisions
        (agent_id,source_instance_id,revision,authored_at,actor_kind,actor_id,policy,policy_sha256)
    values(p_agent,p_source,v_revision,clock_timestamp(),p_actor_kind,p_actor_id,p_policy,
        encode(sha256(convert_to(p_policy::text,'UTF8')),'hex'));
    insert into sli_plugin_file_audit.audit_commands
        (command_id,agent_id,source_instance_id,policy_revision,action,collection_scope_ids,
         requested_at,actor_kind,actor_id,command_sha256)
    values(p_command->>'command_id',p_agent,p_source,v_revision,p_command->>'action',
        array(select jsonb_array_elements_text(p_command->'collection_scope_ids')),
        clock_timestamp(),p_actor_kind,p_actor_id,encode(sha256(convert_to(p_command::text,'UTF8')),'hex'));
end $$;

create function sli_plugin_file_audit.audit_request(p_agent uuid,p_command text)
returns jsonb language sql security definer set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('config',p.policy,'command',jsonb_build_object(
        'contract_id','sli.file-audit.audit-command.v1','command_id',c.command_id,
        'action',c.action,'policy_revision',c.policy_revision::text,'collection_scope_ids',to_jsonb(c.collection_scope_ids)))
    from sli_plugin_file_audit.audit_commands c join sli_plugin_file_audit.policy_revisions p
        on p.agent_id=c.agent_id and p.source_instance_id=c.source_instance_id and p.revision=c.policy_revision
    where c.agent_id=p_agent and c.command_id=p_command;
$$;

create function sli_plugin_file_audit.store_audit_result(p_agent uuid,p_result jsonb)
returns void language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare
    v_command sli_plugin_file_audit.audit_commands%rowtype;
    v_item jsonb;
begin
    select c.* into strict v_command from sli_plugin_file_audit.audit_commands c
        join public.sli_agents a on a.id=c.agent_id
        where c.agent_id=p_agent and a.status='active' and c.command_id=p_result->>'command_id'
        and c.policy_revision=(p_result->>'policy_revision')::bigint and c.action=p_result->>'action';
    for v_item in select jsonb_array_elements(p_result->'snapshots') loop
        if not (v_item->>'collection_scope_id'=any(v_command.collection_scope_ids)) then
            raise exception 'file_audit_scope_invalid';
        end if;
        insert into sli_plugin_file_audit.access_snapshots
            (snapshot_id,agent_id,source_instance_id,collection_scope_id,observed_at,contract_version,
             completeness,snapshot_sha256,snapshot,unread_objects)
        values((v_item->>'snapshot_id')::uuid,p_agent,v_command.source_instance_id,
            v_item->>'collection_scope_id',(v_item->>'observed_at_utc')::timestamptz,1,
            v_item->>'completeness',v_item->>'snapshot_sha256',v_item,(v_item->>'unread_objects')::integer)
        on conflict(snapshot_id) do nothing;
    end loop;
    for v_item in select jsonb_array_elements(p_result->'scopes') loop
        if not (v_item->>'collection_scope_id'=any(v_command.collection_scope_ids)) then
            raise exception 'file_audit_scope_invalid';
        end if;
        insert into sli_plugin_file_audit.audit_receipts
            (receipt_id,command_id,agent_id,source_instance_id,collection_scope_id,policy_revision,
             action,state,observed_at,result_sha256,reason_code)
        values((v_item->>'receipt_id')::uuid,v_command.command_id,p_agent,v_command.source_instance_id,
            v_item->>'collection_scope_id',v_command.policy_revision,v_command.action,v_item->>'state',
            (p_result->>'observed_at_utc')::timestamptz,v_item->>'result_sha256',v_item->>'reason_code')
        on conflict(receipt_id) do nothing;
    end loop;
end $$;
revoke all on function sli_plugin_file_audit.enqueue_audit(uuid,text,jsonb,jsonb,text,bigint) from public;
revoke all on function sli_plugin_file_audit.store_audit_result(uuid,jsonb) from public;
revoke all on function sli_plugin_file_audit.audit_request(uuid,text) from public;
grant usage on schema sli_plugin_file_audit to adlog_user;
grant execute on function sli_plugin_file_audit.enqueue_audit(uuid,text,jsonb,jsonb,text,bigint) to adlog_user;
grant execute on function sli_plugin_file_audit.store_audit_result(uuid,jsonb) to adlog_user;
grant execute on function sli_plugin_file_audit.audit_request(uuid,text) to adlog_user;
reset role;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(185,'file_audit_management');
commit;
