-- Stage 4: bounded security rules and immutable links to core findings.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_rules_v187'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 187 requires storage owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=186 and name='file_audit_collection')
       or exists(select 1 from public.schema_migrations where version>=187) then
        raise exception 'migration 187 requires exact migration 186 file_audit_collection and unused version 187';
    end if;
end $$;
-- Legacy findings remain core-owned. Only the reviewed definer can publish;
-- the application receives no new table grants or role memberships.
grant select(id,fingerprint,rule_code),insert on public.findings to adlog_file_audit_owner;
grant references(id) on public.findings to adlog_file_audit_owner;
grant usage on sequence public.findings_id_seq to adlog_file_audit_owner;
set local role adlog_file_audit_owner;
create table sli_plugin_file_audit.rule_results (
    result_id text primary key check(result_id ~ '^[a-f0-9]{64}$'),
    finding_id bigint not null references public.findings(id),
    agent_id uuid not null,
    source_instance_id text not null,
    collection_scope_id text not null,
    rule_code text not null check(rule_code in ('file-audit.mass-read','file-audit.mass-write',
        'file-audit.mass-delete','file-audit.out-of-hours','file-audit.broad-write',
        'file-audit.direct-user-rights','file-audit.disabled-account-rights','file-audit.acl-review')),
    rule_version integer not null check(rule_version=1),
    conclusion_state text not null check(conclusion_state in ('observed','requires_review')),
    observed_at timestamptz not null,
    result jsonb not null check(jsonb_typeof(result)='object' and octet_length(result::text)<=1048576),
    result_sha256 text not null check(result_sha256 ~ '^[a-f0-9]{64}$')
);
create index file_audit_rule_scope on sli_plugin_file_audit.rule_results
    (agent_id,source_instance_id,collection_scope_id,observed_at,result_id);
create table sli_plugin_file_audit.rule_actions (
    result_id text not null references sli_plugin_file_audit.rule_results(result_id),
    action_id text not null references sli_plugin_file_audit.actions(action_id),
    primary key(result_id,action_id)
);
create table sli_plugin_file_audit.rule_snapshots (
    result_id text not null references sli_plugin_file_audit.rule_results(result_id),
    snapshot_id uuid not null references sli_plugin_file_audit.access_snapshots(snapshot_id),
    primary key(result_id,snapshot_id)
);
revoke all on sli_plugin_file_audit.rule_results,sli_plugin_file_audit.rule_actions,
    sli_plugin_file_audit.rule_snapshots from public,adlog_user,adlog_file_audit_runtime;

create function sli_plugin_file_audit.rule_context(p_agent uuid,p_packet uuid,p_start timestamptz,p_end timestamptz)
returns jsonb language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare
    v_envelope jsonb;
    v_actions jsonb;
    v_snapshots jsonb;
    v_complete boolean;
begin
    select r.envelope into strict v_envelope
    from public.sli_agent_receipts r join public.sli_agent_packet_inbox i on i.packet_id=r.packet_id
    join public.sli_agents a on a.id=r.agent_id
    where r.agent_id=p_agent and r.packet_id=p_packet and r.module_id='sli.file-audit'
      and a.status='active' and a.host_id::text=r.envelope->>'source_instance_id' and i.imported_at is null;
    if p_start is null or p_end is null or p_end<p_start or p_end-p_start>interval '2 days' then
        raise exception 'file_audit_rule_window_invalid';
    end if;
    select coalesce(jsonb_agg(q.action order by q.observed_at,q.action_id),'[]'::jsonb) into v_actions
    from (
        select to_jsonb(a)||jsonb_build_object(
            'observed_at',to_char(a.observed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'evidence',(
            select jsonb_agg(to_jsonb(e) order by e.core_evidence_ref)
            from sli_plugin_file_audit.action_evidence e where e.action_id=a.action_id)) as action,
            a.observed_at,a.action_id
        from sli_plugin_file_audit.actions a
        where a.agent_id=p_agent and a.source_instance_id=v_envelope->>'source_instance_id'
          and a.observed_at between p_start and p_end
          and exists(select 1 from sli_plugin_file_audit.action_evidence e
              join sli_plugin_file_audit.observations o on o.evidence_key=e.evidence_key
              where e.action_id=a.action_id and e.role='primary'
                and o.generation=v_envelope->>'generation')
        order by a.observed_at desc,a.action_id limit 4097
    ) q;
    select coalesce(jsonb_agg(q.snapshot),'[]'::jsonb) into v_snapshots
    from (
        select s.snapshot||jsonb_build_object('agent_id',s.agent_id,'source_instance_id',s.source_instance_id) as snapshot
        from sli_plugin_file_audit.access_snapshots s
        where s.agent_id=p_agent and s.source_instance_id=v_envelope->>'source_instance_id'
          and s.observed_at between p_start-interval '1 day' and p_end
        order by s.observed_at desc,s.snapshot_id limit 101
    ) q;
    v_complete := jsonb_array_length(v_actions)<=4096 and jsonb_array_length(v_snapshots)<=100
        and octet_length(v_actions::text)+octet_length(v_snapshots::text)<=16777216
        and v_envelope->>'continuity_state' is distinct from 'gap'
        and not exists(select 1 from public.sli_agent_packet_inbox i
            where i.envelope->>'agent_id'=p_agent::text and i.envelope->>'module_id'='sli.file-audit'
              and i.envelope->>'generation'=v_envelope->>'generation' and i.imported_at is null
              and (i.envelope->>'sequence')::bigint<(v_envelope->>'sequence')::bigint);
    return jsonb_build_object('complete',v_complete,
        'actions',case when v_complete then v_actions else '[]'::jsonb end,
        'snapshots',case when jsonb_array_length(v_snapshots)<=100 and octet_length(v_snapshots::text)<=8388608
                         then v_snapshots else '[]'::jsonb end);
end $$;

create function sli_plugin_file_audit.publish_rules(p_agent uuid,p_packet uuid,p_command text,p_results jsonb)
returns void language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare
    v_source text;
    v_item jsonb;
    v_hash text;
    v_previous text;
    v_finding bigint;
    v_id text;
    v_snapshot uuid;
begin
    if (p_packet is null)=(p_command is null) or jsonb_typeof(p_results) is distinct from 'array'
       or jsonb_array_length(p_results)>102400 or octet_length(p_results::text)>16777216 then
        raise exception 'file_audit_rules_invalid';
    end if;
    if p_packet is not null then
        select r.envelope->>'source_instance_id' into strict v_source
        from public.sli_agent_receipts r join public.sli_agent_packet_inbox i on i.packet_id=r.packet_id
        join public.sli_agents a on a.id=r.agent_id
        where r.agent_id=p_agent and r.packet_id=p_packet and r.module_id='sli.file-audit'
          and a.status='active' and a.host_id::text=r.envelope->>'source_instance_id' and i.imported_at is null;
    else
        select c.source_instance_id into strict v_source
        from sli_plugin_file_audit.audit_commands c join public.sli_agents a on a.id=c.agent_id
        where c.agent_id=p_agent and c.command_id=p_command and a.status='active'
          and a.host_id::text=c.source_instance_id;
    end if;
    for v_item in select jsonb_array_elements(p_results) loop
        if v_item->>'agent_id' is distinct from p_agent::text
           or v_item->>'source_instance_id' is distinct from v_source
           or jsonb_typeof(v_item->'action_ids') is distinct from 'array'
           or jsonb_typeof(v_item->'snapshot_ids') is distinct from 'array'
           or jsonb_array_length(v_item->'action_ids')+jsonb_array_length(v_item->'snapshot_ids')=0
           or (p_command is not null and jsonb_array_length(v_item->'action_ids')<>0)
           or (p_packet is not null and jsonb_array_length(v_item->'action_ids')=0) then
            raise exception 'file_audit_rule_binding_invalid';
        end if;
        for v_id in select jsonb_array_elements_text(v_item->'action_ids') loop
            if not exists(select 1 from sli_plugin_file_audit.actions a
                where a.action_id=v_id and a.agent_id=p_agent and a.source_instance_id=v_source
                  and a.collection_scope_id=v_item->>'collection_scope_id'
                  and a.subject_sid is not distinct from v_item->>'subject_sid') then
                raise exception 'file_audit_rule_evidence_invalid';
            end if;
        end loop;
        for v_snapshot in select value::uuid from jsonb_array_elements_text(v_item->'snapshot_ids') loop
            if not exists(select 1 from sli_plugin_file_audit.access_snapshots s
                where s.snapshot_id=v_snapshot and s.agent_id=p_agent and s.source_instance_id=v_source
                  and s.collection_scope_id=v_item->>'collection_scope_id'
                  and (p_command is null or exists(
                      select 1 from sli_plugin_file_audit.audit_commands c
                      where c.agent_id=p_agent and c.command_id=p_command
                        and s.snapshot->>'policy_revision'=c.policy_revision::text
                        and s.collection_scope_id=any(c.collection_scope_ids)))) then
                raise exception 'file_audit_rule_evidence_invalid';
            end if;
        end loop;
        v_hash := encode(sha256(convert_to(v_item::text,'UTF8')),'hex');
        select result_sha256 into v_previous from sli_plugin_file_audit.rule_results
            where result_id=v_item->>'result_id';
        if found then
            if v_previous<>v_hash then raise exception 'file_audit_rule_replay_conflict'; end if;
            continue;
        end if;
        insert into public.findings(fingerprint,rule_code,title,severity,confidence,status,first_seen_utc,
            last_seen_utc,actor,source,summary,why_it_matters,recommended_action,evidence_count,status_reason)
        values('file-audit:'||(v_item->>'result_id'),v_item->>'rule_code',v_item->>'rule_code','medium',
            case when v_item->>'conclusion_state'='observed' then 0.9 else 0.4 end,'new',
            v_item->>'observed_at',v_item->>'observed_at',v_item->>'subject_sid',v_source,
            v_item->>'conclusion_state','Review the retained file-audit evidence.',
            'Validate activity, granted permissions and observation coverage.',
            jsonb_array_length(v_item->'action_ids')+jsonb_array_length(v_item->'snapshot_ids'),
            'file-audit rule evaluation') on conflict(fingerprint) do nothing;
        select id into strict v_finding from public.findings
            where fingerprint='file-audit:'||(v_item->>'result_id') and rule_code=v_item->>'rule_code';
        insert into sli_plugin_file_audit.rule_results
            (result_id,finding_id,agent_id,source_instance_id,collection_scope_id,rule_code,rule_version,
             conclusion_state,observed_at,result,result_sha256)
        values(v_item->>'result_id',v_finding,p_agent,v_source,v_item->>'collection_scope_id',v_item->>'rule_code',
            (v_item->>'rule_version')::integer,v_item->>'conclusion_state',(v_item->>'observed_at')::timestamptz,
            v_item,v_hash) on conflict(result_id) do nothing;
        select result_sha256 into strict v_previous from sli_plugin_file_audit.rule_results
            where result_id=v_item->>'result_id';
        if v_previous<>v_hash then raise exception 'file_audit_rule_replay_conflict'; end if;
        insert into sli_plugin_file_audit.rule_actions(result_id,action_id)
            select v_item->>'result_id',jsonb_array_elements_text(v_item->'action_ids') on conflict do nothing;
        insert into sli_plugin_file_audit.rule_snapshots(result_id,snapshot_id)
            select v_item->>'result_id',value::uuid from jsonb_array_elements_text(v_item->'snapshot_ids') on conflict do nothing;
    end loop;
end $$;
revoke all on function sli_plugin_file_audit.rule_context(uuid,uuid,timestamptz,timestamptz) from public;
revoke all on function sli_plugin_file_audit.publish_rules(uuid,uuid,text,jsonb) from public;
grant execute on function sli_plugin_file_audit.rule_context(uuid,uuid,timestamptz,timestamptz) to adlog_user;
grant execute on function sli_plugin_file_audit.publish_rules(uuid,uuid,text,jsonb) to adlog_user;
reset role;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(187,'file_audit_rules');
commit;
