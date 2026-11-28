begin;
select pg_advisory_xact_lock(hashtext('sli_file_ransom_episodes464'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_file_audit_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=464 and name='file_ransom_episodes')
       or exists(select 1 from public.schema_migrations where version>464) then
        raise exception 'file_ransom_episodes464_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

do $patch$
declare
    definition text;
    old_select constant text := 'select rr.result,refs.items,coalesce(continuous,false)';
    new_select constant text := $sql$select rr.result,refs.items,not public.file_ransom_window_has_gap464(s,p_agent,
        (rr.result#>>'{details,window_start}')::timestamptz,(rr.result#>>'{details,window_end}')::timestamptz)$sql$;
    continuity constant text := $sql$    -- Conservative generation-wide continuity: any unknown/gap or pending
    -- receipt keeps episodes incomplete and prevents an invented quiet period.
    select coalesce(bool_and(coalesce(r.envelope->>'continuity_state'='complete'
               and r.receipt->>'status'='committed' and i.imported_at is not null
               and i.envelope=r.envelope,false)),false)
           and min((r.envelope->>'sequence')::bigint)=1
           and count(*)=max((r.envelope->>'sequence')::bigint)-min((r.envelope->>'sequence')::bigint)+1
    into continuous
    from public.sli_agent_receipts r join public.sli_agent_packet_inbox i using(packet_id)
    where r.agent_id=p_agent and r.module_id='sli.file-audit'
      and r.envelope->>'source_instance_id'=s->>'source_instance_id'
      and r.envelope->>'generation'=s->>'source_generation';
$sql$;
begin
    definition := pg_get_functiondef('public.read_file_ransom_results(jsonb,uuid,text,text,integer,integer)'::regprocedure);
    if strpos(definition,new_select)=0 or strpos(definition,'    return query')=0 then
        raise exception 'file_ransom_episodes464_rollback_reader_shape' using errcode='55000';
    end if;
    definition := replace(definition,E'\n\nbegin',E'\ndeclare continuous boolean;\nbegin');
    if strpos(definition,'declare continuous boolean;')=0 then
        raise exception 'file_ransom_episodes464_rollback_continuity_shape' using errcode='55000';
    end if;
    execute replace(replace(definition,new_select,old_select),'    return query',continuity||'    return query');

    definition := pg_get_functiondef('public.file_ransom_evidence_in_root(uuid,text,text,text)'::regprocedure);
    if strpos(definition,$sql$a.operation in ('write','rename','delete')$sql$)=0 then
        raise exception 'file_ransom_episodes464_rollback_evidence_shape' using errcode='55000';
    end if;
    execute replace(definition,$sql$a.operation in ('write','rename','delete')$sql$,$sql$a.operation in ('write','delete')$sql$);
end $patch$;

drop function public.file_ransom_window_has_gap464(jsonb,uuid,timestamptz,timestamptz);
alter table public.semantic_file_ransom_episodes drop column sealed;

reset role;
set local role adlog_file_audit_owner;

do $patch$
declare
    definition text;
    bare_gap constant text := $sql$        and v_envelope->>'continuity_state' is distinct from 'gap'
$sql$;
    action_json constant text := $sql$            'observed_at',to_char(a.observed_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),$sql$;
    source_path constant text := $sql$
            'old_path',case when a.operation='rename' then (
                select o.normalized->>'path'
                from sli_plugin_file_audit.action_evidence e
                join sli_plugin_file_audit.observations o using(evidence_key)
                where e.action_id=a.action_id and e.role='handle_context' and o.event_id=4663
                order by o.record_id desc limit 1
            ) end,$sql$;
    same_handle constant text := $sql$and o.normalized->'facts'->'handle_id'=k->'facts'->'handle_id'))$sql$;
    rename_context constant text := $sql$and (o.normalized->'facts'->'handle_id'=k->'facts'->'handle_id'
                           or (k->>'event_id')::integer in (4656,4663)
                              and k->>'path' is not null
                              and o.observed_at between (k->>'observed_at')::timestamptz-interval '100 milliseconds'
                                  and (k->>'observed_at')::timestamptz
                              and o.record_id<(k->>'record_id')::bigint
                              and (o.event_id in (4658,4660)
                                   or o.event_id in (4656,4663) and (
                                       lower(o.normalized->>'path')=lower(k->>'path')
                                       or starts_with(lower(k->>'path'),lower(o.normalized->>'path')||'.'))))))$sql$;
    cursor_gap constant text := $sql$and (nullif(r.envelope->'cursor_after'->>'token','')::jsonb->>'record_id')::bigint>=v_first_record$sql$;
    actual_gap constant text := $sql$and (
              coalesce((r.envelope->>'lost_count')::bigint,0)>0
                  and (nullif(r.envelope->'cursor_after'->>'token','')::jsonb->>'record_id')::bigint>v_first_record
              or (r.envelope->>'lost_count')::bigint=0
                  and (nullif(r.envelope->'cursor_before'->>'token','')::jsonb->>'record_id')::bigint>=v_first_record
          )$sql$;
    context_bound constant text := $sql$        and octet_length(v_actions::text)+octet_length(v_snapshots::text)<=16777216
$sql$;
begin
    definition := pg_get_functiondef('sli_plugin_file_audit.rule_context(uuid,uuid,timestamptz,timestamptz)'::regprocedure);
    if strpos(definition,source_path)=0 or strpos(definition,context_bound)=0 then
        raise exception 'file_ransom_episodes464_rollback_rule_context_shape' using errcode='55000';
    end if;
    execute replace(replace(definition,action_json||source_path,action_json),context_bound,context_bound||bare_gap);

    definition := pg_get_functiondef('sli_plugin_file_audit.collection_context_for_packet(uuid,uuid,timestamptz,timestamptz,jsonb)'::regprocedure);
    if strpos(definition,rename_context)=0 or strpos(definition,actual_gap)=0 then
        raise exception 'file_ransom_episodes464_rollback_collection_context_shape' using errcode='55000';
    end if;
    execute replace(replace(definition,rename_context,same_handle),actual_gap,cursor_gap);
end $patch$;

reset role;
delete from public.schema_migrations where version=464 and name='file_ransom_episodes';
commit;
