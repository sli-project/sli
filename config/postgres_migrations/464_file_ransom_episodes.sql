begin;
select pg_advisory_xact_lock(hashtext('sli_file_ransom_episodes464'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=463 and name='semantic_outbox_lanes')
       or exists(select 1 from public.schema_migrations where version>=464)
       or not pg_has_role(session_user,'adlog_file_audit_owner','MEMBER') then
        raise exception 'file_ransom_episodes464_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Preserve earlier evidence and publications. The previous generation-wide
-- gap logic could extend these rows across arbitrarily long quiet periods.
alter table public.semantic_file_ransom_episodes add column sealed boolean not null default false;
update public.semantic_file_ransom_episodes set sealed=true where incomplete;

create function public.file_ransom_window_has_gap464(s jsonb,p_agent uuid,p_start timestamptz,p_end timestamptz)
returns boolean language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    with bounds as (
        select min(o.record_id) as first_record,max(o.record_id) as last_record
        from sli_plugin_file_audit.observations o
        where public.file_ransom_scope_allowed(s,p_agent)
          and o.agent_id=p_agent and o.source_instance_id=s->>'source_instance_id'
          and o.generation=s->>'source_generation' and o.observed_at between p_start and p_end
    )
    select exists (
        select 1 from bounds b
        join public.sli_agent_receipts r on r.agent_id=p_agent and r.module_id='sli.file-audit'
            and md5(r.envelope->>'generation')=md5(s->>'source_generation')
        join public.sli_agent_packet_inbox i using(packet_id)
        cross join lateral (select
            (i.packet#>>'{header,cursor,after_record_id}')::bigint as before_record,
            (i.packet#>>'{header,cursor,last_record_id}')::bigint as after_record) cursor_range
        where r.envelope->>'source_instance_id'=s->>'source_instance_id'
          and r.envelope->>'generation'=s->>'source_generation'
          and r.envelope->>'continuity_state'='gap'
          and r.receipt->>'status'='committed' and i.envelope=r.envelope and i.imported_at is not null
          and (
              -- The lost records can be anywhere in this packet's native range.
              coalesce((i.packet#>>'{context,lost_count}')::bigint,0)>0
                  and cursor_range.after_record>b.first_record
                  and coalesce(cursor_range.before_record,0)<b.last_record
              or i.packet#>>'{context,read_error}'='file_audit_journal_gap'
                  and exists(select 1 from jsonb_array_elements(i.event_rows) e
                      where e->>'event_id'='1102'
                        and (e->>'record_id')::bigint between b.first_record and b.last_record)
              -- A resume gap is before the packet. A gap preceding the
              -- first observation of a burst leaves its coverage intact.
              or r.receipt->>'transport_gap'='true'
                  and cursor_range.before_record>=b.first_record
                  and cursor_range.before_record<b.last_record
          )
    )
$$;
revoke all on function public.file_ransom_window_has_gap464(jsonb,uuid,timestamptz,timestamptz) from public;
grant execute on function public.file_ransom_window_has_gap464(jsonb,uuid,timestamptz,timestamptz) to adlog_semantic_worker;

do $patch$
declare
    definition text;
    old_select constant text := 'select rr.result,refs.items,coalesce(continuous,false)';
    new_select constant text := $sql$select rr.result,refs.items,not public.file_ransom_window_has_gap464(s,p_agent,
        (rr.result#>>'{details,window_start}')::timestamptz,(rr.result#>>'{details,window_end}')::timestamptz)$sql$;
begin
    definition := pg_get_functiondef('public.read_file_ransom_results(jsonb,uuid,text,text,integer,integer)'::regprocedure);
    if strpos(definition,'    -- Conservative generation-wide continuity:')=0 or strpos(definition,old_select)=0 then
        raise exception 'file_ransom_episodes464_reader_shape' using errcode='55000';
    end if;
    definition := overlay(definition placing '' from strpos(definition,'    -- Conservative generation-wide continuity:')
        for strpos(definition,'    return query')-strpos(definition,'    -- Conservative generation-wide continuity:'));
    execute replace(replace(definition,'declare continuous boolean;',''),old_select,new_select);

    definition := pg_get_functiondef('public.file_ransom_evidence_in_root(uuid,text,text,text)'::regprocedure);
    if strpos(definition,$sql$a.operation in ('write','delete')$sql$)=0 then
        raise exception 'file_ransom_episodes464_evidence_shape' using errcode='55000';
    end if;
    execute replace(definition,$sql$a.operation in ('write','delete')$sql$,$sql$a.operation in ('write','rename','delete')$sql$);
end $patch$;

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
begin
    definition := pg_get_functiondef('sli_plugin_file_audit.rule_context(uuid,uuid,timestamptz,timestamptz)'::regprocedure);
    if strpos(definition,bare_gap)=0 or strpos(definition,action_json)=0 then
        raise exception 'file_ransom_episodes464_rule_context_shape' using errcode='55000';
    end if;
    -- Keep the bounded context available. The result reader checks whether
    -- confirmed missing records intersect the qualifying time window.
    execute replace(replace(definition,bare_gap,''),action_json,action_json||source_path);

    definition := pg_get_functiondef('sli_plugin_file_audit.collection_context_for_packet(uuid,uuid,timestamptz,timestamptz,jsonb)'::regprocedure);
    if strpos(definition,same_handle)=0 or strpos(definition,cursor_gap)=0 then
        raise exception 'file_ransom_episodes464_collection_context_shape' using errcode='55000';
    end if;
    execute replace(replace(definition,same_handle,rename_context),cursor_gap,actual_gap);
end $patch$;

reset role;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(464,'file_ransom_episodes');
commit;
