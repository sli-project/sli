begin;
select pg_advisory_xact_lock(hashtext('sli_detection_event_clock362'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=357 and name='short_event_id_indexes')
       or exists(select 1 from public.schema_migrations where version>=362) then
        raise exception 'detection_event_clock362_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.detection_event_clock_definitions362(signature text primary key,definition text not null);
revoke all on public.detection_event_clock_definitions362 from public,adlog_user,adlog_semantic_worker;
insert into public.detection_event_clock_definitions362
select oid::regprocedure::text,pg_get_functiondef(oid) from pg_proc
where oid='public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure;

-- Event time is independent of the import/attempt clock. Advance the existing
-- overlapping rule horizon through the backlog instead of dropping old events.
-- Both the reader and the finalizer derive this clock from the same trusted rows.
create function public.password_event_clock362(s jsonb,execution jsonb) returns timestamptz
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare identity jsonb; cutoff timestamptz; first_at timestamptz; last_at timestamptz;
begin
    perform public.password_v2_source_binding(s);
    identity:=public.password_v2_identity(s,execution);
    select c.watermark into cutoff from public.semantic_password_checkpoints c
    where c.scope_digest=decode(identity->>'scope_digest','hex') and c.pin=identity->>'pin';
    select min(e.time_created_utc) filter(where cutoff is null or e.time_created_utc>cutoff),max(e.time_created_utc)
    into first_at,last_at from public.detection_events337 e
    where e.scope_json=s and e.event_id in(4624,4625,4771,4776) and e.time_created_utc<=statement_timestamp();
    if last_at is null then return null; end if;
    return least(statement_timestamp(),greatest(coalesce(first_at+interval '600 seconds',last_at+interval '120 seconds'),
        cutoff+interval '120 seconds'));
end $$;
revoke all on function public.password_event_clock362(jsonb,jsonb) from public,adlog_user;
grant execute on function public.password_event_clock362(jsonb,jsonb) to adlog_semantic_worker;

-- Preserve the byte budgets, source binding and native reference checks of the
-- installed short reader. Only its time origin and signature change.
do $$ declare definition text; begin
    select pg_get_functiondef('public.read_default_password_window_v2_short337(jsonb)'::regprocedure) into strict definition;
    definition:=replace(definition,'FUNCTION public.read_default_password_window_v2_short337(s jsonb)',
        'FUNCTION public.read_password_event_window362(s jsonb, execution jsonb)');
    if strpos(definition,'t timestamp with time zone := statement_timestamp()')>0 then
        definition:=replace(definition,'t timestamp with time zone := statement_timestamp()',
            't timestamp with time zone := public.password_event_clock362(s,execution)');
    elsif strpos(definition,'t timestamptz:=statement_timestamp()')>0 then
        definition:=replace(definition,'t timestamptz:=statement_timestamp()',
            't timestamptz:=public.password_event_clock362(s,execution)');
    else raise exception 'detection_event_clock362_reader_shape' using errcode='55000'; end if;
    execute definition;
    select d.definition into strict definition from public.detection_event_clock_definitions362 d;
    if strpos(definition,'t<c.last_attempt_at or t>stamp')=0 then
        raise exception 'detection_event_clock362_finalizer_shape' using errcode='55000'; end if;
    execute replace(definition,'t<c.last_attempt_at or t>stamp',
        '(case when public.detections_use_short337() and t<c.last_attempt_at then t is distinct from public.password_event_clock362(s,execution)
          else t<c.last_attempt_at end) or t>stamp');
end $$;
revoke all on function public.read_password_event_window362(jsonb,jsonb) from public,adlog_user;
grant execute on function public.read_password_event_window362(jsonb,jsonb) to adlog_semantic_worker;

-- Empty wall-clock checkpoints have no event decisions to preserve. Keep their
-- revision, ownership, attempt history and health; remove only the false cutoff.
update public.semantic_password_checkpoints c
set watermark=null,state_document=jsonb_set(c.state_document,'{watermark}','null'::jsonb)
where c.scope_json->>'plugin_id'='sli.windows.ad-dc' and c.state_document->'window'='[]'::jsonb
  and c.state_document->'episodes'='[]'::jsonb
  and not exists(select 1 from public.semantic_password_episode_budgets b where b.scope_digest=c.scope_digest and b.pin=c.pin);

insert into public.schema_migrations(version,name) values(362,'detection_event_clock');
reset role;
commit;
