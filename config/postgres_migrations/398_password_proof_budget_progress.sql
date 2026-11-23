begin;
select pg_advisory_xact_lock(hashtext('sli_password_proof_budget_progress398'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=397 and name='problem_queue_workflow')
       or exists(select 1 from public.schema_migrations where version>=398) then
        raise exception 'password_proof_budget_progress398_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;

create table public.password_restore398(
    signature regprocedure primary key,definition text not null,owner_oid oid not null,acl aclitem[],
    installed_definition text);
revoke all on public.password_restore398 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_restore398(signature,definition,owner_oid,acl)
select oid,pg_get_functiondef(oid),proowner,proacl from pg_proc where oid=any(array[
    'public.password_event_clock362(jsonb,jsonb)'::regprocedure,
    'public.read_password_event_window362(jsonb,jsonb)'::regprocedure,
    'public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure]);

-- The worker can request fewer decisions in its current transaction. SQL
-- still derives the complete, source-authorized horizon and watermark itself.
create function public.password_decision_limit398() returns integer
language sql stable set search_path=pg_catalog,pg_temp as $$
    select case when requested~'^[1-9][0-9]{0,3}$' then least(6000,requested::integer) else 6000 end
    from (select current_setting('sli.password_decision_limit',true) as requested) setting
$$;
revoke all on function public.password_decision_limit398() from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

do $$ declare body text; before_patch text; begin
    select definition into strict body from public.password_restore398
        where signature='public.password_event_clock362(jsonb,jsonb)'::regprocedure;
    if strpos(body,'decision_members integer:=6000;')=0 or strpos(body,'e.event_kind in(4625,4771,4776)')=0 then
        raise exception 'password_proof_budget_progress398_clock_shape' using errcode='55000'; end if;
    body:=replace(body,'decision_members integer:=6000;',
        'decision_members integer:=public.password_decision_limit398();');
    execute replace(body,'e.event_kind in(4625,4771,4776)',
        '(e.event_kind in(4625,4771,4776) or (e.event_kind=4624 and (execution->>''rule_version'')::integer>=395))');

    select definition into strict body from public.password_restore398
        where signature='public.read_password_event_window362(jsonb,jsonb)'::regprocedure;
    before_patch:=$old$'oversized_count',oversized,'error_code',failure),null::bigint$old$;
    if strpos(body,before_patch)=0 then
        raise exception 'password_proof_budget_progress398_reader_shape' using errcode='55000'; end if;
    execute replace(body,before_patch,$new$'oversized_count',oversized,'error_code',failure) ||
        case when failure='password_v2_xml_budget_exceeded' then
            jsonb_build_object('xml_bytes_checked',total_bytes,'last_document_bytes',bytes)
        else '{}'::jsonb end,null::bigint$new$);

    select definition into strict body from public.password_restore398
        where signature='public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure;
    before_patch:=$old$if t<c.last_attempt_at
           and t is distinct from public.password_event_clock362(s,execution)$old$;
    if strpos(body,before_patch)=0 then
        raise exception 'password_proof_budget_progress398_finalizer_shape' using errcode='55000'; end if;
    execute replace(body,before_patch,$new$if (t<c.last_attempt_at or public.password_decision_limit398()<6000)
           and t is distinct from public.password_event_clock362(s,execution)$new$);
end $$;

update public.password_restore398 d set installed_definition=pg_get_functiondef(d.signature);
do $$ begin
    if exists(select 1 from public.password_restore398 d join pg_proc p on p.oid=d.signature
        where p.proowner is distinct from d.owner_oid or p.proacl is distinct from d.acl) then
        raise exception 'password_proof_budget_progress398_metadata_changed' using errcode='55000'; end if;
end $$;
insert into public.schema_migrations(version,name) values(398,'password_proof_budget_progress');
reset role;
commit;
