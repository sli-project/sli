begin;
select pg_advisory_xact_lock(hashtext('sli_password_pass_recovery393'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=392 and name='ad_snapshot_schedule')
       or exists(select 1 from public.schema_migrations where version>=393) then
        raise exception 'password_pass_recovery393_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;

create table public.password_restore393(
    signature regprocedure primary key, definition text not null, owner_oid oid not null, acl aclitem[],
    installed_definition text);
revoke all on public.password_restore393 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_restore393(signature,definition,owner_oid,acl)
select oid,pg_get_functiondef(oid),proowner,proacl from pg_proc where oid=any(array[
    'public.password_plan388(jsonb,text)'::regprocedure,
    'public.password_event_clock362(jsonb,jsonb)'::regprocedure,
    'public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure,
    'public.password_catchup_status388()'::regprocedure,
    'public.password_is_catchup388(jsonb)'::regprocedure,
    'public.read_password_detection_coverage(bigint[])'::regprocedure]);

-- The 388 fork rows and proof chains stay immutable. One routing row selects
-- the execution that writes live decisions and, while needed, a history cursor.
create table public.password_pass_state393(
    scope_digest bytea not null,
    rule_id text not null check(rule_id in ('qw.password-brute-force','qw.password-spray')),
    definition_revision integer not null check(definition_revision>=2),
    live_pin text not null,
    history_pin text,
    history_from timestamptz,
    history_to timestamptz,
    primary key(scope_digest,rule_id),
    foreign key(scope_digest,live_pin) references public.semantic_password_checkpoints(scope_digest,pin),
    foreign key(scope_digest,history_pin) references public.semantic_password_checkpoints(scope_digest,pin),
    check(history_pin is distinct from live_pin),
    check((history_pin is null and history_from is null and history_to is null)
       or (history_pin is not null and history_from is not null and history_to is not null and history_from<=history_to)));
revoke all on public.password_pass_state393 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

-- Upgrades keep the latest live checkpoint and recover the unprocessed range
-- from the earliest unfinished predecessor through the latest live seam.
with latest as (
    select distinct on (p.scope_digest,p.live_execution->>'rule_id')
        p.scope_digest,p.live_execution->>'rule_id' as rule_id,p.live_pin,p.live_from
    from public.password_passes388 p
    order by p.scope_digest,p.live_execution->>'rule_id',(p.live_execution->>'rule_version')::integer desc
)
insert into public.password_pass_state393
select l.scope_digest,l.rule_id,2,l.live_pin,h.previous_pin,h.history_from,
    case when h.previous_pin is not null then l.live_from end
from latest l left join lateral (
    select p.previous_pin,p.history_from from public.password_passes388 p
    join public.semantic_password_checkpoints c on c.scope_digest=p.scope_digest and c.pin=p.previous_pin
    where p.scope_digest=l.scope_digest and p.live_execution->>'rule_id'=l.rule_id
      and (c.watermark is null or c.watermark<p.live_from)
    order by (p.live_execution->>'rule_version')::integer limit 1
) h on true;

-- A future rule migration advances this definition revision with its codec.
-- The execution revision may be higher because 388 minted pins on restarts.
create function public.password_definition_revision393(r text) returns integer
language sql immutable set search_path=pg_catalog,pg_temp as $$ select 2 $$;
revoke all on function public.password_definition_revision393(text) from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

create table public.password_policy_retired393(
    policy_id text not null, policy_version integer not null, previous_status text not null,
    retirement_audit_id bigint not null, primary key(policy_id,policy_version));
revoke all on public.password_policy_retired393 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

-- Call under the same family/policy/source locks as the planner. Keep queued
-- work claimable and leave administrator decisions and custom policies intact.
create function public.password_retire_policies393(s jsonb,r text,live_pin text,history_pin text) returns void
language plpgsql volatile set search_path=pg_catalog,pg_temp as $$
declare p record; retirement_id bigint;
begin
    for p in
        select policy.policy_id,policy.policy_version,policy.lifecycle_status
        from public.semantic_risk_policies policy
        join public.semantic_policy_admission a using(policy_id,policy_version)
        cross join lateral (select policy.definition_json#>'{source_selector,execution}' as execution) x
        cross join lateral (select encode(sha256(convert_to(public.password_v2_json_compact(x.execution),'UTF8')),'hex') as pin) identity
        cross join lateral (
            select audit.details from public.semantic_control_audit audit
            where audit.action='password_policy_managed' and audit.target=policy.policy_id||':'||policy.policy_version
            order by audit.occurred_at desc,audit.id desc limit 1
        ) managed
        where policy.source_kind='qw_signal' and policy.policy_version=1 and a.enabled
          and x.execution->'scope'=s and x.execution->>'rule_id'=r
          and identity.pin<>live_pin and identity.pin is distinct from history_pin
          and policy.policy_id='default:'||r||':'||substr(identity.pin,1,32)
          and policy.lifecycle_status in ('enabled','shadow')
          and policy.definition_json=public.password_policy_definition_v275(x.execution)
          and policy.definition_sha256=sha256(convert_to(public.password_policy_json_v275(policy.definition_json),'UTF8'))
          and managed.details->>'kind'='seed'
          and managed.details->>'status'=policy.lifecycle_status
          and managed.details->>'definition_sha256'=encode(policy.definition_sha256,'hex')
          and managed.details->'execution'=x.execution
          and managed.details->>'admission_audit_id'=(
              select audit.id::text from public.semantic_control_audit audit
              where audit.action='policy_admission' and audit.target=policy.policy_id||':'||policy.policy_version
              order by audit.occurred_at desc,audit.id desc limit 1)
          and managed.details->>'lifecycle_audit_id' is not distinct from (
              select audit.id::text from public.semantic_control_audit audit
              where audit.action='password_policy_lifecycle' and audit.target=policy.policy_id||':'||policy.policy_version
              order by audit.occurred_at desc,audit.id desc limit 1)
          and not exists(select 1 from public.semantic_risk_evaluation_jobs j
              where j.policy_id=policy.policy_id and j.policy_version=policy.policy_version
                and j.evaluation_status in ('queued','leased','failed'))
        order by policy.policy_id
    loop
        update public.semantic_risk_policies set lifecycle_status='deprecated',updated_at=now()
            where policy_id=p.policy_id and policy_version=p.policy_version;
        perform public.password_policy_provenance_v275(p.policy_id,p.policy_version,'retirement');
        select id into strict retirement_id from public.semantic_control_audit
            where action='password_policy_lifecycle' and target=p.policy_id||':'||p.policy_version
            order by occurred_at desc,id desc limit 1;
        insert into public.password_policy_retired393
            values(p.policy_id,p.policy_version,p.lifecycle_status,retirement_id);
    end loop;
end $$;
revoke all on function public.password_retire_policies393(jsonb,text,text,text) from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

create or replace function public.password_plan388(s jsonb,r text) returns jsonb
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare route public.password_pass_state393; c public.semantic_password_checkpoints; x jsonb;
    scope_key bytea; revision integer; first_at timestamptz; seam timestamptz;
    history jsonb; live jsonb; next_pin text;
begin
    perform public.password_policy_family_lock_v275(s,r);
    perform 1 from public.semantic_risk_policies p where p.source_kind='qw_signal'
        and p.definition_json#>'{source_selector,execution,scope}'=s
        and p.definition_json#>>'{source_selector,execution,rule_id}'=r order by p.policy_id,p.policy_version for update;
    scope_key:=public.password_v2_scope_key(s);
    perform pg_advisory_xact_lock(hashtextextended(encode(scope_key,'hex'),0));
    if public.password_source_ready_v314(s) is not true then return null; end if;
    revision:=public.password_definition_revision393(r);
    select * into route from public.password_pass_state393 p where p.scope_digest=scope_key and p.rule_id=r;
    if route.live_pin is null then
        x:=public.password_v2_coverage_execution(s,r);
        c:=public.password_v2_locked_checkpoint(s,x,false);
        if c.pin is null then
            -- The first activation may start live alongside an existing backlog.
            select min(h.time_created_utc) into first_at from public.event_hot h
            where h.source_sha256 is not null and h.method->>'$channel'='Security'
              and h.method#>>'{$origin,source_instance_id}'=s->>'source_instance_id'
              and (h.method->'$origin')-'agent_id'-'log_source_id'=s and h.event_kind in(4624,4625,4771,4776);
            c:=public.password_v2_locked_checkpoint(s,x,true);
        end if;
        insert into public.password_pass_state393(scope_digest,rule_id,definition_revision,live_pin)
            values(scope_key,r,2,c.pin) returning * into route;
    end if;

    if route.history_pin is not null then
        select * into strict c from public.semantic_password_checkpoints
            where scope_digest=scope_key and pin=route.history_pin;
        if c.watermark>=route.history_to then
            update public.password_pass_state393 set history_pin=null,history_from=null,history_to=null
                where scope_digest=scope_key and rule_id=r returning * into route;
        end if;
    end if;

    select execution_json into strict live from public.semantic_password_checkpoints
        where scope_digest=scope_key and pin=route.live_pin;
    if route.history_pin is null and (revision>route.definition_revision or first_at<statement_timestamp()-interval '720 seconds') then
        c:=public.password_v2_locked_checkpoint(s,live,true);
        seam:=greatest(c.watermark,statement_timestamp()-interval '600 seconds');
        x:=public.password_execution388(s,r,greatest(revision,(live->>'rule_version')::integer+1));
        next_pin:=encode(sha256(convert_to(public.password_v2_json_compact(x),'UTF8')),'hex');
        insert into public.password_passes388(scope_digest,previous_pin,live_pin,live_execution,previous_watermark,history_from,live_from)
            values(scope_key,c.pin,next_pin,x,c.watermark,coalesce(c.watermark,first_at,seam),seam);
        perform public.password_v2_locked_checkpoint(s,x,true);
        update public.password_pass_state393 set definition_revision=revision,live_pin=next_pin,
            history_pin=c.pin,history_from=coalesce(c.watermark,first_at,seam),history_to=seam
            where scope_digest=scope_key and rule_id=r returning * into route;
        insert into public.semantic_control_audit(actor,action,target,details)
            values('system:password-producer','password_live_first',next_pin,jsonb_build_object(
                'db_actor',session_user,'scope',s,'rule',r,'previous_pin',c.pin,'live_pin',next_pin,
                'previous_watermark',public.password_v2_iso(c.watermark),'history_from',public.password_v2_iso(route.history_from),
                'live_from',public.password_v2_iso(seam),'at',public.password_v2_iso(clock_timestamp())));
        live:=x;
    end if;
    select jsonb_build_array(execution_json) into history from public.semantic_password_checkpoints
        where scope_digest=scope_key and pin=route.history_pin;
    perform public.password_retire_policies393(s,r,route.live_pin,route.history_pin);
    return jsonb_build_object('live',live,'catchup',coalesce(history,'[]'::jsonb));
end $$;

-- Reader and completion validate the same cutoff for the batch transaction.
-- Recovery has one finite target per rule, including when the seam has no event.
do $$ declare body text; patched text; begin
    select definition into strict body from public.password_restore393 where signature='public.password_event_clock362(jsonb,jsonb)'::regprocedure;
    patched:=replace(body,'left join public.password_passes388 p on p.scope_digest=decode(identity->>''scope_digest'',''hex'') and p.previous_pin=identity->>''pin''',
        'left join public.password_pass_state393 p on p.scope_digest=decode(identity->>''scope_digest'',''hex'') and p.history_pin=identity->>''pin''');
    patched:=replace(patched,'decision_members integer:=6000;',
        'history_end timestamptz; decision_members integer:=6000;');
    patched:=replace(patched,'select least(final_target,p.live_from) into final_target',
        'select p.history_to into history_end');
    patched:=replace(patched,'    if cutoff>=final_target',
        E'    final_target:=least(final_target,history_end);\n    if cutoff>=final_target');
    patched:=replace(patched,'if cutoff is not null or exists(select 1 from public.event_hot h',
        'if history_end is not null or cutoff is not null or exists(select 1 from public.event_hot h');
    patched:=replace(patched,'statement_timestamp()','transaction_timestamp()');
    if patched=body or strpos(patched,'select p.history_to into history_end')=0
        or strpos(patched,'p.history_pin=identity')=0 or strpos(patched,'if history_end is not null')=0 then
        raise exception 'password_pass_recovery393_clock_shape' using errcode='55000'; end if;
    execute patched;
end $$;

-- A newly committed import can still change the selected range under read
-- committed. Reject the same window as before, but let the worker reread it.
do $$ declare body text; patched text; begin
    select definition into strict body from public.password_restore393
        where signature='public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure;
    patched:=replace(body,$old$if (t<c.last_attempt_at and t is distinct from public.password_event_clock362(s,execution)) or t>stamp$old$,
        $new$if t<c.last_attempt_at
           and t is distinct from public.password_event_clock362(s,execution) then
            raise exception 'password_v2_window_changed393' using errcode='40001'; end if;
        if t>stamp$new$);
    if patched=body then raise exception 'password_pass_recovery393_completion_shape' using errcode='55000'; end if;
    execute patched;
end $$;

create or replace function public.password_catchup_status388() returns jsonb
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select case when count(*)=0 then null else jsonb_build_object(
        'from',public.password_v2_iso(min(p.history_from)),'to',public.password_v2_iso(max(p.history_to)),
        'cursor',public.password_v2_iso(min(coalesce(c.watermark,p.history_from))),
        'heartbeat',public.password_v2_iso(max(c.last_completed_at))) end
    from public.password_pass_state393 p join public.semantic_password_checkpoints c
        on c.scope_digest=p.scope_digest and c.pin=p.history_pin
    where c.watermark is null or c.watermark<p.history_to
$$;

create or replace function public.password_is_catchup388(x jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists(select 1 from public.password_pass_state393 p
        where p.scope_digest=public.password_v2_scope_key(x->'scope') and p.rule_id=x->>'rule_id'
          and p.live_pin<>encode(sha256(convert_to(public.password_v2_json_compact(x),'UTF8')),'hex'))
$$;

create function public.password_live_execution393(s jsonb,r text) returns jsonb
language sql stable set search_path=pg_catalog,pg_temp as $$
    select coalesce((select c.execution_json from public.password_pass_state393 p
        join public.semantic_password_checkpoints c using(scope_digest)
        where p.scope_digest=public.password_v2_scope_key(s) and p.rule_id=r and c.pin=p.live_pin),
        public.password_v2_coverage_execution(s,r))
$$;
revoke all on function public.password_live_execution393(jsonb,text) from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

do $$ declare body text; begin
    select definition into strict body from public.password_restore393 where signature='public.read_password_detection_coverage(bigint[])'::regprocedure;
    if strpos(body,'public.password_v2_coverage_execution(ctx.identity')=0 then
        raise exception 'password_pass_recovery393_coverage_shape' using errcode='55000'; end if;
    execute replace(body,'public.password_v2_coverage_execution(ctx.identity','public.password_live_execution393(ctx.identity');
    if exists(select 1 from public.password_restore393 d join pg_proc p on p.oid=d.signature
        where p.proowner is distinct from d.owner_oid or p.proacl is distinct from d.acl) then
        raise exception 'password_pass_recovery393_metadata_changed' using errcode='55000'; end if;
end $$;

update public.password_restore393 set installed_definition=pg_get_functiondef(signature);
insert into public.schema_migrations(version,name) values(393,'password_pass_recovery');
reset role;
commit;
