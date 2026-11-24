begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_live_recovery404'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=403 and name='password_checkpoint_proof')
       or exists(select 1 from public.schema_migrations where version>=404) then
        raise exception 'password_live_recovery404_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Snapshot the installed failed live pins. This migration can recover each
-- recorded pin once, without changing the policy for future worker restarts.
create table public.password_recovery_candidates404(
    scope_digest bytea not null,rule_id text not null,previous_pin text not null,
    primary key(scope_digest,rule_id),
    foreign key(scope_digest,previous_pin) references public.semantic_password_checkpoints(scope_digest,pin));
revoke all on public.password_recovery_candidates404 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_recovery_candidates404
select p.scope_digest,p.rule_id,p.live_pin
from public.password_pass_state393 p join public.semantic_password_checkpoints c
    on c.scope_digest=p.scope_digest and c.pin=p.live_pin
where c.health_status='error' and c.health_reason='source_error'
    and c.watermark<statement_timestamp()-interval '720 seconds';

-- A recovery fork is already durable in 388. While a different history
-- interval occupies the scheduler, the immutable fork identifies the second
-- interval exactly. Once promoted, 393 owns it just like any other history.
create function public.password_parked_history404(p_scope bytea,p_rule text)
returns table(scope_digest bytea,rule_id text,pin text,history_from timestamptz,history_to timestamptz,
    watermark timestamptz,last_completed_at timestamptz)
language sql stable set search_path=pg_catalog,pg_temp as $$
    select p.scope_digest,p.rule_id,f.previous_pin,f.history_from,f.live_from,c.watermark,c.last_completed_at
    from public.password_recovery_candidates404 r
    join public.password_pass_state393 p using(scope_digest,rule_id)
    join public.password_passes388 f
      on f.scope_digest=r.scope_digest and f.previous_pin=r.previous_pin and f.live_pin=p.live_pin
    join public.semantic_password_checkpoints c on c.scope_digest=f.scope_digest and c.pin=f.previous_pin
    where (p_scope is null or p.scope_digest=p_scope) and (p_rule is null or p.rule_id=p_rule)
      and p.history_pin is distinct from f.previous_pin and (c.watermark is null or c.watermark<f.live_from)
$$;
revoke all on function public.password_parked_history404(bytea,text)
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

create table public.password_restore404(
    signature regprocedure primary key,definition text not null,owner_oid oid not null,acl aclitem[],
    installed_definition text);
revoke all on public.password_restore404 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_restore404(signature,definition,owner_oid,acl)
select oid,pg_get_functiondef(oid),proowner,proacl from pg_proc where oid=any(array[
    'public.password_plan388(jsonb,text)'::regprocedure,
    'public.password_retire_policies393(jsonb,text,text,text)'::regprocedure,
    'public.password_event_clock362(jsonb,jsonb)'::regprocedure,
    'public.password_catchup_status388()'::regprocedure,
    'public.read_password_live_status400(bigint[])'::regprocedure
]) and proowner='adlog_storage_owner'::regrole;

do $patch$
declare saved record; body text;
begin
    if (select count(*) from public.password_restore404)<>5 then
        raise exception 'password_live_recovery404_function_owner' using errcode='55000';
    end if;
    for saved in select * from public.password_restore404 loop
        body:=saved.definition;
        case saved.signature
        when 'public.password_plan388(jsonb,text)'::regprocedure then
            if strpos(body,'history jsonb; live jsonb; next_pin text;')=0
                or strpos(body,'    perform public.password_policy_family_lock_v275(s,r);')=0
                or strpos(body,'set history_pin=null,history_from=null,history_to=null')=0
                or strpos(body,'    select execution_json into strict live from public.semantic_password_checkpoints')=0
                or strpos(body,'if route.history_pin is null and (revision>route.definition_revision')=0
                or strpos(body,'history_pin=c.pin,history_from=coalesce(c.watermark,least(first_at,seam)),history_to=seam')=0
                or strpos(body,'''history_from'',public.password_v2_iso(route.history_from)')=0 then
                raise exception 'password_live_recovery404_planner_shape' using errcode='55000';
            end if;
            body:=replace(body,'history jsonb; live jsonb; next_pin text;',
                'history jsonb; live jsonb; next_pin text; recover404 boolean; deferred404 boolean;');
            body:=replace(body,'    perform public.password_policy_family_lock_v275(s,r);',$lock$
    perform pg_advisory_xact_lock_shared(hashtext('sli_password_live_recovery404'));
    perform public.password_policy_family_lock_v275(s,r);$lock$);
            body:=replace(body,'set history_pin=null,history_from=null,history_to=null',$promote$set (history_pin,history_from,history_to)=(
                    select parked.pin,parked.history_from,parked.history_to from public.password_parked_history404(scope_key,r) parked
                )$promote$);
            body:=replace(body,$old$    select execution_json into strict live from public.semantic_password_checkpoints
        where scope_digest=scope_key and pin=route.live_pin;
    if route.history_pin is null and (revision>route.definition_revision$old$,$new$    select * into strict c from public.semantic_password_checkpoints
        where scope_digest=scope_key and pin=route.live_pin;
    live:=c.execution_json;
    recover404:=coalesce(c.watermark<statement_timestamp()-interval '720 seconds'
        and c.health_status='error' and c.health_reason='source_error',false) and exists (
        select 1 from public.password_recovery_candidates404 pending
        where pending.scope_digest=scope_key and pending.rule_id=r and pending.previous_pin=c.pin
    );
    if recover404 or route.history_pin is null and (revision>route.definition_revision$new$);
            body:=replace(body,'history_pin=c.pin,history_from=coalesce(c.watermark,least(first_at,seam)),history_to=seam',$defer$
            history_pin=case when deferred404 then route.history_pin else c.pin end,
            history_from=case when deferred404 then route.history_from else coalesce(c.watermark,least(first_at,seam)) end,
            history_to=case when deferred404 then route.history_to else seam end$defer$);
            body:=replace(body,'        seam:=greatest(c.watermark,',$seam$        deferred404:=recover404 and route.history_pin is not null;
        seam:=greatest(c.watermark,$seam$);
            body:=replace(body,'''history_from'',public.password_v2_iso(route.history_from)',$audit$
                'history_from',public.password_v2_iso(coalesce(c.watermark,least(first_at,seam))),
                'recovery',recover404,'history_deferred',deferred404$audit$);
            if strpos(body,'recover404:=coalesce')=0 or strpos(body,'deferred404:=recover404')=0 then
                raise exception 'password_live_recovery404_planner_shape' using errcode='55000';
            end if;
        when 'public.password_retire_policies393(jsonb,text,text,text)'::regprocedure then
            body:=replace(body,'          and identity.pin<>live_pin and identity.pin is distinct from history_pin',$policy$          and identity.pin<>live_pin and identity.pin is distinct from history_pin
          and not exists(select 1 from public.password_parked_history404(public.password_v2_scope_key(s),r) parked
              where parked.pin=identity.pin)$policy$);
        when 'public.password_event_clock362(jsonb,jsonb)'::regprocedure then
            body:=replace(body,'    identity:=public.password_v2_identity(s,execution);',$clock$    identity:=public.password_v2_identity(s,execution);
    if exists(select 1 from public.password_parked_history404(decode(identity->>'scope_digest','hex'),execution->>'rule_id') parked
        where parked.pin=identity->>'pin') then return null; end if;$clock$);
        when 'public.password_catchup_status388()'::regprocedure then
            body:=replace(body,'coalesce(c.watermark,p.history_from)','coalesce(p.watermark,p.history_from)');
            body:=replace(body,'max(c.last_completed_at)','max(p.last_completed_at)');
            body:=replace(body,$old$    from public.password_pass_state393 p join public.semantic_password_checkpoints c
        on c.scope_digest=p.scope_digest and c.pin=p.history_pin
    where c.watermark is null or c.watermark<p.history_to$old$,$new$    from (
        select p.history_from,p.history_to,c.watermark,c.last_completed_at
        from public.password_pass_state393 p join public.semantic_password_checkpoints c
            on c.scope_digest=p.scope_digest and c.pin=p.history_pin
        where c.watermark is null or c.watermark<p.history_to
        union all
        select d.history_from,d.history_to,d.watermark,d.last_completed_at from public.password_parked_history404(null,null) d
    ) p$new$);
        when 'public.read_password_live_status400(bigint[])'::regprocedure then
            body:=replace(body,$old$p.history_pin is not null and (h.watermark is null or h.watermark<p.history_to) as history_pending,$old$,$new$
            (p.history_pin is not null and (h.watermark is null or h.watermark<p.history_to)
                or p.scope_digest is not null and exists(select 1 from public.password_parked_history404(p.scope_digest,p.rule_id))) as history_pending,$new$);
        end case;
        if body=saved.definition then
            raise exception 'password_live_recovery404_function_shape:%',saved.signature using errcode='55000';
        end if;
        execute body;
        if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
            and p.proacl is not distinct from saved.acl) then
            raise exception 'password_live_recovery404_metadata' using errcode='55000';
        end if;
    end loop;
    update public.password_restore404 set installed_definition=pg_get_functiondef(signature);
end $patch$;

reset role;
insert into public.schema_migrations(version,name) values(404,'password_live_recovery');
commit;
