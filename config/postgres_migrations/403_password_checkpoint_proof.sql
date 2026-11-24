begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_checkpoint_proof403'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=402 and name='password_locked_episode_proof')
       or exists(select 1 from public.schema_migrations where version>=403) then
        raise exception 'password_checkpoint_proof403_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.password_restore403(
    signature regprocedure primary key,definition text not null,owner_oid oid not null,acl aclitem[],
    installed_definition text);
revoke all on public.password_restore403 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_restore403(signature,definition,owner_oid,acl)
select oid,pg_get_functiondef(oid),proowner,proacl from pg_proc
where oid='public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure
    and proowner='adlog_storage_owner'::regrole and prosecdef and provolatile='v'
    and proconfig=array['search_path=pg_catalog, pg_temp'];

-- Verify two disjoint units in the finalizer's transaction. Long-lived origins,
-- closing admissions and frozen endpoints belong to continuity. An identical
-- witness in the rolling window is charged only once; conflicts fail closed.
create function public.password_checkpoint_native_cost403(s jsonb,st jsonb,source_digest bytea,pin_id text,entities text[])
returns bigint language plpgsql stable set search_path=pg_catalog,pg_temp as $$
declare continuity jsonb; window_only jsonb; conflicted boolean; cost bigint;
begin
    with episodes as materialized (
        select e.value from public.password_state_episodes385(st) e(value)
    ), obligations as (
        select e.value->'seed' as witness,true as is_continuity from episodes e
        union all select e.value->'last',true from episodes e
        union all select w.value,true from episodes e
            cross join lateral jsonb_array_elements(e.value->'prequalification') w(value)
        union all select q.tracking_endpoint,true from public.semantic_password_episode_budgets q
            where q.scope_digest=source_digest and q.pin=pin_id and q.barrier_unresolved and q.entity=any(entities)
        union all select m.value->'witness',false from jsonb_array_elements(st->'window') m(value)
    ), distinct_witnesses as materialized (
        select witness,bool_or(is_continuity) as is_continuity,witness#>>'{ref,native_id}' as id
        from obligations group by witness
    )
    select coalesce(jsonb_agg(witness order by id collate "C") filter (where is_continuity),'[]'::jsonb),
           coalesce(jsonb_agg(witness order by id collate "C") filter (where not is_continuity),'[]'::jsonb),
           count(*)<>count(distinct id)
      into continuity,window_only,conflicted from distinct_witnesses;

    if conflicted then raise exception 'password_v2_native_content_conflict' using errcode='55000'; end if;
    -- The existing verifier validates source access, each original native row
    -- and its declared content, with the same 10,000 references, 32 MiB XML
    -- per unit and 4 MiB per native document. A failed unit aborts the advance.
    cost:=public.password_v2_native_cost(s,continuity);
    if window_only<>'[]'::jsonb then cost:=cost+public.password_v2_native_cost(s,window_only); end if;
    return cost;
end $$;
revoke all on function public.password_checkpoint_native_cost403(jsonb,jsonb,bytea,text,text[])
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

do $patch$
declare saved record;
    old_entry constant text:='    c:=public.password_v2_locked_checkpoint(s,execution,false);';
    new_entry constant text:=$entry$    perform pg_advisory_xact_lock_shared(hashtext('sli_password_checkpoint_proof403'));
    c:=public.password_v2_locked_checkpoint(s,execution,false);$entry$;
    old_proof constant text:=$old$    if mode='advance' then
        select coalesce(jsonb_agg(needed.w order by needed.w#>>'{ref,native_id}'),'[]'::jsonb) into witnesses from (
            select distinct a.value->'witness' as w from jsonb_array_elements(next_st->'window') a(value)
            union select a.value->'seed' from public.password_state_episodes385(next_st) a(value)
            union select a.value->'last' from public.password_state_episodes385(next_st) a(value)
            union select p.value from public.password_state_episodes385(next_st) a(value)
                cross join lateral jsonb_array_elements(a.value->'prequalification') p(value)
            union select q.tracking_endpoint from public.semantic_password_episode_budgets q
                where q.scope_digest=c.scope_digest and q.pin=c.pin and q.barrier_unresolved and q.entity=any(entities)
        ) needed;
        actual:=public.password_v2_native_cost(s,witnesses);
    end if;$old$;
    new_proof constant text:=$new$    if mode='advance' then
        actual:=public.password_checkpoint_native_cost403(s,next_st,c.scope_digest,c.pin,entities);
    end if;$new$;
    found_at integer;
begin
    select * into strict saved from public.password_restore403;
    found_at:=strpos(saved.definition,old_proof);
    if found_at=0 or strpos(substr(saved.definition,found_at+length(old_proof)),old_proof)<>0
        or strpos(saved.definition,old_entry)=0 then
        raise exception 'password_checkpoint_proof403_finalizer_shape' using errcode='55000';
    end if;
    execute replace(replace(saved.definition,old_proof,new_proof),old_entry,new_entry);
    if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
        and p.proacl is not distinct from saved.acl) then
        raise exception 'password_checkpoint_proof403_finalizer_metadata' using errcode='55000';
    end if;
    update public.password_restore403 set installed_definition=pg_get_functiondef(signature);
end $patch$;

reset role;
insert into public.schema_migrations(version,name) values(403,'password_checkpoint_proof');
commit;
