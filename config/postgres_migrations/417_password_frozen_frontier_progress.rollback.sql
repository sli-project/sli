begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_checkpoint_proof403'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=417 and name='password_frozen_frontier_progress')
       or exists(select 1 from public.schema_migrations where version>417) then
        raise exception 'password_frozen_frontier417_rollback_preflight' using errcode='55000';
    end if;
end $$;

set local role adlog_storage_owner;

-- Restore the former finalizer without rewinding checkpoints or changing evidence.
do $patch$
declare
    finalizer constant regprocedure :=
        'public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure;
    previous_fragment constant text := $from$    if mode='advance' then
        for l in select q.* from public.semantic_password_episode_budgets q
            where q.scope_digest=c.scope_digest and q.pin=c.pin and q.barrier_unresolved and q.entity=any(entities)
            order by q.episode_key loop
            -- Keep this barrier unchanged until the valid cutoff catches up.
            if l.tracking_through>f then continue; end if;
            track_endpoint:=l.tracking_endpoint; tracked:=false;$from$;
    next_fragment constant text := $to$    if mode='advance' then
        for l in select q.* from public.semantic_password_episode_budgets q
            where q.scope_digest=c.scope_digest and q.pin=c.pin and q.barrier_unresolved and q.entity=any(entities)
            order by q.episode_key loop
            track_endpoint:=l.tracking_endpoint; tracked:=false;$to$;
    definition text;
    previous_owner oid;
    previous_acl aclitem[];
    fragment_start integer;
begin
    select pg_get_functiondef(oid),proowner,proacl into definition,previous_owner,previous_acl
    from pg_proc where oid=finalizer and proowner='adlog_storage_owner'::regrole
        and prosecdef and provolatile='v' and proconfig=array['search_path=pg_catalog, pg_temp'];
    fragment_start:=coalesce(strpos(definition,previous_fragment),0);
    if fragment_start=0
       or strpos(substr(definition,fragment_start+length(previous_fragment)),previous_fragment)>0 then
        raise exception 'password_frozen_frontier417_rollback_shape' using errcode='55000';
    end if;

    definition:=replace(definition,previous_fragment,next_fragment);
    execute definition;
    if pg_get_functiondef(finalizer) is distinct from definition or not exists(
        select 1 from pg_proc where oid=finalizer and proowner=previous_owner and proacl is not distinct from previous_acl
    ) then raise exception 'password_frozen_frontier417_rollback_metadata' using errcode='55000'; end if;
end $patch$;

reset role;
delete from public.schema_migrations where version=417 and name='password_frozen_frontier_progress';
commit;
