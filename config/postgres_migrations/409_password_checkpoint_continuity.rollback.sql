begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_checkpoint_proof403'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=409 and name='password_checkpoint_continuity')
       or exists(select 1 from public.schema_migrations where version>409) then
        raise exception 'password_checkpoint_continuity409_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- Also fence direct tracking calls that can replace unresolved endpoints.
lock table public.semantic_password_checkpoints,public.semantic_password_episode_budgets in share mode nowait;

do $$ declare saved record; begin
    select * into strict saved from public.password_continuity_restore409;
    if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
        and p.proacl is not distinct from saved.acl and pg_get_functiondef(p.oid)=saved.installed_definition) then
        raise exception 'password_checkpoint_continuity409_rollback_metadata' using errcode='55000';
    end if;
    -- Include every saved pin, including parked catch-up, and every unresolved
    -- endpoint that the old finalizer could still need.
    if exists (
        select 1 from public.semantic_password_checkpoints c
        where exists (
            with episodes as materialized (select e.value from public.password_state_episodes385(c.state_document) e(value))
            select 1 from (
                select e.value->'seed' as witness from episodes e
                union select e.value->'last' from episodes e
                union select w.value from episodes e cross join lateral jsonb_array_elements(e.value->'prequalification') w(value)
                union select q.tracking_endpoint from public.semantic_password_episode_budgets q
                    where q.scope_digest=c.scope_digest and q.pin=c.pin and q.barrier_unresolved
            ) continuity
            having count(*)>10000 or sum((witness->>'xml_bytes')::bigint)>33554432
        )
    ) then raise exception 'password_checkpoint_continuity409_rollback_pending_state' using errcode='55000'; end if;
    execute saved.definition;
end $$;

drop function public.password_continuity_native_cost409(jsonb,jsonb);
drop table public.password_continuity_restore409;
reset role;
delete from public.schema_migrations where version=409 and name='password_checkpoint_continuity';
commit;
