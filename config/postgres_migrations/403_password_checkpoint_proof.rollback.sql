begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_checkpoint_proof403'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=403 and name='password_checkpoint_proof')
       or exists(select 1 from public.schema_migrations where version>403) then
        raise exception 'password_checkpoint_proof403_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Freeze direct tracking writes while checking the legacy proof bound. A
-- busy writer must finish before this schema-only downgrade can be retried.
lock table public.semantic_password_episode_budgets in share mode nowait;

do $$ declare saved record; begin
    select * into strict saved from public.password_restore403;
    if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
        and p.proacl is not distinct from saved.acl and pg_get_functiondef(p.oid)=saved.installed_definition) then
        raise exception 'password_checkpoint_proof403_rollback_finalizer_metadata' using errcode='55000';
    end if;
    -- A SQL-only downgrade would strand any scheduled state the old single
    -- verifier cannot admit. Package rollback uses the pre-upgrade DB backup.
    if exists (
        select 1 from public.semantic_password_checkpoints c
        where c.state_document is not null
          and (exists(select 1 from public.password_pass_state393 p
                where p.scope_digest=c.scope_digest and c.pin in (p.live_pin,p.history_pin))
            or not exists(select 1 from public.password_pass_state393 p where p.scope_digest=c.scope_digest
                and p.rule_id=c.execution_json->>'rule_id'))
          and exists (
            select 1 from (
                select w.value->'witness' as witness from jsonb_array_elements(c.state_document->'window') w(value)
                union select e.value->'seed' from public.password_state_episodes385(c.state_document) e(value)
                union select e.value->'last' from public.password_state_episodes385(c.state_document) e(value)
                union select w.value from public.password_state_episodes385(c.state_document) e(value)
                    cross join lateral jsonb_array_elements(e.value->'prequalification') w(value)
                union select q.tracking_endpoint from public.semantic_password_episode_budgets q
                    where q.scope_digest=c.scope_digest and q.pin=c.pin and q.barrier_unresolved
            ) refs
            having count(*)>10000 or sum((witness->>'xml_bytes')::bigint)>33554432
          )
    ) then raise exception 'password_checkpoint_proof403_rollback_pending_state' using errcode='55000'; end if;
    execute saved.definition;
end $$;

drop function public.password_checkpoint_native_cost403(jsonb,jsonb,bytea,text,text[]);
drop table public.password_restore403;
reset role;
delete from public.schema_migrations where version=403 and name='password_checkpoint_proof';
commit;
