begin;
select pg_advisory_xact_lock(hashtext('sli_password_state_and_step385'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=385 and name='password_state_and_step')
       or exists(select 1 from public.schema_migrations where version>385) then
        raise exception 'password_state_and_step385_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
do $$ declare r record; expanded jsonb; begin
    for r in select * from public.password_restore385 loop
        if pg_get_functiondef(r.signature::regprocedure) is distinct from r.installed_definition
           or exists(select 1 from pg_proc where oid=r.signature::regprocedure
                and (proowner is distinct from r.owner_oid or proacl is distinct from r.acl)) then
            raise exception 'password_state_and_step385_rollback_changed' using errcode='55000'; end if;
    end loop;
    -- Preserve all working data. Refuse an unsafe downgrade rather than lose
    -- qualified history or install a validator unable to read the checkpoint.
    for r in select * from public.semantic_password_checkpoints where state_document is not null for update loop
        -- Expired admission confirmations already have their immutable ledger
        -- and jobs. Like the next producer batch, discard only this working copy.
        expanded:=jsonb_set(r.state_document-'closed_admissions','{episodes}',(select coalesce(jsonb_agg(e),'[]'::jsonb)
            from public.password_state_episodes385(r.state_document-'closed_admissions') e));
        if octet_length(expanded::text)>4194304 or public.password_v2_json_bytes(expanded)>4194304 then
            raise exception 'password_state_and_step385_rollback_state_bound' using errcode='54000'; end if;
        update public.semantic_password_checkpoints set state_document=expanded where scope_digest=r.scope_digest and pin=r.pin;
    end loop;
end $$;
set constraints all immediate;
do $$ declare r record; begin
    for r in select * from public.password_restore385 loop execute r.definition; end loop;
end $$;
drop function public.password_read_from385(jsonb,jsonb,timestamptz);
drop function public.password_state_episodes385(jsonb);
drop table public.password_restore385;
delete from public.schema_migrations where version=385 and name='password_state_and_step';
reset role;
commit;
