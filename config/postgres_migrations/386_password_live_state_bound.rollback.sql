begin;
select pg_advisory_xact_lock(hashtext('sli_password_live_state_bound386'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=386 and name='password_live_state_bound')
       or exists(select 1 from public.schema_migrations where version>386) then
        raise exception 'password_live_state_bound386_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
do $$ declare r record; begin
    for r in select * from public.password_restore386 loop
        if pg_get_functiondef(r.signature::regprocedure) is distinct from r.installed_definition
           or exists(select 1 from pg_proc where oid=r.signature::regprocedure
                and (proowner is distinct from r.owner_oid or proacl is distinct from r.acl)) then
            raise exception 'password_live_state_bound386_rollback_changed' using errcode='55000'; end if;
    end loop;
    -- A downgrade must never erase live origins to satisfy the old limit.
    -- Lock checkpoints before checking size; leave all event and ledger data intact.
    for r in select state_document from public.semantic_password_checkpoints where state_document is not null for update loop
        if octet_length(r.state_document::text)>4194304 or public.password_v2_json_bytes(r.state_document)>4194304 then
            raise exception 'password_live_state_bound386_rollback_state_bound' using errcode='54000'; end if;
    end loop;
    for r in select * from public.password_restore386 loop execute r.definition; end loop;
end $$;
drop table public.password_restore386;
delete from public.schema_migrations where version=386 and name='password_live_state_bound';
reset role;
commit;
