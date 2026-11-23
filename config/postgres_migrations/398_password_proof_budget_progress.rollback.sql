begin;
select pg_advisory_xact_lock(hashtext('sli_password_proof_budget_progress398'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=398 and name='password_proof_budget_progress')
       or exists(select 1 from public.schema_migrations where version>398) then
        raise exception 'password_proof_budget_progress398_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;

do $$ declare saved record; begin
    for saved in select * from public.password_restore398 loop
        if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
            and p.proacl is not distinct from saved.acl and pg_get_functiondef(p.oid)=saved.installed_definition) then
            raise exception 'password_proof_budget_progress398_rollback_metadata_changed' using errcode='55000'; end if;
        execute saved.definition;
    end loop;
end $$;

drop function public.password_decision_limit398();
drop table public.password_restore398;
delete from public.schema_migrations where version=398 and name='password_proof_budget_progress';
reset role;
commit;
