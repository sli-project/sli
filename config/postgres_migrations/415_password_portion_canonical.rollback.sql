begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_checkpoint_proof403'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=415 and name='password_portion_canonical')
       or exists(select 1 from public.schema_migrations where version>415) then
        raise exception 'password_portion_canonical415_rollback_preflight' using errcode='55000';
    end if;
end $$;

set local role adlog_storage_owner;

do $rollback$
declare saved public.password_portion_canonical_restore415%rowtype;
begin
    select * into strict saved from public.password_portion_canonical_restore415
    where signature='public.password_v2_decode(jsonb,jsonb,jsonb)'::regprocedure;
    if pg_get_functiondef(saved.signature) is distinct from saved.installed_definition then
        raise exception 'password_portion_canonical415_rollback_shape' using errcode='55000';
    end if;
    execute saved.original_definition;
    if pg_get_functiondef(saved.signature) is distinct from saved.original_definition or not exists(
        select 1 from pg_proc where oid=saved.signature and proowner=saved.owner_oid and proacl is not distinct from saved.acl
    ) then raise exception 'password_portion_canonical415_rollback_metadata' using errcode='55000'; end if;
end $rollback$;

drop table public.password_portion_canonical_restore415;
reset role;
delete from public.schema_migrations where version=415 and name='password_portion_canonical';
commit;
