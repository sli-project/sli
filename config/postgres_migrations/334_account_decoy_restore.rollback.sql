begin;
select pg_advisory_xact_lock(hashtext('sli_account_decoy_restore_v334'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'account_decoy_restore_334_rollback_preflight' using errcode='55000';
    end if;
    if not exists(select 1 from public.schema_migrations where version=333 and name='storage_lifecycle_wait')
       or not exists(select 1 from public.schema_migrations where version=334 and name='account_decoy_restore')
       or exists(select 1 from public.schema_migrations where version>334)
       or to_regclass('public.account_decoy_definition334') is null
       or (select proowner from pg_proc where oid='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure)
            is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'account_decoy_restore_334_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

do $$ declare saved record;begin
    if (select count(*) from public.account_decoy_definition334)<>1 then
        raise exception 'account_decoy_restore_334_rollback_snapshot_missing' using errcode='55000';
    end if;
    select * into strict saved from public.account_decoy_definition334
        where signature::regprocedure='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure;
    execute saved.definition;
    if pg_get_functiondef(saved.signature::regprocedure) is distinct from saved.definition
       or (select to_jsonb(p)-'prosrc' from pg_proc p where oid=saved.signature::regprocedure) is distinct from saved.catalog then
        raise exception 'account_decoy_restore_334_rollback_definition_mismatch' using errcode='55000';
    end if;
end $$;
drop table public.account_decoy_definition334;
delete from public.schema_migrations where version=334 and name='account_decoy_restore';
reset role;
commit;
