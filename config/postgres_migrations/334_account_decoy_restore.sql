-- Restore only the decoy reader to its exact pre-327 (326) definition.
-- Keep the directory readers, provenance index and private 327 snapshot intact.
begin;
select pg_advisory_xact_lock(hashtext('sli_account_decoy_restore_v334'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'account_decoy_restore_334_preflight' using errcode='55000';
    end if;
    if not exists(select 1 from public.schema_migrations where version=333 and name='storage_lifecycle_wait')
       or exists(select 1 from public.schema_migrations where version>=334)
       or to_regclass('public.detector_definitions327') is null
       or (select proowner from pg_proc where oid='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure)
            is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'account_decoy_restore_334_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

do $$ begin
    if (select count(*) from public.detector_definitions327
        where signature::regprocedure='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure)<>1 then
        raise exception 'account_decoy_restore_334_snapshot_missing' using errcode='55000';
    end if;
end $$;
create table public.account_decoy_definition334(signature text primary key,definition text not null,catalog jsonb not null);
revoke all on public.account_decoy_definition334 from public,adlog_user,adlog_semantic_worker;
insert into public.account_decoy_definition334
select oid::regprocedure::text,pg_get_functiondef(oid),to_jsonb(p)-'prosrc'
from pg_proc p where oid='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure;

do $$ declare saved record;begin
    select * into strict saved from public.detector_definitions327
        where signature::regprocedure='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure;
    execute saved.definition;
    if pg_get_functiondef(saved.signature::regprocedure) is distinct from saved.definition
       or (select to_jsonb(p)-'prosrc' from pg_proc p where oid=saved.signature::regprocedure)
            is distinct from (select catalog from public.account_decoy_definition334) then
        raise exception 'account_decoy_restore_334_definition_mismatch' using errcode='55000';
    end if;
end $$;
insert into public.schema_migrations(version,name) values(334,'account_decoy_restore');
reset role;
commit;
