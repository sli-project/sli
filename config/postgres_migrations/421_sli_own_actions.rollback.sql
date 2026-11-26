begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_own_actions421'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=421 and name='sli_own_actions')
       or exists(select 1 from public.schema_migrations where version>421) then
        raise exception 'sli_own_actions421_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Retain the recorded decisions on existing findings.
do $$ declare original text; begin
    select definition into strict original from public.sli_catalog_restore421;
    execute original;
end $$;
drop table public.sli_catalog_restore421;
drop function public.sli_audit_apply421(bigint,timestamptz);
drop function public.sli_service_install421(bigint,timestamptz);
drop function public.sli_catalog_maintenance421(integer,text,text,jsonb);
drop table public.sli_maintenance_catalog421;

reset role;
delete from public.schema_migrations where version=421 and name='sli_own_actions';
commit;
