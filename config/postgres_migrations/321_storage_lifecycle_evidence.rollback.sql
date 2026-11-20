begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_storage_lifecycle_evidence_v321'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=320 and name='semantic_import_summary')
       or not exists(select 1 from public.schema_migrations where version=321 and name='storage_lifecycle_evidence')
       or exists(select 1 from public.schema_migrations where version>321) then
        raise exception 'storage_lifecycle_321_rollback_preflight' using errcode='55000';
    end if;
end $$;
drop function public.storage_lifecycle_evidence_v321(bigint,bigint,integer[],text,text);
set local role adlog_storage_owner;
delete from public.schema_migrations where version=321 and name='storage_lifecycle_evidence';
reset role;
commit;
