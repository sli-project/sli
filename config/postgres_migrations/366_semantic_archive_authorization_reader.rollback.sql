begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_archive_authorization_reader366'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=366 and name='semantic_archive_authorization_reader')
       or exists(select 1 from public.schema_migrations where version>366)
       or (select relowner from pg_class where oid=to_regclass('public.storage_v2_runtime_authorizations')) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_archive_authorization_reader366_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

revoke select on public.storage_v2_runtime_authorizations from adlog_semantic_worker;
-- Source evidence, admissions and queued or terminal jobs remain intact.
delete from public.schema_migrations where version=366 and name='semantic_archive_authorization_reader';
reset role;
commit;
