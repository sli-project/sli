begin;
select pg_advisory_xact_lock(hashtext('sli_password_domain_auto371'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=371 and name='password_domain_auto')
       or exists(select 1 from public.schema_migrations where version>371)
       or (select proowner from pg_proc where oid='public.reconcile_password_detection_domain371(uuid)'::regprocedure)
          is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'password_domain_auto371_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.reconcile_password_detection_domain371(uuid);
-- Preserve established ownership, checkpoints, jobs and audit history.
delete from public.schema_migrations where version=371 and name='password_domain_auto';
reset role;
commit;
