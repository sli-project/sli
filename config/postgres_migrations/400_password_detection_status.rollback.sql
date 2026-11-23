begin;
select pg_advisory_xact_lock(hashtext('sli_password_detection_status400'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=400 and name='password_detection_status')
       or exists(select 1 from public.schema_migrations where version>400) then
        raise exception 'password_detection_status400_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
drop function public.read_password_live_status400(bigint[]);
delete from public.schema_migrations where version=400 and name='password_detection_status';
reset role;
commit;
