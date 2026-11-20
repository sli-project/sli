begin;
select pg_advisory_xact_lock(hashtext('ad_log_login_account_throttle_v299'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'rollback 299 requires adlog_storage_owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=299 and name='login_account_throttle')
       or exists(select 1 from public.schema_migrations where version>299) then
        raise exception 'rollback requires exact migration 299 and no successors';
    end if;
end $$;
set local role adlog_storage_owner;
drop table public.auth_login_throttle;
delete from public.schema_migrations where version=299 and name='login_account_throttle';
reset role;
commit;
