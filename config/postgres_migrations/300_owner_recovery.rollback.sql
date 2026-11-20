begin;
select pg_advisory_xact_lock(hashtext('ad_log_owner_recovery_v300'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'rollback 300 requires adlog_storage_owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=300 and name='owner_recovery')
       or exists(select 1 from public.schema_migrations where version>300) then
        raise exception 'rollback requires exact migration 300 and no successors';
    end if;
end $$;
set local role adlog_storage_owner;
drop table public.auth_owner_recovery;
delete from public.schema_migrations where version=300 and name='owner_recovery';
reset role;
commit;
