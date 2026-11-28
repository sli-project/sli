begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_account_check_cleanup461'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=461 and name='account_check_cleanup')
       or exists(select 1 from public.schema_migrations where version>461) then
        raise exception 'account_check_cleanup461_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

revoke maintain on public.semantic_account_decoy_checks,public.semantic_account_watch_checks
    from adlog_storage_lifecycle_delete;
drop function public.mark_account_check_vacuumed461(text);
drop function public.account_check_cleanup_status461(text,boolean);
alter table public.account_check_cleanup460 drop column vacuumed;

reset role;
delete from public.schema_migrations where version=461 and name='account_check_cleanup';
commit;
