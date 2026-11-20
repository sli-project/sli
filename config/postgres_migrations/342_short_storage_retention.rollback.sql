begin;
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'short_storage_retention342_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.expire_short_storage_partitions342(timestamptz,timestamptz,timestamptz);
revoke select,insert on public.ad_snapshot_change_history,public.ad_snapshot_history_confirmations from adlog_context_worker;
revoke execute on function public.create_ad_snapshot_change_partition(timestamptz) from adlog_context_worker;
delete from public.schema_migrations where version=342 and name='short_storage_retention';
reset role;
commit;
