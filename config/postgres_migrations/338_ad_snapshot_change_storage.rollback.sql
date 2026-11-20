begin;
select pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_storage_v338'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=338 and name='ad_snapshot_change_storage')
       or exists(select 1 from public.schema_migrations where version>338)
       or (select relowner from pg_class where oid=to_regclass('public.ad_snapshot_change_history')) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'ad_snapshot_change_storage_338_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.expire_ad_snapshot_change_partitions(timestamptz);
drop function public.create_ad_snapshot_change_partition(timestamptz);
drop table public.ad_snapshot_change_history;
delete from public.schema_migrations where version=338 and name='ad_snapshot_change_storage';
reset role;
commit;
