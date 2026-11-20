begin;
select pg_advisory_xact_lock(hashtext('sli_event_storage_s2_v335'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'event_storage_s2_335_rollback_preflight' using errcode='55000';
    end if;
    if not exists(select 1 from public.schema_migrations where version=334 and name='account_decoy_restore')
       or not exists(select 1 from public.schema_migrations where version=335 and name='event_storage_s2')
       or exists(select 1 from public.schema_migrations where version>335)
       or (select relowner from pg_class where oid=to_regclass('public.event_hot')) is distinct from 'adlog_storage_owner'::regrole
       or (select relowner from pg_class where oid=to_regclass('public.event_cold_facts')) is distinct from 'adlog_storage_owner'::regrole
       or (select relowner from pg_class where oid=to_regclass('public.event_cold_daily')) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'event_storage_s2_335_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.create_event_storage_partitions(date,date);
-- Dropping a partitioned parent removes only its own partitions, no CASCADE.
drop table public.event_cold_daily;
drop table public.event_cold_facts;
drop table public.event_hot;
delete from public.schema_migrations where version=335 and name='event_storage_s2';
reset role;
commit;
