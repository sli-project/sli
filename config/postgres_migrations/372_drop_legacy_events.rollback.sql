-- DDL-only rollback: the retired event/raw/link data is NOT restored.
-- Former event tables and their partitions are recreated EMPTY. Historical
-- foreign keys on surviving reference rows return NOT VALID because their
-- targets no longer exist; all new writes still obey those foreign keys.
begin;
select pg_advisory_xact_lock(hashtext('sli_drop_legacy_events372'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=372 and name='drop_legacy_events')
       or exists(select 1 from public.schema_migrations where version>372) then
        raise exception 'drop_legacy_events372_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
set local check_function_bodies=off;
do $$ declare item record; begin
    for item in select statement from public.legacy_event_rollback372 where phase<30 order by phase,ordinal loop
        execute item.statement;
    end loop;
end $$;
-- Restore the exact former owners and capabilities via the migration session.
-- Some old functions belong to the closed lifecycle guard; no runtime login
-- receives membership in that owner as part of forward or rollback DDL.
reset role;
do $$ declare item record; begin
    for item in select phase,statement from public.legacy_event_rollback372 where phase>=30 order by phase,ordinal loop
        if item.phase in (50,60) and item.statement not like 'CREATE OR REPLACE FUNCTION public.lock_storage_lifecycle_tables_v319(%' then
            set local role adlog_storage_owner;
        end if;
        execute item.statement;
        reset role;
    end loop;
end $$;
set local role adlog_storage_owner;
drop table public.legacy_event_rollback372;
delete from public.schema_migrations where version=372 and name='drop_legacy_events';
reset role;
commit;
