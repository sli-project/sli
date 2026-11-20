-- Roll back migration 10 only before routing migration and while queues/history are empty.
begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_v2_migration_10'));
SET LOCAL ROLE adlog_storage_owner;
DO $$
DECLARE
    populated bigint;
BEGIN
    IF exists (select 1 from schema_migrations where version=11) THEN
        RAISE EXCEPTION 'rollback migration 11 before migration 10';
    END IF;
    select
        coalesce((select count(*) from storage_v2_outbox), 0)
      + coalesce((select count(*) from storage_v2_shadow_results), 0)
      + coalesce((select count(*) from storage_v2_backfill_chunks), 0)
      into populated;
    IF populated <> 0 THEN
        RAISE EXCEPTION 'migration 10 rollback forbidden: support objects contain % rows', populated;
    END IF;
END
$$;
revoke all on table storage_v2_backfill_chunks, storage_v2_outbox, storage_v2_shadow_results from adlog_storage_worker;
drop table if exists storage_v2_shadow_results;
drop table if exists storage_v2_outbox;
drop table if exists storage_v2_backfill_chunks;
delete from schema_migrations where version=10;
commit;
