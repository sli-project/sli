-- Roll back migration 9 only while the dark V2 schema is empty and migrations 10-11 are absent.
begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_v2_migration_9'));
SET LOCAL ROLE adlog_storage_owner;
DO $$
DECLARE
    populated bigint;
BEGIN
    IF exists (select 1 from schema_migrations where version in (10, 11)) THEN
        RAISE EXCEPTION 'rollback migration 10/11 before migration 9';
    END IF;
    select
        coalesce((select count(*) from events_v2_core), 0)
      + coalesce((select count(*) from entities_v2), 0)
      + coalesce((select count(*) from event_entity_link_blocks_v2), 0)
      + coalesce((select count(*) from storage_v2_archive_blocks), 0)
      into populated;
    IF populated <> 0 THEN
        RAISE EXCEPTION 'migration 9 rollback forbidden: V2 objects contain % rows', populated;
    END IF;
END
$$;
drop table if exists storage_v2_backfill_checkpoints;
drop table if exists storage_v2_archive_blocks;
drop table if exists storage_v2_archive_sets;
drop view if exists event_entity_links_v2;
drop table if exists event_entity_link_blocks_v2;
drop table if exists entity_details_v2;
drop table if exists entities_v2;
drop table if exists event_facts_v2;
drop table if exists events_v2_core;
drop table if exists storage_v2_entity_type;
drop table if exists storage_v2_extracted_from;
drop table if exists storage_v2_role;
drop table if exists storage_v2_domain_name;
drop table if exists storage_v2_keywords;
drop table if exists storage_v2_computer;
drop table if exists storage_v2_channel;
drop table if exists storage_v2_provider;
delete from schema_migrations where version=9;
commit;
