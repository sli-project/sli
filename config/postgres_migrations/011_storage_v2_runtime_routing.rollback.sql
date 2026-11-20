-- Roll back migration 11 only while routing remains fully on V1 and the outbox has no work.
begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_v2_migration_11'));
SET LOCAL ROLE adlog_storage_owner;
DO $$
DECLARE
    routing record;
    pending bigint;
BEGIN
    select * into routing from storage_v2_cutover_state where singleton=true;
    IF routing.read_mode <> 'v1' or routing.write_mode <> 'v1' THEN
        RAISE EXCEPTION 'migration 11 rollback forbidden while routing is %, %', routing.read_mode, routing.write_mode;
    END IF;
    select count(*) into pending from storage_v2_outbox where state not in ('completed', 'quarantined');
    IF pending <> 0 THEN
        RAISE EXCEPTION 'migration 11 rollback forbidden: % outbox rows are active', pending;
    END IF;
END
$$;
revoke select on storage_v2_cutover_state from adlog_user;
revoke select on events_v2_core, event_facts_v2, entities_v2, entity_details_v2, event_entity_link_blocks_v2 from adlog_user;
revoke select on event_entity_links_v2 from adlog_user;
revoke references on events_v2_core, entities_v2 from adlog_user;
revoke select on storage_v2_archive_sets, storage_v2_archive_blocks from adlog_user;
revoke select, insert on storage_v2_outbox from adlog_user;
revoke insert on storage_v2_shadow_results from adlog_user;
revoke usage, select on sequence storage_v2_outbox_id_seq, storage_v2_shadow_results_id_seq from adlog_user;
drop table if exists storage_v2_cutover_state;
delete from schema_migrations where version=11;
commit;
