-- Execute every DROP as an individual statement on an autocommit connection.
-- Production entry point:
--   python scripts/maintenance/casefold_indexes_migrate.py --rollback ...

drop index concurrently if exists idx_events_subject_casefold_time;
drop index concurrently if exists idx_events_target_casefold_time;
drop index concurrently if exists idx_entities_natural_casefold;
drop index concurrently if exists idx_entities_display_casefold;
drop index concurrently if exists idx_events_v2_subject_casefold_time;
drop index concurrently if exists idx_events_v2_target_casefold_time;
drop index concurrently if exists idx_entities_v2_natural_casefold;
drop index concurrently if exists idx_entities_v2_display_casefold;

delete from schema_migrations
where version=20 and name='casefold_search_indexes';
