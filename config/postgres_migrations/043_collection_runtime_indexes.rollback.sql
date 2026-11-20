-- Applied online by scripts/maintenance/collection_runtime_indexes_migrate.py.

drop index concurrently if exists idx_events_v2_server_channel_latest;

delete from schema_migrations
where version = 43 and name = 'collection_runtime_indexes';
