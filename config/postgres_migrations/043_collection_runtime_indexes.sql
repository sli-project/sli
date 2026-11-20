-- Migration 043 is applied online by
-- scripts/maintenance/collection_runtime_indexes_migrate.py.
-- CREATE INDEX CONCURRENTLY must run on an autocommit connection.

create index concurrently if not exists idx_events_v2_server_channel_latest
    on events_v2_core(
        server_id,
        channel_id,
        time_created_utc desc,
        event_record_id desc
    );

insert into schema_migrations(version, name)
values (43, 'collection_runtime_indexes')
on conflict(version) do update set name=excluded.name;
