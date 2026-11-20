-- Migration 044 — composite index for the "recent objects" workspace read.
--
-- Root cause it fixes:
--   server/app/reporting_v4.py:workspace() reads
--     select ... from entities_v2 entity
--     join storage_v2_entity_type ...
--     order by entity.last_seen_utc desc nulls last, entity.id desc
--     limit 8
--   with statement_timeout_ms=3000.  There was no index matching that ORDER BY,
--   so PostgreSQL sorted the whole `entities_v2` relation.  On the production
--   table the read exceeded the 3 s budget and the unhandled QueryTimeoutError
--   turned GET /api/v1/workspace — the main screen — into HTTP 500.
--
-- The application-side fail-soft is fixed separately; this migration removes the
-- cause instead of only the symptom.  Same shape as migration 043.
--
-- Applied online. CREATE INDEX CONCURRENTLY must run on an autocommit
-- connection, so this file is executed by
-- scripts/maintenance/entities_v2_recent_index_migrate.py and NOT by the
-- transactional migration runner.
--
-- `nulls last` on a DESC column is PostgreSQL's default ordering, so the index
-- below matches the query's ORDER BY exactly and supports an index-only scan of
-- the first 8 rows.

create index concurrently if not exists idx_entities_v2_recent
    on entities_v2(
        last_seen_utc desc,
        id desc
    );

insert into schema_migrations(version, name)
values (44, 'entities_v2_recent_index')
on conflict(version) do update set name=excluded.name;
