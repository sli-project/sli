-- Rollback for migration 044.
--
-- Dropping an index is non-destructive to data: the workspace read falls back to
-- the previous full sort of `entities_v2`.  The application-side fail-soft in
-- reporting_v4.workspace() keeps the main screen alive in that case, degrading
-- `recent_objects_state` to `temporarily_unavailable` instead of HTTP 500.
--
-- DROP INDEX CONCURRENTLY must also run on an autocommit connection.

drop index concurrently if exists idx_entities_v2_recent;

delete from schema_migrations where version = 44;
