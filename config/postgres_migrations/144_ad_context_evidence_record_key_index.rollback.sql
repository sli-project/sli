-- Rollback for migration 144.
--
-- Dropping the index is non-destructive to data: the AD Context evidence read
-- falls back to a full scan of ad_context_evidence (slow, bounded by its 5 s
-- statement budget). DROP INDEX CONCURRENTLY must also run outside a
-- transaction block.

drop index concurrently if exists idx_ad_context_evidence_run_type_record_key;

delete from schema_migrations where version = 144;
