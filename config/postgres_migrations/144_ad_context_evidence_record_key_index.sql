-- Migration 144 — index for the entity card's AD Context evidence read.
--
-- Root cause it fixes:
--   server/ad_context/integration.py joins ad_context_evidence to entity and
--   relation versions on
--     evidence.source_run_id = version.source_run_id
--     and evidence.evidence_type = 'entity_observation' | 'relation_observation'
--     and evidence.locator_json->>'record_key' = <version record key>
--   ad_context_evidence had no index on that key, so every entity card read the
--   whole table (stand: ~310k rows / 285 MB, 3.4-3.8 s per card request, close
--   to the 5 s statement budget). With this index the read drops below the
--   500 ms slow-query threshold.
--
-- Additive and non-destructive. CREATE INDEX CONCURRENTLY must run outside a
-- transaction block: the bootstrap executes migration files with psql -f, one
-- autocommit statement at a time; do not wrap this file in a transaction.

create index concurrently if not exists idx_ad_context_evidence_run_type_record_key
    on ad_context_evidence (source_run_id, evidence_type, (locator_json->>'record_key'));

insert into schema_migrations(version, name)
values (144, 'ad_context_evidence_record_key_index')
on conflict(version) do update set name=excluded.name;
