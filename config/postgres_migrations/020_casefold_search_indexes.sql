-- Migration 020 is an online index migration.  Every CREATE INDEX must be
-- issued as an individual statement on an autocommit connection; PostgreSQL
-- rejects CREATE INDEX CONCURRENTLY inside a transaction block.
--
-- Production entry point:
--   python scripts/maintenance/casefold_indexes_migrate.py --json
-- followed by its explicit --apply confirmation flow.  Do not feed this file
-- to a migration executor that wraps the complete file in one transaction.

create index concurrently if not exists idx_events_subject_casefold_time
    on events ((lower(subject_user_name)) text_pattern_ops, time_created_utc desc, id desc)
    where subject_user_name is not null;
create index concurrently if not exists idx_events_target_casefold_time
    on events ((lower(target_user_name)) text_pattern_ops, time_created_utc desc, id desc)
    where target_user_name is not null;
create index concurrently if not exists idx_entities_natural_casefold
    on observed_entities ((lower(natural_key)) text_pattern_ops, last_seen_utc desc, id desc);
create index concurrently if not exists idx_entities_display_casefold
    on observed_entities ((lower(display_name)) text_pattern_ops, last_seen_utc desc, id desc);

create index concurrently if not exists idx_events_v2_subject_casefold_time
    on events_v2_core ((lower(subject_user_name)) text_pattern_ops, time_created_utc desc, id desc)
    where subject_user_name is not null;
create index concurrently if not exists idx_events_v2_target_casefold_time
    on events_v2_core ((lower(target_user_name)) text_pattern_ops, time_created_utc desc, id desc)
    where target_user_name is not null;
create index concurrently if not exists idx_entities_v2_natural_casefold
    on entities_v2 ((lower(natural_key)) text_pattern_ops, last_seen_utc desc, id desc);
create index concurrently if not exists idx_entities_v2_display_casefold
    on entities_v2 ((lower(display_name)) text_pattern_ops, last_seen_utc desc, id desc);

-- The runner writes this marker only after every index is valid and ready.
insert into schema_migrations(version, name)
values (20, 'casefold_search_indexes')
on conflict(version) do update set name=excluded.name;
