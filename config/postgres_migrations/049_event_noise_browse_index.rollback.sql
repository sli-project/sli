drop index concurrently if exists idx_events_v2_browse_visible_latest;

delete from schema_migrations
where version=49 and name='event_noise_browse_index';
