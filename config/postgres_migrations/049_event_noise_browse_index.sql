-- Phase 3 of the online event-noise projection.
-- Apply only through event_noise_classification_migrate.py after its bounded
-- backfill reports zero pending rows.  CONCURRENTLY requires autocommit.
do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=48 and name='event_noise_classification_columns'
    ) then
        raise exception 'migration 049 requires migration 048';
    end if;
    if exists (
        select 1 from events_v2_core
        where noise_catalog_version='pending-backfill'
        limit 1
    ) then
        raise exception 'migration 049 requires a completed noise-class backfill';
    end if;
end
$$;

create index concurrently if not exists idx_events_v2_browse_visible_latest
    on events_v2_core(
        time_created_utc desc,
        (coalesce(event_record_id, -1)) desc,
        id desc
    )
    where noise_class in ('signal', 'not_classified');

insert into schema_migrations(version, name)
values (49, 'event_noise_browse_index')
on conflict(version) do update set name=excluded.name, applied_at=now();
