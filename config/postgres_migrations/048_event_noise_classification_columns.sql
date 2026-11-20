-- Phase 1 of the online event-noise projection.
-- Existing rows receive an explicit pending revision without a table rewrite
-- on supported PostgreSQL versions.  The bounded application backfill replaces
-- it before migration 049 builds the browsing index.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_event_noise_columns_v48'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=47 and name='collector_partial_failure_evidence'
    ) then
        raise exception 'migration 048 requires migration 047';
    end if;
    if to_regclass('events_v2_core') is null then
        raise exception 'migration 048 requires events_v2_core';
    end if;
end
$$;

alter table events_v2_core
    add column if not exists noise_class text
        not null default 'not_classified',
    add column if not exists noise_catalog_version text
        not null default 'pending-backfill';

alter table events_v2_core
    drop constraint if exists events_v2_core_noise_class,
    add constraint events_v2_core_noise_class check (
        noise_class in ('signal', 'context', 'noise', 'not_classified')
    ) not valid,
    drop constraint if exists events_v2_core_noise_catalog_version,
    add constraint events_v2_core_noise_catalog_version check (
        length(noise_catalog_version) between 1 and 255
    ) not valid;

insert into schema_migrations(version, name)
values (48, 'event_noise_classification_columns')
on conflict(version) do update set name=excluded.name, applied_at=now();

commit;
