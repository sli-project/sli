-- Register the event catalogue revision emitted by the current direct V2 importer.
-- Additive only: no event rows or earlier catalogue revisions are changed.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_current_event_catalog_revision_v92')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 092 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=91 and name='storage_v2_runtime_authorization'
    ) then
        raise exception 'migration 092 requires migration 091';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=51 and name='event_catalog_revision_reference'
    ) then
        raise exception 'migration 092 requires migration 051';
    end if;
    if to_regclass('event_catalog_revisions') is null then
        raise exception 'migration 092 requires event_catalog_revisions';
    end if;
    if to_regprocedure('set_event_noise_catalog_revision()') is null then
        raise exception 'migration 092 requires the catalog revision trigger function';
    end if;
    if exists(select 1 from schema_migrations where version=92) then
        raise exception 'migration 092 version is already recorded';
    end if;
end
$$;

set local role adlog_storage_owner;

insert into event_catalog_revisions(version)
values('2026-08-25-descriptor-v7-stage8-process-activity')
on conflict(version) do nothing;

insert into schema_migrations(version,name)
values(92,'current_event_catalog_revision')
on conflict(version) do update set name=excluded.name;

commit;
