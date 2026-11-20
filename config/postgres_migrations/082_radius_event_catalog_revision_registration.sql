-- Register the exact catalogue revision emitted by the bundled RADIUS source
-- pack.  Migration 051 remains the sole owner of the registry and trigger.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_event_catalog_revision_registration_v82')
);

do $$
declare
    revision_function oid;
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 082 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=51 and name='event_catalog_revision_reference'
    ) then
        raise exception 'migration 082 requires migration 051';
    end if;
    if exists(select 1 from schema_migrations where version=82) then
        raise exception 'migration 082 version is already recorded';
    end if;
    if to_regclass('public.event_catalog_revisions') is null then
        raise exception 'migration 082 requires event_catalog_revisions';
    end if;
    if to_regclass('public.events_v2_core') is null then
        raise exception 'migration 082 requires events_v2_core';
    end if;

    revision_function := to_regprocedure(
        'public.set_event_noise_catalog_revision()'
    );
    if revision_function is null or not exists (
        select 1
        from pg_trigger
        where tgname='events_v2_core_catalog_revision'
          and tgrelid='public.events_v2_core'::regclass
          and tgfoid=revision_function
          and not tgisinternal
          and tgenabled in ('O','A')
    ) then
        raise exception 'migration 082 requires the catalog revision trigger';
    end if;
end
$$;

set local role adlog_storage_owner;

insert into event_catalog_revisions(version)
values('2026-07-30-radius-descriptor-v1')
on conflict(version) do nothing;

insert into schema_migrations(version,name)
values(82,'radius_event_catalog_revision_registration');

commit;
