-- Remove migration 092 only while no V2 event references its catalogue revision.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_current_event_catalog_revision_v92')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 092 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=92 and name='current_event_catalog_revision'
    ) then
        raise exception 'rollback 092 requires migration 092';
    end if;
    if exists (
        select 1
        from events_v2_core
        where noise_catalog_version='2026-08-25-descriptor-v7-stage8-process-activity'
    ) then
        raise exception 'rollback 092 blocked: events_v2_core references the current event catalogue revision';
    end if;
end
$$;

set local role adlog_storage_owner;

delete from event_catalog_revisions
where version='2026-08-25-descriptor-v7-stage8-process-activity';

delete from schema_migrations where version=92;

commit;
